package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/pgwire"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
)

// startFakePostgres runs a minimal PostgreSQL Wire Protocol v3 server in-memory for race-tested CI integration tests.
func startFakePostgres(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakePGConn(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveFakePGConn(c net.Conn) {
	defer c.Close()
	for {
		pkt, err := pgwire.ReadStartupPacket(c)
		if err != nil {
			return
		}
		if pkt.Code == pgwire.SSLRequestCode || pkt.Code == pgwire.GSSENCRequestCode {
			_, _ = c.Write([]byte{'N'})
			continue
		}
		break
	}
	// AuthOK (0) + ReadyForQuery ('I')
	var authOK [4]byte
	_ = pgwire.WriteMessage(c, pgwire.MsgAuth, authOK[:])
	_ = pgwire.WriteMessage(c, pgwire.MsgParameterStatus, []byte("server_version\x0016.4\x00"))
	_ = pgwire.WriteMessage(c, pgwire.MsgParameterStatus, []byte("client_encoding\x00UTF8\x00"))
	_ = pgwire.WriteMessage(c, pgwire.MsgParameterStatus, []byte("standard_conforming_strings\x00on\x00"))
	_ = pgwire.WriteMessage(c, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))

	r := bufio.NewReader(c)
	var lastParsed string
	for {
		mType, payload, err := pgwire.ReadMessage(r)
		if err != nil {
			return
		}
		switch mType {
		case pgwire.MsgTerminate:
			return
		case pgwire.MsgQuery:
			sql := strings.ToUpper(strings.TrimSpace(pgwire.ParseSimpleQuery(payload)))
			sendFakeResult(c, sql)
			_ = pgwire.WriteMessage(c, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
		case pgwire.MsgParse:
			_, q, _ := pgwire.ParseParseMessage(payload)
			lastParsed = strings.ToUpper(strings.TrimSpace(q))
		case pgwire.MsgSync:
			_ = pgwire.WriteMessage(c, pgwire.MsgParseComplete, nil)
			_ = pgwire.WriteMessage(c, pgwire.MsgBindComplete, nil)
			sendFakeResult(c, lastParsed)
			_ = pgwire.WriteMessage(c, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery('I'))
		}
	}
}

func sendFakeResult(w io.Writer, sql string) {
	if strings.HasPrefix(sql, "UPDATE") {
		_ = pgwire.WriteMessage(w, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete("UPDATE 1"))
		return
	}
	if strings.Contains(sql, "DISPLAY_NAME") {
		rowDesc := encodeRowDesc([]string{"id", "display_name"})
		_ = pgwire.WriteMessage(w, pgwire.MsgRowDescription, rowDesc)
		dr := pgwire.EncodeDataRow([][]byte{[]byte("1"), []byte("Ahmet Yılmaz")})
		_ = pgwire.WriteMessage(w, pgwire.MsgDataRow, dr)
		_ = pgwire.WriteMessage(w, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete("SELECT 1"))
		return
	}
	// Return 40 synthetic PII rows for customers query
	rowDesc := encodeRowDesc([]string{"id", "email", "tckn", "iban", "note"})
	_ = pgwire.WriteMessage(w, pgwire.MsgRowDescription, rowDesc)
	count := 3
	if strings.Contains(sql, "ALL_ROWS") {
		count = 40
	}
	for i := 1; i <= count; i++ {
		dr := pgwire.EncodeDataRow([][]byte{
			[]byte("1"),
			[]byte("ayse.kaya@example.com.tr"),
			[]byte("10000000146"),
			[]byte("TR330006100519786457841326"),
			[]byte("Call me or refund card 4242-4242-4242-4242 and key AKIAIOSFODNN7EXAMPLE"),
		})
		_ = pgwire.WriteMessage(w, pgwire.MsgDataRow, dr)
	}
	_ = pgwire.WriteMessage(w, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete("SELECT 40"))
}

func encodeRowDesc(cols []string) []byte {
	var buf []byte
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(cols)))
	buf = append(buf, cnt[:]...)
	for i, name := range cols {
		buf = append(buf, []byte(name)...)
		buf = append(buf, 0)
		var meta [18]byte
		binary.BigEndian.PutUint32(meta[0:4], 16384)
		binary.BigEndian.PutUint16(meta[4:6], uint16(i+1))
		binary.BigEndian.PutUint32(meta[6:10], 25) // text OID
		binary.BigEndian.PutUint16(meta[10:12], 0xFFFF)
		binary.BigEndian.PutUint32(meta[12:16], 0xFFFFFFFF)
		binary.BigEndian.PutUint16(meta[16:18], 0) // text format
		buf = append(buf, meta[:]...)
	}
	return buf
}

func TestEndToEndWireMaskingFirewallAndLiveHITL(t *testing.T) {
	pgAddr, stopPG := startFakePostgres(t)
	defer stopPG()

	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mgr.Config()
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.Server.UpstreamAddr = pgAddr

	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	hitlMgr := hitl.NewManager(50)
	bus := events.NewBus(100, policy.KafkaConfig{}, metrics)
	defer bus.Close()

	srv, err := NewServer(mgr, hitlMgr, bus, metrics, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Start(ctx) }()
	// Wait for ephemeral listener to bind
	var proxyAddr string
	for i := 0; i < 50; i++ {
		if a := srv.Addr(); a != "" {
			proxyAddr = a
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if proxyAddr == "" {
		t.Fatal("proxy did not bind")
	}

	// Connect via real jackc/pgx/v5 driver as ai_agent!
	dsn := "postgres://pgveil:pw@" + proxyAddr + "/pgveil_demo?sslmode=disable&application_name=claude-mcp-agent"
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	var notices []string
	connCfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		notices = append(notices, n.Message)
	}

	conn, err := pgx.ConnectConfig(ctx, connCfg)
	if err != nil {
		t.Fatalf("pgx connect through pgveil failed: %v", err)
	}
	defer conn.Close(ctx)

	// 1. Dynamic wire-speed PII masking + auto-detection on unstructured note column
	var id, email, tckn, iban, note string
	err = conn.QueryRow(ctx, "SELECT id, email, tckn, iban, note FROM customers LIMIT 1").Scan(&id, &email, &tckn, &iban, &note)
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if strings.Contains(email, "ayse.kaya") || strings.Contains(tckn, "10000000146") || strings.Contains(iban, "1978645784") {
		t.Fatalf("PII leaked over wire: email=%q tckn=%q iban=%q", email, tckn, iban)
	}
	if strings.Contains(note, "4242-4242-4242-4242") || strings.Contains(note, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("free-text PII/secret leaked in note: %q", note)
	}

	// 2. AST Firewall blocks DROP TABLE cleanly and keeps connection alive!
	if _, err := conn.Exec(ctx, "DROP TABLE orders"); err == nil {
		t.Fatal("expected DROP TABLE to be blocked by AST firewall")
	}

	// 3. Row-exfiltration cap (ai_agent max_rows = 25) truncates 40 rows to 25 + emits PostgreSQL NOTICE
	rows, err := conn.Query(ctx, "SELECT id, email, tckn, iban, note FROM customers /* ALL_ROWS */")
	if err != nil {
		t.Fatalf("bulk SELECT failed: %v", err)
	}
	gotRows := 0
	for rows.Next() {
		gotRows++
	}
	rows.Close()
	if gotRows != 25 {
		t.Fatalf("expected wire row cap of 25, got %d", gotRows)
	}
	if len(notices) == 0 || !strings.Contains(notices[0], "truncated to 25 rows") {
		t.Fatalf("expected pgveil truncation NOTICE, got %v", notices)
	}

	// 4. Live Synchronous HITL Approval Hold: UPDATE pauses until operator approves!
	go func() {
		for i := 0; i < 100; i++ {
			pending := hitlMgr.List("PENDING")
			if len(pending) > 0 {
				_, _ = hitlMgr.Resolve(pending[0].ID, true, "test-dba", "approved in test")
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	tag, err := conn.Exec(ctx, "UPDATE orders SET status = 'refunded' WHERE id = 1001")
	if err != nil {
		t.Fatalf("HITL-approved UPDATE failed: %v", err)
	}
	if tag.String() != "UPDATE 1" {
		t.Fatalf("expected UPDATE 1, got %q", tag.String())
	}

	// 5. PII Side-Channel Oracle probe blocked cleanly on the wire
	if _, err := conn.Exec(ctx, "SELECT id, full_name FROM customers WHERE tckn LIKE '100000%'"); err == nil {
		t.Fatal("expected PII side-channel WHERE tckn LIKE probe to be blocked")
	}

	// Verify audit bus recorded all events cleanly
	sum := bus.Summary()
	if sum.TotalQueries < 5 || sum.BlockedQueries < 2 || sum.TotalPIIFields < 5 || sum.TruncatedQueries < 1 || sum.HITLTriggered < 1 {
		t.Fatalf("unexpected audit summary: %+v", sum)
	}
}

func TestShadowAuditModeAndRunawayLoopBreaker(t *testing.T) {
	pgAddr, stopPG := startFakePostgres(t)
	defer stopPG()

	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mgr.Config()
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.Server.UpstreamAddr = pgAddr

	// Enable loop threshold on ai_agent and set analyst to shadow audit mode
	for i := range cfg.Profiles {
		if cfg.Profiles[i].Name == "ai_agent" {
			cfg.Profiles[i].Firewall.RateLimit.LoopThreshold = 3
			cfg.Profiles[i].Firewall.RateLimit.LoopWindow = "10s"
		}
		if cfg.Profiles[i].Name == "analyst" {
			cfg.Profiles[i].Mode = "audit"
		}
	}

	bus := events.NewBus(100, policy.KafkaConfig{}, nil)
	defer bus.Close()
	srv, err := NewServer(mgr, hitl.NewManager(20), bus, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	var proxyAddr string
	for i := 0; i < 50; i++ {
		if a := srv.Addr(); a != "" {
			proxyAddr = a
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 1. Runaway loop circuit breaker trips on 4th identical query from ai_agent
	dsnAI := "postgres://pgveil:pw@" + proxyAddr + "/pgveil_demo?sslmode=disable&application_name=ai_agent"
	ccAI, _ := pgx.ParseConfig(dsnAI)
	ccAI.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cAI, err := pgx.ConnectConfig(ctx, ccAI)
	if err != nil {
		t.Fatal(err)
	}
	defer cAI.Close(ctx)

	for i := 0; i < 3; i++ {
		rows, err := cAI.Query(ctx, "SELECT id FROM customers LIMIT 1")
		if err != nil {
			t.Fatalf("query %d unexpectedly failed: %v", i+1, err)
		}
		rows.Close()
	}
	if _, err := cAI.Exec(ctx, "SELECT id FROM customers LIMIT 1"); err == nil || !strings.Contains(err.Error(), "Runaway query loop") {
		t.Fatalf("expected runaway loop circuit breaker error on 4th repeat, got: %v", err)
	}

	// 2. Shadow/Audit-only mode logs WOULD_BLOCK without breaking the query
	dsnShadow := "postgres://pgveil:pw@" + proxyAddr + "/pgveil_demo?sslmode=disable&application_name=analyst"
	ccSh, _ := pgx.ParseConfig(dsnShadow)
	ccSh.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cSh, err := pgx.ConnectConfig(ctx, ccSh)
	if err != nil {
		t.Fatal(err)
	}
	defer cSh.Close(ctx)

	rows, err := cSh.Query(ctx, "DROP TABLE orders")
	if err != nil {
		t.Fatalf("shadow audit mode should NOT block queries, got: %v", err)
	}
	rows.Close()

	recent := bus.Recent(5, "WOULD_BLOCK", "analyst")
	if len(recent) == 0 {
		t.Fatalf("expected WOULD_BLOCK audit event in shadow mode, recent=%+v", bus.Recent(5, "", "analyst"))
	}
}

func TestWireSecurityRegressions_FastPathAliasAndPipelineBypass(t *testing.T) {
	pgAddr, stopPG := startFakePostgres(t)
	defer stopPG()

	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := mgr.Config()
	cfg.Server.ListenAddr = "127.0.0.1:0"
	cfg.Server.UpstreamAddr = pgAddr

	bus := events.NewBus(100, policy.KafkaConfig{}, nil)
	defer bus.Close()
	srv, err := NewServer(mgr, hitl.NewManager(20), bus, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	var proxyAddr string
	for i := 0; i < 50; i++ {
		if a := srv.Addr(); a != "" {
			proxyAddr = a
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 1. Raw wire test: Fast-Path FunctionCall ('F') MUST be blocked & Pipelined Parse(DROP) + Parse(SELECT 1) + Sync MUST be blocked!
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send StartupMessage v3.0 (user=pgveil, database=pgveil_demo, application_name=ai_agent)
	var startupBody []byte
	startupBody = append(startupBody, 0, 3, 0, 0) // 196608
	for _, kv := range [][2]string{{"user", "pgveil"}, {"database", "pgveil_demo"}, {"application_name", "ai_agent"}} {
		startupBody = append(startupBody, []byte(kv[0])...)
		startupBody = append(startupBody, 0)
		startupBody = append(startupBody, []byte(kv[1])...)
		startupBody = append(startupBody, 0)
	}
	startupBody = append(startupBody, 0)
	startup := make([]byte, 4+len(startupBody))
	binary.BigEndian.PutUint32(startup[0:4], uint32(len(startup)))
	copy(startup[4:], startupBody)
	if _, err := conn.Write(startup); err != nil {
		t.Fatal(err)
	}
	for {
		mt, _, err := pgwire.ReadMessage(conn)
		if err != nil {
			t.Fatal(err)
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}

	// 1a. Legacy Fast-Path FunctionCall ('F') frame MUST return ErrorResponse + ReadyForQuery
	if err := pgwire.WriteMessage(conn, pgwire.MsgFunctionCall, []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	mt, payload, err := pgwire.ReadMessage(conn)
	if err != nil || mt != pgwire.MsgErrorResponse || !strings.Contains(string(payload), "FunctionCall") {
		t.Fatalf("expected Fast-Path FunctionCall block, got type=%q payload=%q err=%v", mt, string(payload), err)
	}
	if mt, _, err := pgwire.ReadMessage(conn); err != nil || mt != pgwire.MsgReadyForQuery {
		t.Fatalf("expected ReadyForQuery after FunctionCall error, got %q err=%v", mt, err)
	}

	// 1b. Pipelined Extended Query Bypass: Parse("DROP TABLE orders") + Parse("SELECT 1") + Sync MUST be BLOCKED!
	buildParse := func(stmt, q string) []byte {
		var p []byte
		p = append(p, []byte(stmt)...)
		p = append(p, 0)
		p = append(p, []byte(q)...)
		p = append(p, 0, 0, 0)
		return p
	}
	_ = pgwire.WriteMessage(conn, pgwire.MsgParse, buildParse("s1", "DROP TABLE orders"))
	_ = pgwire.WriteMessage(conn, pgwire.MsgParse, buildParse("s2", "SELECT 1"))
	_ = pgwire.WriteMessage(conn, pgwire.MsgSync, nil)

	mt, payload, err = pgwire.ReadMessage(conn)
	if err != nil || mt != pgwire.MsgErrorResponse || !strings.Contains(string(payload), "block_ddl") {
		t.Fatalf("pipelined DROP TABLE bypassed firewall! got type=%q payload=%q err=%v", mt, string(payload), err)
	}
	if mt, _, err := pgwire.ReadMessage(conn); err != nil || mt != pgwire.MsgReadyForQuery {
		t.Fatalf("expected ReadyForQuery after pipelined block, got %q err=%v", mt, err)
	}

	// 2. Column-alias masking bypass test: `SELECT id, full_name AS display_name FROM customers`
	// Even though RowDescription sends column name "display_name", AST provenance MUST apply `full_name: hash`!
	dsnAI := "postgres://pgveil:pw@" + proxyAddr + "/pgveil_demo?sslmode=disable&application_name=ai_agent"
	ccAI, _ := pgx.ParseConfig(dsnAI)
	ccAI.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cAI, err := pgx.ConnectConfig(ctx, ccAI)
	if err != nil {
		t.Fatal(err)
	}
	defer cAI.Close(ctx)

	var id, displayName string
	if err := cAI.QueryRow(ctx, "SELECT id, full_name AS display_name FROM customers LIMIT 1").Scan(&id, &displayName); err != nil {
		t.Fatalf("aliased query failed: %v", err)
	}
	if strings.Contains(displayName, "Ahmet") || !strings.HasPrefix(displayName, "tok_") {
		t.Fatalf("column alias bypassed full_name hash masking! got display_name=%q", displayName)
	}
}
