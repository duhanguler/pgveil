package proxy_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/pgwire"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

func generateTempSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

func TestProxyTLSFlushHITLModesRowBlockAndWebhook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	upAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo start: %v", err)
	}

	var webhookHits atomic.Int32
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	certFile, keyFile := generateTempSelfSignedCert(t)
	cfgYAML := `
server:
  listen_addr: "127.0.0.1:0"
  upstream_addr: "` + upAddr + `"
  upstream_user: "pgveil"
  upstream_database: "pgveil_demo"
  tls:
    enabled: true
    cert_file: "` + certFile + `"
    key_file: "` + keyFile + `"
notifications:
  webhook_url: "` + whSrv.URL + `"
security:
  masking_secret: "proxy-cov-secret"
  compliance_packs: ["gdpr", "kvkk", "pci-dss", "hipaa", "secrets"]
default_profile: "strict_block"
profiles:
  - name: "strict_block"
    match:
      application_names: ["strict_block"]
    firewall:
      allow_statements: ["SELECT", "SHOW"]
      block_ddl: true
      block_multi_statement: true
      block_write_without_where: true
      require_hitl_statements: ["UPDATE"]
      hitl_mode: "reject"
      max_rows: 2
      max_rows_action: "block"
    masking:
      enabled: true
      auto_detect_pii: true
      column_rules:
        - column: "tckn"
          strategy: "partial"
  - name: "hold_deny"
    match:
      application_names: ["hold_deny"]
    firewall:
      allow_statements: ["SELECT"]
      require_hitl_statements: ["UPDATE", "DELETE"]
      hitl_mode: "hold"
      hitl_timeout: "120ms"
      row_filters:
        - table: "customers"
          predicate: "city = 'Istanbul'"
    masking:
      enabled: true
      auto_detect_pii: true
      column_rules:
        - column: "tckn"
          strategy: "partial"
  - name: "shadow_ext"
    mode: "audit"
    match:
      application_names: ["shadow_ext"]
    firewall:
      allow_statements: ["SELECT"]
      block_ddl: true
      require_hitl_statements: ["UPDATE"]
      rate_limit:
        max_queries_per_minute: 1
`
	mgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hitlMgr := hitl.NewManager(50)
	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	tracer, shutdown := telemetry.InitTracer(ctx, "pgveil-proxy-test", false, "")
	defer func() { _ = shutdown(context.Background()) }()

	bus := events.NewBus(100, policy.KafkaConfig{}, metrics)
	defer bus.Close()

	srv, err := proxy.NewServer(mgr, hitlMgr, bus, metrics, tracer)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	pAddr := srv.Addr()

	// 1. Handshake edge cases: GSSENCRequest ('N'), CancelRequest, invalid protocol code
	for _, code := range []uint32{pgwire.GSSENCRequestCode, pgwire.CancelRequestCode, 99999} {
		c, err := net.Dial("tcp", pAddr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		var b [8]byte
		binary.BigEndian.PutUint32(b[0:4], 8)
		binary.BigEndian.PutUint32(b[4:8], code)
		_, _ = c.Write(b[:])
		var rep [32]byte
		_, _ = c.Read(rep[:])
		_ = c.Close()
	}

	// 2. Client TLS connection (SSLRequest -> 'S' TLS upgrade!) + max_rows_action: "block" + HITL reject + CRITICAL webhook
	tlsDSN := "postgres://pgveil@" + pAddr + "/pgveil_demo?sslmode=require&application_name=strict_block"
	connCfg, _ := pgx.ParseConfig(tlsDSN)
	connCfg.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	conn, err := pgx.ConnectConfig(ctx, connCfg)
	if err != nil {
		t.Fatalf("TLS connect via proxy: %v", err)
	}
	// Exceeds max_rows=2 with max_rows_action=block -> ERROR 42501
	rows, err := conn.Query(ctx, "SELECT id, tckn FROM customers LIMIT 5")
	if err == nil {
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
	}
	if err == nil {
		t.Fatal("expected max_rows_action=block to fail query")
	}
	// HITL reject mode -> immediate rejection
	if _, err := conn.Exec(ctx, "UPDATE orders SET status = 'x' WHERE id = 1001"); err == nil {
		t.Fatal("expected HITL reject mode to reject UPDATE")
	}
	// CRITICAL block fires async webhook
	if _, err := conn.Exec(ctx, "DROP TABLE customers"); err == nil {
		t.Fatal("expected DROP TABLE blocked")
	}
	_ = conn.Close(ctx)

	// 3. HITL hold -> Denied + Expired + Named Prepared Statement with Virtual RLS reuse + Close
	holdCfg, _ := pgx.ParseConfig("postgres://pgveil@" + pAddr + "/pgveil_demo?sslmode=disable&application_name=hold_deny")
	hConn, err := pgx.ConnectConfig(ctx, holdCfg)
	if err != nil {
		t.Fatalf("hold_deny connect: %v", err)
	}
	// Prepare once, execute twice (exercises cached stmtRLS & Close on Deallocate)
	sd, err := hConn.Prepare(ctx, "st_rls", "SELECT id, city, tckn FROM customers WHERE id >= $1")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	r1, err := hConn.Query(ctx, sd.Name, 1)
	if err != nil {
		t.Fatalf("Exec prepared 1: %v", err)
	}
	for r1.Next() {
	}
	r1.Close()
	_ = hConn.Deallocate(ctx, sd.Name)

	// Trigger HITL deny
	go func() {
		for i := 0; i < 40; i++ {
			if p := hitlMgr.List("PENDING"); len(p) > 0 {
				_, _ = hitlMgr.Resolve(p[0].ID, false, "sec", "nope")
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if _, err := hConn.Exec(ctx, "UPDATE orders SET status = 'x' WHERE id = 1001"); err == nil {
		t.Fatal("expected denied HITL UPDATE to error")
	}
	// Trigger HITL timeout expiry (120ms)
	if _, err := hConn.Exec(ctx, "DELETE FROM orders WHERE id = 1001"); err == nil {
		t.Fatal("expected expired HITL DELETE to error")
	}
	_ = hConn.Close(ctx)

	// 4. Raw wire Extended Query Flush (`'H'`) without Sync -> exercises relayUntilFlush!
	rawConn, err := net.Dial("tcp", pAddr)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer rawConn.Close()
	// Send StartupMessage
	var sb bytes.Buffer
	_ = binary.Write(&sb, binary.BigEndian, pgwire.ProtocolVersion30)
	sb.WriteString("user\x00pgveil\x00database\x00pgveil_demo\x00application_name\x00shadow_ext\x00\x00")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(4+sb.Len()))
	_, _ = rawConn.Write(hdr[:])
	_, _ = rawConn.Write(sb.Bytes())
	// Read until ReadyForQuery
	for {
		mt, _, err := pgwire.ReadMessage(rawConn)
		if err != nil {
			t.Fatalf("handshake read: %v", err)
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}
	// Send Parse + Describe('S') + Flush('H')
	parsePayload := append([]byte("fstmt\x00SELECT id FROM customers LIMIT 1\x00"), 0, 0)
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgParse, parsePayload)
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgDescribe, []byte("Sfstmt\x00"))
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgFlush, nil)
	gotPC, gotPD, gotRD := false, false, false
	for !(gotPC && gotPD && gotRD) {
		mt, _, err := pgwire.ReadMessage(rawConn)
		if err != nil {
			t.Fatalf("flush read: %v", err)
		}
		switch mt {
		case pgwire.MsgParseComplete:
			gotPC = true
		case pgwire.MsgParameterDescription:
			gotPD = true
		case pgwire.MsgRowDescription:
			gotRD = true
		}
	}
	// Also test fast-path FunctionCall ('F') block and non-ASCII/shadow Extended batch
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgFunctionCall, []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	for {
		mt, _, err := pgwire.ReadMessage(rawConn)
		if err != nil {
			t.Fatalf("func call read: %v", err)
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}

	// Also test shadow audit mode on Extended batch (DROP TABLE + rate limit -> WOULD_BLOCK)
	badParse := append([]byte("\x00DROP TABLE customers\x00"), 0, 0)
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgParse, badParse)
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgSync, nil)
	for {
		mt, _, err := pgwire.ReadMessage(rawConn)
		if err != nil {
			t.Fatalf("shadow read: %v", err)
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}
	_ = pgwire.WriteMessage(rawConn, pgwire.MsgTerminate, nil)

	// Wait briefly for async webhook hit
	for i := 0; i < 20 && webhookHits.Load() == 0; i++ {
		time.Sleep(15 * time.Millisecond)
	}
	if webhookHits.Load() == 0 {
		t.Fatal("expected async webhook call on CRITICAL block")
	}
}

func TestProxyUpstreamTLSAndPasswordAuthRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certFile, keyFile := generateTempSelfSignedCert(t)
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Mock upstream that negotiates SSLRequest ('S'), TLS, AuthenticationCleartextPassword, then serves 1 query
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	go func() {
		for {
			raw, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read SSLRequest (8 bytes)
				var sslReq [8]byte
				if _, err := c.Read(sslReq[:]); err != nil {
					return
				}
				_, _ = c.Write([]byte{'S'})
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{tlsCert}})
				if err := tc.Handshake(); err != nil {
					return
				}
				if _, err := pgwire.ReadStartupPacket(tc); err != nil {
					return
				}
				// Request cleartext password (auth type 3)
				var authReq [4]byte
				binary.BigEndian.PutUint32(authReq[:], 3)
				_ = pgwire.WriteMessage(tc, pgwire.MsgAuth, authReq[:])
				mt, _, err := pgwire.ReadMessage(tc)
				if err != nil || mt != pgwire.MsgPassword {
					return
				}
				// Send AuthenticationOk (0) + ParameterStatus + BackendKeyData + ReadyForQuery
				var authOK [4]byte
				_ = pgwire.WriteMessage(tc, pgwire.MsgAuth, authOK[:])
				_ = pgwire.WriteMessage(tc, pgwire.MsgParameterStatus, []byte("server_version\x0017.0\x00"))
				_ = pgwire.WriteMessage(tc, pgwire.MsgBackendKeyData, make([]byte, 8))
				_ = pgwire.WriteMessage(tc, pgwire.MsgReadyForQuery, []byte{'I'})
				for {
					mt, _, err := pgwire.ReadMessage(tc)
					if err != nil || mt == pgwire.MsgTerminate {
						return
					}
					_ = pgwire.WriteMessage(tc, pgwire.MsgCommandComplete, pgwire.BuildCommandComplete("SELECT 0"))
					_ = pgwire.WriteMessage(tc, pgwire.MsgReadyForQuery, []byte{'I'})
				}
			}(raw)
		}
	}()

	cfgYAML := `
server:
  listen_addr: "127.0.0.1:0"
  upstream_addr: "` + upLn.Addr().String() + `"
  upstream_tls:
    enabled: true
    insecure_skip_verify: true
default_profile: ai_agent
profiles:
  - name: ai_agent
    match:
      application_names: ["*"]
    firewall:
      allow_statements: ["SELECT"]
`
	mgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics(prometheus.NewRegistry())
	tracer, shutdown := telemetry.InitTracer(ctx, "pgveil-test", false, "")
	defer func() { _ = shutdown(context.Background()) }()
	bus := events.NewBus(16, policy.KafkaConfig{}, metrics)
	defer bus.Close()
	srv, err := proxy.NewServer(mgr, hitl.NewManager(16), bus, metrics, tracer)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Start(ctx) }()
	for i := 0; i < 50 && srv.Addr() == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	// Client connects, answers cleartext password prompt, runs SELECT 1
	c, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var sb bytes.Buffer
	_ = binary.Write(&sb, binary.BigEndian, pgwire.ProtocolVersion30)
	sb.WriteString("user\x00alice\x00database\x00app\x00\x00")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(4+sb.Len()))
	_, _ = c.Write(hdr[:])
	_, _ = c.Write(sb.Bytes())

	for {
		mt, payload, err := pgwire.ReadMessage(c)
		if err != nil {
			t.Fatalf("auth relay read: %v", err)
		}
		if mt == pgwire.MsgAuth && len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == 3 {
			_ = pgwire.WriteMessage(c, pgwire.MsgPassword, []byte("secret\x00"))
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}
	_ = pgwire.WriteMessage(c, pgwire.MsgQuery, pgwire.BuildSimpleQuery("SELECT 1"))
	for {
		mt, _, err := pgwire.ReadMessage(c)
		if err != nil {
			t.Fatalf("query read: %v", err)
		}
		if mt == pgwire.MsgReadyForQuery {
			break
		}
	}
	_ = pgwire.WriteMessage(c, pgwire.MsgTerminate, nil)

	// 2. Upstream declines TLS ('N') -> proxy responds with ErrorResponse cleanly
	declineLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer declineLn.Close()
	go func() {
		conn, err := declineLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var buf [8]byte
		_, _ = conn.Read(buf[:])
		_, _ = conn.Write([]byte{'N'})
	}()
	mgr2, _ := policy.LoadBytes([]byte(`
server:
  listen_addr: "127.0.0.1:0"
  upstream_addr: "` + declineLn.Addr().String() + `"
  upstream_tls:
    enabled: true
default_profile: ai_agent
profiles:
  - name: ai_agent
    match:
      application_names: ["*"]
`))
	bus2 := events.NewBus(8, policy.KafkaConfig{}, metrics)
	defer bus2.Close()
	srv2, err := proxy.NewServer(mgr2, hitl.NewManager(8), bus2, metrics, tracer)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv2.Start(ctx) }()
	for i := 0; i < 50 && srv2.Addr() == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	c2, err := net.DialTimeout("tcp", srv2.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_, _ = c2.Write(hdr[:])
	_, _ = c2.Write(sb.Bytes())
	mt, _, err := pgwire.ReadMessage(c2)
	if err != nil || mt != pgwire.MsgErrorResponse {
		t.Fatalf("expected ErrorResponse when upstream declines TLS, got %q (err=%v)", mt, err)
	}
}
