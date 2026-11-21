package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/pgwire"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/ratelimit"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Server is the Zero-Trust PostgreSQL Wire Protocol v3 proxy server.
type Server struct {
	policyMgr *policy.Manager
	hitlMgr   *hitl.Manager
	eventBus  *events.Bus
	metrics   *telemetry.Metrics
	tracer    trace.Tracer
	limiter   *ratelimit.Limiter
	tlsConfig *tls.Config

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

// NewServer constructs a PostgreSQL wire proxy server.
func NewServer(
	policyMgr *policy.Manager,
	hitlMgr *hitl.Manager,
	eventBus *events.Bus,
	metrics *telemetry.Metrics,
	tracer trace.Tracer,
) (*Server, error) {
	s := &Server{
		policyMgr: policyMgr,
		hitlMgr:   hitlMgr,
		eventBus:  eventBus,
		metrics:   metrics,
		tracer:    tracer,
		limiter:   ratelimit.NewLimiter(),
	}
	cfg := policyMgr.Config()
	if cfg.Server.TLS.Enabled && cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS keypair: %w", err)
		}
		s.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}
	return s, nil
}

// Start binds the TCP listener and accepts PostgreSQL client connections until ctx is canceled.
func (s *Server) Start(ctx context.Context) error {
	addr := s.policyMgr.Config().Server.ListenAddr
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	slog.Info("pgveil wire proxy listening",
		"listen_addr", ln.Addr().String(),
		"upstream_addr", s.policyMgr.Config().Server.UpstreamAddr,
		"tls", s.tlsConfig != nil,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Warn("accept error", "err", err)
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConnection(ctx, c)
		}(conn)
	}

	s.wg.Wait()
	return nil
}

// Addr returns the bound listener address (useful in tests with :0 ephemeral ports).
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

type sessionMeta struct {
	clientAddr string
	dbUser     string
	database   string
	appName    string
	txStatus   byte
	prepStmts  map[string]string
	stmtFields map[string][]pgwire.FieldDescription
	stmtRLS    map[string]firewall.RLSResult
}

func (m *sessionMeta) rlsSession(profileName string) firewall.SessionContext {
	return firewall.SessionContext{
		DBUser:          m.dbUser,
		Database:        m.database,
		ApplicationName: m.appName,
		RoleProfile:     profileName,
	}
}

type wireMsg struct {
	msgType byte
	payload []byte
}

func (s *Server) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	if s.metrics != nil {
		s.metrics.ActiveConnections.Inc()
		defer s.metrics.ActiveConnections.Dec()
	}

	// 1. Startup / SSL / GSSENC / Cancel handshake
	startup, conn, err := s.negotiateStartup(clientConn)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			slog.Debug("startup negotiation failed", "client", clientConn.RemoteAddr().String(), "err", err)
		}
		return
	}
	clientConn = conn

	upstreamAddr := s.policyMgr.Config().Server.UpstreamAddr
	if startup.Code == pgwire.CancelRequestCode {
		s.forwardCancel(upstreamAddr, startup.Raw)
		return
	}
	if startup.Code != pgwire.ProtocolVersion30 {
		_ = pgwire.WriteMessage(clientConn, pgwire.MsgErrorResponse,
			pgwire.BuildErrorResponse("FATAL", "0A000", fmt.Sprintf("unsupported PostgreSQL protocol code: %d", startup.Code), "", ""))
		return
	}

	meta := &sessionMeta{
		clientAddr: clientConn.RemoteAddr().String(),
		dbUser:     startup.Params["user"],
		database:   startup.Params["database"],
		appName:    startup.Params["application_name"],
		txStatus:   'I',
		prepStmts:  make(map[string]string),
		stmtFields: make(map[string][]pgwire.FieldDescription),
		stmtRLS:    make(map[string]firewall.RLSResult),
	}
	if meta.database == "" {
		meta.database = meta.dbUser
	}

	// 2. Dial upstream PostgreSQL server (with optional PostgreSQL wire SSLRequest TLS upgrade for RDS/Cloud SQL/Neon)
	upstreamConn, err := s.dialUpstream(ctx, s.policyMgr.Config().Server)
	if err != nil {
		slog.Error("upstream PostgreSQL unreachable", "upstream", upstreamAddr, "err", err)
		_ = pgwire.WriteMessage(clientConn, pgwire.MsgErrorResponse,
			pgwire.BuildErrorResponse("FATAL", "08006", "pgveil cannot reach upstream PostgreSQL", err.Error(), "Verify upstream_addr / upstream_tls in pgveil.yaml"))
		return
	}
	defer upstreamConn.Close()

	// Forward exact StartupMessage to upstream and relay authentication handshake
	if _, err := upstreamConn.Write(startup.Raw); err != nil {
		return
	}

	clientReader := bufio.NewReaderSize(clientConn, 32*1024)
	upstreamReader := bufio.NewReaderSize(upstreamConn, 32*1024)

	if err := s.relayAuthHandshake(clientReader, clientConn, upstreamReader, upstreamConn, meta); err != nil {
		if !errors.Is(err, io.EOF) {
			slog.Debug("auth handshake terminated", "user", meta.dbUser, "err", err)
		}
		return
	}

	slog.Debug("session authenticated",
		"client", meta.clientAddr,
		"user", meta.dbUser,
		"db", meta.database,
		"app", meta.appName,
		"profile", s.policyMgr.MatchProfile(meta.dbUser, meta.appName).Name,
	)

	// 3. Main PostgreSQL wire command loop (Simple & Extended Query Protocol)
	var extBatch []wireMsg
	for {
		msgType, payload, err := pgwire.ReadMessage(clientReader)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				slog.Debug("client read closed", "client", meta.clientAddr, "err", err)
			}
			return
		}

		switch msgType {
		case pgwire.MsgTerminate:
			_ = pgwire.WriteMessage(upstreamConn, msgType, payload)
			return

		case pgwire.MsgQuery:
			sql := pgwire.ParseSimpleQuery(payload)
			if err := s.handleSimpleQuery(ctx, clientConn, upstreamReader, upstreamConn, meta, sql, payload); err != nil {
				return
			}

		case pgwire.MsgParse, pgwire.MsgBind, pgwire.MsgDescribe, pgwire.MsgExecute, pgwire.MsgClose:
			extBatch = append(extBatch, wireMsg{msgType: msgType, payload: payload})

		case pgwire.MsgSync, pgwire.MsgFlush:
			extBatch = append(extBatch, wireMsg{msgType: msgType, payload: payload})
			if err := s.handleExtendedBatch(ctx, clientConn, upstreamReader, upstreamConn, meta, extBatch); err != nil {
				return
			}
			extBatch = extBatch[:0]

		case pgwire.MsgFunctionCall:
			// Block legacy PostgreSQL Wire v3 Fast-Path FunctionCall ('F') frames which can invoke
			// arbitrary server functions by OID (e.g., lo_export, pg_read_file) bypassing SQL AST parsing.
			profile := s.policyMgr.MatchProfile(meta.dbUser, meta.appName)
			dec := firewall.Decision{
				Action:        firewall.ActionBlock,
				StatementType: "FUNCTION_CALL",
				RiskLevel:     "CRITICAL",
				Rule:          "block_fastpath_function_call",
				Reason:        "Legacy PostgreSQL wire fast-path FunctionCall ('F') is blocked by pgveil",
				Fingerprint:   "wire_fastpath_fn",
			}
			s.recordAndEmitBlocked(nil, meta, profile, "<wire-fastpath-function-call>", dec, "BLOCKED", 0)
			if err := s.sendBlockedErrorCode(clientConn, meta.txStatus, "0A000", dec.Reason, "rule=block_fastpath_function_call", "Use standard SQL queries instead of legacy fast-path function calls"); err != nil {
				return
			}

		default:
			// Pass through other frontend frames (e.g., CopyData/CopyDone/CopyFail)
			if err := pgwire.WriteMessage(upstreamConn, msgType, payload); err != nil {
				return
			}
		}
	}
}

func (s *Server) negotiateStartup(conn net.Conn) (*pgwire.StartupPacket, net.Conn, error) {
	for {
		pkt, err := pgwire.ReadStartupPacket(conn)
		if err != nil {
			return nil, conn, err
		}
		switch pkt.Code {
		case pgwire.SSLRequestCode:
			if s.tlsConfig != nil {
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return nil, conn, err
				}
				tlsConn := tls.Server(conn, s.tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					return nil, conn, err
				}
				conn = tlsConn
			} else {
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return nil, conn, err
				}
			}
		case pgwire.GSSENCRequestCode:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, conn, err
			}
		default:
			return pkt, conn, nil
		}
	}
}

func (s *Server) forwardCancel(upstreamAddr string, raw []byte) {
	c, err := net.DialTimeout("tcp", upstreamAddr, 3*time.Second)
	if err != nil {
		return
	}
	defer c.Close()
	_, _ = c.Write(raw)
}

func (s *Server) relayAuthHandshake(
	clientR io.Reader, clientW io.Writer,
	upstreamR io.Reader, upstreamW io.Writer,
	meta *sessionMeta,
) error {
	for {
		mType, payload, err := pgwire.ReadMessage(upstreamR)
		if err != nil {
			return err
		}
		if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
			return err
		}
		switch mType {
		case pgwire.MsgAuth:
			if len(payload) >= 4 {
				authCode := binary.BigEndian.Uint32(payload[0:4])
				// Cleartext(3), MD5(5), SASL(10), SASLContinue(11) require client Password/SASL response ('p')
				if authCode == 3 || authCode == 5 || authCode == 10 || authCode == 11 {
					cType, cPayload, err := pgwire.ReadMessage(clientR)
					if err != nil {
						return err
					}
					if err := pgwire.WriteMessage(upstreamW, cType, cPayload); err != nil {
						return err
					}
				}
			}
		case pgwire.MsgErrorResponse:
			return errors.New("upstream authentication failed")
		case pgwire.MsgReadyForQuery:
			if len(payload) > 0 {
				meta.txStatus = payload[0]
			}
			return nil
		}
	}
}

func (s *Server) handleSimpleQuery(
	ctx context.Context,
	clientW io.Writer,
	upstreamR io.Reader,
	upstreamW io.Writer,
	meta *sessionMeta,
	sql string,
	rawPayload []byte,
) error {
	profile := s.policyMgr.MatchProfile(meta.dbUser, meta.appName)
	spanCtx, span := s.startSpan(ctx, "pgveil.simple_query", meta, profile)
	defer span.End()

	astStart := time.Now()
	dec := firewall.Evaluate(sql, profile)
	proxyOverhead := time.Since(astStart)

	// Per-profile QPM rate limiter & runaway AI-agent loop circuit breaker
	if rl := s.checkRateLimit(meta, profile, dec.Fingerprint); !rl.Allowed {
		dec.Rule = rl.Rule
		dec.Reason = rl.Reason
		dec.RiskLevel = "HIGH"
		if !profile.IsAuditOnly() {
			s.recordAndEmitBlocked(span, meta, profile, sql, dec, "BLOCKED", proxyOverhead)
			return s.sendBlockedErrorCode(clientW, meta.txStatus, "53300", rl.Reason, fmt.Sprintf("rule=%s profile=%s", rl.Rule, profile.Name), "Slow down query frequency or break agent retry loop")
		}
		s.recordAndEmitBlocked(span, meta, profile, sql, dec, "WOULD_BLOCK", proxyOverhead)
	}

	hitlOutcome := ""
	switch dec.Action {
	case firewall.ActionBlock:
		if profile.IsAuditOnly() {
			hitlOutcome = "WOULD_BLOCK"
		} else {
			s.recordAndEmitBlocked(span, meta, profile, sql, dec, "BLOCKED", proxyOverhead)
			return s.sendBlockedError(clientW, meta.txStatus, dec.Reason, fmt.Sprintf("rule=%s profile=%s", dec.Rule, profile.Name), "Blocked by pgveil AST SQL Firewall")
		}

	case firewall.ActionRequireHITL:
		if profile.IsAuditOnly() {
			hitlOutcome = "WOULD_HITL"
		} else {
			approved, outcome, detail := s.handleHITL(spanCtx, meta, profile, sql, dec)
			hitlOutcome = outcome
			if !approved {
				s.recordAndEmitBlocked(span, meta, profile, sql, dec, outcome, proxyOverhead)
				return s.sendBlockedError(clientW, meta.txStatus, detail, fmt.Sprintf("rule=%s profile=%s status=%s", dec.Rule, profile.Name, outcome), "Approve pending query in the pgveil Web Console")
			}
		}
	}

	// Apply AST-level Virtual Row-Level Security (RLS) predicate injection strictly AFTER
	// original-SQL firewall checks and HITL approval have passed.
	var rlsRes firewall.RLSResult
	if !profile.IsAuditOnly() && len(profile.Firewall.RowFilters) > 0 {
		rlsStart := time.Now()
		var rlsErr error
		rlsRes, rlsErr = firewall.RewriteWithRLS(sql, profile, meta.rlsSession(profile.Name))
		proxyOverhead += time.Since(rlsStart)
		if rlsErr != nil {
			dec.Rule = "virtual_rls_error"
			dec.Reason = rlsErr.Error()
			dec.RiskLevel = "HIGH"
			s.recordAndEmitBlocked(span, meta, profile, sql, dec, "BLOCKED", proxyOverhead)
			return s.sendBlockedError(clientW, meta.txStatus, "pgveil virtual RLS rewrite failed: "+rlsErr.Error(), fmt.Sprintf("rule=virtual_rls_error profile=%s", profile.Name), "Verify row_filters policy predicates")
		}
		if rlsRes.Rewritten {
			rawPayload = pgwire.BuildSimpleQuery(rlsRes.SQL)
		}
	}

	// Forward approved (and optionally RLS-rewritten) SQL to upstream PostgreSQL
	upstreamStart := time.Now()
	if err := pgwire.WriteMessage(upstreamW, pgwire.MsgQuery, rawPayload); err != nil {
		return err
	}
	return s.relayResponseCycle(span, clientW, upstreamR, meta, profile, sql, "", dec, rlsRes, hitlOutcome, proxyOverhead, upstreamStart)
}

func (s *Server) handleExtendedBatch(
	ctx context.Context,
	clientW io.Writer,
	upstreamR io.Reader,
	upstreamW io.Writer,
	meta *sessionMeta,
	batch []wireMsg,
) error {
	profile := s.policyMgr.MatchProfile(meta.dbUser, meta.appName)
	spanCtx, span := s.startSpan(ctx, "pgveil.extended_query", meta, profile)
	defer span.End()

	// Inspect EVERY Parse and Bind statement in this pipeline batch so a blocked or HITL
	// statement can NEVER hide behind a subsequent benign `SELECT 1` in the same pipeline!
	type inspectedStmt struct {
		sql string
		dec firewall.Decision
	}
	var inspected []inspectedStmt
	var pendingStmts []struct {
		name  string
		query string
	}
	var activeStmtName string
	var proxyOverhead time.Duration
	hasSync := false
	parsedInBatch := make(map[string]bool)

	for i := range batch {
		m := &batch[i]
		switch m.msgType {
		case pgwire.MsgSync:
			hasSync = true
		case pgwire.MsgParse:
			stmtName, query, err := pgwire.ParseParseMessage(m.payload)
			if err != nil {
				continue
			}
			pendingStmts = append(pendingStmts, struct {
				name  string
				query string
			}{name: stmtName, query: query})
			parsedInBatch[stmtName] = true
			activeStmtName = stmtName
			t0 := time.Now()
			dec := firewall.Evaluate(query, profile)
			proxyOverhead += time.Since(t0)
			inspected = append(inspected, inspectedStmt{sql: query, dec: dec})
		case pgwire.MsgDescribe:
			if len(m.payload) >= 2 && m.payload[0] == 'S' {
				activeStmtName = pgwire.ParseSimpleQuery(m.payload[1:])
			}
		case pgwire.MsgBind:
			_, stmtName, _, err := pgwire.RewriteBindResultFormatsToText(m.payload)
			if err == nil {
				// Preserve exact client-requested Bind format codes so strict extended-protocol drivers
				// (pgx/v5, psycopg3, JDBC) keep native binary framing for int4/uuid/timestamp while
				// pgveil masks UTF-8 string OIDs seamlessly in both text and binary wire formats.
				activeStmtName = stmtName
				// Re-evaluate cached prepared statements not freshly parsed in this same batch
				if !parsedInBatch[stmtName] {
					if cachedSQL, ok := meta.prepStmts[stmtName]; ok && cachedSQL != "" {
						t0 := time.Now()
						dec := firewall.Evaluate(cachedSQL, profile)
						proxyOverhead += time.Since(t0)
						inspected = append(inspected, inspectedStmt{sql: cachedSQL, dec: dec})
					}
				}
			}
		case pgwire.MsgClose:
			if len(m.payload) >= 2 && m.payload[0] == 'S' {
				name := pgwire.ParseSimpleQuery(m.payload[1:])
				delete(meta.prepStmts, name)
				delete(meta.stmtFields, name)
				delete(meta.stmtRLS, name)
			}
		}
	}

	var primarySQL string
	var primaryDec firewall.Decision
	hasQuery := len(inspected) > 0
	hitlOutcome := ""

	if hasQuery {
		// Default to the last statement for column provenance / audit metadata,
		// unless any statement in the batch is BLOCKED or requires HITL (strictest wins!).
		primarySQL = inspected[len(inspected)-1].sql
		primaryDec = inspected[len(inspected)-1].dec

		for _, item := range inspected {
			if rl := s.checkRateLimit(meta, profile, item.dec.Fingerprint); !rl.Allowed {
				dec := item.dec
				dec.Rule = rl.Rule
				dec.Reason = rl.Reason
				dec.RiskLevel = "HIGH"
				if !profile.IsAuditOnly() {
					s.recordAndEmitBlocked(span, meta, profile, item.sql, dec, "BLOCKED", proxyOverhead)
					return s.sendBlockedErrorCode(clientW, meta.txStatus, "53300", rl.Reason, fmt.Sprintf("rule=%s profile=%s", rl.Rule, profile.Name), "Slow down query frequency or break agent retry loop")
				}
				hitlOutcome = "WOULD_BLOCK"
				primarySQL = item.sql
				primaryDec = dec
			}
			if item.dec.Action == firewall.ActionBlock {
				primarySQL = item.sql
				primaryDec = item.dec
				if profile.IsAuditOnly() {
					hitlOutcome = "WOULD_BLOCK"
					continue
				}
				s.recordAndEmitBlocked(span, meta, profile, item.sql, item.dec, "BLOCKED", proxyOverhead)
				return s.sendBlockedError(clientW, meta.txStatus, item.dec.Reason, fmt.Sprintf("rule=%s profile=%s", item.dec.Rule, profile.Name), "Blocked by pgveil AST SQL Firewall")
			}
		}
		for _, item := range inspected {
			if item.dec.Action == firewall.ActionRequireHITL {
				primarySQL = item.sql
				primaryDec = item.dec
				if profile.IsAuditOnly() {
					hitlOutcome = "WOULD_HITL"
					continue
				}
				approved, outcome, detail := s.handleHITL(spanCtx, meta, profile, item.sql, item.dec)
				hitlOutcome = outcome
				if !approved {
					s.recordAndEmitBlocked(span, meta, profile, item.sql, item.dec, outcome, proxyOverhead)
					return s.sendBlockedError(clientW, meta.txStatus, detail, fmt.Sprintf("rule=%s profile=%s status=%s", item.dec.Rule, profile.Name, outcome), "Approve pending query in the pgveil Web Console")
				}
			}
		}
	}

	// Apply AST-level Virtual RLS rewriting to every Parse ('P') frame strictly AFTER
	// original-SQL firewall evaluation and HITL approval have passed.
	var batchRLS firewall.RLSResult
	pendingRLS := make(map[string]firewall.RLSResult)
	if !profile.IsAuditOnly() && len(profile.Firewall.RowFilters) > 0 {
		sessCtx := meta.rlsSession(profile.Name)
		for i := range batch {
			if batch[i].msgType != pgwire.MsgParse {
				continue
			}
			stmtName, query, err := pgwire.ParseParseMessage(batch[i].payload)
			if err != nil {
				continue
			}
			t0 := time.Now()
			rlsRes, rlsErr := firewall.RewriteWithRLS(query, profile, sessCtx)
			proxyOverhead += time.Since(t0)
			if rlsErr != nil {
				primaryDec.Rule = "virtual_rls_error"
				primaryDec.Reason = rlsErr.Error()
				primaryDec.RiskLevel = "HIGH"
				s.recordAndEmitBlocked(span, meta, profile, query, primaryDec, "BLOCKED", proxyOverhead)
				return s.sendBlockedError(clientW, meta.txStatus, "pgveil virtual RLS rewrite failed: "+rlsErr.Error(), fmt.Sprintf("rule=virtual_rls_error profile=%s", profile.Name), "Verify row_filters policy predicates")
			}
			if rlsRes.Rewritten {
				rewrittenPayload, perr := pgwire.RewriteParseMessage(batch[i].payload, rlsRes.SQL)
				if perr != nil {
					primaryDec.Rule = "virtual_rls_error"
					primaryDec.Reason = perr.Error()
					primaryDec.RiskLevel = "HIGH"
					s.recordAndEmitBlocked(span, meta, profile, query, primaryDec, "BLOCKED", proxyOverhead)
					return s.sendBlockedError(clientW, meta.txStatus, "pgveil virtual RLS frame rewrite failed: "+perr.Error(), fmt.Sprintf("rule=virtual_rls_error profile=%s", profile.Name), "Verify Parse wire framing")
				}
				batch[i].payload = rewrittenPayload
				pendingRLS[stmtName] = rlsRes
				batchRLS = rlsRes
			}
		}
	}

	// Only cache parsed statements in session metadata AFTER every statement in the batch passed policy!
	for _, ps := range pendingStmts {
		meta.prepStmts[ps.name] = ps.query
		delete(meta.stmtFields, ps.name)
		if r, ok := pendingRLS[ps.name]; ok {
			meta.stmtRLS[ps.name] = r
		} else {
			delete(meta.stmtRLS, ps.name)
		}
	}
	if !batchRLS.Rewritten && activeStmtName != "" {
		if cached, ok := meta.stmtRLS[activeStmtName]; ok {
			batchRLS = cached
		}
	}

	upstreamStart := time.Now()
	for _, m := range batch {
		if err := pgwire.WriteMessage(upstreamW, m.msgType, m.payload); err != nil {
			return err
		}
	}
	if !hasSync {
		// Flush-only cycle without Sync: relay every response expected for the requests in this batch
		return s.relayUntilFlush(clientW, upstreamR, meta, activeStmtName, batch)
	}
	if !hasQuery {
		primaryDec = firewall.Decision{Action: firewall.ActionAllow, StatementType: "EXTENDED", RiskLevel: "LOW", Rule: "policy_allow"}
	}
	return s.relayResponseCycle(span, clientW, upstreamR, meta, profile, primarySQL, activeStmtName, primaryDec, batchRLS, hitlOutcome, proxyOverhead, upstreamStart)
}

func (s *Server) relayUntilFlush(clientW io.Writer, upstreamR io.Reader, meta *sessionMeta, stmtName string, batch []wireMsg) error {
	expected := 0
	for _, m := range batch {
		switch m.msgType {
		case pgwire.MsgParse, pgwire.MsgBind, pgwire.MsgClose:
			expected++
		case pgwire.MsgDescribe:
			if len(m.payload) >= 1 && m.payload[0] == 'S' {
				expected += 2 // ParameterDescription ('t') + RowDescription ('T') or NoData ('n')
			} else {
				expected++ // Portal describe: RowDescription ('T') or NoData ('n')
			}
		case pgwire.MsgExecute:
			expected++ // Terminal CommandComplete ('C') / PortalSuspended ('s') / EmptyQuery ('I')
		}
	}
	if expected == 0 {
		expected = 1
	}
	completed := 0
	for completed < expected {
		mType, payload, err := pgwire.ReadMessage(upstreamR)
		if err != nil {
			return err
		}
		if mType == pgwire.MsgRowDescription && stmtName != "" {
			if parsed, perr := pgwire.ParseRowDescription(payload); perr == nil {
				meta.stmtFields[stmtName] = parsed
			}
		}
		if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
			return err
		}
		switch mType {
		case pgwire.MsgParseComplete, pgwire.MsgBindComplete, pgwire.MsgCloseComplete,
			pgwire.MsgParameterDescription, pgwire.MsgRowDescription, pgwire.MsgNoData,
			pgwire.MsgCommandComplete, pgwire.MsgPortalSuspended, pgwire.MsgEmptyQuery:
			completed++
		case pgwire.MsgErrorResponse:
			return nil
		}
	}
	return nil
}

func isUTF8TextOID(oid uint32) bool {
	// PostgreSQL built-in UTF-8 string OIDs whose binary wire format is identical to raw UTF-8 text:
	// 18=char, 19=name, 25=text, 114=json, 1042=bpchar, 1043=varchar
	switch oid {
	case 18, 19, 25, 114, 1042, 1043:
		return true
	default:
		return false
	}
}

func (s *Server) relayResponseCycle(
	span trace.Span,
	clientW io.Writer,
	upstreamR io.Reader,
	meta *sessionMeta,
	profile *policy.RoleProfile,
	sql string,
	stmtName string,
	dec firewall.Decision,
	rlsRes firewall.RLSResult,
	hitlOutcome string,
	proxyOverhead time.Duration,
	upstreamStart time.Time,
) error {
	masker := s.policyMgr.Masker()
	maskingEnabled := profile.Masking.Enabled
	autoDetect := profile.Masking.AutoDetectPII
	enabledEntities := profile.EnabledEntities()
	maxRows := profile.Firewall.MaxRows
	maxRowsBlock := profile.Firewall.MaxRowsAction == "block"

	var fields []pgwire.FieldDescription
	var colStrategies []pii.Strategy
	var colHintNames []string
	anyColRule := false

	initFieldStrategies := func(fds []pgwire.FieldDescription) {
		fields = fds
		colStrategies = make([]pii.Strategy, len(fields))
		colHintNames = make([]string, len(fields))
		anyColRule = false
		if maskingEnabled {
			for i, f := range fields {
				colHintNames[i] = f.Name
				st := profile.ColumnStrategy(f.Name)
				// AST projection provenance: prevent column-alias masking bypasses (e.g. SELECT full_name AS fn)
				if st == "" && i < len(dec.TargetSources) {
					for _, src := range dec.TargetSources[i] {
						if srcStrat := profile.ColumnStrategy(src); srcStrat != "" {
							st = srcStrat
							colHintNames[i] = src
							break
						}
					}
				}
				if st == "" && len(dec.AliasSources) > 0 {
					for _, src := range dec.AliasSources[strings.ToLower(f.Name)] {
						if srcStrat := profile.ColumnStrategy(src); srcStrat != "" {
							st = srcStrat
							colHintNames[i] = src
							break
						}
					}
				}
				colStrategies[i] = st
				if st != "" {
					anyColRule = true
				}
			}
		}
	}

	// Pre-populate column descriptors from cached prepared statement (for Extended Query Execute without Describe)
	if stmtName != "" {
		if cached, ok := meta.stmtFields[stmtName]; ok && len(cached) > 0 {
			initFieldStrategies(cached)
		}
	}

	rowsReturned := 0
	rowsDropped := 0
	rowsTruncated := false
	budgetBlocked := false
	piiFieldsMasked := 0
	piiEntityCounts := make(map[string]int)

	for {
		mType, payload, err := pgwire.ReadMessage(upstreamR)
		if err != nil {
			return err
		}

		switch mType {
		case pgwire.MsgRowDescription:
			if parsed, perr := pgwire.ParseRowDescription(payload); perr == nil {
				initFieldStrategies(parsed)
				if stmtName != "" {
					meta.stmtFields[stmtName] = parsed
				}
			}
			if !budgetBlocked {
				if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
					return err
				}
			}

		case pgwire.MsgDataRow:
			if maxRows > 0 && rowsReturned >= maxRows {
				rowsDropped++
				rowsTruncated = true
				if maxRowsBlock {
					budgetBlocked = true
				}
				continue
			}

			rowsReturned++
			outPayload := payload
			if maskingEnabled && (anyColRule || autoDetect) && len(fields) > 0 {
				t0 := time.Now()
				cols, perr := pgwire.ParseDataRow(payload)
				if perr == nil {
					changed := false
					for i := 0; i < len(cols) && i < len(fields); i++ {
						if cols[i] == nil || len(cols[i]) == 0 {
							continue
						}
						// Mask text-format cells OR binary-format cells whose OID has raw UTF-8 wire representation
						if fields[i].FormatCode != 0 && !isUTF8TextOID(fields[i].DataTypeOID) {
							continue
						}
						rawVal := string(cols[i])
						strat := colStrategies[i]
						hintCol := colHintNames[i]
						maskedVal, setNull, found := masker.MaskColumn(hintCol, rawVal, strat, autoDetect, enabledEntities)
						if setNull {
							cols[i] = nil
							changed = true
							piiFieldsMasked++
							for k, v := range found {
								piiEntityCounts[k] += v
							}
						} else if len(found) > 0 && maskedVal != rawVal {
							cols[i] = []byte(maskedVal)
							changed = true
							piiFieldsMasked++
							for k, v := range found {
								piiEntityCounts[k] += v
							}
						}
					}
					if changed {
						outPayload = pgwire.EncodeDataRow(cols)
					}
				}
				proxyOverhead += time.Since(t0)
			}

			if !budgetBlocked {
				if err := pgwire.WriteMessage(clientW, pgwire.MsgDataRow, outPayload); err != nil {
					return err
				}
			}

		case pgwire.MsgCommandComplete:
			if budgetBlocked {
				// Emit ErrorResponse instead of CommandComplete
				msg := fmt.Sprintf("pgveil: query exceeded row exfiltration budget (limit %d rows for profile %q)", maxRows, profile.Name)
				if err := pgwire.WriteMessage(clientW, pgwire.MsgErrorResponse,
					pgwire.BuildErrorResponse("ERROR", "42501", msg, "rule=max_rows_budget", "Add a smaller LIMIT clause")); err != nil {
					return err
				}
				continue
			}
			if rowsTruncated {
				notice := fmt.Sprintf("pgveil: result truncated to %d rows (%d excess rows suppressed by profile %q row-exfiltration budget)",
					rowsReturned, rowsDropped, profile.Name)
				_ = pgwire.WriteMessage(clientW, pgwire.MsgNoticeResponse, pgwire.BuildNoticeResponse("NOTICE", "01000", notice))
				// Update SELECT tag count to match delivered rows
				origTag := pgwire.ParseSimpleQuery(payload)
				if strings.HasPrefix(origTag, "SELECT ") {
					payload = pgwire.BuildCommandComplete(fmt.Sprintf("SELECT %d", rowsReturned))
				}
			}
			if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
				return err
			}

		case pgwire.MsgReadyForQuery:
			if len(payload) > 0 {
				meta.txStatus = payload[0]
			}
			totalElapsed := time.Since(upstreamStart)
			upstreamDur := totalElapsed - proxyOverhead
			if upstreamDur < 0 {
				upstreamDur = 0
			}

			finalDecision := "ALLOW"
			policyReason := dec.Reason
			if hitlOutcome != "" {
				finalDecision = hitlOutcome
			} else if budgetBlocked {
				finalDecision = "BLOCKED"
				policyReason = fmt.Sprintf("Exceeded row exfiltration budget (%d rows)", maxRows)
			} else if rowsTruncated {
				finalDecision = "TRUNCATED"
				policyReason = fmt.Sprintf("Truncated to %d rows (%d dropped)", rowsReturned, rowsDropped)
			} else if piiFieldsMasked > 0 {
				finalDecision = "MASKED"
			}

			s.emitTelemetryAndAudit(span, meta, profile, sql, dec, rlsRes, finalDecision, policyReason,
				rowsReturned, rowsDropped, rowsTruncated, piiFieldsMasked, piiEntityCounts,
				proxyOverhead, upstreamDur)

			if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
				return err
			}
			return nil

		default:
			if !budgetBlocked {
				if err := pgwire.WriteMessage(clientW, mType, payload); err != nil {
					return err
				}
			}
		}
	}
}

func (s *Server) handleHITL(
	ctx context.Context,
	meta *sessionMeta,
	profile *policy.RoleProfile,
	sql string,
	dec firewall.Decision,
) (approved bool, outcome string, detail string) {
	timeout := profile.HITLTimeoutDuration(60 * time.Second)
	req := s.hitlMgr.Create(hitl.ApprovalRequest{
		ClientAddr:      meta.clientAddr,
		DBUser:          meta.dbUser,
		Database:        meta.database,
		ApplicationName: meta.appName,
		RoleProfile:     profile.Name,
		StatementType:   dec.StatementType,
		RiskLevel:       dec.RiskLevel,
		Rule:            dec.Rule,
		Reason:          dec.Reason,
		Tables:          dec.Tables,
		SQL:             sql,
	}, timeout)

	if profile.Firewall.HITLMode == "reject" {
		_, _ = s.hitlMgr.Resolve(req.ID, false, "policy:reject-mode", dec.Reason)
		if s.metrics != nil {
			s.metrics.HITLDecisions.WithLabelValues(profile.Name, "rejected_immediate").Inc()
		}
		return false, "HITL_DENIED", fmt.Sprintf("pgveil HITL approval required (request %s): %s", req.ID, dec.Reason)
	}

	slog.Info("query paused for live HITL approval",
		"approval_id", req.ID,
		"profile", profile.Name,
		"statement", dec.StatementType,
		"timeout", timeout.String(),
	)
	s.fireWebhookAsync(fmt.Sprintf("[pgveil HITL PENDING %s] Profile=%q Statement=%s SQL=%q — Approve in Web Console", req.ID, profile.Name, dec.StatementType, sql))

	status, note := s.hitlMgr.Wait(ctx, req)
	if s.metrics != nil {
		s.metrics.HITLDecisions.WithLabelValues(profile.Name, strings.ToLower(string(status))).Inc()
	}
	switch status {
	case hitl.StatusApproved:
		return true, "HITL_APPROVED", "Approved by operator"
	case hitl.StatusDenied:
		msg := fmt.Sprintf("pgveil HITL request %s denied by operator", req.ID)
		if note != "" {
			msg += ": " + note
		}
		return false, "HITL_DENIED", msg
	default:
		return false, "HITL_EXPIRED", fmt.Sprintf("pgveil HITL request %s timed out waiting for approval", req.ID)
	}
}

func (s *Server) sendBlockedError(w io.Writer, txStatus byte, msg, detail, hint string) error {
	return s.sendBlockedErrorCode(w, txStatus, "42501", msg, detail, hint)
}

func (s *Server) sendBlockedErrorCode(w io.Writer, txStatus byte, sqlState, msg, detail, hint string) error {
	if err := pgwire.WriteMessage(w, pgwire.MsgErrorResponse,
		pgwire.BuildErrorResponse("ERROR", sqlState, msg, detail, hint)); err != nil {
		return err
	}
	return pgwire.WriteMessage(w, pgwire.MsgReadyForQuery, pgwire.BuildReadyForQuery(txStatus))
}

func (s *Server) dialUpstream(ctx context.Context, scfg policy.ServerConfig) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", scfg.UpstreamAddr)
	if err != nil {
		return nil, err
	}
	if !scfg.UpstreamTLS.Enabled {
		return conn, nil
	}
	// Negotiate PostgreSQL Wire Protocol SSLRequest (len=8, code=80877103)
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], pgwire.SSLRequestCode)
	if _, err := conn.Write(sslReq[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write upstream SSLRequest: %w", err)
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read upstream SSLRequest reply: %w", err)
	}
	if resp[0] != 'S' {
		_ = conn.Close()
		return nil, errors.New("upstream PostgreSQL server declined TLS (responded 'N')")
	}
	serverName := scfg.UpstreamTLS.ServerName
	if serverName == "" {
		host, _, _ := net.SplitHostPort(scfg.UpstreamAddr)
		serverName = host
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: scfg.UpstreamTLS.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	return tlsConn, nil
}

func (s *Server) checkRateLimit(meta *sessionMeta, profile *policy.RoleProfile, fp string) ratelimit.Decision {
	if s.limiter == nil || profile == nil {
		return ratelimit.Decision{Allowed: true}
	}
	rl := profile.Firewall.RateLimit
	if rl.MaxQueriesPerMinute <= 0 && rl.LoopThreshold <= 0 {
		return ratelimit.Decision{Allowed: true}
	}
	host, _, err := net.SplitHostPort(meta.clientAddr)
	if err != nil {
		host = meta.clientAddr
	}
	key := profile.Name + ":" + host
	return s.limiter.Check(key, fp, rl.MaxQueriesPerMinute, rl.LoopThreshold, profile.Firewall.LoopWindowDuration())
}

func (s *Server) fireWebhookAsync(message string) {
	url := s.policyMgr.Config().Notifications.WebhookURL
	if url == "" {
		return
	}
	go func() {
		payload, _ := json.Marshal(map[string]any{"text": message, "content": message})
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
}

func (s *Server) recordAndEmitBlocked(
	span trace.Span,
	meta *sessionMeta,
	profile *policy.RoleProfile,
	sql string,
	dec firewall.Decision,
	decisionLabel string,
	proxyOverhead time.Duration,
) {
	if s.metrics != nil {
		s.metrics.QueriesTotal.WithLabelValues(profile.Name, dec.StatementType, decisionLabel).Inc()
		s.metrics.BlockedTotal.WithLabelValues(profile.Name, dec.Rule, dec.RiskLevel).Inc()
		s.metrics.ProxyOverheadUs.WithLabelValues(profile.Name).Observe(float64(proxyOverhead.Microseconds()))
	}
	traceID := ""
	if span != nil && span.SpanContext().IsValid() {
		traceID = span.SpanContext().TraceID().String()
		span.SetAttributes(
			attribute.String("pgveil.decision", decisionLabel),
			attribute.String("pgveil.rule", dec.Rule),
		)
	}
	if s.eventBus != nil {
		s.eventBus.Publish(events.AuditEvent{
			TraceID:         traceID,
			ClientAddr:      meta.clientAddr,
			DBUser:          meta.dbUser,
			DatabaseName:    meta.database,
			ApplicationName: meta.appName,
			RoleProfile:     profile.Name,
			StatementType:   dec.StatementType,
			SQLFingerprint:  dec.Fingerprint,
			RawSQLPreview:   strings.TrimSpace(sql),
			Decision:        decisionLabel,
			RiskLevel:       dec.RiskLevel,
			PolicyRule:      dec.Rule,
			PolicyReason:    dec.Reason,
			TablesAccessed:  dec.Tables,
			ProxyOverheadUs: proxyOverhead.Microseconds(),
		})
	}
	if dec.RiskLevel == "CRITICAL" && decisionLabel == "BLOCKED" {
		s.fireWebhookAsync(fmt.Sprintf("[pgveil CRITICAL BLOCK] Profile=%q Rule=%s Reason=%q SQL=%q", profile.Name, dec.Rule, dec.Reason, strings.TrimSpace(sql)))
	}
}

func (s *Server) emitTelemetryAndAudit(
	span trace.Span,
	meta *sessionMeta,
	profile *policy.RoleProfile,
	sql string,
	dec firewall.Decision,
	rlsRes firewall.RLSResult,
	finalDecision string,
	policyReason string,
	rowsReturned int,
	rowsDropped int,
	rowsTruncated bool,
	piiFieldsMasked int,
	piiEntities map[string]int,
	proxyOverhead time.Duration,
	upstreamDur time.Duration,
) {
	// Skip noisy empty/driver-housekeeping audit logs only if empty SQL
	if strings.TrimSpace(sql) == "" {
		return
	}

	if s.metrics != nil {
		s.metrics.QueriesTotal.WithLabelValues(profile.Name, dec.StatementType, finalDecision).Inc()
		s.metrics.RowsReturned.WithLabelValues(profile.Name).Add(float64(rowsReturned))
		if rowsDropped > 0 {
			s.metrics.RowsTruncated.WithLabelValues(profile.Name).Add(float64(rowsDropped))
		}
		for ent, count := range piiEntities {
			s.metrics.PIIFieldsMasked.WithLabelValues(profile.Name, ent).Add(float64(count))
		}
		s.metrics.ProxyOverheadUs.WithLabelValues(profile.Name).Observe(float64(proxyOverhead.Microseconds()))
		s.metrics.UpstreamDurationUs.WithLabelValues(profile.Name).Observe(float64(upstreamDur.Microseconds()))
	}

	traceID := ""
	if span != nil && span.SpanContext().IsValid() {
		traceID = span.SpanContext().TraceID().String()
		span.SetAttributes(
			attribute.String("pgveil.decision", finalDecision),
			attribute.Int("pgveil.rows_returned", rowsReturned),
			attribute.Int("pgveil.pii_fields_masked", piiFieldsMasked),
			attribute.Bool("pgveil.rls_rewritten", rlsRes.Rewritten),
			attribute.Int64("pgveil.proxy_overhead_us", proxyOverhead.Microseconds()),
		)
	}

	if s.eventBus != nil {
		rewrittenPreview := ""
		if rlsRes.Rewritten {
			rewrittenPreview = strings.TrimSpace(rlsRes.SQL)
		}
		s.eventBus.Publish(events.AuditEvent{
			TraceID:             traceID,
			ClientAddr:          meta.clientAddr,
			DBUser:              meta.dbUser,
			DatabaseName:        meta.database,
			ApplicationName:     meta.appName,
			RoleProfile:         profile.Name,
			StatementType:       dec.StatementType,
			SQLFingerprint:      dec.Fingerprint,
			RawSQLPreview:       strings.TrimSpace(sql),
			RLSRewritten:        rlsRes.Rewritten,
			RLSRulesApplied:     rlsRes.RulesApplied,
			RewrittenSQLPreview: rewrittenPreview,
			Decision:            finalDecision,
			RiskLevel:           dec.RiskLevel,
			PolicyRule:          dec.Rule,
			PolicyReason:        policyReason,
			TablesAccessed:      dec.Tables,
			RowsReturned:        rowsReturned,
			RowsTruncated:       rowsTruncated,
			PIIFieldsMasked:     piiFieldsMasked,
			PIIEntities:         piiEntities,
			ProxyOverheadUs:     proxyOverhead.Microseconds(),
			UpstreamDurationUs:  upstreamDur.Microseconds(),
		})
	}
}

func (s *Server) startSpan(ctx context.Context, name string, meta *sessionMeta, profile *policy.RoleProfile) (context.Context, trace.Span) {
	if s.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return s.tracer.Start(ctx, name, trace.WithAttributes(
		attribute.String("db.system", "postgresql"),
		attribute.String("db.user", meta.dbUser),
		attribute.String("db.name", meta.database),
		attribute.String("pgveil.role_profile", profile.Name),
		attribute.String("pgveil.application_name", meta.appName),
	))
}
