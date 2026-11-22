package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/duhanguler/pgveil/internal/chatops"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/jwtauth"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/ratelimit"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	ProtocolVersion           = "2024-11-05"
	StreamableProtocolVersion = "2025-03-26"
)

type callerCtxKey struct{}

// CallerIdentity carries authenticated HTTP/JWT caller attributes into MCP tool execution.
type CallerIdentity struct {
	Subject     string
	ProfileName string
	Claims      map[string]string
	Source      string
	ClientAddr  string
}

func WithCallerIdentity(ctx context.Context, c CallerIdentity) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

func callerFromContext(ctx context.Context, defaultProfile string) CallerIdentity {
	if v, ok := ctx.Value(callerCtxKey{}).(CallerIdentity); ok {
		if v.ProfileName == "" {
			v.ProfileName = defaultProfile
		}
		if v.Subject == "" {
			v.Subject = "anonymous"
		}
		if v.Source == "" {
			v.Source = "mcp-http"
		}
		return v
	}
	return CallerIdentity{
		Subject:     "stdio",
		ProfileName: defaultProfile,
		Source:      "mcp-stdio",
		ClientAddr:  "mcp-stdio",
	}
}

// RPCRequest represents an inbound JSON-RPC 2.0 MCP message over stdio.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RPCResponse represents an outbound JSON-RPC 2.0 MCP response.
type RPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server exposes a zero-trust, native Model Context Protocol (MCP) server over stdio
// directly backed by pgveil's PostgreSQL 17 AST firewall, PII side-channel guard,
// runaway-loop rate limiter, and dynamic multi-compliance PII masker.
type Server struct {
	policyMgr   *policy.Manager
	profileName string
	dsn         string
	limiter     *ratelimit.Limiter
	costRunner  *firewall.CostRunner
	hitlMgr     *hitl.Manager
	eventBus    *events.Bus
	chatOps     *chatops.Notifier
	metrics     *telemetry.Metrics
	verifier    *jwtauth.Verifier
	version     string

	poolMu  sync.Mutex
	pool    *pgxpool.Pool
	poolDSN string

	sessMu   sync.Mutex
	sessions map[string]*mcpSession
}

func NewServer(policyMgr *policy.Manager, profileName, dsn, version string) *Server {
	if profileName == "" {
		profileName = "ai_agent"
	}
	return &Server{
		policyMgr:   policyMgr,
		profileName: profileName,
		dsn:         dsn,
		limiter:     ratelimit.NewLimiter(),
		costRunner:  firewall.NewCostRunner(policyMgr, dsn),
		verifier:    jwtauth.NewVerifier(policyMgr),
		version:     version,
		sessions:    make(map[string]*mcpSession),
	}
}

// AttachControlPlane links the MCP server to the live HITL approval coordinator, audit event bus,
// shared sideband CostRunner, ChatOps notifier, and Prometheus metrics when hosted in `pgveil serve` / `demo`.
func (s *Server) AttachControlPlane(
	hitlMgr *hitl.Manager,
	eventBus *events.Bus,
	costRunner *firewall.CostRunner,
	chatOps *chatops.Notifier,
	metrics *telemetry.Metrics,
) *Server {
	s.hitlMgr = hitlMgr
	s.eventBus = eventBus
	if costRunner != nil {
		s.costRunner.Close()
		s.costRunner = costRunner
	}
	s.chatOps = chatOps
	s.metrics = metrics
	return s
}

// Close releases pooled upstream database connections.
func (s *Server) Close() {
	s.poolMu.Lock()
	if s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}
	s.poolMu.Unlock()
}

// ServeStdio reads newline-delimited JSON-RPC 2.0 MCP messages from in and writes responses to out.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(out)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req RPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(RPCResponse{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
			})
			continue
		}
		resp := s.HandleRequest(ctx, req)
		if resp != nil {
			if err := enc.Encode(resp); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

// HandleRequest processes a single MCP JSON-RPC request.
func (s *Server) HandleRequest(ctx context.Context, req RPCRequest) *RPCResponse {
	switch req.Method {
	case "notifications/initialized", "notifications/cancelled":
		return nil // JSON-RPC notification: no response
	case "ping":
		return &RPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "initialize":
		protoVer := ProtocolVersion
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(req.Params) > 0 && json.Unmarshal(req.Params, &initParams) == nil {
			if initParams.ProtocolVersion == StreamableProtocolVersion {
				protoVer = StreamableProtocolVersion
			}
		}
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": protoVer,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    "pgveil-mcp",
					"version": s.version,
				},
			},
		}
	case "tools/list":
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return &RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "invalid tool call params: " + err.Error()},
			}
		}
		text, isErr := s.callTool(ctx, params.Name, params.Arguments)
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": text},
				},
				"isError": isErr,
			},
		}
	default:
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

func (s *Server) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_tables",
			"description": "List accessible PostgreSQL tables (restricted/secret tables are automatically hidden by pgveil policy).",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "describe_table",
			"description": "Inspect column names, data types, and active PII masking rules for an allowed PostgreSQL table.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"table": map[string]any{"type": "string", "description": "Table name (e.g., customers, orders)"},
				},
				"required": []string{"table"},
			},
		},
		{
			"name":        "query",
			"description": "Execute a read-only SQL query protected by pgveil's PostgreSQL 17 AST firewall, PII side-channel guard, dynamic GDPR/KVKK/PCI-DSS masker, and row-exfiltration cap.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"sql": map[string]any{"type": "string", "description": "PostgreSQL SELECT / EXPLAIN / SHOW statement"},
				},
				"required": []string{"sql"},
			},
		},
		{
			"name":        "explain_query",
			"description": "Inspect the PostgreSQL execution plan (EXPLAIN) for a query without exposing table rows.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"sql": map[string]any{"type": "string", "description": "SELECT statement to analyze"},
				},
				"required": []string{"sql"},
			},
		},
	}
}

func (s *Server) activeProfileFor(name string) *policy.RoleProfile {
	if name == "" {
		name = s.profileName
	}
	if prof, ok := s.policyMgr.GetProfileByName(name); ok {
		return prof
	}
	return s.policyMgr.MatchProfile("", name)
}

func (s *Server) activeProfile() *policy.RoleProfile {
	return s.activeProfileFor(s.profileName)
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (string, bool) {
	caller := callerFromContext(ctx, s.profileName)
	prof := s.activeProfileFor(caller.ProfileName)
	switch name {
	case "list_tables":
		return s.toolListTables(ctx, prof)
	case "describe_table":
		tbl, _ := args["table"].(string)
		return s.toolDescribeTable(ctx, prof, tbl)
	case "query":
		sqlStr, _ := args["sql"].(string)
		return s.toolQuery(ctx, prof, caller, sqlStr)
	case "explain_query":
		sqlStr, _ := args["sql"].(string)
		explainSQL, err := firewall.InspectExplainPlanOnly(sqlStr)
		if err != nil {
			return err.Error(), true
		}
		return s.toolQuery(ctx, prof, caller, explainSQL)
	default:
		return fmt.Sprintf("unknown tool %q", name), true
	}
}

func (s *Server) toolListTables(ctx context.Context, prof *policy.RoleProfile) (string, bool) {
	pool, err := s.getPool(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}

	denied := make(map[string]bool)
	for _, t := range prof.Firewall.DeniedTables {
		denied[strings.ToLower(strings.TrimSpace(t))] = true
	}
	allowed := make(map[string]bool)
	for _, t := range prof.Firewall.AllowedTables {
		if lt := strings.ToLower(strings.TrimSpace(t)); lt != "" {
			allowed[lt] = true
		}
	}

	rows, err := pool.Query(ctx, `
		SELECT table_schema, table_name
		FROM information_schema.tables
		WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
		  AND table_type = 'BASE TABLE'
		ORDER BY table_schema, table_name
	`)
	if err != nil {
		return "query error: " + err.Error(), true
	}
	defer rows.Close()

	var visible []string
	hiddenCount := 0
	for rows.Next() {
		var sch, tbl string
		if err := rows.Scan(&sch, &tbl); err != nil {
			continue
		}
		full := strings.ToLower(sch + "." + tbl)
		bare := strings.ToLower(tbl)
		if denied[bare] || denied[full] || (len(allowed) > 0 && !allowed[bare] && !allowed[full]) {
			hiddenCount++
			continue
		}
		visible = append(visible, sch+"."+tbl)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"profile":            prof.Name,
		"accessible_tables":  visible,
		"restricted_omitted": hiddenCount,
	}, "", "  ")
	return string(out), false
}

func (s *Server) toolDescribeTable(ctx context.Context, prof *policy.RoleProfile, table string) (string, bool) {
	raw := strings.TrimSpace(table)
	if raw == "" {
		return "table parameter is required", true
	}
	// Strip optional quotes and split optional schema.table so both "api_secrets" and "public.api_secrets" are enforced
	cleaned := strings.ReplaceAll(raw, `"`, "")
	schemaFilter := ""
	bareTable := cleaned
	if idx := strings.LastIndexByte(cleaned, '.'); idx >= 0 {
		schemaFilter = strings.TrimSpace(cleaned[:idx])
		bareTable = strings.TrimSpace(cleaned[idx+1:])
	}
	if bareTable == "" {
		return "table parameter is invalid", true
	}
	lowFull := strings.ToLower(cleaned)
	lowBare := strings.ToLower(bareTable)
	for _, d := range prof.Firewall.DeniedTables {
		ld := strings.ToLower(strings.TrimSpace(d))
		if ld == lowFull || ld == lowBare {
			return fmt.Sprintf("pgveil policy denied schema inspection of restricted table %q for profile %q", raw, prof.Name), true
		}
	}
	if len(prof.Firewall.AllowedTables) > 0 {
		ok := false
		for _, a := range prof.Firewall.AllowedTables {
			la := strings.ToLower(strings.TrimSpace(a))
			if la == lowFull || la == lowBare {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Sprintf("pgveil policy denied schema inspection: table %q is outside allowed_tables for profile %q", raw, prof.Name), true
		}
	}
	if prof.Firewall.BlockSystemCatalogs && (strings.EqualFold(schemaFilter, "pg_catalog") || strings.HasPrefix(lowBare, "pg_")) {
		return fmt.Sprintf("pgveil policy denied schema inspection of system catalog %q for profile %q", raw, prof.Name), true
	}
	pool, err := s.getPool(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}

	rows, err := pool.Query(ctx, `
		SELECT column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE lower(table_name) = lower($1)
		  AND ($2 = '' OR lower(table_schema) = lower($2))
		  AND table_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY ordinal_position
	`, bareTable, schemaFilter)
	if err != nil {
		return "describe error: " + err.Error(), true
	}
	defer rows.Close()

	type colMeta struct {
		Column          string `json:"column"`
		Type            string `json:"type"`
		Nullable        string `json:"nullable"`
		MaskingStrategy string `json:"masking_strategy,omitempty"`
	}
	var cols []colMeta
	for rows.Next() {
		var c colMeta
		if err := rows.Scan(&c.Column, &c.Type, &c.Nullable); err == nil {
			if st := prof.ColumnStrategy(c.Column); st != "" {
				c.MaskingStrategy = string(st)
			}
			cols = append(cols, c)
		}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"table":   raw,
		"profile": prof.Name,
		"columns": cols,
	}, "", "  ")
	return string(out), false
}

func (s *Server) toolQuery(ctx context.Context, prof *policy.RoleProfile, caller CallerIdentity, sqlStr string) (string, bool) {
	if strings.TrimSpace(sqlStr) == "" {
		return "sql parameter is required", true
	}

	t0 := time.Now()
	// 1. PostgreSQL 17 AST Firewall + PII Side-Channel + Timeout GUC Guard
	dec := firewall.Evaluate(sqlStr, prof)
	if dec.Action == firewall.ActionBlock && !prof.IsAuditOnly() {
		s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "BLOCKED", dec.Reason, 0, false, 0, nil, time.Since(t0), 0)
		return fmt.Sprintf("BLOCKED by pgveil AST Firewall [%s]: %s", dec.Rule, dec.Reason), true
	}

	// 2. Tenant/Subject-Isolated Rate Limit & Runaway Loop Circuit Breaker
	rlKey := "mcp:" + prof.Name + ":" + caller.Subject
	rl := s.limiter.Check(rlKey, dec.Fingerprint,
		prof.Firewall.RateLimit.MaxQueriesPerMinute,
		prof.Firewall.RateLimit.LoopThreshold,
		prof.Firewall.LoopWindowDuration(),
	)
	if !rl.Allowed && !prof.IsAuditOnly() {
		dec.Rule = rl.Rule
		dec.Reason = rl.Reason
		dec.RiskLevel = "HIGH"
		s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "BLOCKED", rl.Reason, 0, false, 0, nil, time.Since(t0), 0)
		return fmt.Sprintf("THROTTLED by pgveil [%s]: %s", rl.Rule, rl.Reason), true
	}

	// 3. Zero-DB-Connection Live Human-in-the-Loop (HITL) Hold
	hitlDecision := ""
	if dec.Action == firewall.ActionRequireHITL && !prof.IsAuditOnly() {
		if s.hitlMgr == nil {
			return fmt.Sprintf("APPROVAL REQUIRED [%s]: %s (connect via pgveil serve /mcp or wire port 6432 for live HITL holds)", dec.Rule, dec.Reason), true
		}
		timeout := prof.HITLTimeoutDuration(60 * time.Second)
		cfg := s.policyMgr.Config()
		req, qErr := s.hitlMgr.CreateWithQuota(hitl.ApprovalRequest{
			ClientAddr:      caller.ClientAddr,
			DBUser:          cfg.Server.UpstreamUser,
			Database:        cfg.Server.UpstreamDatabase,
			ApplicationName: caller.Source + ":" + caller.Subject,
			RoleProfile:     prof.Name,
			StatementType:   dec.StatementType,
			RiskLevel:       dec.RiskLevel,
			Rule:            dec.Rule,
			Reason:          dec.Reason,
			Tables:          dec.Tables,
			SQL:             sqlStr,
			ActorKey:        rlKey,
		}, timeout, hitl.DefaultMaxPendingGlobal, hitl.DefaultMaxPendingPerActor)
		if qErr != nil {
			dec.Rule = "hitl_quota_exceeded"
			dec.Reason = qErr.Error()
			s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "BLOCKED", qErr.Error(), 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("BLOCKED by pgveil HITL quota: %v", qErr), true
		}
		if prof.Firewall.HITLMode == "reject" {
			_, _ = s.hitlMgr.Resolve(req.ID, false, "policy:reject-mode", dec.Reason)
			s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "HITL_DENIED", dec.Reason, 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("APPROVAL REQUIRED [%s]: request %s rejected immediately by hitl_mode=reject", dec.Rule, req.ID), true
		}
		if s.chatOps != nil {
			s.chatOps.NotifyHITLPending(*req)
		}
		st, note := s.hitlMgr.Wait(ctx, req)
		switch st {
		case hitl.StatusApproved:
			hitlDecision = "HITL_APPROVED"
		case hitl.StatusDenied:
			s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "HITL_DENIED", note, 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("DENIED by operator (request %s): %s", req.ID, note), true
		default:
			s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "HITL_EXPIRED", note, 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("EXPIRED waiting for operator approval (request %s)", req.ID), true
		}
	}

	// 4. Typed AST Virtual Row-Level Security (RLS) with fail-closed {{jwt.*}} claim binding
	execSQL := sqlStr
	var rlsRes firewall.RLSResult
	if !prof.IsAuditOnly() && len(prof.Firewall.RowFilters) > 0 {
		cfg := s.policyMgr.Config()
		var rlsErr error
		rlsRes, rlsErr = firewall.RewriteWithRLS(sqlStr, prof, firewall.SessionContext{
			DBUser:          cfg.Server.UpstreamUser,
			Database:        cfg.Server.UpstreamDatabase,
			ApplicationName: caller.Source,
			RoleProfile:     prof.Name,
			Claims:          caller.Claims,
		})
		if rlsErr != nil {
			dec.Rule = "virtual_rls_missing_claim"
			dec.Reason = rlsErr.Error()
			dec.RiskLevel = "HIGH"
			s.emitAudit(prof, caller, sqlStr, dec, firewall.RLSResult{}, nil, "BLOCKED", rlsErr.Error(), 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("BLOCKED by pgveil Virtual RLS: %v", rlsErr), true
		}
		if rlsRes.Rewritten {
			execSQL = rlsRes.SQL
		}
	}

	// 5. Sideband EXPLAIN (FORMAT JSON) Cost & Blast-Radius Guard
	var planMetrics *firewall.PlanMetrics
	if s.costRunner != nil && prof.Firewall.CostGuard.Enabled {
		cv := s.costRunner.Check(ctx, execSQL, dec.Fingerprint, rlsRes.RulesApplied, prof)
		planMetrics = cv.Metrics
		if cv.Evaluated && s.metrics != nil && s.metrics.CostGuardEvaluations != nil {
			outcome := "allow"
			if cv.Fallback {
				outcome = "fallback"
			} else if cv.Blocked {
				outcome = "block"
			}
			cacheLbl := "miss"
			if cv.CacheHit {
				cacheLbl = "hit"
			}
			s.metrics.CostGuardEvaluations.WithLabelValues(prof.Name, outcome, cacheLbl).Inc()
		}
		if cv.Blocked && !prof.IsAuditOnly() {
			dec.Rule = cv.Rule
			dec.Reason = cv.Reason
			dec.RiskLevel = "HIGH"
			s.emitAudit(prof, caller, sqlStr, dec, rlsRes, planMetrics, "BLOCKED", cv.Reason, 0, false, 0, nil, time.Since(t0), 0)
			return fmt.Sprintf("BLOCKED by pgveil Cost Guard [%s]: %s", cv.Rule, cv.Reason), true
		}
	}

	proxyOverhead := time.Since(t0)

	// 6. Execute via pooled PostgreSQL connection with enforced max_query_duration
	pool, err := s.getPool(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}

	qTimeout := prof.Firewall.MaxQueryDurationParsed()
	ctxTimeout := qTimeout
	if ctxTimeout <= 0 {
		ctxTimeout = 15 * time.Second
	}
	qCtx, cancel := context.WithTimeout(ctx, ctxTimeout)
	defer cancel()

	// Acquire a dedicated pooled connection so server-side PostgreSQL statement_timeout is enforced
	// atomically per profile and cleanly reset to 0 before returning the connection to the pool.
	conn, err := pool.Acquire(qCtx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}
	appliedTimeout := false
	if qTimeout > 0 {
		ms := qTimeout.Milliseconds()
		if ms < 1 {
			ms = 1
		}
		if _, terr := conn.Exec(qCtx, fmt.Sprintf("SET statement_timeout = '%dms'", ms)); terr == nil {
			appliedTimeout = true
		}
	}
	defer func() {
		if appliedTimeout {
			rctx, rcancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_, _ = conn.Exec(rctx, "SET statement_timeout = 0")
			rcancel()
		}
		conn.Release()
	}()

	upStart := time.Now()
	rows, err := conn.Query(qCtx, execSQL)
	if err != nil {
		return "PostgreSQL error: " + err.Error(), true
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	cols := make([]string, len(fds))
	strats := make([]pii.Strategy, len(fds))
	hintCols := make([]string, len(fds))
	for i, fd := range fds {
		cols[i] = string(fd.Name)
		hintCols[i] = cols[i]
		if prof.Masking.Enabled {
			st := prof.ColumnStrategy(cols[i])
			if st == "" && i < len(dec.TargetSources) {
				for _, src := range dec.TargetSources[i] {
					if srcStrat := prof.ColumnStrategy(src); srcStrat != "" {
						st = srcStrat
						hintCols[i] = src
						break
					}
				}
			}
			if st == "" && len(dec.AliasSources) > 0 {
				for _, src := range dec.AliasSources[strings.ToLower(cols[i])] {
					if srcStrat := prof.ColumnStrategy(src); srcStrat != "" {
						st = srcStrat
						hintCols[i] = src
						break
					}
				}
			}
			strats[i] = st
		}
	}

	masker := s.policyMgr.Masker()
	enabled := prof.EnabledEntities()
	maxRows := prof.Firewall.MaxRows
	result := make([]map[string]any, 0, 32)
	truncated := false
	maskedCells := 0
	entityCounts := make(map[string]int)

	for rows.Next() {
		if maxRows > 0 && len(result) >= maxRows {
			truncated = true
			break
		}
		rawVals := rows.RawValues()
		rec := make(map[string]any, len(cols))
		for i, col := range cols {
			if i >= len(rawVals) || rawVals[i] == nil {
				rec[col] = nil
				continue
			}
			val := string(rawVals[i])
			if prof.Masking.Enabled {
				mv, setNull, found := masker.MaskColumn(hintCols[i], val, strats[i], prof.Masking.AutoDetectPII, enabled)
				if setNull {
					rec[col] = nil
					maskedCells++
					for k, v := range found {
						entityCounts[k] += v
					}
					continue
				}
				if len(found) > 0 && mv != val {
					val = mv
					maskedCells++
					for k, v := range found {
						entityCounts[k] += v
					}
				}
			}
			rec[col] = val
		}
		result = append(result, rec)
	}
	if err := rows.Err(); err != nil {
		return "PostgreSQL error: " + err.Error(), true
	}
	rows.Close()
	cmdTag := rows.CommandTag().String()
	if cmdTag == "" {
		cmdTag = fmt.Sprintf("SELECT %d", len(result))
	}
	upDur := time.Since(upStart)

	finalDecision := "ALLOW"
	if hitlDecision != "" {
		finalDecision = hitlDecision
	} else if truncated {
		finalDecision = "TRUNCATED"
	} else if maskedCells > 0 {
		finalDecision = "MASKED"
	}
	s.emitAudit(prof, caller, sqlStr, dec, rlsRes, planMetrics, finalDecision, dec.Reason, len(result), truncated, maskedCells, entityCounts, proxyOverhead, upDur)

	outMap := map[string]any{
		"profile":          prof.Name,
		"columns":          cols,
		"command_tag":      cmdTag,
		"row_count":        len(result),
		"truncated":        truncated,
		"pii_cells_masked": maskedCells,
		"rows":             result,
	}
	if rlsRes.Rewritten {
		outMap["rls_rewritten"] = true
		outMap["rls_rules_applied"] = rlsRes.RulesApplied
	}
	if planMetrics != nil {
		outMap["estimated_cost"] = planMetrics.TotalCost
		outMap["estimated_rows"] = planMetrics.PlanRows
	}
	payload, _ := json.MarshalIndent(outMap, "", "  ")
	return string(payload), false
}

func (s *Server) emitAudit(
	prof *policy.RoleProfile,
	caller CallerIdentity,
	sqlStr string,
	dec firewall.Decision,
	rlsRes firewall.RLSResult,
	pm *firewall.PlanMetrics,
	decision string,
	reason string,
	rowsReturned int,
	truncated bool,
	maskedCells int,
	entities map[string]int,
	overhead time.Duration,
	upDur time.Duration,
) {
	if s.eventBus == nil {
		return
	}
	cfg := s.policyMgr.Config()
	rewrittenPreview := ""
	if rlsRes.Rewritten {
		rewrittenPreview = rlsRes.SQL
	}
	ev := events.AuditEvent{
		ClientAddr:          caller.ClientAddr,
		Source:              caller.Source,
		AuthSubject:         caller.Subject,
		DBUser:              cfg.Server.UpstreamUser,
		DatabaseName:        cfg.Server.UpstreamDatabase,
		ApplicationName:     caller.Source,
		RoleProfile:         prof.Name,
		StatementType:       dec.StatementType,
		SQLFingerprint:      dec.Fingerprint,
		RawSQLPreview:       strings.TrimSpace(sqlStr),
		RLSRewritten:        rlsRes.Rewritten,
		RLSRulesApplied:     rlsRes.RulesApplied,
		RewrittenSQLPreview: rewrittenPreview,
		Decision:            decision,
		RiskLevel:           dec.RiskLevel,
		PolicyRule:          dec.Rule,
		PolicyReason:        reason,
		TablesAccessed:      dec.Tables,
		RowsReturned:        rowsReturned,
		RowsTruncated:       truncated,
		PIIFieldsMasked:     maskedCells,
		PIIEntities:         entities,
		ProxyOverheadUs:     overhead.Microseconds(),
		UpstreamDurationUs:  upDur.Microseconds(),
	}
	if pm != nil {
		ev.EstimatedCost = pm.TotalCost
		ev.EstimatedRows = pm.PlanRows
		ev.SeqScanTables = pm.SeqScanTables
	}
	s.eventBus.Publish(ev)
}

func (s *Server) resolveDSN() string {
	if s.dsn != "" {
		return s.dsn
	}
	cfg := s.policyMgr.Config()
	return policy.BuildDSN(
		cfg.Server.UpstreamAddr,
		cfg.Server.UpstreamUser,
		cfg.Server.UpstreamPassword,
		cfg.Server.UpstreamDatabase,
		"pgveil-mcp",
		cfg.Server.UpstreamTLS.Enabled,
	)
}

func (s *Server) getPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := s.resolveDSN()
	s.poolMu.Lock()
	defer s.poolMu.Unlock()

	if s.pool != nil && s.poolDSN == dsn {
		return s.pool, nil
	}
	if s.pool != nil {
		s.pool.Close()
		s.pool = nil
	}

	pcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pcfg.MaxConns = 10
	pcfg.MinConns = 0
	pcfg.MaxConnIdleTime = 2 * time.Minute
	pcfg.ConnConfig.ConnectTimeout = 3 * time.Second
	pcfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, err
	}
	s.pool = pool
	s.poolDSN = dsn
	return pool, nil
}
