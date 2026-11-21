package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/ratelimit"
	"github.com/jackc/pgx/v5"
)

const ProtocolVersion = "2024-11-05"

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
	version     string
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
		version:     version,
	}
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
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": ProtocolVersion,
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

func (s *Server) activeProfile() *policy.RoleProfile {
	if prof, ok := s.policyMgr.GetProfileByName(s.profileName); ok {
		return prof
	}
	return s.policyMgr.MatchProfile("", s.profileName)
}

func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (string, bool) {
	prof := s.activeProfile()
	switch name {
	case "list_tables":
		return s.toolListTables(ctx, prof)
	case "describe_table":
		tbl, _ := args["table"].(string)
		return s.toolDescribeTable(ctx, prof, tbl)
	case "query":
		sqlStr, _ := args["sql"].(string)
		return s.toolQuery(ctx, prof, sqlStr)
	case "explain_query":
		sqlStr, _ := args["sql"].(string)
		trimmed := strings.TrimSpace(sqlStr)
		if trimmed == "" {
			return "sql parameter is required", true
		}
		upper := strings.ToUpper(trimmed)
		// Block ANALYZE inside explain_query so this tool NEVER executes or mutates rows
		if strings.Contains(upper, "ANALYZE") {
			return "BLOCKED by pgveil: explain_query is plan-only and disallows EXPLAIN ANALYZE", true
		}
		if strings.HasPrefix(upper, "EXPLAIN ") || upper == "EXPLAIN" {
			return s.toolQuery(ctx, prof, trimmed)
		}
		return s.toolQuery(ctx, prof, "EXPLAIN "+trimmed)
	default:
		return fmt.Sprintf("unknown tool %q", name), true
	}
}

func (s *Server) toolListTables(ctx context.Context, prof *policy.RoleProfile) (string, bool) {
	conn, err := s.dialDB(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}
	defer conn.Close(context.Background())

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

	rows, err := conn.Query(ctx, `
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
	conn, err := s.dialDB(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(ctx, `
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

func (s *Server) toolQuery(ctx context.Context, prof *policy.RoleProfile, sqlStr string) (string, bool) {
	if strings.TrimSpace(sqlStr) == "" {
		return "sql parameter is required", true
	}

	// 1. PostgreSQL 17 AST Firewall + PII Side-Channel Guard
	dec := firewall.Evaluate(sqlStr, prof)
	if dec.Action == firewall.ActionBlock {
		return fmt.Sprintf("BLOCKED by pgveil AST Firewall [%s]: %s", dec.Rule, dec.Reason), true
	}
	if dec.Action == firewall.ActionRequireHITL {
		return fmt.Sprintf("APPROVAL REQUIRED [%s]: %s (connect via pgveil wire port 6432 for live HITL holds)", dec.Rule, dec.Reason), true
	}

	// 2. Per-Profile Rate Limit & Runaway Loop Circuit Breaker
	rl := s.limiter.Check("mcp:"+prof.Name, dec.Fingerprint,
		prof.Firewall.RateLimit.MaxQueriesPerMinute,
		prof.Firewall.RateLimit.LoopThreshold,
		prof.Firewall.LoopWindowDuration(),
	)
	if !rl.Allowed {
		return fmt.Sprintf("THROTTLED by pgveil [%s]: %s", rl.Rule, rl.Reason), true
	}

	// 3. AST-level Virtual Row-Level Security (RLS) predicate injection
	execSQL := sqlStr
	var rlsRes firewall.RLSResult
	if !prof.IsAuditOnly() && len(prof.Firewall.RowFilters) > 0 {
		cfg := s.policyMgr.Config()
		var rlsErr error
		rlsRes, rlsErr = firewall.RewriteWithRLS(sqlStr, prof, firewall.SessionContext{
			DBUser:          cfg.Server.UpstreamUser,
			Database:        cfg.Server.UpstreamDatabase,
			ApplicationName: "pgveil-mcp",
			RoleProfile:     prof.Name,
		})
		if rlsErr != nil {
			return fmt.Sprintf("BLOCKED by pgveil Virtual RLS: %v", rlsErr), true
		}
		if rlsRes.Rewritten {
			execSQL = rlsRes.SQL
		}
	}

	conn, err := s.dialDB(ctx)
	if err != nil {
		return "database connection error: " + err.Error(), true
	}
	defer conn.Close(context.Background())

	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

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
					continue
				}
				if len(found) > 0 && mv != val {
					val = mv
					maskedCells++
				}
			}
			rec[col] = val
		}
		result = append(result, rec)
	}
	if err := rows.Err(); err != nil {
		return "PostgreSQL error: " + err.Error(), true
	}

	outMap := map[string]any{
		"profile":          prof.Name,
		"row_count":        len(result),
		"truncated":        truncated,
		"pii_cells_masked": maskedCells,
		"rows":             result,
	}
	if rlsRes.Rewritten {
		outMap["rls_rewritten"] = true
		outMap["rls_rules_applied"] = rlsRes.RulesApplied
	}
	payload, _ := json.MarshalIndent(outMap, "", "  ")
	return string(payload), false
}

func (s *Server) dialDB(ctx context.Context) (*pgx.Conn, error) {
	dsn := s.dsn
	if dsn == "" {
		cfg := s.policyMgr.Config()
		dsn = policy.BuildDSN(
			cfg.Server.UpstreamAddr,
			cfg.Server.UpstreamUser,
			cfg.Server.UpstreamPassword,
			cfg.Server.UpstreamDatabase,
			"pgveil-mcp",
			cfg.Server.UpstreamTLS.Enabled,
		)
	}
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return pgx.ConnectConfig(ctx, connCfg)
}
