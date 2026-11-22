package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/chatops"
	"github.com/duhanguler/pgveil/internal/discover"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/mcpserver"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves the Control Plane REST API, real-time SSE stream, Prometheus /metrics,
// live SQL Playground (wired through pgveil's real wire proxy!), and embedded Web Console.
type Server struct {
	policyMgr  *policy.Manager
	hitlMgr    *hitl.Manager
	eventBus   *events.Bus
	costRunner *firewall.CostRunner
	chatOps    *chatops.Notifier
	mcpSrv     *mcpserver.Server
	metrics    *telemetry.Metrics
	proxyAddr  func() string
	promReg    prometheus.Gatherer
	webFS      fs.FS
	version    string
}

func NewServer(
	policyMgr *policy.Manager,
	hitlMgr *hitl.Manager,
	eventBus *events.Bus,
	proxyAddr func() string,
	promReg prometheus.Gatherer,
	webFS fs.FS,
	version string,
) *Server {
	if promReg == nil {
		promReg = prometheus.DefaultGatherer
	}
	cr := firewall.NewCostRunner(policyMgr, "")
	co := chatops.NewNotifier(policyMgr, nil)
	ms := mcpserver.NewServer(policyMgr, "ai_agent", "", version).AttachControlPlane(hitlMgr, eventBus, cr, co, nil)
	return &Server{
		policyMgr:  policyMgr,
		hitlMgr:    hitlMgr,
		eventBus:   eventBus,
		costRunner: cr,
		chatOps:    co,
		mcpSrv:     ms,
		proxyAddr:  proxyAddr,
		promReg:    promReg,
		webFS:      webFS,
		version:    version,
	}
}

// AttachRuntime wires shared CostRunner, ChatOps Notifier, and Prometheus Metrics from the wire proxy
// so both Wire Proxy and Streamable HTTP /mcp share a single PlanCache, HITL dispatcher, and metric registry.
func (s *Server) AttachRuntime(costRunner *firewall.CostRunner, chatOps *chatops.Notifier, metrics *telemetry.Metrics) *Server {
	if costRunner != nil {
		if s.costRunner != nil && s.costRunner != costRunner {
			s.costRunner.Close()
		}
		s.costRunner = costRunner
	}
	if chatOps != nil {
		s.chatOps = chatOps
	}
	s.metrics = metrics
	s.mcpSrv.AttachControlPlane(s.hitlMgr, s.eventBus, s.costRunner, s.chatOps, metrics)
	return s
}

// Close releases pooled MCP and sideband CostRunner resources owned by the API server.
func (s *Server) Close() {
	if s.mcpSrv != nil {
		s.mcpSrv.Close()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health & Observability
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleHealth)
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.promReg, promhttp.HandlerOpts{}))

	// Control Plane REST API
	mux.HandleFunc("GET /api/v1/summary", s.handleSummary)
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /api/v1/policies", s.handleGetPolicies)
	mux.HandleFunc("PUT /api/v1/policies/yaml", s.handleReloadPolicies)
	mux.HandleFunc("POST /api/v1/inspect", s.handleInspect)
	mux.HandleFunc("POST /api/v1/playground/query", s.handlePlaygroundQuery)
	mux.HandleFunc("POST /api/v1/discover", s.handleDiscover)

	// Human-in-the-Loop (HITL) Approvals
	mux.HandleFunc("GET /api/v1/approvals", s.handleListApprovals)
	mux.HandleFunc("POST /api/v1/approvals/{id}/approve", s.handleResolveApproval(true))
	mux.HandleFunc("POST /api/v1/approvals/{id}/deny", s.handleResolveApproval(false))
	mux.HandleFunc("POST /api/v1/chatops/test", s.handleChatOpsTest)

	// Cryptographically Verified ChatOps Webhooks (outside /api/v1/ admin_token; verified by HMAC-SHA256)
	mux.HandleFunc("POST /webhooks/slack/interactions", s.handleSlackInteraction)
	mux.HandleFunc("GET /webhooks/hitl/callback", s.handleHITLCallbackPreview)
	mux.HandleFunc("POST /webhooks/hitl/callback", s.handleHITLCallbackAction)

	// Streamable HTTP Model Context Protocol (2025-03-26) endpoint
	mux.HandleFunc("/mcp", s.handleMCPHTTP)

	// Embedded React Web Console
	if s.webFS != nil {
		mux.Handle("/", s.spaHandler(s.webFS))
	}

	return s.withCORS(s.withOptionalAuth(mux))
}

func (s *Server) withOptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := s.policyMgr.Config().Security.AdminToken
		if token == "" || !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		const prefix = "Bearer "
		provided := ""
		if strings.HasPrefix(authz, prefix) {
			provided = strings.TrimSpace(strings.TrimPrefix(authz, prefix))
		} else if qTok := r.URL.Query().Get("token"); qTok != "" && r.URL.Path == "/api/v1/events/stream" {
			// EventSource in browsers cannot set custom Authorization headers; allow query token on SSE only.
			provided = qTok
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pgveil"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized: valid Bearer token required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	cfg := s.policyMgr.Config()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"version":            s.version,
		"proxy_addr":         s.resolveProxyAddr(),
		"upstream_addr":      cfg.Server.UpstreamAddr,
		"kafka_enabled":      cfg.Kafka.Enabled,
		"mcp_http_enabled":   cfg.MCP.HTTPEnabled,
		"mcp_auth_enabled":   cfg.MCP.Auth.Enabled,
		"chatops_configured": s.chatOps.IsConfigured(),
		"profiles_count":     len(cfg.Profiles),
		"pending_hitl":       s.hitlMgr.PendingCount(),
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sum := s.eventBus.Summary()
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":      sum,
		"pending_hitl": s.hitlMgr.PendingCount(),
		"proxy_addr":   s.resolveProxyAddr(),
		"version":      s.version,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	decision := r.URL.Query().Get("decision")
	role := r.URL.Query().Get("role")
	writeJSON(w, http.StatusOK, map[string]any{
		"events": s.eventBus.Recent(limit, decision, role),
	})
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	evCh, unsubEv := s.eventBus.Subscribe()
	defer unsubEv()
	hitlCh, unsubHITL := s.hitlMgr.Subscribe()
	defer unsubHITL()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Send initial handshake comment
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-evCh:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			_, _ = fmt.Fprintf(w, "event: audit\ndata: %s\n\n", b)
			flusher.Flush()
		case req, ok := <-hitlCh:
			if !ok {
				return
			}
			b, _ := json.Marshal(req)
			_, _ = fmt.Fprintf(w, "event: approval\ndata: %s\n\n", b)
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	cfg := s.policyMgr.Config()
	redactedYAML, version := s.policyMgr.RedactedYAML()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         version,
		"default_profile": cfg.DefaultProfile,
		"profiles":        cfg.Profiles,
		"compliance_packs": map[string][]pii.EntityType{
			"kvkk":    pii.PackEntities[pii.PackKVKK],
			"gdpr":    pii.PackEntities[pii.PackGDPR],
			"pci-dss": pii.PackEntities[pii.PackPCIDSS],
			"hipaa":   pii.PackEntities[pii.PackHIPAA],
			"lgpd":    pii.PackEntities[pii.PackLGPD],
			"pipeda":  pii.PackEntities[pii.PackPIPEDA],
			"uk-gdpr": pii.PackEntities[pii.PackUKGDPR],
			"secrets": pii.PackEntities[pii.PackSecrets],
		},
		"yaml": redactedYAML,
	})
}

func (s *Server) handleReloadPolicies(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var payload struct {
		YAML string `json:"yaml"`
	}
	raw := body
	if err := json.Unmarshal(body, &payload); err == nil && payload.YAML != "" {
		raw = []byte(payload.YAML)
	}
	if err := s.policyMgr.ReloadBytes(raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	_, ver := s.policyMgr.RawYAML()
	slog.Info("policies hot-reloaded via Control Plane API", "version", ver)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "reloaded",
		"version": ver,
	})
}

func (s *Server) handleInspect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SQL       string            `json:"sql"`
		Profile   string            `json:"profile"`
		Sample    string            `json:"sample_text"`
		JWTClaims map[string]string `json:"jwt_claims"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	prof, ok := s.policyMgr.GetProfileByName(req.Profile)
	if !ok {
		prof = s.policyMgr.MatchProfile("", req.Profile)
	}
	dec := firewall.Evaluate(req.SQL, prof)
	cfg := s.policyMgr.Config()
	var rlsRes firewall.RLSResult
	if dec.Action != firewall.ActionBlock && len(prof.Firewall.RowFilters) > 0 {
		res, rerr := firewall.RewriteWithRLS(req.SQL, prof, firewall.SessionContext{
			DBUser:          cfg.Server.UpstreamUser,
			Database:        cfg.Server.UpstreamDatabase,
			ApplicationName: prof.Name,
			RoleProfile:     prof.Name,
			Claims:          req.JWTClaims,
		})
		if rerr != nil {
			dec.Action = firewall.ActionBlock
			dec.Rule = "virtual_rls_missing_claim"
			dec.Reason = rerr.Error()
			dec.RiskLevel = "HIGH"
		} else {
			rlsRes = res
		}
	}

	var costInfo map[string]any
	if dec.Action != firewall.ActionBlock && s.costRunner != nil && prof.Firewall.CostGuard.Enabled {
		evalSQL := req.SQL
		if rlsRes.Rewritten {
			evalSQL = rlsRes.SQL
		}
		cv := s.costRunner.Check(r.Context(), evalSQL, dec.Fingerprint, rlsRes.RulesApplied, prof)
		if cv.Evaluated {
			costInfo = map[string]any{
				"evaluated": true,
				"cache_hit": cv.CacheHit,
				"fallback":  cv.Fallback,
				"blocked":   cv.Blocked,
				"rule":      cv.Rule,
				"reason":    cv.Reason,
				"metrics":   cv.Metrics,
			}
			if cv.Blocked {
				dec.Action = firewall.ActionBlock
				dec.Rule = cv.Rule
				dec.Reason = cv.Reason
				dec.RiskLevel = "HIGH"
			}
		}
	}

	var maskedSample string
	var entities map[string]int
	if req.Sample != "" {
		maskedSample, entities = s.policyMgr.Masker().MaskText(req.Sample, prof.EnabledEntities())
	}
	resp := map[string]any{
		"profile":       prof.Name,
		"decision":      dec,
		"masked_sample": maskedSample,
		"entities":      entities,
	}
	if rlsRes.Rewritten {
		resp["rls_rewritten"] = true
		resp["rewritten_sql"] = rlsRes.SQL
		resp["rls_rules"] = rlsRes.RulesApplied
	}
	if costInfo != nil {
		resp["cost_guard"] = costInfo
	}
	writeJSON(w, http.StatusOK, resp)
}

// handlePlaygroundQuery executes a live PostgreSQL query THROUGH pgveil's real wire proxy (:6432)
// using the chosen role profile's application_name, demonstrating authentic wire-protocol masking,
// AST blocking, row truncation, and live synchronous HITL hold/approve!
func (s *Server) handlePlaygroundQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SQL       string            `json:"sql"`
		Profile   string            `json:"profile"`
		JWTClaims map[string]string `json:"jwt_claims"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.SQL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sql cannot be empty"})
		return
	}

	prof, ok := s.policyMgr.GetProfileByName(req.Profile)
	if !ok {
		prof = s.policyMgr.MatchProfile("", req.Profile)
	}
	astDec := firewall.Evaluate(req.SQL, prof)

	// When testing a profile that binds {{jwt.*}} claims (or explicit jwt_claims in the Playground),
	// execute through the real MCP runtime so claim-bound AST Virtual RLS + Cost Guard + HITL are exercised end-to-end.
	if profileUsesJWTPlaceholders(prof) || len(req.JWTClaims) > 0 {
		s.handleMCPPlaygroundQuery(w, r, prof, astDec, req.SQL, req.JWTClaims)
		return
	}

	cfg := s.policyMgr.Config()
	proxyTarget := s.resolveProxyAddr()
	appName := s.synthesizeAppNameForProfile(prof, cfg.Server.UpstreamUser)

	// Build pgx connection config targeting pgveil wire proxy with profile-matched application_name
	connStr := policy.BuildDSN(
		proxyTarget,
		cfg.Server.UpstreamUser,
		cfg.Server.UpstreamPassword,
		cfg.Server.UpstreamDatabase,
		appName,
		cfg.Server.TLS.Enabled,
	)
	connCfg, err := pgx.ParseConfig(connStr)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// Use Simple Protocol so multi-statement injection tests reach the proxy cleanly
	connCfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	var notices []string
	connCfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		notices = append(notices, n.Message)
	}

	// Allow enough time for live synchronous HITL approvals (up to 70s)
	qCtx, cancel := context.WithTimeout(r.Context(), 70*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := pgx.ConnectConfig(qCtx, connCfg)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"status":   "connection_error",
			"error":    err.Error(),
			"profile":  prof.Name,
			"decision": astDec,
		})
		return
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(qCtx, req.SQL)
	if err != nil {
		elapsed := time.Since(start)
		pgCode := ""
		pgDetail := ""
		var pgErr *pgconn.PgError
		if asPgErr(err, &pgErr) {
			pgCode = pgErr.Code
			pgDetail = pgErr.Detail
		}
		enrichedDec, latestAudit := s.enrichBlockedDecision(prof, astDec)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "blocked",
			"profile":     prof.Name,
			"decision":    enrichedDec,
			"error":       err.Error(),
			"sqlstate":    pgCode,
			"detail":      pgDetail,
			"notices":     notices,
			"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
			"audit":       latestAudit,
		})
		return
	}
	defer rows.Close()

	fds := rows.FieldDescriptions()
	cols := make([]string, len(fds))
	for i, fd := range fds {
		cols[i] = string(fd.Name)
	}

	resultRows := make([][]any, 0, 64)
	for rows.Next() {
		rawVals := rows.RawValues()
		row := make([]any, len(rawVals))
		for i, rv := range rawVals {
			if rv == nil {
				row[i] = nil
			} else {
				row[i] = string(rv)
			}
		}
		resultRows = append(resultRows, row)
	}
	if rerr := rows.Err(); rerr != nil {
		elapsed := time.Since(start)
		enrichedDec, latestAudit := s.enrichBlockedDecision(prof, astDec)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "blocked",
			"profile":     prof.Name,
			"decision":    enrichedDec,
			"error":       rerr.Error(),
			"notices":     notices,
			"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
			"audit":       latestAudit,
		})
		return
	}

	cmdTag := rows.CommandTag().String()
	elapsed := time.Since(start)
	// Grab the latest audit event for exact proxy overhead & masked field breakdown
	var latestAudit *events.AuditEvent
	recent := s.eventBus.Recent(5, "", prof.Name)
	for i := range recent {
		if recent[i].SQLFingerprint == astDec.Fingerprint {
			latestAudit = &recent[i]
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"profile":     prof.Name,
		"decision":    astDec,
		"columns":     cols,
		"rows":        resultRows,
		"row_count":   len(resultRows),
		"command_tag": cmdTag,
		"notices":     notices,
		"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
		"audit":       latestAudit,
	})
}

func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	writeJSON(w, http.StatusOK, map[string]any{
		"approvals": s.hitlMgr.List(status),
		"pending":   s.hitlMgr.PendingCount(),
	})
}

func (s *Server) handleResolveApproval(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var body struct {
			Reviewer string `json:"reviewer"`
			Note     string `json:"note"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&body)
		req, err := s.hitlMgr.Resolve(id, approve, body.Reviewer, body.Note)
		if err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, req)
	}
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SampleRows int `json:"sample_rows"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req)
	if req.SampleRows <= 0 {
		req.SampleRows = 50
	}
	cfg := s.policyMgr.Config()
	dsn := policy.BuildDSN(
		cfg.Server.UpstreamAddr,
		cfg.Server.UpstreamUser,
		cfg.Server.UpstreamPassword,
		cfg.Server.UpstreamDatabase,
		"pgveil-discover",
		cfg.Server.UpstreamTLS.Enabled,
	)
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	report, err := discover.Scan(ctx, dsn, req.SampleRows, cfg.Security.MaskingSecret)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) spaHandler(root fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if f, err := root.Open(path); err == nil {
			_ = f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fallback to index.html for SPA routes
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

func (s *Server) resolveProxyAddr() string {
	if s.proxyAddr != nil {
		if a := s.proxyAddr(); a != "" {
			return a
		}
	}
	return s.policyMgr.Config().Server.ListenAddr
}

func asPgErr(err error, target **pgconn.PgError) bool {
	return errors.As(err, target)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) isCORSOriginAllowed(origin string) bool {
	allowed := s.policyMgr.Config().MCP.AllowedOrigins
	if len(allowed) > 0 {
		for _, a := range allowed {
			a = strings.TrimSpace(a)
			if a == "*" || strings.EqualFold(a, origin) {
				return true
			}
		}
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if s.isCORSOriginAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id")
				w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if r.Method == http.MethodOptions {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "CORS origin not allowed"})
				return
			}
		} else if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) synthesizeAppNameForProfile(prof *policy.RoleProfile, dbUser string) string {
	if prof == nil {
		return ""
	}
	for _, cand := range prof.Match.ApplicationNames {
		c := strings.TrimSpace(cand)
		if c != "" && !strings.ContainsAny(c, "*?[]") {
			if s.policyMgr.MatchProfile(dbUser, c).Name == prof.Name {
				return c
			}
		}
	}
	for _, cand := range prof.Match.ApplicationNames {
		c := strings.TrimSpace(cand)
		if c == "" {
			continue
		}
		synth := strings.ReplaceAll(c, "*", "pg")
		synth = strings.ReplaceAll(synth, "?", "a")
		if s.policyMgr.MatchProfile(dbUser, synth).Name == prof.Name {
			return synth
		}
	}
	return prof.Name
}

func (s *Server) enrichBlockedDecision(prof *policy.RoleProfile, astDec firewall.Decision) (firewall.Decision, *events.AuditEvent) {
	if s.eventBus == nil || prof == nil {
		return astDec, nil
	}
	recent := s.eventBus.Recent(5, "", prof.Name)
	for i := range recent {
		ev := recent[i]
		if ev.SQLFingerprint == astDec.Fingerprint &&
			(ev.Decision == "BLOCKED" || ev.Decision == "HITL_DENIED" || ev.Decision == "HITL_EXPIRED") {
			if ev.PolicyRule != "" {
				astDec.Action = firewall.ActionBlock
				astDec.Rule = ev.PolicyRule
				if ev.RiskLevel != "" {
					astDec.RiskLevel = ev.RiskLevel
				}
				if ev.PolicyReason != "" {
					astDec.Reason = ev.PolicyReason
				}
			}
			return astDec, &ev
		}
	}
	return astDec, nil
}

func profileUsesJWTPlaceholders(prof *policy.RoleProfile) bool {
	if prof == nil {
		return false
	}
	for _, rf := range prof.Firewall.RowFilters {
		if strings.Contains(rf.Predicate, "{{jwt.") {
			return true
		}
	}
	return false
}

func (s *Server) handleMCPPlaygroundQuery(
	w http.ResponseWriter,
	r *http.Request,
	prof *policy.RoleProfile,
	astDec firewall.Decision,
	sqlStr string,
	claims map[string]string,
) {
	start := time.Now()
	sub := "playground-jwt"
	if s := strings.TrimSpace(claims["sub"]); s != "" {
		sub = s
	}
	callCtx := mcpserver.WithCallerIdentity(r.Context(), mcpserver.CallerIdentity{
		Subject:     sub,
		ProfileName: prof.Name,
		Claims:      claims,
		Source:      "mcp-http",
		ClientAddr:  r.RemoteAddr,
	})
	rawParams, _ := json.Marshal(map[string]any{
		"name":      "query",
		"arguments": map[string]any{"sql": sqlStr},
	})
	rpcResp := s.mcpSrv.HandleRequest(callCtx, mcpserver.RPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  rawParams,
	})
	elapsed := time.Since(start)

	resMap, _ := rpcResp.Result.(map[string]any)
	isErr, _ := resMap["isError"].(bool)
	textOut := ""
	if content, ok := resMap["content"].([]map[string]any); ok && len(content) > 0 {
		textOut, _ = content[0]["text"].(string)
	}

	if isErr {
		enrichedDec, latestAudit := s.enrichBlockedDecision(prof, astDec)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "blocked",
			"profile":     prof.Name,
			"decision":    enrichedDec,
			"error":       textOut,
			"sqlstate":    "42501",
			"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
			"audit":       latestAudit,
		})
		return
	}

	var parsed struct {
		Columns        []string         `json:"columns"`
		CommandTag     string           `json:"command_tag"`
		RowCount       int              `json:"row_count"`
		Truncated      bool             `json:"truncated"`
		PIICellsMasked int              `json:"pii_cells_masked"`
		Rows           []map[string]any `json:"rows"`
	}
	_ = json.Unmarshal([]byte(textOut), &parsed)

	cols := parsed.Columns
	if len(cols) == 0 && len(parsed.Rows) > 0 {
		for k := range parsed.Rows[0] {
			cols = append(cols, k)
		}
		sort.Strings(cols)
	}
	cmdTag := parsed.CommandTag
	if cmdTag == "" {
		cmdTag = fmt.Sprintf("SELECT %d", len(parsed.Rows))
	}
	resultRows := make([][]any, 0, len(parsed.Rows))
	for _, rec := range parsed.Rows {
		row := make([]any, len(cols))
		for i, c := range cols {
			row[i] = rec[c]
		}
		resultRows = append(resultRows, row)
	}

	var latestAudit *events.AuditEvent
	recent := s.eventBus.Recent(5, "", prof.Name)
	for i := range recent {
		if recent[i].SQLFingerprint == astDec.Fingerprint {
			latestAudit = &recent[i]
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"profile":     prof.Name,
		"decision":    astDec,
		"columns":     cols,
		"rows":        resultRows,
		"row_count":   len(resultRows),
		"command_tag": cmdTag,
		"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
		"audit":       latestAudit,
	})
}

func (s *Server) handleMCPHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.policyMgr.Config().MCP.HTTPEnabled {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "Streamable HTTP MCP is disabled (enable mcp.http_enabled: true in pgveil.yaml)",
		})
		return
	}
	s.mcpSrv.HTTPHandler().ServeHTTP(w, r)
}

func (s *Server) handleSlackInteraction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload too large"})
		return
	}

	signingSecret := s.policyMgr.Config().Notifications.Slack.SigningSecret
	ts := r.Header.Get("X-Slack-Request-Timestamp")
	sig := r.Header.Get("X-Slack-Signature")
	if err := chatops.VerifySlackSignature(signingSecret, ts, sig, rawBody, time.Now()); err != nil {
		if s.metrics != nil && s.metrics.HITLChatOps != nil {
			s.metrics.HITLChatOps.WithLabelValues("slack", "invalid_sig").Inc()
		}
		slog.Warn("rejected Slack interaction with invalid signature", "err", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	vals, err := url.ParseQuery(string(rawBody))
	if err != nil || vals.Get("payload") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing form payload"})
		return
	}

	var interaction struct {
		User struct {
			Username string `json:"username"`
			Name     string `json:"name"`
			ID       string `json:"id"`
		} `json:"user"`
		Actions []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}
	if err := json.Unmarshal([]byte(vals.Get("payload")), &interaction); err != nil || len(interaction.Actions) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid Slack interaction payload"})
		return
	}

	act := interaction.Actions[0]
	var approve bool
	switch act.ActionID {
	case chatops.ActionIDApprove:
		approve = true
	case chatops.ActionIDDeny:
		approve = false
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported action_id"})
		return
	}

	reviewer := interaction.User.Username
	if reviewer == "" {
		reviewer = interaction.User.Name
	}
	if reviewer == "" {
		reviewer = interaction.User.ID
	}
	reviewer = "slack:@" + reviewer

	resolvedReq, resErr := s.hitlMgr.Resolve(act.Value, approve, reviewer, "Resolved via Slack Block Kit")
	var alreadyErr *hitl.AlreadyResolvedError
	if resErr != nil {
		if errors.As(resErr, &alreadyErr) && alreadyErr.Request != nil {
			writeJSON(w, http.StatusOK, chatops.BuildSlackResolvedResponse(alreadyErr.Request, true))
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": resErr.Error()})
		return
	}

	if s.metrics != nil && s.metrics.HITLChatOps != nil {
		ev := "denied"
		if approve {
			ev = "approved"
		}
		s.metrics.HITLChatOps.WithLabelValues("slack", ev).Inc()
	}
	writeJSON(w, http.StatusOK, chatops.BuildSlackResolvedResponse(resolvedReq, false))
}

// handleHITLCallbackPreview handles GET /webhooks/hitl/callback strictly as a READ-ONLY preview card.
// Link unfurlers / email security scanners (Slack, Discord, Teams, Defender SafeLinks) can prefetch
// this URL repeatedly without ever mutating HITL approval state.
func (s *Server) handleHITLCallbackPreview(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	expStr := strings.TrimSpace(r.URL.Query().Get("exp"))
	sig := strings.TrimSpace(r.URL.Query().Get("sig"))

	if err := s.chatOps.VerifyPreviewParams(id, expStr, sig, time.Now()); err != nil {
		if s.metrics != nil && s.metrics.HITLChatOps != nil {
			s.metrics.HITLChatOps.WithLabelValues("callback", "invalid_sig").Inc()
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	req, ok := s.hitlMgr.Get(id)
	previewNotice := ""
	isDemoPreview := false
	if !ok {
		if id == "hitl_test_preview" {
			cfg := s.policyMgr.Config()
			req = &hitl.ApprovalRequest{
				ID:            "hitl_test_preview",
				CreatedAt:     time.Now().UTC(),
				ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
				DBUser:        cfg.Server.UpstreamUser,
				Database:      cfg.Server.UpstreamDatabase,
				RoleProfile:   "ai_agent",
				StatementType: "UPDATE",
				RiskLevel:     "HIGH",
				Rule:          "require_hitl_update",
				Reason:        "ChatOps connectivity verification test",
				SQL:           "UPDATE orders SET status = 'approved' WHERE id = 1001;",
				Status:        hitl.StatusPending,
				Reviewer:      "demo-preview",
			}
			isDemoPreview = true
			previewNotice = "Demo Preview Card — HMAC-SHA256 signature verified (read-only preview; no live database query is paused)."
		} else {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "approval request not found"})
			return
		}
	}

	expInt, _ := strconv.ParseInt(expStr, 10, 64)
	approveTok := ""
	denyTok := ""
	if !isDemoPreview {
		approveTok = s.chatOps.SignActionToken(id, "approve", expInt)
		denyTok = s.chatOps.SignActionToken(id, "deny", expInt)
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") && !strings.Contains(r.Header.Get("Accept"), "text/html") {
		resp := map[string]any{
			"request":       req,
			"approve_token": approveTok,
			"deny_token":    denyTok,
			"exp":           expStr,
		}
		if isDemoPreview {
			resp["demo_preview"] = true
			resp["notice"] = previewNotice
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(chatops.RenderReviewCardHTML(req, expStr, approveTok, denyTok, previewNotice)))
}

// handleHITLCallbackAction handles state-mutating POST /webhooks/hitl/callback submissions.
func (s *Server) handleHITLCallbackAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var id, action, expStr, token, reviewer string

	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			ID       string `json:"id"`
			Action   string `json:"action"`
			Exp      string `json:"exp"`
			Token    string `json:"token"`
			Reviewer string `json:"reviewer"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		id, action, expStr, token, reviewer = body.ID, body.Action, body.Exp, body.Token, body.Reviewer
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form body"})
			return
		}
		id = r.FormValue("id")
		action = r.FormValue("action")
		expStr = r.FormValue("exp")
		token = r.FormValue("token")
		reviewer = r.FormValue("reviewer")
	}

	if err := s.chatOps.VerifyActionToken(id, action, expStr, token, time.Now()); err != nil {
		if s.metrics != nil && s.metrics.HITLChatOps != nil {
			s.metrics.HITLChatOps.WithLabelValues("callback", "invalid_sig").Inc()
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	if reviewer == "" {
		reviewer = "chatops-signed-callback"
	}
	approve := action == "approve"
	resolvedReq, resErr := s.hitlMgr.Resolve(id, approve, reviewer, "Resolved via signed ChatOps callback")
	notice := ""
	var alreadyErr *hitl.AlreadyResolvedError
	if resErr != nil {
		if errors.As(resErr, &alreadyErr) && alreadyErr.Request != nil {
			resolvedReq = alreadyErr.Request
			notice = fmt.Sprintf("Request was already %s earlier by %s.", resolvedReq.Status, resolvedReq.Reviewer)
		} else {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": resErr.Error()})
			return
		}
	} else {
		if s.metrics != nil && s.metrics.HITLChatOps != nil {
			ev := "denied"
			if approve {
				ev = "approved"
			}
			s.metrics.HITLChatOps.WithLabelValues("callback", ev).Inc()
		}
		notice = fmt.Sprintf("Query %s successfully.", resolvedReq.Status)
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") && !strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  resolvedReq.Status,
			"request": resolvedReq,
			"notice":  notice,
		})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(chatops.RenderReviewCardHTML(resolvedReq, expStr, "", "", notice)))
}

func (s *Server) handleChatOpsTest(w http.ResponseWriter, r *http.Request) {
	sample := hitl.ApprovalRequest{
		ID:            "hitl_test_preview",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(5 * time.Minute),
		DBUser:        s.policyMgr.Config().Server.UpstreamUser,
		Database:      s.policyMgr.Config().Server.UpstreamDatabase,
		RoleProfile:   "ai_agent",
		StatementType: "UPDATE",
		RiskLevel:     "HIGH",
		Rule:          "require_hitl_update",
		Reason:        "ChatOps connectivity verification test",
		SQL:           "UPDATE orders SET status = 'approved' WHERE id = 1001;",
		Status:        hitl.StatusPending,
	}
	baseURL := s.policyMgr.Config().Notifications.PublicBaseURL
	if baseURL == "" && r.Host != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		baseURL = scheme + "://" + r.Host
	}
	previewURL := s.chatOps.SignPreviewURL(baseURL, sample.ID, sample.ExpiresAt)
	s.chatOps.NotifyHITLPending(sample)
	writeJSON(w, http.StatusOK, map[string]any{
		"dispatched":         s.chatOps.IsConfigured(),
		"sample_preview_url": previewURL,
		"slack_blocks":       chatops.BuildSlackPendingBlocks(sample, s.policyMgr.Config().Notifications.Slack.Channel, previewURL),
	})
}
