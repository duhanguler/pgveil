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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/discover"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/pii"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves the Control Plane REST API, real-time SSE stream, Prometheus /metrics,
// live SQL Playground (wired through pgveil's real wire proxy!), and embedded Web Console.
type Server struct {
	policyMgr *policy.Manager
	hitlMgr   *hitl.Manager
	eventBus  *events.Bus
	proxyAddr func() string
	promReg   prometheus.Gatherer
	webFS     fs.FS
	version   string
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
	return &Server{
		policyMgr: policyMgr,
		hitlMgr:   hitlMgr,
		eventBus:  eventBus,
		proxyAddr: proxyAddr,
		promReg:   promReg,
		webFS:     webFS,
		version:   version,
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

	// Embedded React Web Console
	if s.webFS != nil {
		mux.Handle("/", s.spaHandler(s.webFS))
	}

	return withCORS(s.withOptionalAuth(mux))
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
		"status":         "ok",
		"version":        s.version,
		"proxy_addr":     s.resolveProxyAddr(),
		"upstream_addr":  cfg.Server.UpstreamAddr,
		"kafka_enabled":  cfg.Kafka.Enabled,
		"profiles_count": len(cfg.Profiles),
		"pending_hitl":   s.hitlMgr.PendingCount(),
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
		SQL     string `json:"sql"`
		Profile string `json:"profile"`
		Sample  string `json:"sample_text"`
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
	var maskedSample string
	var entities map[string]int
	if req.Sample != "" {
		maskedSample, entities = s.policyMgr.Masker().MaskText(req.Sample, prof.EnabledEntities())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"profile":       prof.Name,
		"decision":      dec,
		"masked_sample": maskedSample,
		"entities":      entities,
	})
}

// handlePlaygroundQuery executes a live PostgreSQL query THROUGH pgveil's real wire proxy (:6432)
// using the chosen role profile's application_name, demonstrating authentic wire-protocol masking,
// AST blocking, row truncation, and live synchronous HITL hold/approve!
func (s *Server) handlePlaygroundQuery(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SQL     string `json:"sql"`
		Profile string `json:"profile"`
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

	cfg := s.policyMgr.Config()
	proxyTarget := s.resolveProxyAddr()
	appName := prof.Name
	for _, cand := range prof.Match.ApplicationNames {
		c := strings.TrimSpace(cand)
		if c != "" && !strings.ContainsAny(c, "*?[]") {
			appName = c
			break
		}
	}

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
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "blocked",
			"profile":     prof.Name,
			"decision":    astDec,
			"error":       err.Error(),
			"sqlstate":    pgCode,
			"detail":      pgDetail,
			"notices":     notices,
			"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
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
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "blocked",
			"profile":     prof.Name,
			"decision":    astDec,
			"error":       rerr.Error(),
			"notices":     notices,
			"duration_ms": float64(elapsed.Microseconds()) / 1000.0,
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

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
