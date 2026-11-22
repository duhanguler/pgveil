package mcpserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/jwtauth"
)

const (
	maxMCPHTTPBodyBytes = 1024 * 1024 // 1 MiB JSON-RPC payload cap
	maxMCPBatchSize     = 20          // Cap JSON-RPC batch size to prevent amplification DoS
	maxMCPSessions      = 4096
	mcpSessionTTL       = 30 * time.Minute
	headerMCPSessionID  = "Mcp-Session-Id"
)

type mcpSession struct {
	id         string
	subject    string
	profile    string
	lastActive time.Time
}

// HTTPHandler exposes the Model Context Protocol Streamable HTTP transport (2025-03-26 spec)
// with Bearer JWT / JWKS / API-Key verification, Origin DNS-rebinding defense, and subject-bound Mcp-Session-Id.
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Browser Origin validation (MCP 2025-03-26 DNS-rebinding protection)
		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if !s.isOriginAllowed(origin) {
				s.recordHTTPMetric("origin_check", s.profileName, "403")
				writeHTTPError(w, http.StatusForbidden, "origin not allowed by mcp.allowed_origins")
				return
			}
		}

		// 2. Bearer JWT / JWKS / Static API Key authentication
		ident, err := s.verifier.AuthenticateHeader(r.Context(), r.Header.Get("Authorization"), s.profileName)
		if err != nil {
			if errors.Is(err, jwtauth.ErrProfileNotPermitted) {
				s.recordHTTPMetric("auth", s.profileName, "403")
				writeHTTPError(w, http.StatusForbidden, err.Error())
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="pgveil-mcp"`)
			s.recordHTTPMetric("auth", s.profileName, "401")
			writeHTTPError(w, http.StatusUnauthorized, err.Error())
			return
		}

		switch r.Method {
		case http.MethodDelete:
			sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID))
			if sid != "" {
				if !s.deleteSession(sid, ident.Subject) {
					s.recordHTTPMetric("DELETE", ident.Profile, "403")
					writeHTTPError(w, http.StatusForbidden, "session does not belong to authenticated subject")
					return
				}
			}
			s.recordHTTPMetric("DELETE", ident.Profile, "204")
			w.WriteHeader(http.StatusNoContent)
			return

		case http.MethodGet:
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				if sid := strings.TrimSpace(r.Header.Get(headerMCPSessionID)); sid != "" {
					if code, msg := s.validateSession(sid, ident.Subject); code != 0 {
						s.recordHTTPMetric("GET", ident.Profile, fmt.Sprintf("%d", code))
						writeHTTPError(w, code, msg)
						return
					}
				}
				flusher, ok := w.(http.Flusher)
				if !ok {
					writeHTTPError(w, http.StatusInternalServerError, "streaming unsupported")
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				_, _ = w.Write([]byte(": pgveil-mcp stream ready\n\n"))
				flusher.Flush()
				s.recordHTTPMetric("GET", ident.Profile, "200")
				<-r.Context().Done()
				return
			}
			s.recordHTTPMetric("GET", ident.Profile, "405")
			writeHTTPError(w, http.StatusMethodNotAllowed, "POST JSON-RPC 2.0 to /mcp or GET with Accept: text/event-stream")
			return

		case http.MethodPost:
			// Handled below
		default:
			s.recordHTTPMetric(r.Method, ident.Profile, "405")
			writeHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		// 3. Enforce 1 MiB body size cap
		r.Body = http.MaxBytesReader(w, r.Body, maxMCPHTTPBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.recordHTTPMetric("POST", ident.Profile, "413")
			writeHTTPError(w, http.StatusRequestEntityTooLarge, "MCP request payload exceeds 1 MiB limit")
			return
		}
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 {
			s.recordHTTPMetric("POST", ident.Profile, "400")
			writeHTTPError(w, http.StatusBadRequest, "empty JSON-RPC body")
			return
		}

		// 4. Validate subject-bound Mcp-Session-Id when provided on non-initialize calls
		incomingSID := strings.TrimSpace(r.Header.Get(headerMCPSessionID))

		var reqs []RPCRequest
		isBatch := trimmed[0] == '['
		if isBatch {
			if err := json.Unmarshal(trimmed, &reqs); err != nil || len(reqs) == 0 {
				s.recordHTTPMetric("batch", ident.Profile, "400")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(RPCResponse{
					JSONRPC: "2.0",
					Error:   &RPCError{Code: -32700, Message: "parse error: invalid JSON-RPC batch"},
				})
				return
			}
			if len(reqs) > maxMCPBatchSize {
				s.recordHTTPMetric("batch", ident.Profile, "400")
				writeHTTPError(w, http.StatusBadRequest, fmt.Sprintf("JSON-RPC batch size %d exceeds maximum allowed (%d)", len(reqs), maxMCPBatchSize))
				return
			}
		} else {
			var single RPCRequest
			if err := json.Unmarshal(trimmed, &single); err != nil {
				s.recordHTTPMetric("parse_error", ident.Profile, "400")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(RPCResponse{
					JSONRPC: "2.0",
					Error:   &RPCError{Code: -32700, Message: "parse error: " + err.Error()},
				})
				return
			}
			reqs = []RPCRequest{single}
		}

		hasInitialize := false
		for _, rq := range reqs {
			if rq.Method == "initialize" {
				hasInitialize = true
				break
			}
		}
		if hasInitialize && len(reqs) > 1 {
			s.recordHTTPMetric("initialize", ident.Profile, "400")
			writeHTTPError(w, http.StatusBadRequest, "initialize must be sent as a standalone JSON-RPC request, not inside a multi-request batch")
			return
		}
		if incomingSID != "" && !hasInitialize {
			if code, msg := s.validateSession(incomingSID, ident.Subject); code != 0 {
				s.recordHTTPMetric(reqs[0].Method, ident.Profile, fmt.Sprintf("%d", code))
				writeHTTPError(w, code, msg)
				return
			}
		}

		callCtx := WithCallerIdentity(r.Context(), CallerIdentity{
			Subject:     ident.Subject,
			ProfileName: ident.Profile,
			Claims:      ident.Claims,
			Source:      "mcp-http",
			ClientAddr:  r.RemoteAddr,
		})

		var resps []*RPCResponse
		for _, rq := range reqs {
			if resp := s.HandleRequest(callCtx, rq); resp != nil {
				resps = append(resps, resp)
			}
		}

		if hasInitialize {
			newSID := s.createSession(ident.Subject, ident.Profile)
			w.Header().Set(headerMCPSessionID, newSID)
		} else if incomingSID != "" {
			w.Header().Set(headerMCPSessionID, incomingSID)
		}

		primaryMethod := reqs[0].Method
		if len(resps) == 0 {
			// Notification-only payload per MCP Streamable HTTP spec -> 202 Accepted
			s.recordHTTPMetric(primaryMethod, ident.Profile, "202")
			w.WriteHeader(http.StatusAccepted)
			return
		}

		s.recordHTTPMetric(primaryMethod, ident.Profile, "200")
		accept := r.Header.Get("Accept")
		wantsSSE := strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "application/json")
		if wantsSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			for _, rp := range resps {
				b, _ := json.Marshal(rp)
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
			}
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if isBatch {
			_ = json.NewEncoder(w).Encode(resps)
		} else {
			_ = json.NewEncoder(w).Encode(resps[0])
		}
	})
}

func (s *Server) isOriginAllowed(origin string) bool {
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
	// Default DNS-rebinding defense: permit loopback browser origins (e.g. embedded local Workbench),
	// reject arbitrary third-party web origins unless explicitly listed in mcp.allowed_origins.
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

func (s *Server) createSession(subject, profile string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	sid := "mcps_" + hex.EncodeToString(b[:])
	now := time.Now()

	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	if len(s.sessions) >= maxMCPSessions {
		cutoff := now.Add(-mcpSessionTTL)
		for k, sess := range s.sessions {
			if sess.lastActive.Before(cutoff) {
				delete(s.sessions, k)
			}
		}
		// Hard cap eviction if all active
		if len(s.sessions) >= maxMCPSessions {
			for k := range s.sessions {
				delete(s.sessions, k)
				break
			}
		}
	}

	s.sessions[sid] = &mcpSession{
		id:         sid,
		subject:    subject,
		profile:    profile,
		lastActive: now,
	}
	return sid
}

func (s *Server) validateSession(sid, subject string) (int, string) {
	now := time.Now()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	sess, ok := s.sessions[sid]
	if !ok {
		return http.StatusNotFound, "unknown or expired Mcp-Session-Id"
	}
	if now.Sub(sess.lastActive) > mcpSessionTTL {
		delete(s.sessions, sid)
		return http.StatusNotFound, "Mcp-Session-Id expired"
	}
	if sess.subject != subject {
		return http.StatusForbidden, "Mcp-Session-Id bound to a different authenticated subject"
	}
	sess.lastActive = now
	return 0, ""
}

func (s *Server) deleteSession(sid, subject string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return true
	}
	if sess.subject != subject {
		return false
	}
	delete(s.sessions, sid)
	return true
}

func normalizeMCPMetricMethod(method string) string {
	switch method {
	case "initialize", "notifications/initialized", "ping", "tools/list", "tools/call",
		"GET", "POST", "DELETE", "origin_check", "auth", "batch", "parse_error":
		return method
	default:
		return "other"
	}
}

func (s *Server) recordHTTPMetric(method, profile, status string) {
	if s.metrics != nil && s.metrics.MCPHTTPRequests != nil {
		if profile == "" {
			profile = "unknown"
		}
		s.metrics.MCPHTTPRequests.WithLabelValues(normalizeMCPMetricMethod(method), profile, status).Inc()
	}
}

func writeHTTPError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
