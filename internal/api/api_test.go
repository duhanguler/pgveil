package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

func TestControlPlaneEndpoints(t *testing.T) {
	mgr, err := policy.LoadFile("../../configs/pgveil.yaml")
	if err != nil {
		t.Fatal(err)
	}
	hitlMgr := hitl.NewManager(50)
	bus := events.NewBus(50, policy.KafkaConfig{}, nil)
	defer bus.Close()

	srv := NewServer(mgr, hitlMgr, bus, func() string { return "127.0.0.1:6432" }, prometheus.NewRegistry(), nil, "0.1.0-test")
	h := srv.Handler()

	// 1. /healthz
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("/healthz unexpected: %d %s", rec.Code, rec.Body.String())
	}

	// 2. /api/v1/inspect (AST block + KVKK/Secrets masking)
	body := `{"sql":"DELETE FROM orders WHERE 1=1","profile":"ai_agent","sample_text":"TCKN 10000000146 AWS AKIAIOSFODNN7EXAMPLE"}`
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/inspect", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/v1/inspect failed: %d %s", rec.Code, rec.Body.String())
	}
	var inspectResp struct {
		Decision struct {
			Action string `json:"action"`
			Rule   string `json:"rule"`
		} `json:"decision"`
		MaskedSample string `json:"masked_sample"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &inspectResp); err != nil {
		t.Fatal(err)
	}
	if inspectResp.Decision.Action != "BLOCK" || inspectResp.Decision.Rule != "block_write_without_where" {
		t.Fatalf("unexpected inspect decision: %+v", inspectResp.Decision)
	}
	if strings.Contains(inspectResp.MaskedSample, "10000000146") || strings.Contains(inspectResp.MaskedSample, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("PII leaked in inspect response: %q", inspectResp.MaskedSample)
	}

	// 3. /api/v1/policies MUST redact upstream_password and masking_secret
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kvkk"`) {
		t.Fatalf("/api/v1/policies unexpected: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "pgveil_dev_password") || strings.Contains(rec.Body.String(), "pgveil-change-me-in-production-hmac-key") {
		t.Fatalf("/api/v1/policies leaked plaintext secrets in YAML response!")
	}
	if !strings.Contains(rec.Body.String(), policy.RedactedPlaceholder) {
		t.Fatalf("expected %q placeholder in redacted policy YAML", policy.RedactedPlaceholder)
	}

	// 4. Reloading redacted YAML via PUT /api/v1/policies/yaml MUST preserve real secrets!
	var polResp struct {
		YAML string `json:"yaml"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &polResp)
	reloadBody, _ := json.Marshal(map[string]string{"yaml": polResp.YAML})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/policies/yaml", bytes.NewReader(reloadBody)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/policies/yaml failed: %d %s", rec.Code, rec.Body.String())
	}
	if mgr.Config().Server.UpstreamPassword != "pgveil_dev_password" {
		t.Fatalf("reloading redacted YAML clobbered upstream_password: got %q", mgr.Config().Server.UpstreamPassword)
	}

	// 5. Optional AdminToken Bearer auth enforcement
	mgr.Config().Security.AdminToken = "super-secret-token"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when AdminToken set and header missing, got %d", rec.Code)
	}
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/summary", nil)
	authReq.Header.Set("Authorization", "Bearer super-secret-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid Bearer token, got %d", rec.Code)
	}
}
