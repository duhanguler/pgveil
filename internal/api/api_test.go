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

	// 3. /api/v1/policies
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kvkk"`) {
		t.Fatalf("/api/v1/policies unexpected: %d", rec.Code)
	}
}
