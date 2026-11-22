package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/events"
)

func TestBurstTrackerAndHelpers(t *testing.T) {
	bt := newBurstTracker(3, time.Minute)
	base := time.Now()
	if trig, c := bt.RecordBlocked("ai_agent", base); trig || c != 1 {
		t.Fatalf("unexpected 1st: %v %d", trig, c)
	}
	if trig, c := bt.RecordBlocked("ai_agent", base.Add(5*time.Second)); trig || c != 2 {
		t.Fatalf("unexpected 2nd: %v %d", trig, c)
	}
	if trig, c := bt.RecordBlocked("ai_agent", base.Add(10*time.Second)); !trig || c != 3 {
		t.Fatalf("expected trigger on 3rd: %v %d", trig, c)
	}
	// After window expires, old entries pruned
	if trig, c := bt.RecordBlocked("ai_agent", base.Add(2*time.Minute)); trig || c != 1 {
		t.Fatalf("expected window reset: %v %d", trig, c)
	}

	t.Setenv("PGVEIL_TEST_ENV_KEY", "custom_val")
	if got := envOr("PGVEIL_TEST_ENV_KEY", "fallback"); got != "custom_val" {
		t.Fatalf("expected custom_val, got %q", got)
	}
	if got := envOr("PGVEIL_TEST_MISSING_KEY", "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}

	csv := splitCSV(" broker1:9092 , , broker2:9092 ")
	if len(csv) != 2 || csv[0] != "broker1:9092" || csv[1] != "broker2:9092" {
		t.Fatalf("unexpected splitCSV: %v", csv)
	}

	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fireWebhook(srv.URL, events.AuditEvent{RoleProfile: "ai_agent", PolicyRule: "block_ddl"}, 5)
	if !strings.Contains(gotBody, "Burst anomaly") || !strings.Contains(gotBody, "block_ddl") {
		t.Fatalf("unexpected webhook body: %q", gotBody)
	}
}
