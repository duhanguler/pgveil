package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/duhanguler/pgveil/internal/api"
	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/proxy"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAPIControlPlaneFullLifecycleAgainstDemoServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	upAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("demo start: %v", err)
	}

	cfgYAML := demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", upAddr)
	mgr, err := policy.LoadBytes(cfgYAML)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	hitlMgr := hitl.NewManager(50)
	bus := events.NewBus(100, policy.KafkaConfig{}, nil)
	defer bus.Close()

	wireProxy, err := proxy.NewServer(mgr, hitlMgr, bus, nil, nil)
	if err != nil {
		t.Fatalf("proxy.NewServer: %v", err)
	}
	go func() { _ = wireProxy.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for wireProxy.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	mockFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>pgveil-ui</html>")},
		"app.js":     {Data: []byte("console.log('ok')")},
	}
	reg := prometheus.NewRegistry()
	apiSrv := api.NewServer(mgr, hitlMgr, bus, wireProxy.Addr, reg, mockFS, "0.4.0")
	ts := httptest.NewServer(apiSrv.Handler())
	defer ts.Close()

	for _, ep := range []string{"/healthz", "/readyz", "/metrics", "/api/v1/summary", "/api/v1/events", "/api/v1/policies", "/", "/app.js", "/spa-route"} {
		resp, err := http.Get(ts.URL + ep)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s failed: err=%v status=%v", ep, err, resp)
		}
		_ = resp.Body.Close()
	}

	optReq, _ := http.NewRequest(http.MethodOptions, ts.URL+"/api/v1/summary", nil)
	optResp, err := http.DefaultClient.Do(optReq)
	if err != nil || optResp.StatusCode != http.StatusNoContent {
		t.Fatalf("OPTIONS CORS expected 204, got %v %v", optResp, err)
	}
	_ = optResp.Body.Close()

	insBody := `{"sql":"SELECT id, full_name FROM customers","profile":"tenant_tr","sample_text":"TCKN 10000000146"}`
	resp, err := http.Post(ts.URL+"/api/v1/inspect", "application/json", strings.NewReader(insBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /inspect failed: %v", err)
	}
	var insOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&insOut)
	_ = resp.Body.Close()
	if insOut["rls_rewritten"] != true || !strings.Contains(insOut["rewritten_sql"].(string), "Istanbul") {
		t.Fatalf("expected RLS rewrite in /inspect, got %+v", insOut)
	}
	if !strings.Contains(insOut["masked_sample"].(string), "100******46") {
		t.Fatalf("expected masked sample, got %+v", insOut)
	}
	badResp, _ := http.Post(ts.URL+"/api/v1/inspect", "application/json", strings.NewReader("{bad"))
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad inspect JSON, got %d", badResp.StatusCode)
	}
	_ = badResp.Body.Close()

	pgAllowed := `{"sql":"SELECT id, full_name, city, tckn FROM customers ORDER BY id","profile":"tenant_tr"}`
	resp, err = http.Post(ts.URL+"/api/v1/playground/query", "application/json", strings.NewReader(pgAllowed))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("playground allowed failed: %v", err)
	}
	var pgOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&pgOut)
	_ = resp.Body.Close()
	if pgOut["status"] != "ok" || int(pgOut["row_count"].(float64)) != 9 {
		t.Fatalf("expected 9 Istanbul rows from playground tenant_tr, got %+v", pgOut)
	}

	pgBlocked := `{"sql":"DROP TABLE customers","profile":"ai_agent"}`
	resp, err = http.Post(ts.URL+"/api/v1/playground/query", "application/json", strings.NewReader(pgBlocked))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("playground blocked failed: %v", err)
	}
	var blkOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&blkOut)
	_ = resp.Body.Close()
	if blkOut["status"] != "blocked" || blkOut["sqlstate"] != "42501" {
		t.Fatalf("expected blocked/42501, got %+v", blkOut)
	}

	emptyResp, _ := http.Post(ts.URL+"/api/v1/playground/query", "application/json", strings.NewReader(`{"sql":"   ","profile":"ai_agent"}`))
	if emptyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty SQL, got %d", emptyResp.StatusCode)
	}
	_ = emptyResp.Body.Close()

	resp, err = http.Post(ts.URL+"/api/v1/discover", "application/json", strings.NewReader(`{"sample_rows":25}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /discover failed: err=%v status=%v", err, resp)
	}
	var discOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&discOut)
	_ = resp.Body.Close()
	if int(discOut["tables_scanned"].(float64)) != 5 {
		t.Fatalf("expected 5 tables discovered, got %+v", discOut)
	}

	reqItem := hitlMgr.Create(hitl.ApprovalRequest{RoleProfile: "ai_agent", SQL: "UPDATE orders SET status='x' WHERE id=1001"}, 30*time.Second)
	resp, _ = http.Get(ts.URL + "/api/v1/approvals?status=PENDING")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /approvals status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, _ = http.Post(ts.URL+"/api/v1/approvals/"+reqItem.ID+"/approve", "application/json", strings.NewReader(`{"reviewer":"qa","note":"ok"}`))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST approve status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, _ = http.Post(ts.URL+"/api/v1/approvals/"+reqItem.ID+"/deny", "application/json", strings.NewReader(`{"reviewer":"qa"}`))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on double resolve, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	sseCtx, sseCancel := context.WithTimeout(ctx, 2*time.Second)
	defer sseCancel()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL+"/api/v1/events/stream", nil)
	sseResp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		bus.Publish(events.AuditEvent{RoleProfile: "ai_agent", Decision: "ALLOW", RawSQLPreview: "SELECT 1"})
		hitlMgr.Create(hitl.ApprovalRequest{RoleProfile: "ai_agent", SQL: "UPDATE orders SET status='y' WHERE id=1002"}, 5*time.Second)
	}()
	sc := bufio.NewScanner(sseResp.Body)
	gotAudit, gotApproval := false, false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: audit") {
			gotAudit = true
		}
		if strings.HasPrefix(line, "event: approval") {
			gotApproval = true
		}
		if gotAudit && gotApproval {
			sseCancel()
			break
		}
	}
	_ = sseResp.Body.Close()
	if !gotAudit || !gotApproval {
		t.Fatalf("expected both audit and approval SSE events, got audit=%v approval=%v", gotAudit, gotApproval)
	}

	putBad, _ := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/policies/yaml", bytes.NewBufferString("invalid: ["))
	rBad, _ := http.DefaultClient.Do(putBad)
	if rBad.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid YAML, got %d", rBad.StatusCode)
	}
	_ = rBad.Body.Close()

	resp, _ = http.Get(ts.URL + "/api/v1/events?limit=5&role=tenant_tr")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET filtered events status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
