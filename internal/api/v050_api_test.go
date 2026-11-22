package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/chatops"
	"github.com/duhanguler/pgveil/internal/demo"
	"github.com/duhanguler/pgveil/internal/events"
	"github.com/duhanguler/pgveil/internal/firewall"
	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

func TestAPIV050SlackWebhookUnfurlSafeCallbackAndJWTPlayground(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	upAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	baseYAML := string(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", upAddr))
	baseYAML = strings.Replace(baseYAML, "notifications:\n  webhook_url: \"\"", `notifications:
  webhook_url: ""
  public_base_url: "http://127.0.0.1:8088"
  callback_secret: "api-test-cb-secret"
  slack:
    signing_secret: "api-test-slack-secret"
    channel: "#sec"`, 1)

	mgr, err := policy.LoadBytes([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	metrics := telemetry.NewMetrics(reg)
	hitlMgr := hitl.NewManager(50)
	bus := events.NewBus(100, policy.KafkaConfig{}, metrics)
	defer bus.Close()
	cr := firewall.NewCostRunner(mgr, "")
	defer cr.Close()
	co := chatops.NewNotifier(mgr, metrics)

	srv := NewServer(mgr, hitlMgr, bus, func() string { return "" }, reg, nil, "0.5.0").AttachRuntime(cr, co, metrics)
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Link-Unfurler Torture Test: 5 consecutive GET requests MUST leave approval PENDING!
	pending1 := hitlMgr.Create(hitl.ApprovalRequest{
		RoleProfile:   "ai_agent",
		DBUser:        "claude",
		StatementType: "DELETE",
		RiskLevel:     "HIGH",
		SQL:           "DELETE FROM orders WHERE id = 1001",
	}, 2*time.Minute)
	previewURL := co.SignPreviewURL(ts.URL, pending1.ID, pending1.ExpiresAt)

	for i := 0; i < 5; i++ {
		r, err := http.Get(previewURL)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK || !strings.Contains(string(b), "Confirm Approve") {
			t.Fatalf("GET preview #%d failed: code=%d", i+1, r.StatusCode)
		}
	}
	cur, _ := hitlMgr.Get(pending1.ID)
	if cur.Status != hitl.StatusPending {
		t.Fatalf("LINK UNFURLER BUG: GET mutated status to %s!", cur.Status)
	}

	// Fetch JSON preview tokens and POST action-bound approve token -> transitions to APPROVED!
	jsonReq, _ := http.NewRequest(http.MethodGet, previewURL, nil)
	jsonReq.Header.Set("Accept", "application/json")
	jsonResp, _ := http.DefaultClient.Do(jsonReq)
	var prevData struct {
		ApproveToken string `json:"approve_token"`
		Exp          string `json:"exp"`
	}
	_ = json.NewDecoder(jsonResp.Body).Decode(&prevData)
	_ = jsonResp.Body.Close()

	postForm := url.Values{
		"id":     {pending1.ID},
		"action": {"approve"},
		"exp":    {prevData.Exp},
		"token":  {prevData.ApproveToken},
	}
	pResp, err := http.PostForm(ts.URL+"/webhooks/hitl/callback", postForm)
	if err != nil {
		t.Fatal(err)
	}
	_ = pResp.Body.Close()
	if pResp.StatusCode != http.StatusOK {
		t.Fatalf("POST callback failed: %d", pResp.StatusCode)
	}
	cur, _ = hitlMgr.Get(pending1.ID)
	if cur.Status != hitl.StatusApproved {
		t.Fatalf("expected APPROVED after POST, got %s", cur.Status)
	}
	// Second POST returns graceful idempotent AlreadyResolved HTML (200 OK)
	pResp2, _ := http.PostForm(ts.URL+"/webhooks/hitl/callback", postForm)
	b2, _ := io.ReadAll(pResp2.Body)
	_ = pResp2.Body.Close()
	if pResp2.StatusCode != http.StatusOK || !strings.Contains(string(b2), "already APPROVED") {
		t.Fatalf("expected graceful duplicate POST message, got %d %s", pResp2.StatusCode, string(b2))
	}

	// 2. Slack Block Kit Interaction Endpoint (HMAC-SHA256 verified + duplicate click gracefully handled)
	pending2 := hitlMgr.Create(hitl.ApprovalRequest{
		RoleProfile:   "ai_agent",
		DBUser:        "cursor",
		StatementType: "UPDATE",
		RiskLevel:     "HIGH",
		SQL:           "UPDATE orders SET status = 'cancelled' WHERE id = 1002",
	}, 2*time.Minute)

	slackPayload, _ := json.Marshal(map[string]any{
		"user": map[string]any{"username": "duhan"},
		"actions": []map[string]any{
			{"action_id": chatops.ActionIDDeny, "value": pending2.ID},
		},
	})
	formBody := []byte("payload=" + url.QueryEscape(string(slackPayload)))
	tsNow := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte("api-test-slack-secret"))
	mac.Write([]byte("v0:" + tsNow + ":"))
	mac.Write(formBody)
	sig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	// Invalid signature -> 401
	badSlackReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhooks/slack/interactions", bytes.NewReader(formBody))
	badSlackReq.Header.Set("X-Slack-Request-Timestamp", tsNow)
	badSlackReq.Header.Set("X-Slack-Signature", "v0=deadbeef")
	badSlackResp, _ := http.DefaultClient.Do(badSlackReq)
	_ = badSlackResp.Body.Close()
	if badSlackResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad Slack signature, got %d", badSlackResp.StatusCode)
	}

	// Valid signature -> 200 DENIED + Block Kit replacement
	okSlackReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhooks/slack/interactions", bytes.NewReader(formBody))
	okSlackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okSlackReq.Header.Set("X-Slack-Request-Timestamp", tsNow)
	okSlackReq.Header.Set("X-Slack-Signature", sig)
	okSlackResp, _ := http.DefaultClient.Do(okSlackReq)
	okSlackBody, _ := io.ReadAll(okSlackResp.Body)
	_ = okSlackResp.Body.Close()
	if okSlackResp.StatusCode != http.StatusOK || !strings.Contains(string(okSlackBody), "DENIED") || !strings.Contains(string(okSlackBody), "slack:@duhan") {
		t.Fatalf("unexpected Slack interaction response: %d %s", okSlackResp.StatusCode, string(okSlackBody))
	}

	// 3. Inspector + Playground with jwt_claims + ChatOps test endpoint + mounted /mcp
	inspResp, _ := http.Post(ts.URL+"/api/v1/inspect", "application/json", strings.NewReader(`{"sql":"SELECT id, city FROM customers","profile":"tenant_jwt","jwt_claims":{"city":"Istanbul"}}`))
	inspBody, _ := io.ReadAll(inspResp.Body)
	_ = inspResp.Body.Close()
	if !strings.Contains(string(inspBody), `"rls_rewritten":true`) || !strings.Contains(string(inspBody), `"cost_guard"`) {
		t.Fatalf("expected Inspector RLS + CostGuard preview, got %s", string(inspBody))
	}

	pgResp, _ := http.Post(ts.URL+"/api/v1/playground/query", "application/json", strings.NewReader(`{"sql":"SELECT id, email, city FROM customers","profile":"tenant_jwt","jwt_claims":{"city":"Istanbul"}}`))
	pgBody, _ := io.ReadAll(pgResp.Body)
	_ = pgResp.Body.Close()
	if !strings.Contains(string(pgBody), `"status":"ok"`) || strings.Contains(string(pgBody), "Ankara") {
		t.Fatalf("expected Playground JWT query to filter to Istanbul, got %s", string(pgBody))
	}

	// Missing claim in Playground -> blocked!
	pgBlock, _ := http.Post(ts.URL+"/api/v1/playground/query", "application/json", strings.NewReader(`{"sql":"SELECT id, city FROM customers","profile":"tenant_jwt"}`))
	pgBlockBody, _ := io.ReadAll(pgBlock.Body)
	_ = pgBlock.Body.Close()
	if !strings.Contains(string(pgBlockBody), `"status":"blocked"`) {
		t.Fatalf("expected Playground missing claim block, got %s", string(pgBlockBody))
	}

	testCO, _ := http.Post(ts.URL+"/api/v1/chatops/test", "application/json", strings.NewReader(`{}`))
	_ = testCO.Body.Close()
	if testCO.StatusCode != http.StatusOK {
		t.Fatalf("chatops test failed: %d", testCO.StatusCode)
	}

	mcpPing, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	mcpPing.Header.Set("Authorization", "Bearer pgv_demo_istanbul_tenant")
	mcpPingResp, _ := http.DefaultClient.Do(mcpPing)
	_ = mcpPingResp.Body.Close()
	if mcpPingResp.StatusCode != http.StatusOK {
		t.Fatalf("mounted /mcp ping failed: %d", mcpPingResp.StatusCode)
	}

	// 4. JSON callback POST + invalid callback sig 401 + missing ID 404 + duplicate Slack click (AlreadyResolved)
	dupSlackReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhooks/slack/interactions", bytes.NewReader(formBody))
	dupSlackReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dupSlackReq.Header.Set("X-Slack-Request-Timestamp", tsNow)
	dupSlackReq.Header.Set("X-Slack-Signature", sig)
	dupSlackResp, _ := http.DefaultClient.Do(dupSlackReq)
	dupSlackBody, _ := io.ReadAll(dupSlackResp.Body)
	_ = dupSlackResp.Body.Close()
	if dupSlackResp.StatusCode != http.StatusOK || !strings.Contains(string(dupSlackBody), "Already resolved") {
		t.Fatalf("expected graceful AlreadyResolved Slack reply, got %d %s", dupSlackResp.StatusCode, string(dupSlackBody))
	}

	badCB, _ := http.Get(ts.URL + "/webhooks/hitl/callback?id=x&exp=1&sig=bad")
	_ = badCB.Body.Close()
	if badCB.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad callback sig, got %d", badCB.StatusCode)
	}

	pending3 := hitlMgr.Create(hitl.ApprovalRequest{RoleProfile: "ai_agent", StatementType: "UPDATE", SQL: "UPDATE orders SET status='x' WHERE id=1"}, time.Minute)
	exp3 := strconv.FormatInt(pending3.ExpiresAt.Unix(), 10)
	tok3 := co.SignActionToken(pending3.ID, "deny", pending3.ExpiresAt.Unix())
	jsonCBBody, _ := json.Marshal(map[string]string{"id": pending3.ID, "action": "deny", "exp": exp3, "token": tok3, "reviewer": "secops-bot"})
	jsonCBReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhooks/hitl/callback", bytes.NewReader(jsonCBBody))
	jsonCBReq.Header.Set("Content-Type", "application/json")
	jsonCBReq.Header.Set("Accept", "application/json")
	jsonCBResp, _ := http.DefaultClient.Do(jsonCBReq)
	_ = jsonCBResp.Body.Close()
	if jsonCBResp.StatusCode != http.StatusOK {
		t.Fatalf("JSON callback POST failed: %d", jsonCBResp.StatusCode)
	}
}
