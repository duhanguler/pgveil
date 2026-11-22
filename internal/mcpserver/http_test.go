package mcpserver

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func makeTestHS256(secret string, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pay, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pay)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestStreamableHTTPMCPJWTClaimsSessionBindingAndLiveHITL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	demoPG := demo.NewServer()
	upAddr, err := demoPG.Start(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := policy.LoadBytes(demo.BuildDemoConfigYAML("127.0.0.1:0", "127.0.0.1:0", upAddr))
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics(prometheus.NewRegistry())
	hitlMgr := hitl.NewManager(50)
	bus := events.NewBus(100, policy.KafkaConfig{}, metrics)
	defer bus.Close()
	costRunner := firewall.NewCostRunner(mgr, "")
	defer costRunner.Close()
	co := chatops.NewNotifier(mgr, metrics)

	mcpSrv := NewServer(mgr, "ai_agent", "", "0.5.0").AttachControlPlane(hitlMgr, bus, costRunner, co, metrics)
	defer mcpSrv.Close()

	ts := httptest.NewServer(mcpSrv.HTTPHandler())
	defer ts.Close()

	// 1. Unauthenticated request rejected with 401 WWW-Authenticate
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("expected 401 Bearer challenge, got %d", resp.StatusCode)
	}

	// 2. Evil third-party Origin rejected (DNS-rebinding protection)
	evilReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	evilReq.Header.Set("Origin", "https://evil-rebinding.example")
	evilReq.Header.Set("Authorization", "Bearer pgv_demo_istanbul_tenant")
	evilResp, err := http.DefaultClient.Do(evilReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = evilResp.Body.Close()
	if evilResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for untrusted Origin, got %d", evilResp.StatusCode)
	}

	// 3. Streamable HTTP 2025-03-26 initialize -> mints Mcp-Session-Id
	now := time.Now().Unix()
	ankaraJWT := makeTestHS256("pgveil-demo-jwt-hs256-secret", map[string]any{
		"sub":  "tenant-ankara-user",
		"role": "tenant_jwt",
		"city": "Ankara",
		"exp":  now + 300,
	})
	initReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`))
	initReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	initReq.Header.Set("Origin", "http://127.0.0.1:8088")
	initResp, err := http.DefaultClient.Do(initReq)
	if err != nil {
		t.Fatal(err)
	}
	initBody, _ := io.ReadAll(initResp.Body)
	_ = initResp.Body.Close()
	sessionID := initResp.Header.Get("Mcp-Session-Id")
	if initResp.StatusCode != http.StatusOK || sessionID == "" || !strings.Contains(string(initBody), "2025-03-26") {
		t.Fatalf("initialize failed: status=%d sid=%q body=%s", initResp.StatusCode, sessionID, string(initBody))
	}

	// 4. Cross-tenant Mcp-Session-Id hijack MUST fail with 403 Forbidden
	otherJWT := makeTestHS256("pgveil-demo-jwt-hs256-secret", map[string]any{
		"sub":  "tenant-izmir-user",
		"role": "tenant_jwt",
		"city": "Izmir",
		"exp":  now + 300,
	})
	hijackReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
	hijackReq.Header.Set("Authorization", "Bearer "+otherJWT)
	hijackReq.Header.Set("Mcp-Session-Id", sessionID)
	hijackResp, err := http.DefaultClient.Do(hijackReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = hijackResp.Body.Close()
	if hijackResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-subject session hijack, got %d", hijackResp.StatusCode)
	}

	// 5. Notification-only returns 202 Accepted
	notifReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	notifReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	notifReq.Header.Set("Mcp-Session-Id", sessionID)
	notifResp, err := http.DefaultClient.Do(notifReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = notifResp.Body.Close()
	if notifResp.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for notification, got %d", notifResp.StatusCode)
	}

	// 6. Query customers with Ankara JWT -> ONLY Ankara rows returned & PII masked!
	qPayload := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT id, email, city, tckn FROM customers"}}}`
	qReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(qPayload))
	qReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	qReq.Header.Set("Mcp-Session-Id", sessionID)
	qResp, err := http.DefaultClient.Do(qReq)
	if err != nil {
		t.Fatal(err)
	}
	qBody, _ := io.ReadAll(qResp.Body)
	_ = qResp.Body.Close()
	if !strings.Contains(string(qBody), "Ankara") || strings.Contains(string(qBody), "Istanbul") || strings.Contains(string(qBody), "10000000146") {
		t.Fatalf("expected only masked Ankara rows via {{jwt.city}} RLS, got: %s", string(qBody))
	}

	// 7. Missing {{jwt.city}} claim -> strict fail-closed block!
	missingClaimJWT := makeTestHS256("pgveil-demo-jwt-hs256-secret", map[string]any{
		"sub":  "no-city-user",
		"role": "tenant_jwt",
		"exp":  now + 300,
	})
	mcReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(qPayload))
	mcReq.Header.Set("Authorization", "Bearer "+missingClaimJWT)
	mcResp, _ := http.DefaultClient.Do(mcReq)
	mcBody, _ := io.ReadAll(mcResp.Body)
	_ = mcResp.Body.Close()
	if !strings.Contains(string(mcBody), "missing required JWT claim") {
		t.Fatalf("expected fail-closed missing claim block, got: %s", string(mcBody))
	}

	// 8. Cost Guard blocks 3-way cartesian join over MCP + SSE response framing + Batch JSON-RPC
	bombPayload := `[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT c.id FROM customers c, orders o, payments p"}}}]`
	bReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(bombPayload))
	bReq.Header.Set("Authorization", "Bearer pgv_demo_istanbul_tenant")
	bReq.Header.Set("Accept", "text/event-stream")
	bResp, _ := http.DefaultClient.Do(bReq)
	bBody, _ := io.ReadAll(bResp.Body)
	_ = bResp.Body.Close()
	if !strings.Contains(bResp.Header.Get("Content-Type"), "text/event-stream") || !strings.Contains(string(bBody), "cost_guard_max_cost") {
		t.Fatalf("expected SSE Cost Guard block, got ct=%q body=%s", bResp.Header.Get("Content-Type"), string(bBody))
	}

	// 9. Live zero-DB-conn HITL hold over HTTP MCP -> approved asynchronously -> query executes!
	subCh, unsub := hitlMgr.Subscribe()
	defer unsub()
	go func() {
		ev := <-subCh
		if ev.Status == hitl.StatusPending {
			time.Sleep(30 * time.Millisecond)
			_, _ = hitlMgr.Resolve(ev.ID, true, "test-operator", "LGTM")
		}
	}()
	updPayload := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query","arguments":{"sql":"UPDATE orders SET status = 'shipped' WHERE id = 1001"}}}`
	uReq, _ := http.NewRequest(http.MethodPost, ts.URL, bytes.NewBufferString(updPayload))
	uReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	uResp, err := http.DefaultClient.Do(uReq)
	if err != nil {
		t.Fatal(err)
	}
	uBody, _ := io.ReadAll(uResp.Body)
	_ = uResp.Body.Close()
	if strings.Contains(string(uBody), `"isError":true`) {
		t.Fatalf("expected live HITL-approved MCP UPDATE to succeed, got: %s", string(uBody))
	}

	// 10. DELETE /mcp terminates session cleanly
	delReq, _ := http.NewRequest(http.MethodDelete, ts.URL, nil)
	delReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	delReq.Header.Set("Mcp-Session-Id", sessionID)
	delResp, _ := http.DefaultClient.Do(delReq)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on DELETE /mcp, got %d", delResp.StatusCode)
	}

	// 11. HTTP protocol edge cases: unknown session 404, GET 405, GET SSE 200, PUT 405, empty body 400, invalid JSON 400, invalid batch 400
	staleReq, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	staleReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	staleReq.Header.Set("Mcp-Session-Id", sessionID) // deleted above!
	staleResp, _ := http.DefaultClient.Do(staleReq)
	_ = staleResp.Body.Close()
	if staleResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 on deleted Mcp-Session-Id, got %d", staleResp.StatusCode)
	}

	getPlain, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	getPlain.Header.Set("Authorization", "Bearer "+ankaraJWT)
	getPlainResp, _ := http.DefaultClient.Do(getPlain)
	_ = getPlainResp.Body.Close()
	if getPlainResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on plain GET, got %d", getPlainResp.StatusCode)
	}

	sseCtx, sseCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer sseCancel()
	getSSE, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, ts.URL, nil)
	getSSE.Header.Set("Authorization", "Bearer "+ankaraJWT)
	getSSE.Header.Set("Accept", "text/event-stream")
	getSSEResp, err := http.DefaultClient.Do(getSSE)
	if err == nil {
		_ = getSSEResp.Body.Close()
	}

	putReq, _ := http.NewRequest(http.MethodPut, ts.URL, nil)
	putReq.Header.Set("Authorization", "Bearer "+ankaraJWT)
	putResp, _ := http.DefaultClient.Do(putReq)
	_ = putResp.Body.Close()
	if putResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on PUT, got %d", putResp.StatusCode)
	}

	for _, badBody := range []string{"   ", "{bad_json", "[]"} {
		br, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(badBody))
		br.Header.Set("Authorization", "Bearer "+ankaraJWT)
		bresp, _ := http.DefaultClient.Do(br)
		_ = bresp.Body.Close()
		if bresp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 on body %q, got %d", badBody, bresp.StatusCode)
		}
	}
}
