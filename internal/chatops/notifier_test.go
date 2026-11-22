package chatops

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSlackSignatureAndUnfurlSafeCallbacks(t *testing.T) {
	var slackHits, webhookHits atomic.Int32
	mockSlack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), ActionIDApprove) && strings.Contains(string(b), ActionIDDeny) {
			slackHits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockSlack.Close()

	mockWebhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "/webhooks/hitl/callback?") {
			webhookHits.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockWebhook.Close()

	cfgYAML := `
notifications:
  webhook_url: "` + mockWebhook.URL + `"
  public_base_url: "https://pgveil.example.internal"
  callback_secret: "callback-hmac-secret-test"
  slack:
    signing_secret: "slack-signing-secret-test"
    webhook_url: "` + mockSlack.URL + `"
    channel: "#db-approvals"
profiles:
  - name: ai_agent
    masking:
      enabled: true
`
	mgr, err := policy.LoadBytes([]byte(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewMetrics(prometheus.NewRegistry())
	n := NewNotifier(mgr, metrics)
	if !n.IsConfigured() {
		t.Fatal("expected notifier to report configured")
	}

	now := time.Now().UTC()
	exp := now.Add(5 * time.Minute)
	req := hitl.ApprovalRequest{
		ID:            "hitl_abc123",
		CreatedAt:     now,
		ExpiresAt:     exp,
		RoleProfile:   "ai_agent",
		DBUser:        "claude",
		StatementType: "DELETE",
		RiskLevel:     "HIGH",
		SQL:           "DELETE FROM orders WHERE id = 42;",
		Status:        hitl.StatusPending,
	}

	// 1. Outbound async Slack Block Kit & generic webhook dispatch
	n.NotifyHITLPending(req)
	for i := 0; i < 30 && (slackHits.Load() == 0 || webhookHits.Load() == 0); i++ {
		time.Sleep(15 * time.Millisecond)
	}
	if slackHits.Load() != 1 || webhookHits.Load() != 1 {
		t.Fatalf("expected slackHits=1 webhookHits=1, got %d / %d", slackHits.Load(), webhookHits.Load())
	}

	// 2. Unfurler-Safe Preview URL vs Action Token separation
	previewURL := n.SignPreviewURL("https://pgveil.example.internal", req.ID, exp)
	u, err := url.Parse(previewURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if err := n.VerifyPreviewParams(q.Get("id"), q.Get("exp"), q.Get("sig"), now); err != nil {
		t.Fatalf("VerifyPreviewParams failed: %v", err)
	}
	// Preview signature MUST NOT be accepted as an action token!
	if err := n.VerifyActionToken(q.Get("id"), "approve", q.Get("exp"), q.Get("sig"), now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("preview sig must not pass VerifyActionToken, got %v", err)
	}
	// Expired preview rejected
	if err := n.VerifyPreviewParams(q.Get("id"), q.Get("exp"), q.Get("sig"), exp.Add(10*time.Second)); !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("expected ErrExpiredSignature, got %v", err)
	}

	// Action-bound token: approve token MUST NOT validate "deny"
	approveTok := n.SignActionToken(req.ID, "approve", exp.Unix())
	expStr := strconv.FormatInt(exp.Unix(), 10)
	if err := n.VerifyActionToken(req.ID, "approve", expStr, approveTok, now); err != nil {
		t.Fatalf("expected valid approve action token, got %v", err)
	}
	if err := n.VerifyActionToken(req.ID, "deny", expStr, approveTok, now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("approve token must not authorize deny, got %v", err)
	}

	// 3. HTML Review Card escaping & POST form generation
	card := RenderReviewCardHTML(&req, expStr, approveTok, n.SignActionToken(req.ID, "deny", exp.Unix()), "Heads up <script>")
	if strings.Contains(card, "<script>") || !strings.Contains(card, `method="POST"`) {
		t.Fatalf("unexpected review card HTML: %s", card)
	}
	reqDone := req
	reqDone.Status = hitl.StatusApproved
	reqDone.Reviewer = "slack:@duhan"
	resolvedBlocks := BuildSlackResolvedResponse(&reqDone, true)
	if resolvedBlocks["replace_original"] != true {
		t.Fatalf("expected replace_original=true")
	}

	// 4. Slack X-Slack-Signature HMAC-SHA256 & Replay Window verification
	body := []byte("payload=%7B%22type%22%3A%22block_actions%22%7D")
	tsStr := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("slack-signing-secret-test"))
	mac.Write([]byte("v0:" + tsStr + ":"))
	mac.Write(body)
	validSig := "v0=" + hex.EncodeToString(mac.Sum(nil))

	if err := VerifySlackSignature("slack-signing-secret-test", tsStr, validSig, body, now); err != nil {
		t.Fatalf("valid Slack signature rejected: %v", err)
	}
	if err := VerifySlackSignature("slack-signing-secret-test", tsStr, validSig, []byte("tampered"), now); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered Slack body must fail, got %v", err)
	}
	if err := VerifySlackSignature("slack-signing-secret-test", tsStr, validSig, body, now.Add(10*time.Minute)); !errors.Is(err, ErrExpiredSignature) {
		t.Fatalf("stale Slack timestamp must fail replay check, got %v", err)
	}

	// 5. Fallback secret derivation when callback_secret is empty + nil-safe notifier methods
	fallbackMgr, _ := policy.LoadBytes([]byte("security:\n  masking_secret: \"m\"\nprofiles:\n  - name: a\n"))
	fn := NewNotifier(fallbackMgr, nil)
	if fn.IsConfigured() {
		t.Fatal("expected unconfigured notifier")
	}
	if u2 := fn.SignPreviewURL("http://localhost:8088", "hitl_1", exp); u2 == "" {
		t.Fatal("expected fallback derived secret to sign URL")
	}
	if fn.SignPreviewURL("", "hitl_1", exp) != "" {
		t.Fatal("expected empty baseURL to return empty string")
	}
	var nilNotifier *Notifier
	nilNotifier.NotifyHITLPending(req)
}
