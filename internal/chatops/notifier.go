package chatops

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/duhanguler/pgveil/internal/hitl"
	"github.com/duhanguler/pgveil/internal/policy"
	"github.com/duhanguler/pgveil/internal/telemetry"
)

const (
	ActionIDApprove  = "pgveil_hitl_approve"
	ActionIDDeny     = "pgveil_hitl_deny"
	slackReplayLimit = 300 // ±5 minutes per Slack security specification
)

var (
	ErrInvalidSignature = errors.New("invalid cryptographic signature")
	ErrExpiredSignature = errors.New("signed callback or timestamp has expired")
)

// Notifier dispatches interactive Human-in-the-Loop approval cards to Slack Block Kit
// and generic webhook endpoints (Discord / Teams / custom bots) with unfurler-safe signed review links.
type Notifier struct {
	policyMgr  *policy.Manager
	metrics    *telemetry.Metrics
	httpClient *http.Client
}

func NewNotifier(policyMgr *policy.Manager, metrics *telemetry.Metrics) *Notifier {
	return &Notifier{
		policyMgr: policyMgr,
		metrics:   metrics,
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

// IsConfigured reports whether any outbound ChatOps channel or signed callback URL is active.
func (n *Notifier) IsConfigured() bool {
	if n == nil || n.policyMgr == nil {
		return false
	}
	cfg := n.policyMgr.Config().Notifications
	return cfg.WebhookURL != "" || cfg.Slack.WebhookURL != "" || (cfg.Slack.BotToken != "" && cfg.Slack.Channel != "") || cfg.PublicBaseURL != ""
}

func (n *Notifier) effectiveCallbackSecret() []byte {
	cfg := n.policyMgr.Config()
	if s := strings.TrimSpace(cfg.Notifications.CallbackSecret); s != "" {
		return []byte(s)
	}
	// Derive a domain-separated HMAC key from MaskingSecret so operators don't have to manage two secrets
	mac := hmac.New(sha256.New, []byte("pgveil-hitl-callback-v1"))
	seed := cfg.Security.MaskingSecret
	if seed == "" {
		seed = "pgveil-default-dev-callback-seed"
	}
	mac.Write([]byte(seed))
	return mac.Sum(nil)
}

// SignPreviewURL builds an idempotent, unfurler-safe GET review link.
// Fetching this URL via GET NEVER mutates HITL state; state changes require a separate action-bound POST token.
func (n *Notifier) SignPreviewURL(baseURL, approvalID string, expiresAt time.Time) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return ""
	}
	exp := expiresAt.Unix()
	sig := n.computeHMAC(fmt.Sprintf("preview:%s:%d", approvalID, exp))
	q := url.Values{}
	q.Set("id", approvalID)
	q.Set("exp", strconv.FormatInt(exp, 10))
	q.Set("sig", sig)
	return base + "/webhooks/hitl/callback?" + q.Encode()
}

// VerifyPreviewParams validates the query parameters of GET /webhooks/hitl/callback.
func (n *Notifier) VerifyPreviewParams(approvalID, expStr, sigHex string, now time.Time) error {
	if approvalID == "" || expStr == "" || sigHex == "" {
		return ErrInvalidSignature
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	expected := n.computeHMAC(fmt.Sprintf("preview:%s:%d", approvalID, exp))
	if !hmacEqualHex(expected, sigHex) {
		return ErrInvalidSignature
	}
	if now.Unix() > exp {
		return ErrExpiredSignature
	}
	return nil
}

// SignActionToken produces an action-bound POST token ("approve" or "deny") embedded in the HTML review form.
func (n *Notifier) SignActionToken(approvalID, action string, exp int64) string {
	return n.computeHMAC(fmt.Sprintf("act:%s:%s:%d", approvalID, action, exp))
}

// VerifyActionToken validates a state-mutating POST /webhooks/hitl/callback submission.
func (n *Notifier) VerifyActionToken(approvalID, action, expStr, tokenHex string, now time.Time) error {
	if approvalID == "" || (action != "approve" && action != "deny") || expStr == "" || tokenHex == "" {
		return ErrInvalidSignature
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	expected := n.SignActionToken(approvalID, action, exp)
	if !hmacEqualHex(expected, tokenHex) {
		return ErrInvalidSignature
	}
	if now.Unix() > exp {
		return ErrExpiredSignature
	}
	return nil
}

// VerifySlackSignature verifies Slack's X-Slack-Request-Timestamp (±5m) and X-Slack-Signature (v0=HMAC-SHA256).
func VerifySlackSignature(signingSecret, timestampHeader, sigHeader string, rawBody []byte, now time.Time) error {
	if strings.TrimSpace(signingSecret) == "" || timestampHeader == "" || !strings.HasPrefix(sigHeader, "v0=") {
		return ErrInvalidSignature
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestampHeader), 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	diff := now.Unix() - ts
	if diff > slackReplayLimit || diff < -slackReplayLimit {
		return ErrExpiredSignature
	}
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte("v0:"))
	mac.Write([]byte(strings.TrimSpace(timestampHeader)))
	mac.Write([]byte(":"))
	mac.Write(rawBody)
	expectedHex := hex.EncodeToString(mac.Sum(nil))
	if !hmacEqualHex(expectedHex, strings.TrimPrefix(sigHeader, "v0=")) {
		return ErrInvalidSignature
	}
	return nil
}

func (n *Notifier) computeHMAC(msg string) string {
	mac := hmac.New(sha256.New, n.effectiveCallbackSecret())
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacEqualHex(expectedHex, providedHex string) bool {
	a, err1 := hex.DecodeString(expectedHex)
	b, err2 := hex.DecodeString(providedHex)
	if err1 != nil || err2 != nil || len(a) != len(b) {
		return false
	}
	return hmac.Equal(a, b)
}

// NotifyHITLPending asynchronously dispatches interactive approval cards to configured Slack & webhook endpoints.
func (n *Notifier) NotifyHITLPending(req hitl.ApprovalRequest) {
	if n == nil || n.policyMgr == nil {
		return
	}
	ncfg := n.policyMgr.Config().Notifications
	previewURL := n.SignPreviewURL(ncfg.PublicBaseURL, req.ID, req.ExpiresAt)

	if ncfg.Slack.WebhookURL != "" || (ncfg.Slack.BotToken != "" && ncfg.Slack.Channel != "") {
		go n.sendSlackBlockKit(ncfg.Slack, req, previewURL)
	}
	if ncfg.WebhookURL != "" {
		go n.sendGenericWebhook(ncfg.WebhookURL, req, previewURL)
	}
}

// BuildSlackPendingBlocks builds the Slack Block Kit payload with Approve & Deny interactive buttons.
func BuildSlackPendingBlocks(req hitl.ApprovalRequest, channel string, previewURL string) map[string]any {
	sqlSnippet := truncateRunes(req.SQL, 600)
	metaLine := fmt.Sprintf("*Profile:* `%s`  •  *User:* `%s`  •  *Risk:* `%s`  •  *Expires:* `%s`",
		req.RoleProfile, req.DBUser, req.RiskLevel, req.ExpiresAt.Format("15:04:05 UTC"))

	elements := []map[string]any{
		{
			"type":      "button",
			"style":     "primary",
			"action_id": ActionIDApprove,
			"value":     req.ID,
			"text":      map[string]any{"type": "plain_text", "text": "Approve Query"},
		},
		{
			"type":      "button",
			"style":     "danger",
			"action_id": ActionIDDeny,
			"value":     req.ID,
			"text":      map[string]any{"type": "plain_text", "text": "Deny Query"},
		},
	}
	if previewURL != "" {
		elements = append(elements, map[string]any{
			"type": "button",
			"url":  previewURL,
			"text": map[string]any{"type": "plain_text", "text": "Open Review Card"},
		})
	}

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": fmt.Sprintf("pgveil HITL Hold — %s (%s)", req.StatementType, req.ID)},
		},
		{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": metaLine + "\n```" + sqlSnippet + "```"},
		},
		{
			"type":     "actions",
			"block_id": "pgveil_hitl_actions_" + req.ID,
			"elements": elements,
		},
	}
	payload := map[string]any{
		"text":   fmt.Sprintf("[pgveil HITL] Paused %s query (%s) for profile %s", req.StatementType, req.ID, req.RoleProfile),
		"blocks": blocks,
	}
	if channel != "" {
		payload["channel"] = channel
	}
	return payload
}

// BuildSlackResolvedResponse builds the immediate Block Kit replacement payload after an operator clicks a Slack button.
func BuildSlackResolvedResponse(req *hitl.ApprovalRequest, alreadyResolved bool) map[string]any {
	badge := "✅ APPROVED"
	if req.Status == hitl.StatusDenied {
		badge = "🛑 DENIED"
	} else if req.Status == hitl.StatusExpired {
		badge = "⏱️ EXPIRED"
	}
	prefix := ""
	if alreadyResolved {
		prefix = "Already resolved earlier: "
	}
	sqlSnippet := truncateRunes(req.SQL, 500)
	summary := fmt.Sprintf("%s*%s* by `%s`  •  *Request:* `%s`  •  *Profile:* `%s`\n```%s```",
		prefix, badge, req.Reviewer, req.ID, req.RoleProfile, sqlSnippet)

	return map[string]any{
		"replace_original": true,
		"text":             fmt.Sprintf("[pgveil HITL] %s (%s by %s)", req.ID, req.Status, req.Reviewer),
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": summary},
			},
		},
	}
}

func (n *Notifier) sendSlackBlockKit(scfg policy.SlackConfig, req hitl.ApprovalRequest, previewURL string) {
	bodyMap := BuildSlackPendingBlocks(req, scfg.Channel, previewURL)
	data, _ := json.Marshal(bodyMap)

	targetURL := scfg.WebhookURL
	headers := map[string]string{"Content-Type": "application/json"}
	if scfg.BotToken != "" && scfg.Channel != "" {
		targetURL = "https://slack.com/api/chat.postMessage"
		headers["Authorization"] = "Bearer " + scfg.BotToken
	}
	if targetURL == "" {
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(data))
	if err != nil {
		return
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := n.httpClient.Do(httpReq)
	if err != nil {
		slog.Warn("slack HITL dispatch failed", "err", err)
		n.incMetric("slack", "dispatch_error")
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		n.incMetric("slack", "dispatched")
	} else {
		n.incMetric("slack", "dispatch_error")
	}
}

func (n *Notifier) sendGenericWebhook(webhookURL string, req hitl.ApprovalRequest, previewURL string) {
	msg := fmt.Sprintf("⏸️ [pgveil HITL] Paused %s (%s) on profile=%q user=%q: %s",
		req.StatementType, req.ID, req.RoleProfile, req.DBUser, truncateRunes(req.SQL, 240))
	if previewURL != "" {
		msg += "\nReview & Approve/Deny: " + previewURL
	}
	payload, _ := json.Marshal(map[string]any{
		"text":       msg,
		"content":    msg,
		"review_url": previewURL,
		"hitl": map[string]any{
			"id":             req.ID,
			"role_profile":   req.RoleProfile,
			"db_user":        req.DBUser,
			"statement_type": req.StatementType,
			"risk_level":     req.RiskLevel,
			"sql":            req.SQL,
			"expires_at":     req.ExpiresAt,
		},
	})
	resp, err := n.httpClient.Post(webhookURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		n.incMetric("webhook", "dispatch_error")
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		n.incMetric("webhook", "dispatched")
	} else {
		n.incMetric("webhook", "dispatch_error")
	}
}

func (n *Notifier) incMetric(channel, event string) {
	if n.metrics != nil && n.metrics.HITLChatOps != nil {
		n.metrics.HITLChatOps.WithLabelValues(channel, event).Inc()
	}
}

// RenderReviewCardHTML renders a zero-JS, CSP-safe HTML confirmation card for GET/POST /webhooks/hitl/callback.
// When pending is true, renders POST forms carrying action-bound HMAC tokens so link-preview bots can never trigger approval.
func RenderReviewCardHTML(req *hitl.ApprovalRequest, expStr, approveToken, denyToken, notice string) string {
	escID := html.EscapeString(req.ID)
	escProf := html.EscapeString(req.RoleProfile)
	escUser := html.EscapeString(req.DBUser)
	escStmt := html.EscapeString(req.StatementType)
	escRisk := html.EscapeString(req.RiskLevel)
	escSQL := html.EscapeString(req.SQL)
	escStatus := html.EscapeString(string(req.Status))
	escExp := html.EscapeString(expStr)

	var actionsHTML string
	if req.Status == hitl.StatusPending && approveToken != "" && denyToken != "" {
		actionsHTML = fmt.Sprintf(`
<div style="display:flex;gap:12px;margin-top:20px">
  <form method="POST" action="/webhooks/hitl/callback" style="margin:0">
    <input type="hidden" name="id" value="%s"/>
    <input type="hidden" name="action" value="approve"/>
    <input type="hidden" name="exp" value="%s"/>
    <input type="hidden" name="token" value="%s"/>
    <button type="submit" style="background:#10b981;color:#052e16;font-weight:700;border:0;padding:10px 20px;border-radius:6px;cursor:pointer">Confirm Approve</button>
  </form>
  <form method="POST" action="/webhooks/hitl/callback" style="margin:0">
    <input type="hidden" name="id" value="%s"/>
    <input type="hidden" name="action" value="deny"/>
    <input type="hidden" name="exp" value="%s"/>
    <input type="hidden" name="token" value="%s"/>
    <button type="submit" style="background:#ef4444;color:#fff;font-weight:700;border:0;padding:10px 20px;border-radius:6px;cursor:pointer">Confirm Deny</button>
  </form>
</div>`, escID, escExp, html.EscapeString(approveToken), escID, escExp, html.EscapeString(denyToken))
	} else {
		rev := html.EscapeString(req.Reviewer)
		if rev == "" {
			rev = "system"
		}
		actionsHTML = fmt.Sprintf(`<div style="margin-top:18px;padding:12px;border-radius:6px;background:#18181b;border:1px solid #27272a"><strong>Status:</strong> %s (by %s)</div>`, escStatus, rev)
	}

	banner := ""
	if notice != "" {
		banner = fmt.Sprintf(`<div style="margin-bottom:14px;padding:10px 12px;border-radius:6px;background:#1e293b;color:#e2e8f0">%s</div>`, html.EscapeString(notice))
	}

	return fmt.Sprintf(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>pgveil HITL Review — %s</title></head>
<body style="font-family:ui-sans-serif,system-ui,sans-serif;background:#09090b;color:#f4f4f5;margin:0;padding:32px 16px">
<main style="max-width:680px;margin:0 auto;background:#121215;border:1px solid #27272a;border-radius:10px;padding:24px">
  %s
  <div style="font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#a1a1aa">pgveil Human-in-the-Loop Gate</div>
  <h1 style="font-size:20px;margin:6px 0 16px">%s — %s (%s)</h1>
  <div style="font-size:13px;color:#d4d4d8;margin-bottom:14px">Profile: <code>%s</code> &middot; DB User: <code>%s</code> &middot; Status: <strong>%s</strong></div>
  <pre style="background:#09090b;border:1px solid #27272a;border-radius:6px;padding:14px;overflow-x:auto;font-size:13px;line-height:1.5;color:#fde68a">%s</pre>
  %s
</main></body></html>`, escID, banner, escStmt, escID, escRisk, escProf, escUser, escStatus, escSQL, actionsHTML)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}
