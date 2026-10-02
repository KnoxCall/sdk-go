package knoxcall

// Tests for ConstructWebhookEvent — the Go port of the constructEvent matrix
// required by ../../PARITY.md §10/§12.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

const webhookTestSecret = "whsec_test_secret"

// eventBody builds a realistic request.* delivery body with a current
// envelope timestamp (so the legacy-format tolerance check passes).
func eventBody(event string) []byte {
	return eventBodyAt(event, time.Now())
}

func eventBodyAt(event string, at time.Time) []byte {
	return []byte(fmt.Sprintf(`{
		"event": %q,
		"timestamp": %q,
		"webhook_id": "wh_123",
		"webhook_name": "orders-hook",
		"data": {
			"route_id": "r_1",
			"route_name": "orders",
			"environment": "production",
			"request": {"method": "POST", "path": "/orders", "ip": "203.0.113.9"},
			"response": {"status": 201, "latency_ms": 42}
		}
	}`, event, at.UTC().Format(time.RFC3339)))
}

func hmacHexOf(secret string, parts ...[]byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, p := range parts {
		mac.Write(p)
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func mustVerificationError(t *testing.T, err error) *WebhookSignatureVerificationError {
	t.Helper()
	var ve *WebhookSignatureVerificationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v (%T), want *WebhookSignatureVerificationError", err, err)
	}
	return ve
}

// ── legacy format ─────────────────────────────────────────────────────────────

func TestConstructEventLegacyValid(t *testing.T) {
	body := eventBody("request.success")
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil)
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
	if ev.Event != "request.success" || ev.WebhookID != "wh_123" || ev.WebhookName != "orders-hook" {
		t.Fatalf("event envelope = %+v, want the typed fields populated", ev)
	}
	data, err := ev.RequestData()
	if err != nil {
		t.Fatalf("RequestData: %v", err)
	}
	if data.RouteID != "r_1" || data.Request.Method != "POST" || data.Response.Status != 201 || data.Response.LatencyMs != 42 {
		t.Fatalf("request data = %+v, want the decoded route/request/response fields", data)
	}
}

func TestConstructEventLegacyHeaderLookupIsCaseInsensitive(t *testing.T) {
	body := eventBody("request.success")
	// Deliveries arrive as http.Header, whose Set/Get canonicalize keys —
	// a caller setting any casing must still be found by the verifier.
	h := http.Header{}
	h.Set("x-wEbHoOk-sIgNaTuRe", "sha256="+hmacHexOf(webhookTestSecret, body))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil); err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
}

func TestConstructEventWrongSecretIsTypedError(t *testing.T) {
	body := eventBody("request.success")
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf("the-wrong-secret", body))

	_, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil)
	ve := mustVerificationError(t, err)
	// The message must say what failed WITHOUT echoing the signature/secret.
	if strings.Contains(ve.Error(), "the-wrong-secret") || strings.Contains(ve.Error(), hmacHexOf("the-wrong-secret", body)) {
		t.Fatalf("error message leaked the signature or secret: %v", ve)
	}
}

func TestConstructEventMissingHeaderIsTypedError(t *testing.T) {
	body := eventBody("request.success")
	_, err := ConstructWebhookEvent(body, http.Header{}, webhookTestSecret, nil)
	ve := mustVerificationError(t, err)
	if !strings.Contains(ve.Error(), "X-Webhook-Signature") {
		t.Fatalf("err = %v, want the missing header named", ve)
	}
}

func TestConstructEventStaleEnvelopeTimestampRejected(t *testing.T) {
	body := eventBodyAt("request.success", time.Now().Add(-time.Hour))
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil); err == nil {
		t.Fatalf("want a stale-timestamp error with the default 300s tolerance")
	}

	// Explicitly disabling the tolerance (pointer to 0) skips the check.
	zero := 0
	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{ToleranceSeconds: &zero}); err != nil {
		t.Fatalf("tolerance disabled: %v, want the stale envelope accepted", err)
	}
}

// ── stripe format ─────────────────────────────────────────────────────────────

func TestConstructEventStripeRoundTrip(t *testing.T) {
	body := eventBody("request.completed")
	ts := time.Now().Unix()
	sig := hmacHexOf(webhookTestSecret, []byte(fmt.Sprintf("%d.", ts)), body)
	h := http.Header{}
	h.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", ts, sig))

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe"})
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
	if ev.Event != "request.completed" {
		t.Fatalf("event = %q, want request.completed", ev.Event)
	}
}

func TestConstructEventStripeStaleTimestampRejected(t *testing.T) {
	body := eventBody("request.completed")
	ts := time.Now().Add(-time.Hour).Unix()
	sig := hmacHexOf(webhookTestSecret, []byte(fmt.Sprintf("%d.", ts)), body)
	h := http.Header{}
	h.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", ts, sig))

	_, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe"})
	ve := mustVerificationError(t, err)
	if !strings.Contains(ve.Error(), "tolerance") {
		t.Fatalf("err = %v, want a tolerance-window failure", ve)
	}
}

func TestConstructEventStripeMultipleV1EntriesAnyMatchPasses(t *testing.T) {
	body := eventBody("request.completed")
	ts := time.Now().Unix()
	good := hmacHexOf(webhookTestSecret, []byte(fmt.Sprintf("%d.", ts)), body)
	bogus := strings.Repeat("0", 64)
	h := http.Header{}
	// Rotated-secret shape: a stale v1 first, the matching one second.
	h.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s,v1=%s", ts, bogus, good))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe"}); err != nil {
		t.Fatalf("ConstructWebhookEvent: %v — any matching v1 must pass", err)
	}

	h.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", ts, bogus))
	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe"}); err == nil {
		t.Fatalf("want a mismatch error when no v1 entry matches")
	}
}

// ── slack format ──────────────────────────────────────────────────────────────

func TestConstructEventSlackRoundTrip(t *testing.T) {
	body := eventBody("request.received")
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := hmacHexOf(webhookTestSecret, []byte("v0:"+ts+":"), body)
	h := http.Header{}
	h.Set("X-Slack-Signature", "v0="+sig)
	h.Set("X-Slack-Request-Timestamp", ts)

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "slack"})
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
	if ev.Event != "request.received" {
		t.Fatalf("event = %q, want request.received", ev.Event)
	}
}

func TestConstructEventSlackStaleTimestampRejected(t *testing.T) {
	body := eventBody("request.received")
	ts := fmt.Sprintf("%d", time.Now().Add(-time.Hour).Unix())
	sig := hmacHexOf(webhookTestSecret, []byte("v0:"+ts+":"), body)
	h := http.Header{}
	h.Set("X-Slack-Signature", "v0="+sig)
	h.Set("X-Slack-Request-Timestamp", ts)

	_, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "slack"})
	mustVerificationError(t, err)
}

// ── github / aws-sns / custom formats ─────────────────────────────────────────

func TestConstructEventGitHubFormat(t *testing.T) {
	body := eventBody("request.error")
	h := http.Header{}
	h.Set("X-Hub-Signature-256", "sha256="+hmacHexOf(webhookTestSecret, body))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "github"}); err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
}

func TestConstructEventAwsSnsBase64Format(t *testing.T) {
	body := eventBody("request.timeout")
	mac := hmac.New(sha256.New, []byte(webhookTestSecret))
	mac.Write(body)
	h := http.Header{}
	h.Set("x-amz-sns-signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "aws-sns"}); err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
}

func TestConstructEventCustomHeaderName(t *testing.T) {
	body := eventBody("request.redirect")
	h := http.Header{}
	h.Set("X-Acme-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "custom", HeaderName: "X-Acme-Signature"})
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
	if ev.Event != "request.redirect" {
		t.Fatalf("event = %q, want request.redirect", ev.Event)
	}

	// custom without HeaderName is a typed error, not a panic.
	_, err = ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "custom"})
	mustVerificationError(t, err)
}

// ── body / event-type edge cases ──────────────────────────────────────────────

func TestConstructEventNonJSONBodyIsTypedError(t *testing.T) {
	body := []byte("this is not json")
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	_, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil)
	ve := mustVerificationError(t, err)
	if !strings.Contains(ve.Error(), "JSON") {
		t.Fatalf("err = %v, want a not-valid-JSON failure", ve)
	}
}

func TestConstructEventUnknownEventTypeStillParses(t *testing.T) {
	body := eventBody("request.some_future_event")
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil)
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v — the event-type list is open", err)
	}
	if ev.Event != "request.some_future_event" {
		t.Fatalf("event = %q, want the unknown type passed through", ev.Event)
	}
}

func TestConstructEventAuditEventData(t *testing.T) {
	body := []byte(fmt.Sprintf(`{
		"event": "audit.event",
		"timestamp": %q,
		"data": {
			"id": "al_1",
			"action": "secret.create",
			"resource_type": "secret",
			"resource_id": "sec_1",
			"details": {"name": "STRIPE_KEY"},
			"ip_address": "203.0.113.9"
		}
	}`, time.Now().UTC().Format(time.RFC3339)))
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, nil)
	if err != nil {
		t.Fatalf("ConstructWebhookEvent: %v", err)
	}
	if ev.WebhookID != "" || ev.WebhookName != "" {
		t.Fatalf("audit.event carries no webhook_id/webhook_name, got %+v", ev)
	}
	data, err := ev.AuditData()
	if err != nil {
		t.Fatalf("AuditData: %v", err)
	}
	if data.Action != "secret.create" || data.ResourceType != "secret" || data.ResourceID != "sec_1" {
		t.Fatalf("audit data = %+v, want the decoded audit row", data)
	}
}

func TestConstructEventUnknownFormatIsTypedError(t *testing.T) {
	body := eventBody("request.success")
	_, err := ConstructWebhookEvent(body, http.Header{}, webhookTestSecret, &ConstructEventOptions{Format: "pkcs11"})
	mustVerificationError(t, err)
}

func TestWebhooksResourceConstructEventDelegates(t *testing.T) {
	c := newTestClient(t, "https://api.example.test", nil)
	body := eventBody("request.success")
	h := http.Header{}
	h.Set("X-Webhook-Signature", "sha256="+hmacHexOf(webhookTestSecret, body))

	ev, err := c.Webhooks.ConstructEvent(body, h, webhookTestSecret, nil)
	if err != nil {
		t.Fatalf("ConstructEvent: %v", err)
	}
	if ev.Event != "request.success" {
		t.Fatalf("event = %q, want request.success", ev.Event)
	}
}

// ── boolean VerifySignature helper (default legacy scheme) ────────────────────

// VerifySignature uses the DEFAULT legacy scheme: HMAC-SHA256(secret, body)
// compared to the hex header value. A valid legacy signature must round-trip
// true — the old implementation parsed the compound stripe t=,v1= shape and
// returned false for every legacy delivery.
func TestVerifySignatureLegacyRoundTrip(t *testing.T) {
	body := []byte(`{"event":"request.success","data":{}}`)
	sig := hmacHexOf(webhookTestSecret, body)

	if !VerifySignature(body, sig, webhookTestSecret, 0, 0) {
		t.Fatalf("a valid legacy signature returned false")
	}
	// The X-Webhook-Signature "sha256=" prefix is tolerated.
	if !VerifySignature(body, "sha256="+sig, webhookTestSecret, 0, 0) {
		t.Fatalf("a sha256=-prefixed legacy signature returned false")
	}
	// Wrong secret fails.
	if VerifySignature(body, sig, "the-wrong-secret", 0, 0) {
		t.Fatalf("signature verified under the wrong secret")
	}
	// Tampered body fails.
	if VerifySignature([]byte(`{"event":"tampered"}`), sig, webhookTestSecret, 0, 0) {
		t.Fatalf("signature verified over a tampered body")
	}
}

// With a tolerance and a delivery timestamp, VerifySignature rejects replays;
// tolerance 0 skips the timestamp check entirely.
func TestVerifySignatureTimestampTolerance(t *testing.T) {
	body := []byte(`{"event":"request.success"}`)
	sig := hmacHexOf(webhookTestSecret, body)
	now := time.Now().Unix()

	if VerifySignature(body, sig, webhookTestSecret, 300, now-3600) {
		t.Fatalf("a stale timestamp was accepted with a 300s tolerance")
	}
	if !VerifySignature(body, sig, webhookTestSecret, 300, now-10) {
		t.Fatalf("a fresh timestamp was rejected within tolerance")
	}
	// Tolerance disabled (0): the timestamp is never consulted.
	if !VerifySignature(body, sig, webhookTestSecret, 0, now-3600) {
		t.Fatalf("a stale timestamp was rejected even though tolerance was disabled")
	}
}

// ── §12: timestamp parsing is skipped when tolerance is disabled ──────────────

// A valid-signature stripe delivery whose t= is non-numeric must verify when
// tolerance is disabled (the signature already covers the timestamp), and
// error under the default tolerance — matching python/node.
func TestConstructEventStripeMalformedTimestampSkippedWhenToleranceDisabled(t *testing.T) {
	body := eventBody("request.completed")
	ts := "not-a-number"
	sig := hmacHexOf(webhookTestSecret, []byte(ts+"."), body)
	h := http.Header{}
	h.Set("Stripe-Signature", fmt.Sprintf("t=%s,v1=%s", ts, sig))

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe"}); err == nil {
		t.Fatalf("want a malformed-timestamp error under the default tolerance")
	}

	zero := 0
	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "stripe", ToleranceSeconds: &zero})
	if err != nil {
		t.Fatalf("tolerance disabled: %v, want the valid-signature delivery accepted", err)
	}
	if ev.Event != "request.completed" {
		t.Fatalf("event = %q, want request.completed", ev.Event)
	}
}

func TestConstructEventSlackMalformedTimestampSkippedWhenToleranceDisabled(t *testing.T) {
	body := eventBody("request.received")
	ts := "bogus-ts"
	sig := hmacHexOf(webhookTestSecret, []byte("v0:"+ts+":"), body)
	h := http.Header{}
	h.Set("X-Slack-Signature", "v0="+sig)
	h.Set("X-Slack-Request-Timestamp", ts)

	if _, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "slack"}); err == nil {
		t.Fatalf("want a malformed-timestamp error under the default tolerance")
	}

	zero := 0
	ev, err := ConstructWebhookEvent(body, h, webhookTestSecret, &ConstructEventOptions{Format: "slack", ToleranceSeconds: &zero})
	if err != nil {
		t.Fatalf("tolerance disabled: %v, want the valid-signature delivery accepted", err)
	}
	if ev.Event != "request.received" {
		t.Fatalf("event = %q, want request.received", ev.Event)
	}
}

// The signature comparison must be constant-time. Timing assertions are
// flaky, so this guard checks the implementation directly: every comparison
// in webhook_events.go must go through crypto/hmac's constant-time Equal.
func TestConstructEventUsesConstantTimeCompare(t *testing.T) {
	src, err := os.ReadFile("webhook_events.go")
	if err != nil {
		t.Fatalf("read webhook_events.go: %v", err)
	}
	code := string(src)
	if !strings.Contains(code, "hmac.Equal(") {
		t.Fatalf("webhook_events.go must compare signatures with hmac.Equal (constant-time)")
	}
	for _, banned := range []string{"expected ==", "== expected", "bytes.Equal("} {
		if strings.Contains(code, banned) {
			t.Fatalf("webhook_events.go compares signatures non-constant-time (%q)", banned)
		}
	}
}
