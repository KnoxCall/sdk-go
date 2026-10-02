package knoxcall

// Webhook event construction (see ../../PARITY.md §12): verify a delivery's
// HMAC signature AND parse it into a typed event in one step. The boolean
// VerifySignature helper (client.go) remains for compatibility (default
// legacy format only); ConstructWebhookEvent is the primary API.
//
// Signature formats mirror the server's src/webhooks/hmac-formats.ts exactly.
// All formats are HMAC-SHA256 over a format-specific input, compared in
// constant time:
//
//	legacy   X-Webhook-Signature: sha256=<hex>          hmac(secret, body)
//	stripe   Stripe-Signature: t=<ts>,v1=<hex>          hmac(secret, "<ts>." + body)
//	github   X-Hub-Signature-256: sha256=<hex>          hmac(secret, body)
//	slack    X-Slack-Signature: v0=<hex>                hmac(secret, "v0:<ts>:" + body)
//	         X-Slack-Request-Timestamp: <ts>
//	aws-sns  x-amz-sns-signature: <base64>              hmac(secret, body)
//	custom   <caller-named header>: sha256=<hex>        hmac(secret, body)

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookEvent is a verified webhook delivery envelope:
//
//	{ "event", "timestamp", "webhook_id"?, "webhook_name"?, "data" }
//
// Event is an open set — unknown event types still parse (forward
// compatibility). Today's values: request.received, request.success,
// request.redirect, request.client_error, request.server_error,
// request.timeout, request.error, request.completed, audit.event.
// WebhookID/WebhookName are present on request.* events, absent on
// audit.event. Decode Data with RequestData() or AuditData().
type WebhookEvent struct {
	Event       string          `json:"event"`
	Timestamp   string          `json:"timestamp"`
	WebhookID   string          `json:"webhook_id"`
	WebhookName string          `json:"webhook_name"`
	Data        json.RawMessage `json:"data"`
}

// RequestEventData is the Data payload of the request.* event family.
type RequestEventData struct {
	RouteID     string               `json:"route_id"`
	RouteName   string               `json:"route_name"`
	Environment string               `json:"environment"`
	Request     RequestEventRequest  `json:"request"`
	Response    RequestEventResponse `json:"response"`
}

// RequestEventRequest describes the proxied request of a request.* event.
type RequestEventRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	IP     string `json:"ip"`
}

// RequestEventResponse describes the upstream response of a request.* event.
type RequestEventResponse struct {
	Status    int `json:"status"`
	LatencyMs int `json:"latency_ms"`
}

// AuditEventData is the Data payload of audit.event deliveries.
type AuditEventData struct {
	ID           string          `json:"id"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Details      json.RawMessage `json:"details"`
	IPAddress    string          `json:"ip_address"`
}

// RequestData decodes the event's Data as a request.* payload.
func (e *WebhookEvent) RequestData() (*RequestEventData, error) {
	var d RequestEventData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return nil, fmt.Errorf("knoxcall: decode request event data: %w", err)
	}
	return &d, nil
}

// AuditData decodes the event's Data as an audit.event payload.
func (e *WebhookEvent) AuditData() (*AuditEventData, error) {
	var d AuditEventData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return nil, fmt.Errorf("knoxcall: decode audit event data: %w", err)
	}
	return &d, nil
}

// ConstructEventOptions configures ConstructWebhookEvent.
type ConstructEventOptions struct {
	// Format is the webhook's configured hmac_format: "legacy" (default),
	// "stripe", "github", "slack", "aws-sns", or "custom".
	Format string
	// ToleranceSeconds is the replay window (default 300). For stripe/slack
	// the check runs against the signed header timestamp; for the other
	// formats against the parsed envelope's timestamp field. Point at 0 (or
	// a negative value) to disable timestamp checking entirely.
	ToleranceSeconds *int
	// HeaderName is the signature header — required when Format is
	// "custom", ignored otherwise.
	HeaderName string
}

// ConstructEvent verifies a webhook delivery and returns the typed event —
// see ConstructWebhookEvent.
func (r *WebhooksResource) ConstructEvent(rawBody []byte, headers http.Header, secret string, opts *ConstructEventOptions) (*WebhookEvent, error) {
	return ConstructWebhookEvent(rawBody, headers, secret, opts)
}

// ConstructWebhookEvent verifies a KnoxCall webhook delivery's HMAC-SHA256
// signature and parses the body into a typed WebhookEvent.
//
// rawBody must be the raw request bytes exactly as received (never
// re-serialized JSON); headers is the delivery's header map (http.Header
// lookups are case-insensitive); secret is the endpoint's signing secret
// (the once-only secret_key from webhook creation).
//
// On ANY failure — missing signature header, signature mismatch, stale
// timestamp, or a non-JSON body — it returns a
// *WebhookSignatureVerificationError and never a partially parsed event.
func ConstructWebhookEvent(rawBody []byte, headers http.Header, secret string, opts *ConstructEventOptions) (*WebhookEvent, error) {
	format := "legacy"
	tolerance := 300
	headerName := ""
	if opts != nil {
		if opts.Format != "" {
			format = opts.Format
		}
		if opts.ToleranceSeconds != nil {
			tolerance = *opts.ToleranceSeconds
			if tolerance < 0 {
				tolerance = 0 // explicit disable
			}
		}
		headerName = opts.HeaderName
	}

	// headerTs < 0 means the format carries no signed timestamp, so the
	// envelope's own timestamp field is checked instead (below).
	var headerTs int64 = -1

	switch format {
	case "legacy":
		if err := verifyHexSignature(headers.Get("X-Webhook-Signature"), "X-Webhook-Signature", secret, rawBody); err != nil {
			return nil, err
		}
	case "github":
		if err := verifyHexSignature(headers.Get("X-Hub-Signature-256"), "X-Hub-Signature-256", secret, rawBody); err != nil {
			return nil, err
		}
	case "custom":
		if headerName == "" {
			return nil, &WebhookSignatureVerificationError{Reason: `the "custom" format requires HeaderName`}
		}
		if err := verifyHexSignature(headers.Get(headerName), headerName, secret, rawBody); err != nil {
			return nil, err
		}
	case "aws-sns":
		sig := strings.TrimSpace(headers.Get("x-amz-sns-signature"))
		if sig == "" {
			return nil, &WebhookSignatureVerificationError{Reason: "missing x-amz-sns-signature header"}
		}
		expected := base64.StdEncoding.EncodeToString(hmacSHA256(secret, rawBody))
		if !hmac.Equal([]byte(expected), []byte(sig)) {
			return nil, &WebhookSignatureVerificationError{Reason: "signature mismatch"}
		}
	case "stripe":
		raw := headers.Get("Stripe-Signature")
		if raw == "" {
			return nil, &WebhookSignatureVerificationError{Reason: "missing Stripe-Signature header"}
		}
		ts := ""
		var sigs []string
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if v, ok := strings.CutPrefix(part, "t="); ok {
				ts = v
			} else if v, ok := strings.CutPrefix(part, "v1="); ok {
				sigs = append(sigs, v)
			}
		}
		if ts == "" || len(sigs) == 0 {
			return nil, &WebhookSignatureVerificationError{Reason: "malformed Stripe-Signature header (expected t=<ts>,v1=<sig>)"}
		}
		expected := hex.EncodeToString(hmacSHA256(secret, []byte(ts+"."), rawBody))
		// Multiple v1 entries are accepted — any match passes (mirrors
		// Stripe's own tolerance for rotated secrets). Every candidate is
		// compared so the loop's timing does not depend on which one matches.
		matched := false
		for _, sig := range sigs {
			if hmac.Equal([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(sig)))) {
				matched = true
			}
		}
		if !matched {
			return nil, &WebhookSignatureVerificationError{Reason: "signature mismatch"}
		}
		// The timestamp is already covered by the signature above; parse it
		// only to enforce the replay window. Skipped when tolerance is
		// disabled, so a valid delivery with a non-numeric t= still verifies
		// (matches the python/node references).
		if tolerance > 0 {
			t, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				return nil, &WebhookSignatureVerificationError{Reason: "malformed Stripe-Signature timestamp"}
			}
			headerTs = t
		}
	case "slack":
		sig := headers.Get("X-Slack-Signature")
		ts := strings.TrimSpace(headers.Get("X-Slack-Request-Timestamp"))
		if sig == "" || ts == "" {
			return nil, &WebhookSignatureVerificationError{Reason: "missing X-Slack-Signature or X-Slack-Request-Timestamp header"}
		}
		expected := hex.EncodeToString(hmacSHA256(secret, []byte("v0:"+ts+":"), rawBody))
		provided := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(sig, "v0=")))
		if !hmac.Equal([]byte(expected), []byte(provided)) {
			return nil, &WebhookSignatureVerificationError{Reason: "signature mismatch"}
		}
		// The timestamp is already covered by the signature above; parse it
		// only to enforce the replay window. Skipped when tolerance is
		// disabled (matches the python/node references).
		if tolerance > 0 {
			t, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				return nil, &WebhookSignatureVerificationError{Reason: "malformed X-Slack-Request-Timestamp header"}
			}
			headerTs = t
		}
	default:
		return nil, &WebhookSignatureVerificationError{Reason: fmt.Sprintf("unknown signature format %q", format)}
	}

	now := time.Now().Unix()
	if tolerance > 0 && headerTs >= 0 && abs(now-headerTs) > int64(tolerance) {
		return nil, &WebhookSignatureVerificationError{Reason: "timestamp outside the tolerance window"}
	}

	var ev WebhookEvent
	if err := json.Unmarshal(rawBody, &ev); err != nil {
		return nil, &WebhookSignatureVerificationError{Reason: "request body is not valid JSON"}
	}

	// Formats without a signed timestamp: enforce the replay window against
	// the parsed envelope's own timestamp field (skipped when tolerance is
	// explicitly disabled).
	if tolerance > 0 && headerTs < 0 {
		t, err := time.Parse(time.RFC3339, ev.Timestamp)
		if err != nil {
			return nil, &WebhookSignatureVerificationError{Reason: "delivery timestamp is missing or invalid"}
		}
		if abs(now-t.Unix()) > int64(tolerance) {
			return nil, &WebhookSignatureVerificationError{Reason: "timestamp outside the tolerance window"}
		}
	}
	return &ev, nil
}

// verifyHexSignature checks a `sha256=<hex>` (or bare hex) header value
// against the HMAC-SHA256 of the body, in constant time.
func verifyHexSignature(headerValue, header, secret string, body []byte) error {
	sig := strings.TrimSpace(headerValue)
	if sig == "" {
		return &WebhookSignatureVerificationError{Reason: "missing " + header + " header"}
	}
	sig = strings.ToLower(strings.TrimPrefix(sig, "sha256="))
	expected := hex.EncodeToString(hmacSHA256(secret, body))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return &WebhookSignatureVerificationError{Reason: "signature mismatch"}
	}
	return nil
}

func hmacSHA256(secret string, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}
