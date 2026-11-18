package knoxcall

// AIGW-163 — the AI DATA plane's typed refusal.
//
// The SDK deliberately does not make the data-plane call for you: you point an
// existing provider client at the agent's AgentURL. So what the SDK owes you is
// the ability to TYPE what that client hands back — a
// {error, error_description, code} body, which is NOT the Management API's
// {"error":{"type","message","request_id"}} and must not be mistaken for it.

import (
	"errors"
	"net/http"
	"testing"
)

const aiRefusal = `{"error":"budget_exceeded","error_description":"Daily budget exceeded: $50.0031 >= $50","code":"budget_exceeded","utilization_pct":100.006}`

func TestAIGatewayErrorFrom_TypedFields(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "3600")
	h.Set("X-Request-Id", "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35")

	err := AIGatewayErrorFrom(429, []byte(aiRefusal), h)
	if err == nil {
		t.Fatal("expected a typed AI gateway error")
	}
	if err.Code != "budget_exceeded" {
		t.Fatalf("Code = %q, want budget_exceeded", err.Code)
	}
	if err.StatusCode != 429 {
		t.Fatalf("StatusCode = %d, want 429", err.StatusCode)
	}
	if err.RetryAfter != 3600 {
		t.Fatalf("RetryAfter = %d, want 3600", err.RetryAfter)
	}
	if err.ErrorDescription != "Daily budget exceeded: $50.0031 >= $50" {
		t.Fatalf("ErrorDescription = %q", err.ErrorDescription)
	}
	if err.RequestID != "0d5b2a9e-1f3c-4a7d-8e2b-6c9a1f4d7e35" {
		t.Fatalf("RequestID = %q", err.RequestID)
	}
}

func TestAIGatewayError_UnwrapsToAPIError(t *testing.T) {
	// PARITY §1: every new typed error is re-parented into the hierarchy, so a
	// generic errors.As(err, &apiErr) still matches.
	var err error = AIGatewayErrorFrom(403,
		[]byte(`{"error":"model_not_allowed","error_description":"not on the allowlist","code":"model_not_allowed"}`), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("AIGatewayError must unwrap to *APIError")
	}
	if apiErr.StatusCode != 403 {
		t.Fatalf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
}

func TestAIGatewayErrorFrom_RetryAfterAbsentOrUnusable(t *testing.T) {
	// Absence is meaningful: the gateway sends no header rather than a guess, so
	// 0 must mean "back off on your own schedule", not "retry immediately".
	if e := AIGatewayErrorFrom(429, []byte(aiRefusal), nil); e.RetryAfter != 0 {
		t.Fatalf("no header: RetryAfter = %d, want 0", e.RetryAfter)
	}
	h := http.Header{}
	// An HTTP-date Retry-After is legal but is not delta-seconds.
	h.Set("Retry-After", "Wed, 09 Sep 2026 00:00:00 GMT")
	if e := AIGatewayErrorFrom(429, []byte(aiRefusal), h); e.RetryAfter != 0 {
		t.Fatalf("http-date: RetryAfter = %d, want 0", e.RetryAfter)
	}
}

func TestAIGatewayErrorFrom_RejectsOtherEnvelopes(t *testing.T) {
	cases := map[string]string{
		// The nested shape every other /v1 resource answers. Typing it as an AI
		// refusal would put a control-plane not_found in the same branch as a
		// data-plane budget refusal.
		"management": `{"error":{"type":"not_found","message":"Gateway not found."}}`,
		// RFC 6749 §5.2 — no `code` at all.
		"oauth": `{"error":"invalid_grant","error_description":"bad subject token"}`,
		// The pre-AIGW-163 auth shape: a `code` that is not the `error`.
		"legacyAuth": `{"error":"Unauthorized","code":"expired","reason":"Token has expired"}`,
		"notJSON":    `<html>502 Bad Gateway</html>`,
		"empty":      ``,
	}
	for name, body := range cases {
		if got := AIGatewayErrorFrom(400, []byte(body), nil); got != nil {
			t.Fatalf("%s: expected nil, got %+v", name, got)
		}
		if IsAIGatewayErrorBody([]byte(body)) {
			t.Fatalf("%s: IsAIGatewayErrorBody must be false", name)
		}
	}
	if !IsAIGatewayErrorBody([]byte(aiRefusal)) {
		t.Fatal("the real envelope must be recognised (anti-vacuity)")
	}
}
