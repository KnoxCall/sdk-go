package knoxcall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
)

// APIError is returned when the KnoxCall API responds with a 4xx or 5xx
// status. Specific statuses are returned as typed wrappers
// (AuthenticationError, PermissionDeniedError, NotFoundError, ConflictError,
// ValidationError, RateLimitError, ServerError); all of them unwrap to
// *APIError, so errors.As(err, &apiErr) matches any API error generically.
type APIError struct {
	StatusCode  int
	Message     string `json:"error"`             // machine-readable error code
	Detail      string `json:"message"`           // human-readable message
	Description string `json:"error_description"` // OAuth-style description
	RequestID   string `json:"-"`
}

func (e *APIError) Error() string {
	msg := e.Description
	if msg == "" {
		msg = e.Detail
	}
	if msg == "" {
		msg = e.Message
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("knoxcall: API error %d: %s", e.StatusCode, msg)
}

// AuthenticationError is returned on HTTP 401.
type AuthenticationError struct{ APIError }

func (e *AuthenticationError) Unwrap() error { return &e.APIError }

// PaymentRequiredError is returned on HTTP 402 — a plan/billing limit was hit.
// Two error codes share this status: "plan_limit" (a counted quota was reached)
// and "plan_feature" (the capability itself is not on the tier). The mapping is
// on STATUS, so both land here. Distinct from PermissionDeniedError (403) so
// a caller can show an "upgrade" prompt rather than an "access denied" one.
type PaymentRequiredError struct{ APIError }

func (e *PaymentRequiredError) Unwrap() error { return &e.APIError }

// PermissionDeniedError is returned on HTTP 403.
type PermissionDeniedError struct{ APIError }

func (e *PermissionDeniedError) Unwrap() error { return &e.APIError }

// NotFoundError is returned on HTTP 404.
type NotFoundError struct{ APIError }

func (e *NotFoundError) Unwrap() error { return &e.APIError }

// ConflictError is returned on HTTP 409. Conflicts are never retried — a
// real conflict does not resolve by replaying the request.
type ConflictError struct{ APIError }

func (e *ConflictError) Unwrap() error { return &e.APIError }

// ValidationError is returned on HTTP 422.
type ValidationError struct {
	APIError
	Fields map[string][]string
}

func (e *ValidationError) Unwrap() error { return &e.APIError }

// RateLimitError is returned on HTTP 429. RetryAfter is the server's
// Retry-After header in seconds (0 when absent).
type RateLimitError struct {
	APIError
	RetryAfter int
}

func (e *RateLimitError) Unwrap() error { return &e.APIError }

// ServerError is returned on HTTP 5xx. RetryAfter is the server's Retry-After
// header in seconds (0 when absent): a 503 `dependency_unavailable` — KnoxCall
// could not reach one of its own dependencies in time and did not serve the
// request — sends one, and the retry loop honours it exactly as a 429's
// (PARITY §4). A plain 5xx keeps the jittered backoff.
type ServerError struct {
	APIError
	RetryAfter int
}

func (e *ServerError) Unwrap() error { return &e.APIError }

// AIGatewayError is a refusal from the AI **data plane**
// (POST {agent_url}/…), typed.
//
// WHY IT IS ITS OWN TYPE. The data plane is not the Management API: it answers
// {error, error_description, code} with the machine-readable code in BOTH
// error and code (AIGW-163), while the management plane answers the nested
// {"error":{"type","message","request_id"}}. A Code of "budget_exceeded" and a
// Code of "not_found" come from different contracts, and the status alone
// cannot tell them apart.
//
// The SDK does not make the data-plane call for you — that is the design: you
// point an existing provider client at the agent's AgentURL and it works
// unchanged. So this type is paired with AIGatewayErrorFrom, which types
// whatever that client hands back.
//
// It embeds APIError like every other typed error here, so
// errors.As(err, &apiErr) still matches (sdk/PARITY.md §1).
type AIGatewayError struct {
	APIError
	// Code is the stable identifier. Branch on this, never on the description.
	Code string
	// ErrorDescription is the human sentence. Rewritten whenever a clearer
	// wording is found.
	ErrorDescription string
	// RetryAfter is whole seconds from the Retry-After header, 0 when absent.
	//
	// Absence is meaningful: the gateway sends no header rather than a guess,
	// so 0 means "back off on your own schedule", never "retry immediately".
	RetryAfter int
}

func (e *AIGatewayError) Unwrap() error { return &e.APIError }

// aiGatewayErrorBody is the data plane's envelope. Both string fields must be
// present AND equal — the pre-AIGW-163 auth shape had a `code` that was not the
// `error`, and accepting it would make Code mean two things again.
type aiGatewayErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Code             string `json:"code"`
	RequestID        string `json:"request_id"`
}

// IsAIGatewayErrorBody reports whether body is the AI data plane's envelope.
func IsAIGatewayErrorBody(body []byte) bool {
	var b aiGatewayErrorBody
	if json.Unmarshal(body, &b) != nil {
		return false
	}
	return b.Error != "" && b.Code != "" && b.ErrorDescription != "" && b.Error == b.Code
}

// AIGatewayErrorFrom types a refusal a provider client received from an agent's
// data-plane URL.
//
// Returns nil when body is not the data plane's envelope, so a caller falls
// through to its own handling rather than being handed a mislabelled error:
//
//	res, _ := http.Post(agent.AgentURL+"/v1/messages", "application/json", payload)
//	if res.StatusCode >= 400 {
//	    raw, _ := io.ReadAll(res.Body)
//	    if e := knoxcall.AIGatewayErrorFrom(res.StatusCode, raw, res.Header); e != nil {
//	        if e.Code == "budget_exceeded" {
//	            time.Sleep(time.Duration(max(e.RetryAfter, 60)) * time.Second)
//	        }
//	        return e
//	    }
//	}
//
// header may be nil.
func AIGatewayErrorFrom(status int, body []byte, header http.Header) *AIGatewayError {
	var b aiGatewayErrorBody
	if json.Unmarshal(body, &b) != nil {
		return nil
	}
	if b.Error == "" || b.Code == "" || b.ErrorDescription == "" || b.Error != b.Code {
		return nil
	}
	retryAfter := 0
	requestID := b.RequestID
	if header != nil {
		// Atoi fails on an HTTP-date Retry-After, which is legal but is not
		// delta-seconds; 0 (absent) is the right reading of one we cannot use.
		if n, err := strconv.Atoi(strings.TrimSpace(header.Get("Retry-After"))); err == nil && n > 0 {
			retryAfter = n
		}
		if rid := header.Get("X-Request-Id"); rid != "" {
			requestID = rid
		}
	}
	return &AIGatewayError{
		APIError: APIError{
			StatusCode:  status,
			Message:     b.Code,
			Detail:      b.ErrorDescription,
			Description: b.ErrorDescription,
			RequestID:   requestID,
		},
		Code:             b.Code,
		ErrorDescription: b.ErrorDescription,
		RetryAfter:       retryAfter,
	}
}

// WebhookSignatureVerificationError is returned by ConstructWebhookEvent /
// WebhooksResource.ConstructEvent when a webhook delivery fails verification
// (missing signature header, signature mismatch, stale timestamp, or a body
// that is not valid JSON). Reason says what failed — it never echoes the
// signature or the secret.
type WebhookSignatureVerificationError struct {
	Reason string
}

func (e *WebhookSignatureVerificationError) Error() string {
	return "knoxcall: webhook signature verification failed: " + e.Reason
}

// SignupError is returned when Signup (POST /v1/signup) fails. It unwraps to
// *APIError like every other API error, so errors.As(err, &apiErr) matches:
// StatusCode carries the HTTP status, Message the machine-readable error
// type (e.g. "slug_taken"), and Detail the human-readable message.
type SignupError struct{ APIError }

func (e *SignupError) Unwrap() error { return &e.APIError }

// BootstrapError is returned for credential-bootstrap problems detected
// without (or before) any HTTP round-trip: a tenant slug that is not a valid
// DNS label (see assertTenantSlug), or — as its NotAuthenticatedError subtype
// — no usable credential at all. It is distinct from *APIError (which always
// carries an HTTP status). This is the Go analog of node's BootstrapError
// (src/error.ts); PARITY §1/§2.
type BootstrapError struct{ Message string }

func (e *BootstrapError) Error() string { return e.Message }

// NotAuthenticatedError is returned by credential auto-detection when NO
// credential is found (no explicit creds, env token/keys, credentials file, or
// cloud OIDC), and by the interactive Login/EnsureLogin helpers when they
// refuse to prompt. It embeds BootstrapError and unwraps to *BootstrapError, so
// a generic errors.As(err, &bootErr) still catches it (the Go equivalent of
// node subclassing BootstrapError), while callers can branch specifically on
// "not logged in — offer Login()" with errors.As(err, &notAuthErr). PARITY §1.
type NotAuthenticatedError struct{ BootstrapError }

func (e *NotAuthenticatedError) Unwrap() error { return &e.BootstrapError }

// notAuthenticated builds a *NotAuthenticatedError carrying msg.
func notAuthenticated(msg string) *NotAuthenticatedError {
	return &NotAuthenticatedError{BootstrapError{Message: msg}}
}

// ConnectionError wraps a transport-level failure (DNS, dial, TLS, reset,
// …) so callers never have to match on net/http internals. The underlying
// error is available via errors.Unwrap / errors.Is / errors.As.
type ConnectionError struct{ Err error }

func (e *ConnectionError) Error() string { return "knoxcall: connection error: " + e.Err.Error() }
func (e *ConnectionError) Unwrap() error { return e.Err }

// ConnectionTimeoutError is a ConnectionError caused by a timeout
// (connect/read deadline or context deadline).
type ConnectionTimeoutError struct{ ConnectionError }

func (e *ConnectionTimeoutError) Unwrap() error { return &e.ConnectionError }

// errorFromResponse maps an HTTP error status + body to a typed error.
// Non-JSON bodies (e.g. HTML from an edge proxy) are tolerated. Both server
// error shapes are understood: the /v1 envelope
// {"error": {"type", "message", "request_id"}} and the flat OAuth-style
// {"error": "...", "error_description": "..."}.
func errorFromResponse(status int, body []byte, header http.Header) error {
	var ae APIError
	if len(body) > 0 {
		_ = json.Unmarshal(body, &ae) // best effort; non-JSON keeps zero values
		var env struct {
			Error struct {
				Type      string `json:"type"`
				Message   string `json:"message"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &env) == nil && (env.Error.Type != "" || env.Error.Message != "") {
			ae.Message = env.Error.Type
			ae.Detail = env.Error.Message
			if ae.RequestID == "" {
				ae.RequestID = env.Error.RequestID
			}
		}
	}
	// AIGW-163: the AI data plane sends the code in BOTH `error` and `code`.
	// Prefer the explicit `code` — a future surface could carry one that is not
	// mirrored, and reading the mirror would silently lose it.
	if len(body) > 0 {
		var withCode struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(body, &withCode) == nil && withCode.Code != "" && ae.Message == "" {
			ae.Message = withCode.Code
		}
	}
	ae.StatusCode = status
	if rid := header.Get("X-Request-Id"); rid != "" {
		ae.RequestID = rid
	}

	switch {
	case status == 401:
		return &AuthenticationError{ae}
	case status == 402:
		return &PaymentRequiredError{ae}
	case status == 403:
		return &PermissionDeniedError{ae}
	case status == 404:
		return &NotFoundError{ae}
	case status == 409:
		return &ConflictError{ae}
	case status == 422:
		var v struct {
			Fields map[string][]string `json:"fields"`
		}
		_ = json.Unmarshal(body, &v)
		return &ValidationError{APIError: ae, Fields: v.Fields}
	case status == 429:
		ra, _ := strconv.Atoi(header.Get("Retry-After"))
		return &RateLimitError{APIError: ae, RetryAfter: ra}
	case status >= 500:
		ra, _ := strconv.Atoi(strings.TrimSpace(header.Get("Retry-After")))
		return &ServerError{APIError: ae, RetryAfter: ra}
	}
	return &ae
}

// statusOf returns the HTTP status of any SDK API error (0 otherwise).
func statusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode
	}
	return 0
}

// wrapTransportError maps a raw net/http transport failure to the SDK's
// connection-error types.
func wrapTransportError(err error) error {
	var ne net.Error
	if (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
		return &ConnectionTimeoutError{ConnectionError{Err: err}}
	}
	return &ConnectionError{Err: err}
}

// isConnectError reports whether the failure happened while establishing the
// connection — i.e. the request never left the machine, so replaying it is
// always safe, even for mutating methods.
func isConnectError(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}
