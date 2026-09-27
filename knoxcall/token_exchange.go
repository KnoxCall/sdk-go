package knoxcall

// OIDC workload federation — RFC 8693 token exchange against
// POST /v1/oauth/token (AIGW-26).
//
// Like Signup this is a standalone package function and NOT a method on the
// authenticated client, and for a stronger reason: the whole point is that CI
// holds no KnoxCall credential. Constructing a client to reach this endpoint
// would require the very secret the flow exists to remove.
//
//	res, err := knoxcall.ExchangeToken(ctx, knoxcall.ExchangeTokenInput{
//	    SubjectToken: githubActionsIDToken,
//	}, &knoxcall.ExchangeTokenOptions{Tenant: "acme"})
//	// res.AccessToken is an agent-kind capability token for POST /v1/ai/...
//
// Set Resource — the `resource` field of an MCP server's create/get response —
// to narrow the minted token to "tool" kind, confined to exactly that one
// /v1/mcp/<slug> and refused on /v1/ai.
//
// THE HOST MATTERS, and getting it wrong looks like a credential failure.
// /v1/oauth/token is part of the DATA plane: src/server.ts hands /v1/ai/,
// /v1/mcp/ and /v1/oauth/ to the proxy router only when the request lands on a
// tenant data-plane host ({slug}.knoxcall.com, sandbox-{slug}...). Verified
// against a running server on 2026-08-25: the same request answers 400
// invalid_grant on acme.knoxcall.com and 401 on api.knoxcall.com — a caller who
// points this at the management host reads that 401 as "my CI token was
// rejected" when the endpoint is simply not served there. So Tenant (or an
// explicit BaseURL) is REQUIRED: there is no safe default to guess.
//
// NOT the tenant OAuth 2.1 token endpoint at https://api.knoxcall.com/oauth/token
// (root host, no /v1), which mints kc_ MANAGEMENT tokens from client_credentials
// and friends. Sending a token-exchange grant there is unsupported_grant_type,
// and vice versa.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	// TokenExchangeGrant is the only grant_type POST /v1/oauth/token accepts.
	TokenExchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange"
	// IDTokenType is the only subject_token_type it accepts.
	IDTokenType = "urn:ietf:params:oauth:token-type:id_token"
	// KnoxCallAudience is the default (and only supported) audience.
	KnoxCallAudience = "knoxcall:gateway"
)

// A tenant slug becomes a hostname, so it must be a bare DNS label. This
// mirrors assertTenantSlug in client.go and exists for the same reason: a slug
// adopted from config or an environment variable that is not one ("evil.com#")
// would send the workload's OIDC token to an attacker-controlled host.
var exchangeTenantSlugRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ExchangeTokenInput is the RFC 8693 request.
type ExchangeTokenInput struct {
	// SubjectToken is the workload's OIDC id_token, JWS-compact. Its `iss`
	// must match an OIDC binding registered on the tenant, its signature must
	// verify against that issuer's published JWKS, and it must be unexpired.
	SubjectToken string
	// Resource is the RFC 8707 resource indicator — the `resource` field of an
	// MCP server's create/get response. Setting it narrows the minted token to
	// "tool" kind and binds the resource into its capability HMAC. Leave nil
	// for an "agent"-kind token.
	//
	// A POINTER, not a string, on purpose: an empty Resource must reach the
	// server and be refused invalid_target. Treating "" as absent would hand
	// back an UNCONFINED agent token to a caller who asked for a confined one.
	Resource *string
	// Audience defaults to KnoxCallAudience. Any other value is invalid_target.
	Audience string
}

// ExchangeTokenOptions selects the data-plane host and transport. One of
// Tenant or BaseURL is REQUIRED — see the package comment above.
type ExchangeTokenOptions struct {
	// Tenant is the tenant slug. It resolves to https://{tenant}.knoxcall.com,
	// or https://sandbox-{tenant}.knoxcall.com when Sandbox is set — the tenant
	// data-plane hosts, the only ones that serve this endpoint.
	Tenant string
	// Sandbox selects the Test data space. Ignored when BaseURL is set.
	Sandbox bool
	// BaseURL is the full data-plane origin. Wins over Tenant; required for a
	// self-hosted deployment.
	BaseURL string
	// HTTPClient overrides the default 30s-timeout client.
	HTTPClient *http.Client
}

// resolveExchangeBaseURL picks the data-plane origin. There is no default.
func resolveExchangeBaseURL(opts *ExchangeTokenOptions) (string, error) {
	if opts != nil && opts.BaseURL != "" {
		return strings.TrimRight(opts.BaseURL, "/"), nil
	}
	tenant := ""
	sandbox := false
	if opts != nil {
		tenant = opts.Tenant
		sandbox = opts.Sandbox
	}
	if tenant == "" {
		return "", &BootstrapError{Message: "ExchangeToken needs a Tenant slug or a BaseURL: " +
			"POST /v1/oauth/token is served only on the tenant data-plane host " +
			"(https://{tenant}.knoxcall.com). Pointing it at api.knoxcall.com answers 401, " +
			"which reads like a rejected subject_token but means the endpoint is not there."}
	}
	if !exchangeTenantSlugRE.MatchString(tenant) {
		return "", &BootstrapError{Message: fmt.Sprintf(
			"invalid tenant slug %q — expected a DNS label; refusing to send a subject token to a host derived from it",
			tenant)}
	}
	if sandbox {
		return "https://sandbox-" + tenant + ".knoxcall.com", nil
	}
	return "https://" + tenant + ".knoxcall.com", nil
}

// ExchangeTokenResponse is the RFC 8693 §2.2.1 body — a BARE OAuth response,
// not the {data, meta} envelope the rest of /v1 returns.
type ExchangeTokenResponse struct {
	// AccessToken is the capability token, returned ONCE.
	AccessToken string `json:"access_token"`
	// IssuedTokenType is always urn:ietf:params:oauth:token-type:access_token.
	IssuedTokenType string `json:"issued_token_type"`
	// TokenType is always "Bearer".
	TokenType string `json:"token_type"`
	// ExpiresIn is the lifetime in seconds (server default 900).
	ExpiresIn int `json:"expires_in"`
	// Scope is the capability scope JSON-encoded, for visibility only. The
	// source of truth is the capability HMAC bound into the token.
	Scope string `json:"scope"`
}

// TokenExchangeError is returned when POST /v1/oauth/token refuses. It unwraps
// to *APIError, and Message carries the RFC 6749 §5.2 code (invalid_grant,
// invalid_target, unsupported_grant_type, invalid_request, server_error).
type TokenExchangeError struct{ APIError }

func (e *TokenExchangeError) Unwrap() error { return &e.APIError }

// ExchangeToken trades a CI OIDC token for a short-lived AI-gateway capability
// token.
//
// It requires no constructed client and no KnoxCall credential: SubjectToken IS
// the credential, verified against the issuer's published JWKS. Failures return
// a *TokenExchangeError; transport failures map to the SDK's connection-error
// types.
func ExchangeToken(ctx context.Context, input ExchangeTokenInput, opts *ExchangeTokenOptions) (*ExchangeTokenResponse, error) {
	baseURL, err := resolveExchangeBaseURL(opts)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if opts != nil && opts.HTTPClient != nil {
		hc = opts.HTTPClient
	}

	// the request carries the workload OIDC id_token, which IS a credential -- the
	// whole point of the flow. PARITY 15 already warns when a CLIENT is constructed
	// against plaintext http to a non-loopback host, and this function deliberately
	// constructs no client, so without this the control exists on one path and is
	// simply absent on the parallel one. A warning rather than a refusal because the
	// acceptance harness and local dev legitimately use http://127.0.0.1.
	if isInsecureRemoteURL(baseURL) {
		warnOnce("KNOXCALL_INSECURE_TRANSPORT", fmt.Sprintf(
			"KnoxCall: exchanging a workload OIDC token over plaintext HTTP to %s — the subject "+
				"token is a credential and is readable on the wire. Use https://.", baseURL))
	}

	audience := input.Audience
	if audience == "" {
		audience = KnoxCallAudience
	}
	form := map[string]string{
		"grant_type":         TokenExchangeGrant,
		"subject_token":      input.SubjectToken,
		"subject_token_type": IDTokenType,
		"audience":           audience,
	}
	if input.Resource != nil {
		form["resource"] = *input.Resource
	}

	payload, marshalErr := json.Marshal(form)
	if marshalErr != nil {
		return nil, marshalErr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/oauth/token", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	// Deliberately NO Authorization header: the subject token is the credential.

	res, err := hc.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, wrapTransportError(err)
	}

	var out struct {
		ExchangeTokenResponse
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	// Best effort: a non-JSON error page (a proxy 502) keeps zero values and
	// falls through to the status check rather than masking the status.
	_ = json.Unmarshal(body, &out)

	if res.StatusCode >= 400 || out.AccessToken == "" {
		// AIGW-163: this endpoint is on the TENANT DATA PLANE, so when the AI
		// gateway has failed to boot it is answered by the plane's 503 sentinel
		// — the data-plane envelope with code "ai_gateway_unavailable" and a
		// Retry-After — not by an RFC 6749 error. Typing it means a CI job is
		// told to wait rather than handed a generic exchange failure. The
		// discriminator is exact: an RFC 6749 body carries no `code` at all.
		if aiErr := AIGatewayErrorFrom(res.StatusCode, body, res.Header); aiErr != nil {
			return nil, aiErr
		}
		code := out.Error
		if code == "" {
			code = "token_exchange_failed"
		}
		detail := out.ErrorDescription
		if detail == "" {
			detail = "token exchange failed"
		}
		return nil, &TokenExchangeError{APIError{
			StatusCode: res.StatusCode,
			Message:    code,
			Detail:     detail,
		}}
	}
	r := out.ExchangeTokenResponse
	return &r, nil
}
