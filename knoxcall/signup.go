package knoxcall

// Headless signup — the one /v1 surface that needs no credentials, so these
// are standalone package functions rather than resources on the authenticated
// client.
//
// TWO steps since 2026-08-28 (founder decision F-25). Signup never returns a
// credential: it returns a claim handle and emails a sign-in link, and the
// starter key is minted when that link has been clicked and the claim is
// collected.
//
//	accepted, err := knoxcall.Signup(ctx, knoxcall.SignupInput{
//	    Email: "dev@example.com", TenantName: "Acme Inc",
//	}, nil)
//	// …the account owner clicks the emailed sign-in link…
//	claim, err := knoxcall.ClaimSignup(ctx, accepted.ClaimHandle, nil)
//	for claim.Status == "pending" {
//	    time.Sleep(time.Duration(accepted.PollAfterSeconds) * time.Second)
//	    claim, err = knoxcall.ClaimSignup(ctx, accepted.ClaimHandle, nil)
//	}
//	// claim.Starter.APIKey.APIKey is shown exactly once — store it now.
//	client, err := knoxcall.New(knoxcall.Options{
//	    APIKey: claim.Starter.APIKey.APIKey, Sandbox: true,
//	})

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultSignupBaseURL = "https://api.knoxcall.com"

// SignupInput is the POST /v1/signup request.
type SignupInput struct {
	// Email is the account owner's address; it receives the verification
	// magic link.
	Email string `json:"email"`
	// TenantName is the company or team name.
	TenantName string `json:"tenant_name"`
	// FullName is the owner's full name (defaults to the tenant name).
	FullName string `json:"full_name,omitempty"`
	// TenantSlug is the desired subdomain ({slug}.knoxcall.com). Omit to
	// have one derived from TenantName automatically — recommended for
	// headless callers, the server converges on an available slug.
	TenantSlug string `json:"tenant_slug,omitempty"`
	// Country is an ISO 3166-1 alpha-2 code; derives the data region when
	// Region is omitted.
	Country string `json:"country,omitempty"`
	// Region is the explicit data region ("us" | "eu" | "au"). Immutable
	// after signup.
	Region string `json:"region,omitempty"`
}

// SignupOptions overrides Signup's defaults.
type SignupOptions struct {
	// BaseURL overrides https://api.knoxcall.com.
	BaseURL string
	// HTTPClient overrides the default 30s-timeout client.
	HTTPClient *http.Client
}

// SignupResponse is the 202 every signup gets — identical whether or not the
// address already has an account, which is what makes the call
// enumeration-safe. It carries no credential of any kind.
type SignupResponse struct {
	// Status is always "pending".
	Status string `json:"status"`
	// ClaimHandle is opaque and single-use. Treat it as a secret: it is
	// what collects the starter credential once the emailed sign-in link
	// has been clicked.
	ClaimHandle string `json:"claim_handle"`
	// ClaimPath is the path to poll on the same host ("/v1/signup/claim").
	ClaimPath string `json:"claim_path"`
	// PollAfterSeconds is the suggested delay between polls.
	PollAfterSeconds int `json:"poll_after_seconds"`
	// ExpiresAt is when the handle stops being accepted; after it, the
	// handle is rejected exactly like an unknown one.
	ExpiresAt     string `json:"expires_at"`
	Message       string `json:"message"`
	Documentation string `json:"documentation"`
}

// SignupClaimResponse is POST /v1/signup/claim. Status discriminates:
// "pending" (a 202, and a normal SUCCESS — the sign-in link has not been used
// yet) leaves Tenant/Starter/Sandbox nil; "ready" (the 200, returned exactly
// once) populates them.
type SignupClaimResponse struct {
	Status string `json:"status"`

	// Set on the pending path.
	Message          string `json:"message"`
	PollAfterSeconds int    `json:"poll_after_seconds"`
	ExpiresAt        string `json:"expires_at"`

	// Set on the ready path.
	Tenant *SignupTenant `json:"tenant"`
	// Starter is the seeded Test-mode demo route + one-time test API key.
	Starter       *SignupStarter `json:"starter"`
	Sandbox       *SignupSandbox `json:"sandbox"`
	Documentation string         `json:"documentation"`
}

// SignupTenant identifies the created tenant.
type SignupTenant struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Region string `json:"region"`
	Plan   string `json:"plan"`
}

// SignupStarter is the seeded starter kit.
type SignupStarter struct {
	// Route is nil when the demo route could not be found for the tenant.
	Route       *SignupStarterRoute `json:"route"`
	APIKey      SignupStarterAPIKey `json:"api_key"`
	SandboxHost string              `json:"sandbox_host"`
	// Curl is a ready-to-run command that exercises the demo route.
	Curl string `json:"curl"`
}

// SignupStarterRoute is the seeded demo route.
type SignupStarterRoute struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	TargetBaseURL string `json:"target_base_url"`
}

// SignupStarterAPIKey is the seeded test key. APIKey is the plaintext key —
// only ever present in this response.
type SignupStarterAPIKey struct {
	ID        string `json:"id"`
	KeyID     string `json:"key_id"`
	APIKey    string `json:"api_key"`
	KeyPrefix string `json:"key_prefix"`
	KeyType   string `json:"key_type"` // "test"
}

// SignupSandbox points at the Test-mode surfaces usable immediately.
type SignupSandbox struct {
	ManagementAPI string `json:"management_api"`
	ProxyHost     string `json:"proxy_host"`
	Note          string `json:"note"`
}

// Signup starts creating a KnoxCall account. It always answers 202 with an
// opaque claim handle and emails a sign-in link — no account, tenant or
// credential exists until that link is clicked. Collect the starter kit
// afterwards with ClaimSignup. Rate limited to 3 signups/hour/IP.
//
// Enumeration-safe: the reply is identical for an address that already has an
// account (it receives a sign-in link and a handle that stays pending).
//
// It requires no constructed client and no credentials. Failures return a
// *SignupError (which unwraps to *APIError); transport failures map to the
// SDK's connection-error types.
func Signup(ctx context.Context, input SignupInput, opts *SignupOptions) (*SignupResponse, error) {
	var out SignupResponse
	if err := signupPost(ctx, "/v1/signup", input, opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ClaimSignup polls a claim handle returned by Signup. It returns
// Status=="pending" until the emailed sign-in link has been clicked, then once
// returns Status=="ready" with the tenant and a one-time Test-mode API key.
// Polling again after that returns a *SignupError with StatusCode 409; an
// unknown or expired handle returns one with 404.
//
// Do not poll faster than the PollAfterSeconds that Signup returned.
func ClaimSignup(ctx context.Context, claimHandle string, opts *SignupOptions) (*SignupClaimResponse, error) {
	var out SignupClaimResponse
	body := struct {
		ClaimHandle string `json:"claim_handle"`
	}{ClaimHandle: claimHandle}
	if err := signupPost(ctx, "/v1/signup/claim", body, opts, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// signupPost is the shared credential-less POST. Note what it does NOT treat
// as an error: a 202. Both endpoints use it for a normal, credential-less
// success, so anything below 400 carrying a data object is decoded and
// returned.
func signupPost(ctx context.Context, path string, input any, opts *SignupOptions, out any) error {
	baseURL := defaultSignupBaseURL
	hc := &http.Client{Timeout: 30 * time.Second}
	if opts != nil {
		if opts.BaseURL != "" {
			baseURL = strings.TrimRight(opts.BaseURL, "/")
		}
		if opts.HTTPClient != nil {
			hc = opts.HTTPClient
		}
	}

	payload, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	res, err := hc.Do(req)
	if err != nil {
		return wrapTransportError(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return wrapTransportError(err)
	}

	var env struct {
		Data  json.RawMessage `json:"data"`
		Error struct {
			Type      string `json:"type"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env) // best effort; non-JSON keeps zero values

	if res.StatusCode >= 400 || len(env.Data) == 0 {
		msg := env.Error.Message
		if msg == "" {
			msg = "signup failed"
		}
		return &SignupError{APIError{
			StatusCode: res.StatusCode,
			Message:    env.Error.Type,
			Detail:     msg,
			RequestID:  env.Error.RequestID,
		}}
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return &SignupError{APIError{
			StatusCode: res.StatusCode,
			Message:    "invalid_response",
			Detail:     "signup response could not be decoded",
			RequestID:  env.Error.RequestID,
		}}
	}
	return nil
}
