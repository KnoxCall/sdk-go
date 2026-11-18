// Shared CLI plumbing — thin adapters over internal/clilogin, the single
// source of truth for the login flow (auth-code+PKCE loopback / device code /
// profile persistence). The same flow backs the library-level
// knoxcall.Login / knoxcall.EnsureLogin helpers, so it is never duplicated.
package main

import (
	"context"
	"net/url"
	"time"

	"github.com/knoxcall/sdk-go/internal/clilogin"
)

// cliClientID is the reserved alias accepted by /oauth/authorize and the
// device endpoints; the server lazily provisions the tenant's real CLI client
// and returns its id as the `client_id` extension member on the token response.
const cliClientID = clilogin.CLIClientID

// flow binds this app's injected dependencies (output writer, HTTP client,
// sleeper, browser launcher) to a clilogin.Flow so the CLI shares the one flow
// implementation.
func (a *app) flow() *clilogin.Flow {
	return &clilogin.Flow{
		Stdout:      a.stdout,
		HTTP:        a.http,
		Sleep:       a.sleep,
		OpenBrowser: a.openBrowser,
	}
}

// generatePKCEPair returns (code_verifier, code_challenge) — S256, unpadded
// base64url.
func generatePKCEPair() (verifier, challenge string, err error) {
	return clilogin.GeneratePKCEPair()
}

// buildAuthorizeURL constructs the /oauth/authorize URL for the auth-code flow.
func buildAuthorizeURL(baseURL, redirectURI, state, codeChallenge, tenant string) string {
	return clilogin.BuildAuthorizeURL(baseURL, redirectURI, state, codeChallenge, tenant)
}

// authCodeFlow runs the authorization-code + PKCE loopback flow.
func (a *app) authCodeFlow(ctx context.Context, baseURL, tenant string, timeout time.Duration) (map[string]any, error) {
	return a.flow().AuthCode(ctx, baseURL, tenant, timeout)
}

// deviceFlow runs the RFC 8628 device-code flow.
func (a *app) deviceFlow(ctx context.Context, baseURL string) (map[string]any, error) {
	return a.flow().Device(ctx, baseURL)
}

// pollDeviceToken polls the token endpoint per RFC 8628 §3.5.
func (a *app) pollDeviceToken(ctx context.Context, baseURL, deviceCode string, interval, expiresIn time.Duration) (map[string]any, error) {
	return a.flow().PollDeviceToken(ctx, baseURL, deviceCode, interval, expiresIn)
}

// postForm POSTs a urlencoded form (best-effort revoke, token exchange, …).
func (a *app) postForm(ctx context.Context, urlStr string, form url.Values) (int, map[string]any, error) {
	return a.flow().PostForm(ctx, urlStr, form)
}

// persistLogin stores a successful token response as a credentials-file
// profile UNDER THE FILE LOCK.
func persistLogin(ctx context.Context, path, profile, baseURL string, tokenBody map[string]any, fallbackTenant string) (map[string]any, error) {
	return clilogin.PersistLogin(ctx, path, profile, baseURL, tokenBody, fallbackTenant)
}

// strVal returns m[key] as a string ("" for missing / non-string values).
func strVal(m map[string]any, key string) string { return clilogin.StrVal(m, key) }
