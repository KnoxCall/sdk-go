// Package knoxcall is the official Go SDK for the KnoxCall API.
//
//	client, err := knoxcall.New(knoxcall.Options{Tenant: "acme"})
//	routes, err := client.Routes.List(ctx, nil)
package knoxcall

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBase   = "https://api.knoxcall.com"
	sandboxAPIBase   = "https://sandbox.knoxcall.com"
	defaultCloudHost = "knoxcall.com"
	sdkVersion       = "1.1.0"
	userAgent        = "knoxcall-go/" + sdkVersion

	// defaultAPIVersion is the dated KnoxCall API version this SDK is built
	// against. Sent as the `KnoxCall-Version` header on every management
	// request so the SDK stays pinned to a known API shape even after the
	// server ships a newer default (see the server's
	// src/client-api/versioning.ts). Must be a version the server's registry
	// knows, or requests are rejected 400.
	defaultAPIVersion = "2026-08-05"

	// Refresh tokens this long before expiry — but never more than half the
	// token's lifetime, so short-lived tokens don't degrade into a token
	// fetch per request.
	refreshAheadWindow = 5 * time.Minute
	// A cached token inside the refresh-ahead window is still usable this
	// long before real expiry; used as a fallback when the token endpoint
	// is down.
	staleTokenMinRemaining = 10 * time.Second
	// Honor a server Retry-After up to this long; beyond it, fail fast so
	// callers can apply their own scheduling instead of blocking a worker.
	retryAfterCap = 30 * time.Second

	defaultRetryMaxAttempts = 3
	defaultRetryBaseDelay   = 100 * time.Millisecond
	defaultRetryMaxDelay    = 5 * time.Second
)

// tenantSlugRe matches a bare DNS label (case-insensitive), mirroring node
// core.ts TENANT_SLUG_RE. A tenant slug becomes a data-plane hostname
// (https://<slug>.knoxcall.com), so before it is interpolated into a host it
// MUST be a valid label — otherwise a hostile slug adopted from a token
// response, /v1/account, or the credentials file (e.g. "evil.com#") would
// misdirect the tenant's bearer token to an attacker-controlled host (PARITY §2).
var tenantSlugRe = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)$`)

// assertTenantSlug returns a typed *BootstrapError when tenant is not a bare
// DNS label, refusing to derive a data-plane host from it. Callers must check
// the error BEFORE interpolating the slug into a knoxcall.com hostname.
func assertTenantSlug(tenant string) error {
	if !tenantSlugRe.MatchString(tenant) {
		return &BootstrapError{Message: fmt.Sprintf(
			"knoxcall: invalid tenant slug %q — expected a DNS label; refusing to derive a data-plane host from it",
			tenant,
		)}
	}
	return nil
}

// Options configures a KnoxCall client.
type Options struct {
	// Tenant slug. Falls back to the KNOXCALL_TENANT environment variable.
	Tenant string
	// Environment is the default x-knoxcall-environment for data-plane
	// calls. Falls back to the KNOXCALL_ENVIRONMENT environment variable;
	// per-call CallOptions.Environment and bound-route defaults win.
	Environment string
	// APIKey or client credentials for machine-to-machine auth.
	APIKey       string
	ClientID     string
	ClientSecret string
	// Credentials explicitly sets the bootstrap credential used to mint
	// access tokens (ClientCredentials, AccessToken, OIDCTokenExchange).
	// Mutually exclusive with APIKey / ClientID+ClientSecret — combining
	// them is a construction error.
	Credentials Credentials
	// Override the admin API base URL (default: https://api.knoxcall.com;
	// env: KNOXCALL_BASE_URL, with KNOXCALL_API_BASE_URL as a legacy alias —
	// the canonical name wins when both are set).
	BaseURL string
	// Override the proxy base URL (default: derived from tenant).
	ProxyBaseURL string
	// Sandbox / test mode. When true, defaults BaseURL to
	// https://sandbox.knoxcall.com and ProxyBaseURL to
	// https://sandbox-{tenant}.knoxcall.com — the Stripe-style isolated
	// test environment. Requires a tk_test_ API key. Ignored when an
	// explicit BaseURL is provided.
	Sandbox bool
	// HTTP client to use (default: http.DefaultClient with 30s timeout).
	HTTPClient *http.Client
	// Retry tuning. RetryMaxAttempts counts total attempts (default 3);
	// backoff is exponential with half-jitter from RetryBaseDelay
	// (default 100ms) capped at RetryMaxDelay (default 5s).
	RetryMaxAttempts int
	RetryBaseDelay   time.Duration
	RetryMaxDelay    time.Duration
	// JSONMarshal overrides request-body serialization (caller-supplied
	// encoder hook). Defaults to encoding/json.Marshal, which already
	// covers time.Time and json.Marshaler implementations.
	JSONMarshal func(v any) ([]byte, error)
	// DPoP controls RFC 9449 proof-of-possession token binding: "auto"
	// (default — start Bearer; when the token endpoint answers
	// invalid_dpop_proof because the oauth client requires DPoP, generate a
	// keypair and retry once, operating as DPoP thereafter), "always"
	// (generate the keypair at construction), or "never".
	DPoP string
	// Scope requests specific OAuth scopes on the client_credentials /
	// token-exchange grant. Sent space-joined as the `scope` form field
	// (RFC 6749 §3.3); empty requests the credential's full authorized scope.
	// A client's token cache is per-instance, so scope needs no cache keying
	// here (unlike the shared token stores in the python/node SDKs).
	Scope []string
}

// String implements fmt.Stringer, redacting APIKey and ClientSecret so that
// logging an Options value (%v / %+v) never leaks credentials.
func (o Options) String() string {
	return fmt.Sprintf(
		"knoxcall.Options{Tenant:%q, APIKey:%s, ClientID:%q, ClientSecret:%s, Credentials:%v, BaseURL:%q, ProxyBaseURL:%q, Sandbox:%t}",
		o.Tenant, redactIfSet(o.APIKey), o.ClientID, redactIfSet(o.ClientSecret),
		o.Credentials, o.BaseURL, o.ProxyBaseURL, o.Sandbox,
	)
}

// GoString implements fmt.GoStringer, redacting credentials from %#v.
func (o Options) GoString() string { return o.String() }

// Client is the KnoxCall API client. Use New() to construct.
type Client struct {
	opts         Options
	baseURL      string
	proxyBaseURL string // empty until tenant auto-discovery when no tenant was configured
	proxyShape   string // "plain" | "sandbox" | "" — subdomain shape to derive once discovered
	http         *http.Client
	creds        Credentials
	jsonMarshal  func(v any) ([]byte, error)

	retryMaxAttempts int
	retryBaseDelay   time.Duration
	retryMaxDelay    time.Duration

	mu         sync.Mutex
	tokenCache *cachedToken
	dpopKey    *dpopKeyPair // nil until "always" construction or "auto" upgrade; guarded by mu
	discoverMu sync.Mutex   // serializes tenant discovery so it runs at most once

	Routes       *RoutesResource
	Secrets      *SecretsResource
	Webhooks     *WebhooksResource
	Clients      *ClientsResource
	OAuthClients *OAuthClientsResource
	Environments *EnvironmentsResource
	APIKeys      *APIKeysResource
	Roles        *RolesResource
	Account      *AccountResource
	AuditLogs    *AuditLogsResource
	// Logs is the per-call proxy request log + Merkle inclusion proofs. Not
	// the change log — that is AuditLogs.
	Logs          *LogsResource
	Agents        *AgentsResource
	Crypto        *CryptoResource
	PKI           *PKIResource
	Vaults        *VaultsResource
	DynamicDB     *DynamicDBResource
	AIGateway     *AIGatewayResource
	Workflows     *WorkflowsResource
	Wrap          *WrapResource
	Opportunities *OpportunitiesResource
}

// String keeps fmt output of a Client free of cached tokens and credentials.
func (c *Client) String() string {
	return fmt.Sprintf("knoxcall.Client(tenant=%q, baseURL=%q)", c.opts.Tenant, c.baseURL)
}

// GoString keeps %#v output of a Client free of cached tokens and credentials.
func (c *Client) GoString() string { return c.String() }

type cachedToken struct {
	accessToken string
	tokenType   string
	expiresAt   time.Time
	lifetime    time.Duration // original expires_in; sizes the refresh-ahead window
	tenant      string        // slug from the token response (tenant auto-discovery)
}

// New creates a new KnoxCall client.
//
// Credential resolution (see ../../PARITY.md §2): mutual exclusion is checked
// on the explicitly passed Options first — Credentials cannot be combined
// with the flat APIKey / ClientID+ClientSecret options, APIKey cannot be
// combined with client credentials, and ClientID/ClientSecret must be
// provided together. Only when no explicit credential was passed are the
// environment variables consulted: KNOXCALL_ACCESS_TOKEN (wins), then
// KNOXCALL_API_KEY, then the `knoxcall login` credentials file
// (~/.knoxcall/credentials.json — see StoredCredentials), then
// KNOXCALL_CLIENT_ID+KNOXCALL_CLIENT_SECRET. Tenant falls back to
// KNOXCALL_TENANT, then to the credentials file when it supplied the
// credential.
func New(opts Options) (*Client, error) {
	// Conflicts are checked on explicitly passed options BEFORE any env
	// fill, so a conflict is always a programming error, never an
	// environment-dependent one.
	hasFlat := opts.APIKey != "" || opts.ClientID != "" || opts.ClientSecret != ""
	if opts.Credentials != nil && hasFlat {
		return nil, fmt.Errorf("knoxcall: Credentials cannot be combined with APIKey/ClientID/ClientSecret")
	}
	if opts.APIKey != "" && (opts.ClientID != "" || opts.ClientSecret != "") {
		return nil, fmt.Errorf("knoxcall: APIKey cannot be combined with ClientID/ClientSecret")
	}
	if (opts.ClientID != "") != (opts.ClientSecret != "") {
		return nil, fmt.Errorf("knoxcall: ClientID and ClientSecret must be provided together")
	}
	switch opts.DPoP {
	case "":
		opts.DPoP = "auto"
	case "auto", "always", "never":
	default:
		return nil, fmt.Errorf("knoxcall: invalid DPoP mode %q — expected \"auto\", \"always\", or \"never\"", opts.DPoP)
	}

	// Tenant is optional: when absent it is discovered from the first token
	// response (or /v1/account for pre-acquired tokens). Only the data-plane
	// hostname needs it client-side; management calls resolve the tenant
	// server-side from the credential.
	if opts.Tenant == "" {
		opts.Tenant = os.Getenv("KNOXCALL_TENANT")
	}
	if opts.Environment == "" {
		opts.Environment = os.Getenv("KNOXCALL_ENVIRONMENT")
	}

	// Env credential fill is skipped entirely when any explicit credential
	// was passed (explicit always outranks the environment).
	if opts.Credentials == nil && !hasFlat {
		if tok := os.Getenv("KNOXCALL_ACCESS_TOKEN"); tok != "" {
			opts.APIKey = tok
		} else if key := os.Getenv("KNOXCALL_API_KEY"); key != "" {
			opts.APIKey = key
		} else if credentialsProfileAvailable(resolveCredentialsPath(""), resolveProfile("")) {
			// Chain slot 2 (PARITY §2): the credentials file written by
			// `knoxcall login` — after the pre-acquired env token, before
			// env client-credentials. Present = file exists AND the selected
			// profile parses; anything missing/malformed skips this slot
			// silently and the chain continues.
			opts.Credentials = StoredCredentials{}
		} else if id := os.Getenv("KNOXCALL_CLIENT_ID"); id != "" {
			opts.ClientID = id
			opts.ClientSecret = os.Getenv("KNOXCALL_CLIENT_SECRET")
		}
	}

	// The credentials file seeds tenant/base URL when the caller didn't set
	// them explicitly (explicit constructor values and env vars always win).
	// Runs for both the auto-detected slot above and an explicitly passed
	// StoredCredentials value.
	if sc, ok := opts.Credentials.(StoredCredentials); ok {
		seedFromStoredCredentials(&opts, sc)
	}

	if opts.BaseURL == "" {
		if base := os.Getenv("KNOXCALL_BASE_URL"); base != "" {
			opts.BaseURL = base
		} else if base := os.Getenv("KNOXCALL_API_BASE_URL"); base != "" {
			// Legacy alias; the canonical KNOXCALL_BASE_URL wins when both are set.
			opts.BaseURL = base
		} else if opts.Sandbox {
			opts.BaseURL = sandboxAPIBase
		} else {
			opts.BaseURL = defaultAPIBase
		}
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")

	// proxyShape records the subdomain shape to derive lazily when the
	// tenant is not yet known (tenant auto-discovery, PARITY §2).
	proxyShape := ""
	proxyBase := opts.ProxyBaseURL
	if proxyBase == "" {
		if p := os.Getenv("KNOXCALL_PROXY_BASE_URL"); p != "" {
			proxyBase = p
		} else if strings.Contains(opts.BaseURL, "sandbox.knoxcall.com") || strings.Contains(opts.BaseURL, "sandbox-staging.knoxcall.com") {
			proxyShape = "sandbox"
			if opts.Tenant != "" {
				if err := assertTenantSlug(opts.Tenant); err != nil {
					return nil, err
				}
				proxyBase = fmt.Sprintf("https://sandbox-%s.%s", opts.Tenant, defaultCloudHost)
			}
		} else if strings.HasSuffix(opts.BaseURL, defaultCloudHost) || opts.BaseURL == defaultAPIBase {
			proxyShape = "plain"
			if opts.Tenant != "" {
				if err := assertTenantSlug(opts.Tenant); err != nil {
					return nil, err
				}
				proxyBase = fmt.Sprintf("https://%s.%s", opts.Tenant, defaultCloudHost)
			}
		} else {
			proxyBase = opts.BaseURL // self-hosted: same host, no tenant needed
		}
	}
	proxyBase = strings.TrimRight(proxyBase, "/")

	// Plaintext http:// to a non-loopback host sends credentials and access
	// tokens in the clear — warn once (don't block: http://localhost is the
	// normal dev case). Both the management base URL and the data-plane proxy
	// URL are checked; a deferred (empty) proxyBase warns nothing here and, once
	// discovered, is always an https:// cloud host. Mirrors node core.ts /
	// PARITY §15.
	if isInsecureRemoteURL(opts.BaseURL) {
		warnOnce("KNOXCALL_INSECURE_BASE_URL", fmt.Sprintf(
			"KnoxCall base URL %s uses plaintext http:// to a non-loopback host — "+
				"credentials and access tokens will be sent unencrypted; use https:// "+
				"(plain http:// is only safe for localhost)", opts.BaseURL))
	}
	if isInsecureRemoteURL(proxyBase) {
		warnOnce("KNOXCALL_INSECURE_PROXY_URL", fmt.Sprintf(
			"KnoxCall proxy base URL %s uses plaintext http:// to a non-loopback host — "+
				"proxied requests and the SDK credential will be sent unencrypted; use https:// "+
				"(plain http:// is only safe for localhost)", proxyBase))
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}

	creds := opts.Credentials
	if creds == nil {
		switch {
		case opts.APIKey != "":
			creds = AccessToken{Token: opts.APIKey}
		case opts.ClientID != "":
			creds = ClientCredentials{ClientID: opts.ClientID, ClientSecret: opts.ClientSecret}
		}
	}

	marshal := opts.JSONMarshal
	if marshal == nil {
		marshal = json.Marshal
	}

	c := &Client{
		opts:             opts,
		baseURL:          opts.BaseURL,
		proxyBaseURL:     proxyBase,
		proxyShape:       proxyShape,
		http:             hc,
		creds:            creds,
		jsonMarshal:      marshal,
		retryMaxAttempts: opts.RetryMaxAttempts,
		retryBaseDelay:   opts.RetryBaseDelay,
		retryMaxDelay:    opts.RetryMaxDelay,
	}
	if c.retryMaxAttempts <= 0 {
		c.retryMaxAttempts = defaultRetryMaxAttempts
	}
	if c.retryBaseDelay <= 0 {
		c.retryBaseDelay = defaultRetryBaseDelay
	}
	if c.retryMaxDelay <= 0 {
		c.retryMaxDelay = defaultRetryMaxDelay
	}
	if opts.DPoP == "always" {
		kp, err := generateDpopKeyPair()
		if err != nil {
			return nil, err
		}
		c.dpopKey = kp
	}
	c.Routes = &RoutesResource{c}
	c.Secrets = &SecretsResource{c}
	c.Webhooks = &WebhooksResource{c}
	c.Clients = &ClientsResource{c}
	c.OAuthClients = &OAuthClientsResource{c}
	c.Environments = &EnvironmentsResource{c}
	c.APIKeys = &APIKeysResource{c}
	c.Roles = &RolesResource{c}
	c.Account = &AccountResource{c}
	c.AuditLogs = &AuditLogsResource{c}
	c.Logs = &LogsResource{c}
	c.Agents = &AgentsResource{c}
	c.Crypto = &CryptoResource{c}
	c.PKI = &PKIResource{c}
	c.Vaults = &VaultsResource{c}
	c.DynamicDB = &DynamicDBResource{c}
	c.AIGateway = &AIGatewayResource{c}
	c.Workflows = &WorkflowsResource{c}
	c.Wrap = &WrapResource{c}
	c.Opportunities = &OpportunitiesResource{c}
	return c, nil
}

// -- Token management --------------------------------------------------------

func refreshAhead(tok *cachedToken) time.Duration {
	if tok.lifetime > 0 && tok.lifetime/2 < refreshAheadWindow {
		return tok.lifetime / 2
	}
	return refreshAheadWindow
}

// getToken returns the cached token, refreshing it inside the refresh-ahead
// window. The mutex gives single-flight semantics: only one goroutine mints
// a token; concurrent callers block and then reuse the fresh cache entry.
func (c *Client) getToken(ctx context.Context) (*cachedToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tok := c.tokenCache; tok != nil && time.Until(tok.expiresAt) > refreshAhead(tok) {
		return tok, nil
	}
	fresh, err := c.fetchToken(ctx)
	if err != nil {
		// Token endpoint unreachable or erroring during the refresh-ahead
		// window: a cached token that hasn't actually expired is still
		// good — use it rather than failing the caller's request.
		if stale := c.tokenCache; stale != nil && time.Until(stale.expiresAt) > staleTokenMinRemaining {
			return stale, nil
		}
		return nil, err
	}
	c.tokenCache = fresh
	// Learn the tenant from the token response when constructed without one.
	if c.opts.Tenant == "" && fresh.tenant != "" {
		c.opts.Tenant = fresh.tenant
	}
	return fresh, nil
}

// ensureProxyBaseURL resolves the data-plane base URL, discovering the tenant
// if needed: the token response carries the slug; pre-acquired tokens (and
// older servers) fall back to one GET /v1/account. discoverMu guarantees the
// discovery runs at most once even under concurrent first calls.
func (c *Client) ensureProxyBaseURL(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.proxyBaseURL != "" {
		p := c.proxyBaseURL
		c.mu.Unlock()
		return p, nil
	}
	c.mu.Unlock()

	c.discoverMu.Lock()
	defer c.discoverMu.Unlock()
	c.mu.Lock()
	if c.proxyBaseURL != "" { // discovered while we waited
		p := c.proxyBaseURL
		c.mu.Unlock()
		return p, nil
	}
	tenant := c.opts.Tenant
	c.mu.Unlock()

	if tenant == "" {
		if _, err := c.getToken(ctx); err != nil { // may adopt from the response
			return "", err
		}
		c.mu.Lock()
		tenant = c.opts.Tenant
		c.mu.Unlock()
	}
	if tenant == "" {
		var out struct {
			Data struct {
				Slug string `json:"slug"`
			} `json:"data"`
		}
		if err := c.do(ctx, requestOpts{method: http.MethodGet, path: "/v1/account"}, &out); err != nil {
			return "", err
		}
		if out.Data.Slug == "" {
			return "", fmt.Errorf("knoxcall: could not discover the tenant from the credential — set Options.Tenant or the KNOXCALL_TENANT environment variable")
		}
		tenant = out.Data.Slug
	}

	// A slug adopted from the token response or /v1/account is untrusted until
	// validated: it is about to become a data-plane hostname (PARITY §2).
	if err := assertTenantSlug(tenant); err != nil {
		return "", err
	}

	c.mu.Lock()
	c.opts.Tenant = tenant
	if c.proxyShape == "sandbox" {
		c.proxyBaseURL = fmt.Sprintf("https://sandbox-%s.%s", tenant, defaultCloudHost)
	} else {
		c.proxyBaseURL = fmt.Sprintf("https://%s.%s", tenant, defaultCloudHost)
	}
	p := c.proxyBaseURL
	c.mu.Unlock()
	return p, nil
}

// purgeToken drops the cached token so the next request mints a fresh one.
func (c *Client) purgeToken() {
	c.mu.Lock()
	c.tokenCache = nil
	c.mu.Unlock()
}

// flexSeconds tolerates both numeric and string "expires_in" values.
type flexSeconds float64

func (f *flexSeconds) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*f = 0 // non-numeric expires_in: fall back to the default lifetime
		return nil
	}
	*f = flexSeconds(v)
	return nil
}

type tokenResponse struct {
	AccessToken string      `json:"access_token"`
	TokenType   string      `json:"token_type"`
	ExpiresIn   flexSeconds `json:"expires_in"`
	Tenant      string      `json:"tenant"` // extension member: slug for auto-discovery
}

func (c *Client) fetchToken(ctx context.Context) (*cachedToken, error) {
	switch cr := c.creds.(type) {
	case AccessToken:
		// Static API key / pre-acquired token — use directly as Bearer. A
		// synthetic 1h expiry keeps the refresh-ahead machinery happy; leave
		// lifetime zero because there is nothing to refresh (matches the
		// python/node references). The AccessToken case re-mints from the same
		// value with no HTTP, so the short synthetic window costs nothing.
		return &cachedToken{
			accessToken: cr.Token,
			tokenType:   "Bearer",
			expiresAt:   time.Now().Add(time.Hour),
		}, nil
	case ClientCredentials:
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {cr.ClientID},
			"client_secret": {cr.ClientSecret},
		}
		if s := strings.Join(c.opts.Scope, " "); s != "" {
			form.Set("scope", s)
		}
		return c.postTokenForm(ctx, form)
	case OIDCTokenExchange:
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
			"subject_token":      {cr.SubjectToken},
			"audience":           {"knoxcall:api"},
		}
		if s := strings.Join(c.opts.Scope, " "); s != "" {
			form.Set("scope", s)
		}
		return c.postTokenForm(ctx, form)
	case StoredCredentials:
		// Tokens come from the `knoxcall login` credentials file. The file is
		// the cross-process cache and refresh authority (single-use rotated
		// refresh tokens); scope/DPoP posture is whatever login negotiated.
		return c.fetchStoredToken(ctx, cr)
	}
	// The credential auto-detect chain (New's env/file ladder) found nothing:
	// distinctly typed so callers can branch on "not logged in" and reach for
	// Login()/EnsureLogin(), while errors.As(err, &bootErr) still matches
	// (PARITY §1).
	return nil, notAuthenticated(
		"knoxcall: no KnoxCall credential found — run `knoxcall login` (or call knoxcall.Login/EnsureLogin), " +
			"set KNOXCALL_CLIENT_ID + KNOXCALL_CLIENT_SECRET (or KNOXCALL_API_KEY / KNOXCALL_ACCESS_TOKEN), " +
			"or pass Options.APIKey, Options.ClientID+ClientSecret, or Options.Credentials",
	)
}

// postTokenForm mints a token, handling the DPoP auto-upgrade (PARITY §7):
// in "auto" mode a first refusal with invalid_dpop_proof (the oauth client
// record requires DPoP) generates a keypair and retries the request ONCE
// with a proof — the client operates as DPoP thereafter. Caller (getToken)
// holds c.mu, so c.dpopKey is accessed directly here.
func (c *Client) postTokenForm(ctx context.Context, form url.Values) (*cachedToken, error) {
	tok, err := c.tokenRequest(ctx, form, c.dpopKey)
	if err != nil {
		var ae *APIError
		if c.opts.DPoP == "auto" && c.dpopKey == nil &&
			errors.As(err, &ae) && ae.Message == "invalid_dpop_proof" {
			kp, kerr := generateDpopKeyPair()
			if kerr != nil {
				return nil, kerr
			}
			tok, err = c.tokenRequest(ctx, form, kp)
			if err != nil {
				return nil, err
			}
			c.dpopKey = kp
			return tok, nil
		}
		return nil, err
	}
	return tok, nil
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values, kp *dpopKeyPair) (*cachedToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if kp != nil {
		proof, perr := kp.sign(http.MethodPost, c.baseURL+"/oauth/token", "", "")
		if perr != nil {
			return nil, perr
		}
		req.Header.Set("DPoP", proof)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	if resp.StatusCode >= 400 {
		return nil, errorFromResponse(resp.StatusCode, body, resp.Header)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		// e.g. an HTML page from an edge proxy with a 200 status, or a 200
		// missing access_token — surface a typed error, never a decode panic.
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Detail:     fmt.Sprintf("token endpoint returned an unexpected response (status %d)", resp.StatusCode),
		}
	}
	if tr.TokenType == "DPoP" && kp == nil {
		// Sending "Authorization: DPoP" without a proof would 401-loop
		// forever — fail loudly instead (mode "never", or a server that
		// binds tokens without challenging first).
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Detail:     `server issued a DPoP-bound token but this client holds no DPoP keypair — construct with DPoP mode "auto" or "always"`,
		}
	}
	if tr.TokenType == "" {
		tr.TokenType = "Bearer"
	}
	ttl := time.Duration(float64(tr.ExpiresIn) * float64(time.Second))
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &cachedToken{
		accessToken: tr.AccessToken,
		tokenType:   tr.TokenType,
		expiresAt:   time.Now().Add(ttl),
		lifetime:    ttl,
		tenant:      tr.Tenant,
	}, nil
}

// dpopKeyRef safely reads the keypair outside the token path (attempt /
// proxySend run without c.mu held).
func (c *Client) dpopKeyRef() *dpopKeyPair {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dpopKey
}

// setDpopAuth sets the Authorization header for a DPoP-bound token plus the
// fresh per-request proof (new jti/iat, bound to method + URL + ath).
func (c *Client) setDpopAuth(header http.Header, method, fullURL string, tok *cachedToken) error {
	kp := c.dpopKeyRef()
	if kp == nil {
		return &APIError{Detail: "DPoP-bound token held without a DPoP keypair — this is a bug, please report it"}
	}
	proof, err := kp.sign(method, fullURL, tok.accessToken, "")
	if err != nil {
		return err
	}
	header.Set("Authorization", "DPoP "+tok.accessToken)
	header.Set("DPoP", proof)
	return nil
}

// -- Request body encoding ----------------------------------------------------

// encodeBody serializes a request body, defaulting Content-Type to JSON when
// the caller hasn't set one. []byte / string / json.RawMessage pass through
// untouched (pre-serialized payloads); anything else goes through the
// client's JSONMarshal hook (default encoding/json.Marshal).
func (c *Client) encodeBody(body any, header http.Header) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	if header.Get("Content-Type") == "" {
		header.Set("Content-Type", "application/json")
	}
	switch b := body.(type) {
	case []byte:
		return b, nil
	case json.RawMessage:
		return b, nil
	case string:
		return []byte(b), nil
	}
	bts, err := c.jsonMarshal(body)
	if err != nil {
		return nil, fmt.Errorf("knoxcall: marshal body: %w", err)
	}
	return bts, nil
}

// -- Retry helpers -------------------------------------------------------------

// Retryable statuses for management requests. NOT 409 — a real conflict
// does not resolve by replaying.
func retryableStatus(status int) bool {
	switch status {
	case 408, 429, 500, 502, 503, 504:
		return true
	}
	return false
}

func (c *Client) shouldRetry(err error, attempt int) bool {
	if attempt >= c.retryMaxAttempts {
		return false
	}
	var ce *ConnectionError
	if errors.As(err, &ce) {
		return true // mutations carry idempotency keys, so replay is safe
	}
	return retryableStatus(statusOf(err))
}

func (c *Client) retryDelay(err error, attempt int) time.Duration {
	// A 429's Retry-After, and a 503's (`dependency_unavailable` — the server
	// says how long the dependency needs). Both capped: beyond the cap the
	// caller's own scheduling beats a blocked goroutine.
	retryAfter := 0
	var rl *RateLimitError
	var se *ServerError
	switch {
	case errors.As(err, &rl):
		retryAfter = rl.RetryAfter
	case errors.As(err, &se):
		retryAfter = se.RetryAfter
	}
	if retryAfter > 0 {
		d := time.Duration(retryAfter) * time.Second
		if d > retryAfterCap {
			d = retryAfterCap
		}
		return d
	}
	return c.backoffDelay(attempt)
}

// backoffDelay is exponential with half-jitter: random within [exp/2, exp]
// so a retry never fires immediately but herds still spread out.
func (c *Client) backoffDelay(attempt int) time.Duration {
	exp := float64(c.retryBaseDelay) * math.Pow(2, float64(attempt-1))
	d := time.Duration(exp * (0.5 + rand.Float64()/2))
	if d > c.retryMaxDelay {
		d = c.retryMaxDelay
	}
	return d
}

// sleepCtx sleeps for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// -- Management API pipeline ---------------------------------------------------

type requestOpts struct {
	method string
	path   string
	body   any
	query  url.Values
	// raw: the endpoint returns raw text (PKI PEM / CRL), not the JSON
	// envelope — the body is copied verbatim into out (*string).
	raw bool
	// header: caller headers added to the request (every attempt, so a
	// conditional GET's If-None-Match survives the one re-auth on 401).
	// SDK-set headers (Authorization, the idempotency key) always win.
	header http.Header
	// notModified, when non-nil, opts into 304 Not Modified as a success with
	// no body: attempt sets *notModified = true and leaves out untouched. Auth,
	// the one transparent re-auth on 401 and the retry policy are unchanged.
	// Internal: the one consumer is Wrap.InterceptManifest with IfNoneMatch.
	notModified *bool
}

// do runs a management-API request with retries (408/429/5xx + transport
// errors, exponential half-jitter backoff, Retry-After honored up to 30s),
// one transparent re-auth on 401, and a ULID idempotency key on mutating
// requests that stays stable across retries.
func (c *Client) do(ctx context.Context, r requestOpts, out any) error {
	method := strings.ToUpper(r.method)

	base := make(http.Header)
	base.Set("Accept", "application/json")
	base.Set("User-Agent", userAgent)
	base.Set("KnoxCall-Version", defaultAPIVersion)
	body, err := c.encodeBody(r.body, base)
	if err != nil {
		return err
	}
	for k, vs := range r.header {
		for _, v := range vs {
			base.Add(k, v)
		}
	}
	if method != http.MethodGet && method != http.MethodHead {
		// Generated once per logical request — stable across retries.
		base.Set("X-Idempotency-Key", newULID())
	}

	fullURL := c.baseURL + r.path
	if len(r.query) > 0 {
		fullURL += "?" + r.query.Encode()
	}

	var lastErr error
	reauthDone := false
	for attempt := 1; attempt <= c.retryMaxAttempts; attempt++ {
		err := c.attempt(ctx, method, fullURL, body, base, out, r.raw, r.notModified)
		if err == nil {
			return nil
		}
		lastErr = err
		// One transparent re-auth: attempt() purged the cached token on
		// 401, so the immediate retry runs with freshly minted creds.
		if statusOf(err) == 401 && !reauthDone && attempt < c.retryMaxAttempts {
			reauthDone = true
			continue
		}
		if !c.shouldRetry(err, attempt) {
			return err
		}
		if serr := sleepCtx(ctx, c.retryDelay(err, attempt)); serr != nil {
			return lastErr
		}
	}
	return lastErr
}

func (c *Client) attempt(ctx context.Context, method, fullURL string, body []byte, base http.Header, out any, raw bool, notModified *bool) error {
	tok, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return err
	}
	req.Header = base.Clone()
	if tok.tokenType == "DPoP" {
		if err := c.setDpopAuth(req.Header, method, fullURL, tok); err != nil {
			return err
		}
	} else {
		req.Header.Set("Authorization", tok.tokenType+" "+tok.accessToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return wrapTransportError(err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return wrapTransportError(err)
	}

	if resp.StatusCode == 401 {
		// Purge so the retry (or the caller's next request) re-mints.
		c.purgeToken()
		return errorFromResponse(resp.StatusCode, respBody, resp.Header)
	}
	if resp.StatusCode >= 400 {
		return errorFromResponse(resp.StatusCode, respBody, resp.Header)
	}
	if notModified != nil && resp.StatusCode == http.StatusNotModified {
		// A conditional GET the server answered "unchanged": success, no body.
		*notModified = true
		return nil
	}
	if out != nil && len(respBody) > 0 {
		if raw {
			if s, ok := out.(*string); ok {
				*s = string(respBody)
				return nil
			}
			return fmt.Errorf("knoxcall: raw responses decode into *string, got %T", out)
		}
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("knoxcall: decode response: %w", err)
		}
	}
	return nil
}

// -- Call / Ephemeral ----------------------------------------------------------

// CallOptions configures a proxied route request.
type CallOptions struct {
	Method      string
	Path        string
	Body        any
	Headers     map[string]string
	Environment string
	Query       url.Values

	// interceptOrigin is the route-aware interceptors' reroute marker (PARITY
	// §21.2): when set, the request carries `x-knoxcall-origin: sdk-intercept`
	// so the API Log can show which Route calls the SDK rerouted from a
	// third-party SDK and which were direct. Unexported on purpose — only
	// this package's pipeline (intercept.go) can set it, and nothing in
	// Headers can (the name is stripped there). A direct Call sends nothing:
	// absence IS "direct" on the server.
	interceptOrigin bool
}

// Call makes a proxied request through a KnoxCall route.
// Pass the route UUID (preferred) or name as route.
//
// The raw *http.Response is returned for any upstream HTTP status — the
// proxied upstream's status belongs to the caller. Transport failures map
// to *ConnectionError / *ConnectionTimeoutError and are retried only when
// safe (connect failures always; later failures for GET/HEAD only — a
// mutating request is never replayed). A 401 triggers one token purge +
// re-mint; the second response is returned as-is. For a per-call timeout,
// pass a context with a deadline (context.WithTimeout).
//
// Credential transmission: kc_ OAuth tokens go as Authorization: Bearer;
// any other token value (legacy tk_ API key, AKE access key) goes as the
// x-knoxcall-key header instead — the proxy's OAuth detection matches the
// kc_ prefix only, and a Bearer tk_ would fall through to the legacy auth
// path and 401.
// Where the data plane lives under a proxy base (PARITY §5).
//
// On a KnoxCall CLOUD tenant host the proxy is served ONLY under /api
// (https://{slug}.knoxcall.com/api/<upstream path>: server.ts strips the
// prefix, and every other path on that host is the dashboard). Call therefore
// places the upstream path under /api whenever the base names such a host and
// carries no path of its own — the derived plain/sandbox shapes and an
// explicit override alike, any port. Every other base is used verbatim:
// self-hosted mounts the proxy at /, and a base that already carries a path IS
// the entry point (the agent bundle spells the same base as …knoxcall.com/api).
// Until 2026-09-25 nothing added the prefix, so the documented Path: "/users"
// answered the dashboard HTML on every tenant host; the live smokes hid it by
// hard-coding Path: "/api/get".
var nonTenantLabels = map[string]bool{
	"api": true, "sandbox": true, "api-staging": true, "sandbox-staging": true,
	"www": true, "staging": true, "admin": true,
}

var cloudTenantHostRe = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.knoxcall\.com$`)

func dataPlanePathPrefix(proxyBase string) string {
	u, err := url.Parse(proxyBase)
	if err != nil {
		return ""
	}
	if u.Path != "" && u.Path != "/" {
		return ""
	}
	m := cloudTenantHostRe.FindStringSubmatch(strings.ToLower(u.Hostname()))
	if m == nil || nonTenantLabels[m[1]] {
		return ""
	}
	return "/api"
}

func (c *Client) Call(ctx context.Context, route string, opts *CallOptions) (*http.Response, error) {
	method := http.MethodGet
	path := "/"
	if opts != nil {
		if opts.Method != "" {
			method = strings.ToUpper(opts.Method)
		}
		if opts.Path != "" {
			path = opts.Path
		}
	}

	proxyBase, err := c.ensureProxyBaseURL(ctx)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Path is the UPSTREAM path; the entry point is the SDK's to add (PARITY §5).
	fullURL := proxyBase + dataPlanePathPrefix(proxyBase) + path
	if opts != nil && len(opts.Query) > 0 {
		fullURL += "?" + opts.Query.Encode()
	}

	// SDK headers are applied after the caller's map: explicit arguments
	// (route, environment) always win, and Authorization can't be spoofed.
	sdkHeaders := [][2]string{{"x-knoxcall-route", route}}
	environment := c.opts.Environment
	if opts != nil && opts.Environment != "" {
		environment = opts.Environment
	}
	if environment != "" {
		sdkHeaders = append(sdkHeaders, [2]string{"x-knoxcall-environment", environment})
	}
	if opts != nil && opts.interceptOrigin {
		sdkHeaders = append(sdkHeaders, [2]string{"x-knoxcall-origin", "sdk-intercept"})
	}

	var body any
	var callerHeaders map[string]string
	if opts != nil {
		body = opts.Body
		callerHeaders = opts.Headers
	}
	return c.proxySend(ctx, method, fullURL, body, callerHeaders, sdkHeaders, true)
}

// EphemeralOptions configures a one-shot proxy request.
type EphemeralOptions struct {
	Method    string
	Body      any
	Headers   map[string]string
	Encrypted string
	TimeoutMs int
	// Mode, when set to "transparent" (the only accepted value), sends the
	// X-Knox-Proxy-Mode: transparent header. The proxy then forwards the
	// request body and Content-Type byte-verbatim and skips {{ token }}
	// templating — the mode a wrapped third-party SDK (Stripe,
	// form-urlencoded, …) needs. Empty = default JSON+template behaviour.
	Mode string
	// UpstreamAuthorization is an opaque credential mapped to the upstream's
	// own Authorization header server-side (X-Knox-Upstream-Authorization).
	// It is never logged or stored server-side and does not affect the SDK's
	// own KnoxCall auth. Empty = header omitted.
	UpstreamAuthorization string
	// UpstreamAuthSecret is the NAME of an escrowed wrap credential
	// (X-Knox-Upstream-Auth-Secret). The server resolves and decrypts it and
	// injects it as the upstream Authorization header, host-pinned. On the wire
	// it is mutually exclusive with UpstreamAuthorization (the server rejects
	// both at once); the SDK does not enforce that. Empty = header omitted.
	UpstreamAuthSecret string
	// UpstreamAuthScheme is the auth scheme for the resolved UpstreamAuthSecret
	// (X-Knox-Upstream-Auth-Scheme). Server default is Bearer; "none" sends the
	// raw value. Empty = header omitted.
	UpstreamAuthScheme string
}

// Ephemeral makes a one-shot proxied request through the KnoxCall Ephemeral
// Proxy. Upstream URL is provided directly; the proxy resolves
// {{ token: "..." }} expressions.
//
// Hardening semantics match Call: raw response for any upstream status,
// typed transport errors, safe-only retries, one 401 purge + re-mint.
// Unlike Call, legacy tk_/AKE credentials stay on Authorization: Bearer —
// /v1/proxy's auth accepts any credential format as Bearer.
func (c *Client) Ephemeral(ctx context.Context, upstreamURL string, opts *EphemeralOptions) (*http.Response, error) {
	method := http.MethodGet
	if opts != nil && opts.Method != "" {
		method = strings.ToUpper(opts.Method)
	}

	sdkHeaders := [][2]string{{"X-Knox-Proxy-URL", upstreamURL}}
	var body any
	var callerHeaders map[string]string
	if opts != nil {
		body = opts.Body
		callerHeaders = opts.Headers
		if opts.Encrypted != "" {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Encrypted", opts.Encrypted})
		}
		if opts.TimeoutMs > 0 {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Timeout-Ms", strconv.Itoa(opts.TimeoutMs)})
		}
		if opts.Mode == "transparent" {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Proxy-Mode", "transparent"})
		}
		if opts.UpstreamAuthorization != "" {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Upstream-Authorization", opts.UpstreamAuthorization})
		}
		if opts.UpstreamAuthSecret != "" {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Upstream-Auth-Secret", opts.UpstreamAuthSecret})
		}
		if opts.UpstreamAuthScheme != "" {
			sdkHeaders = append(sdkHeaders, [2]string{"X-Knox-Upstream-Auth-Scheme", opts.UpstreamAuthScheme})
		}
	}
	return c.proxySend(ctx, method, c.baseURL+"/v1/proxy", body, callerHeaders, sdkHeaders, false)
}

// proxyAuthHeaders are the proxy-consumed auth headers the SDK owns
// exclusively on the data plane. A caller-supplied value for any of these is
// stripped before dispatch so SDK auth is authoritative (PARITY §5) — the SDK
// then sets its own credential. Names are matched case-insensitively via
// http.Header canonicalization.
var proxyAuthHeaders = []string{
	"x-knoxcall-agent-id",
	"x-knoxcall-agent-token",
	"x-knoxcall-key",
	"Authorization",
	"DPoP",
}

// sdkMarkerHeaders are the markers the SDK owns on the data plane (PARITY
// §21.2). Not auth — the server treats them as informational — but a
// caller-supplied copy is stripped the same way, so a caller cannot relabel
// its own calls as interceptor traffic through the Headers map. The pipeline
// sets the marker through CallOptions.interceptOrigin, never through Headers.
var sdkMarkerHeaders = []string{
	"x-knoxcall-origin",
}

// proxySend is the shared data-plane sender for Call/Ephemeral.
//
// Proxied responses are returned raw (the upstream's status belongs to the
// caller), but transport failures are mapped to the SDK's connection-error
// types and retried when safe, and a 401 triggers one token purge + re-mint
// so a revoked token can't wedge a long-lived client.
//
// legacyKeyAsHeader is set on Call requests: the proxy's OAuth detection
// matches the kc_ token prefix only, so a legacy tk_/AKE credential must
// travel as x-knoxcall-key (Bearer would fall through to the legacy path
// and 401). Ephemeral targets /v1/proxy, which accepts any format as Bearer.
func (c *Client) proxySend(ctx context.Context, method, fullURL string, body any, callerHeaders map[string]string, sdkHeaders [][2]string, legacyKeyAsHeader bool) (*http.Response, error) {
	base := make(http.Header)
	for k, v := range callerHeaders {
		base.Set(k, v)
	}
	// SECURITY: the SDK is the ONLY source of proxy auth on the data plane.
	// Strip any caller-supplied proxy-consumed auth headers before dispatch so
	// a caller can never impersonate another agent or smuggle a bearer/DPoP
	// the proxy would honor; the SDK sets its own credential per attempt below.
	// http.Header canonicalizes on Set/Del, so this is case-insensitive across
	// whatever casing the caller used. Applies to Call (incl. bound routes,
	// which delegate here) and Ephemeral; management requests never take
	// caller proxy headers and go through a separate pipeline.
	for _, h := range proxyAuthHeaders {
		base.Del(h)
	}
	for _, h := range sdkMarkerHeaders {
		base.Del(h)
	}
	if base.Get("User-Agent") == "" {
		base.Set("User-Agent", userAgent)
	}
	bodyBytes, err := c.encodeBody(body, base) // respects caller Content-Type
	if err != nil {
		return nil, err
	}
	// Explicit SDK arguments always win over the caller's headers map.
	for _, kv := range sdkHeaders {
		base.Set(kv[0], kv[1])
	}

	reauthDone := false
	for attempt := 1; ; attempt++ {
		tok, err := c.getToken(ctx)
		if err != nil {
			return nil, err
		}

		var bodyReader io.Reader
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header = base.Clone()
		if legacyKeyAsHeader && tok.tokenType == "Bearer" && !strings.HasPrefix(tok.accessToken, "kc_") {
			req.Header.Set("x-knoxcall-key", tok.accessToken)
		} else if tok.tokenType == "DPoP" {
			if err := c.setDpopAuth(req.Header, method, fullURL, tok); err != nil {
				return nil, err
			}
		} else {
			req.Header.Set("Authorization", tok.tokenType+" "+tok.accessToken)
		}

		res, err := c.http.Do(req)
		if err != nil {
			if c.proxyRetryable(err, method, attempt) {
				if serr := sleepCtx(ctx, c.backoffDelay(attempt)); serr != nil {
					return nil, wrapTransportError(err)
				}
				continue
			}
			return nil, wrapTransportError(err)
		}

		// A 401 the UPSTREAM answered and the data plane relayed (the response
		// block's X-Knox-Upstream-Status, or the ephemeral proxy's older
		// X-Knox-Destination-Status) says nothing about OUR token: it is the
		// caller's to handle, and spending the one re-mint on it would leave a
		// real revocation un-recoverable on this call. Only a KnoxCall-origin
		// 401 triggers the purge + re-mint. Mirrors node core.ts #proxySend.
		if res.StatusCode == 401 && !reauthDone && !upstreamAnswered(res) {
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			c.purgeToken()
			reauthDone = true
			continue
		}
		return res, nil
	}
}

// upstreamAnswered reports whether a data-plane response came from the
// upstream (relayed) rather than from KnoxCall itself.
func upstreamAnswered(res *http.Response) bool {
	return res.Header.Get("X-Knox-Upstream-Status") != "" || res.Header.Get("X-Knox-Destination-Status") != ""
}

func (c *Client) proxyRetryable(err error, method string, attempt int) bool {
	if attempt >= c.retryMaxAttempts {
		return false
	}
	// The connection was never established, so the request was never
	// sent — always safe to retry, even for mutating methods.
	if isConnectError(err) {
		return true
	}
	// Anything later (read timeout, idle-keepalive reset, …) may have
	// reached the upstream; only replay methods that are safe to repeat.
	return method == http.MethodGet || method == http.MethodHead
}

// VerifySignature verifies a KnoxCall webhook signature using the DEFAULT
// legacy scheme: HMAC-SHA256(secret, rawBody), compared in constant time to
// the hex value carried by the X-Webhook-Signature header (an optional leading
// "sha256=" prefix is tolerated). rawBody is the raw request bytes; signature
// is that header's value.
//
// Pass toleranceSeconds>0 together with the delivery timestamp to reject
// replays: the check fails when abs(now-timestamp) exceeds the tolerance.
// For the compound stripe/slack formats — and a parsed, typed event — use
// ConstructWebhookEvent instead.
func VerifySignature(rawBody []byte, signature, secret string, toleranceSeconds int, timestamp int64) bool {
	if toleranceSeconds > 0 && timestamp > 0 {
		if abs(time.Now().Unix()-timestamp) > int64(toleranceSeconds) {
			return false
		}
	}
	sig := strings.TrimPrefix(strings.TrimSpace(signature), "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawBody)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
