package knoxcall

// Tests for flat construction, env fallbacks, legacy-key transmission, and
// bound routes — the Go port of the shapes in
// knoxcall-python/tests/test_construction.py (see ../../PARITY.md §2/§5/§6).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// clearConstructionEnv blanks every env var New() consults so a developer's
// real environment can't leak into these tests. t.Setenv restores the
// originals afterwards; "" reads as unset everywhere in New(). The
// credentials-file provider is pointed at a path inside t.TempDir() that was
// never written, so a real ~/.knoxcall/credentials.json is never read; the
// returned path is where credentials-file tests write their fixture.
func clearConstructionEnv(t *testing.T) string {
	t.Helper()
	for _, v := range []string{
		"KNOXCALL_TENANT",
		"KNOXCALL_ENVIRONMENT",
		"KNOXCALL_BASE_URL",
		"KNOXCALL_API_BASE_URL",
		"KNOXCALL_PROXY_BASE_URL",
		"KNOXCALL_ACCESS_TOKEN",
		"KNOXCALL_API_KEY",
		"KNOXCALL_CLIENT_ID",
		"KNOXCALL_CLIENT_SECRET",
		"KNOXCALL_PROFILE",
	} {
		t.Setenv(v, "")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("KNOXCALL_CREDENTIALS_FILE", path)
	return path
}

// captureProxyServer serves /oauth/token and records the last non-token
// request's headers, method, and URL.
func captureProxyServer(t *testing.T) (*httptest.Server, func() (http.Header, string, string)) {
	t.Helper()
	var mu sync.Mutex
	var seen http.Header
	seenMethod, seenURL := "", ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		seen = r.Header.Clone()
		seenMethod = r.Method
		seenURL = r.URL.String()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	captured := func() (http.Header, string, string) {
		mu.Lock()
		defer mu.Unlock()
		return seen, seenMethod, seenURL
	}
	return ts, captured
}

// ── Tenant env fallback / zero-option ─────────────────────────────────────────

func TestTenantFromEnvEnablesZeroTenantConstruction(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_TENANT", "envcorp")
	c, err := New(Options{APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "envcorp" {
		t.Fatalf("tenant = %q, want envcorp", c.opts.Tenant)
	}
	// proxy URL must derive from the env-resolved tenant
	if c.proxyBaseURL != "https://envcorp.knoxcall.com" {
		t.Fatalf("proxyBaseURL = %q, want https://envcorp.knoxcall.com", c.proxyBaseURL)
	}
}

func TestExplicitTenantBeatsEnv(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_TENANT", "envcorp")
	c, err := New(Options{Tenant: "explicit", APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "explicit" {
		t.Fatalf("tenant = %q, want explicit", c.opts.Tenant)
	}
}

func TestTenantAdoptedFromTokenResponse(t *testing.T) {
	clearConstructionEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"kc_live_a","token_type":"Bearer","expires_in":3600,"tenant":"discovered"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	// Self-hosted BaseURL keeps the proxy on the same host, so the call
	// works without a tenant — and the slug is still adopted from the
	// token response for anything that needs it later.
	c, err := New(Options{ClientID: "tk_x", ClientSecret: "s", BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	res.Body.Close()
	c.mu.Lock()
	got := c.opts.Tenant
	c.mu.Unlock()
	if got != "discovered" {
		t.Fatalf("tenant = %q, want discovered (adopted from the token response)", got)
	}
}

func TestProxyURLDerivedLazilyFromDiscoveredTenant(t *testing.T) {
	clearConstructionEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"kc_live_a","token_type":"Bearer","expires_in":3600,"tenant":"discovered"}`))
	}))
	defer ts.Close()

	// Cloud-shaped BaseURL with no tenant: proxy URL must start empty and
	// derive from the discovered tenant.
	c, err := New(Options{ClientID: "tk_x", ClientSecret: "s", BaseURL: "https://api.knoxcall.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = ts.URL // token endpoint reachable; proxy never contacted
	if c.proxyBaseURL != "" {
		t.Fatalf("proxyBaseURL = %q, want empty before discovery", c.proxyBaseURL)
	}
	got, err := c.ensureProxyBaseURL(context.Background())
	if err != nil {
		t.Fatalf("ensureProxyBaseURL: %v", err)
	}
	if got != "https://discovered.knoxcall.com" {
		t.Fatalf("proxyBaseURL = %q, want https://discovered.knoxcall.com", got)
	}
}

func TestTenantDiscoveredViaAccountForStaticTokens(t *testing.T) {
	clearConstructionEnv(t)
	var mu sync.Mutex
	accountCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/account" {
			mu.Lock()
			accountCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"slug":"fromaccount","name":"X"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c, err := New(Options{APIKey: "kc_live_pre", BaseURL: "https://api.knoxcall.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = ts.URL
	for range 2 {
		got, err := c.ensureProxyBaseURL(context.Background())
		if err != nil {
			t.Fatalf("ensureProxyBaseURL: %v", err)
		}
		if got != "https://fromaccount.knoxcall.com" {
			t.Fatalf("proxyBaseURL = %q, want https://fromaccount.knoxcall.com", got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if accountCalls != 1 {
		t.Fatalf("accountCalls = %d, want exactly 1 (discovered once, then cached)", accountCalls)
	}
}

func TestUndiscoverableTenantReturnsActionableError(t *testing.T) {
	clearConstructionEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"name":"no slug here"}}`))
	}))
	defer ts.Close()

	c, err := New(Options{APIKey: "kc_live_pre", BaseURL: "https://api.knoxcall.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = ts.URL
	_, err = c.ensureProxyBaseURL(context.Background())
	if err == nil || !strings.Contains(err.Error(), "KNOXCALL_TENANT") {
		t.Fatalf("err = %v, want a discovery error mentioning KNOXCALL_TENANT", err)
	}
}

func TestConcurrentFirstCallsDiscoverOnce(t *testing.T) {
	clearConstructionEnv(t)
	var mu sync.Mutex
	tokenCalls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"kc_live_a","token_type":"Bearer","expires_in":3600,"tenant":"discovered"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c, err := New(Options{ClientID: "tk_x", ClientSecret: "s", BaseURL: "https://api.knoxcall.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = ts.URL

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ensureProxyBaseURL(context.Background()); err != nil {
				t.Errorf("ensureProxyBaseURL: %v", err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 1 {
		t.Fatalf("tokenCalls = %d, want 1 (single-flight discovery)", tokenCalls)
	}
}

func TestZeroOptionConstructionWithFullEnv(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_TENANT", "envcorp")
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec")
	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "envcorp" {
		t.Fatalf("tenant = %q, want envcorp", c.opts.Tenant)
	}
	cc, ok := c.creds.(ClientCredentials)
	if !ok || cc.ClientID != "tk_env" || cc.ClientSecret != "sec" {
		t.Fatalf("creds = %v, want ClientCredentials from the environment", c.creds)
	}
}

// ── Base URL + credential env precedence ──────────────────────────────────────

func TestCanonicalBaseURLBeatsLegacyAlias(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_BASE_URL", "https://canonical.example.test")
	t.Setenv("KNOXCALL_API_BASE_URL", "https://legacy.example.test")
	c, err := New(Options{Tenant: "acme", APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.baseURL != "https://canonical.example.test" {
		t.Fatalf("baseURL = %q, want the canonical KNOXCALL_BASE_URL to win", c.baseURL)
	}
}

func TestLegacyBaseURLAliasStillWorks(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_API_BASE_URL", "https://legacy.example.test")
	c, err := New(Options{Tenant: "acme", APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.baseURL != "https://legacy.example.test" {
		t.Fatalf("baseURL = %q, want the legacy KNOXCALL_API_BASE_URL fallback", c.baseURL)
	}
}

func TestEnvAccessTokenBeatsEnvAPIKey(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_ACCESS_TOKEN", "kc_env_access")
	t.Setenv("KNOXCALL_API_KEY", "kc_env_key")
	c, err := New(Options{Tenant: "acme"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	at, ok := c.creds.(AccessToken)
	if !ok || at.Token != "kc_env_access" {
		t.Fatalf("creds = %v, want AccessToken from KNOXCALL_ACCESS_TOKEN (wins over KNOXCALL_API_KEY)", c.creds)
	}
}

// ── Mutual-exclusion conflict matrix ──────────────────────────────────────────

func TestConflictMatrixErrorsAtConstruction(t *testing.T) {
	clearConstructionEnv(t)
	cases := map[string]Options{
		"Credentials + APIKey":       {Tenant: "acme", Credentials: AccessToken{Token: "kc_a"}, APIKey: "kc_b"},
		"Credentials + client creds": {Tenant: "acme", Credentials: ClientCredentials{ClientID: "tk_x", ClientSecret: "s"}, ClientID: "tk_x", ClientSecret: "s"},
		"APIKey + client creds":      {Tenant: "acme", APIKey: "kc_a", ClientID: "tk_x", ClientSecret: "s"},
		"ClientID without secret":    {Tenant: "acme", ClientID: "tk_x"},
		"ClientSecret without id":    {Tenant: "acme", ClientSecret: "s"},
	}
	for name, opts := range cases {
		if _, err := New(opts); err == nil {
			t.Errorf("%s: New() succeeded, want a construction conflict error", name)
		}
	}
}

func TestEnvFillSkippedWhenExplicitCredentialsPassed(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_ACCESS_TOKEN", "kc_env_access")
	t.Setenv("KNOXCALL_API_KEY", "kc_env_key")
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec_env")
	c, err := New(Options{Tenant: "acme", Credentials: ClientCredentials{ClientID: "tk_explicit", ClientSecret: "s"}})
	if err != nil {
		t.Fatalf("New: %v — env-filled values must never create conflicts", err)
	}
	cc, ok := c.creds.(ClientCredentials)
	if !ok || cc.ClientID != "tk_explicit" {
		t.Fatalf("creds = %v, want the explicit Credentials object (env fill skipped entirely)", c.creds)
	}
}

func TestEnvFillSkippedWhenExplicitFlatCredentialPassed(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_ACCESS_TOKEN", "kc_env_access")
	c, err := New(Options{Tenant: "acme", ClientID: "tk_explicit", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cc, ok := c.creds.(ClientCredentials)
	if !ok || cc.ClientID != "tk_explicit" {
		t.Fatalf("creds = %v, want ClientCredentials from the explicit flat options (env fill skipped)", c.creds)
	}
}

// ── Flat credentials on the wire ──────────────────────────────────────────────

func TestFlatClientCredentialsMintIdenticallyToCredentialsObject(t *testing.T) {
	var mu sync.Mutex
	form := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			form = string(b)
			mu.Unlock()
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Credentials = nil
		o.ClientID = "tk_x"
		o.ClientSecret = "sec"
	})
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(form, "grant_type=client_credentials") || !strings.Contains(form, "client_id=tk_x") {
		t.Fatalf("token form = %q, want a client_credentials grant minted from the flat options", form)
	}
}

// PARITY §2/§3: Options.Scope rides the client_credentials grant as a
// space-joined `scope` form field (RFC 6749 §3.3), matching python/node.
func TestScopeSentInClientCredentialsTokenForm(t *testing.T) {
	var mu sync.Mutex
	form := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			form = string(b)
			mu.Unlock()
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Scope = []string{"routes:read", "secrets:read"}
	})
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	parsed, err := url.ParseQuery(form)
	if err != nil {
		t.Fatalf("parse token form %q: %v", form, err)
	}
	if got := parsed.Get("grant_type"); got != "client_credentials" {
		t.Fatalf("grant_type = %q, want client_credentials", got)
	}
	if got := parsed.Get("scope"); got != "routes:read secrets:read" {
		t.Fatalf("scope form field = %q, want %q (space-joined, request order)", got, "routes:read secrets:read")
	}
}

// An empty Options.Scope sends no scope field at all (request the credential's
// full authorized scope), never an empty `scope=`.
func TestNoScopeFieldWhenScopeUnset(t *testing.T) {
	var mu sync.Mutex
	form := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			form = string(b)
			mu.Unlock()
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil) // no Scope set
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	parsed, err := url.ParseQuery(form)
	if err != nil {
		t.Fatalf("parse token form %q: %v", form, err)
	}
	if _, ok := parsed["scope"]; ok {
		t.Fatalf("scope field present (%q) with no Options.Scope set, want it omitted", parsed.Get("scope"))
	}
}

func TestFlatAPIKeyAttachesBearerWithoutTokenEndpoint(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	var seen http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		seen = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Credentials = nil
		o.APIKey = "kc_live_pre"
	})
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	for _, p := range paths {
		if p == "/oauth/token" {
			t.Fatalf("a pre-acquired kc_ token must never hit the token endpoint (paths = %v)", paths)
		}
	}
	if got := seen.Get("Authorization"); got != "Bearer kc_live_pre" {
		t.Fatalf("Authorization = %q, want Bearer kc_live_pre", got)
	}
	if got := seen.Get("x-knoxcall-key"); got != "" {
		t.Fatalf("x-knoxcall-key = %q, want absent for kc_ tokens", got)
	}
}

// ── Legacy-key transmission (PARITY §5) ───────────────────────────────────────

func TestLegacyTkKeyTravelsAsXKnoxcallKeyOnCall(t *testing.T) {
	ts, captured := captureProxyServer(t)
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Credentials = nil
		o.APIKey = "tk_live_legacy"
	})
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	seen, _, _ := captured()
	// The proxy's OAuth detection matches `Bearer kc_` only — tk_ must use the header.
	if got := seen.Get("x-knoxcall-key"); got != "tk_live_legacy" {
		t.Errorf("x-knoxcall-key = %q, want tk_live_legacy", got)
	}
	if got := seen.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want absent (Bearer tk_ falls to the legacy path and 401s)", got)
	}
}

func TestEphemeralKeepsLegacyKeyAsBearer(t *testing.T) {
	ts, captured := captureProxyServer(t)
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Credentials = nil
		o.APIKey = "tk_live_legacy"
	})
	res, err := c.Ephemeral(context.Background(), "https://upstream.example.test/v1/x", nil)
	if err != nil {
		t.Fatalf("Ephemeral: %v", err)
	}
	mustClose(t, res)

	seen, _, _ := captured()
	if got := seen.Get("Authorization"); got != "Bearer tk_live_legacy" {
		t.Errorf("Authorization = %q, want Bearer tk_live_legacy (/v1/proxy accepts any format as Bearer)", got)
	}
	if got := seen.Get("x-knoxcall-key"); got != "" {
		t.Errorf("x-knoxcall-key = %q, want absent on the ephemeral path", got)
	}
}

// ── Bound routes (PARITY §6) ──────────────────────────────────────────────────

func TestBoundRouteInjectsRouteEnvironmentAndHeaders(t *testing.T) {
	ts, captured := captureProxyServer(t)
	defer ts.Close()
	c := newTestClient(t, ts.URL, nil)

	printnode := c.Route("r_1", &BoundRouteOptions{
		Environment: "production",
		Headers:     map[string]string{"X-A": "bound"},
	})
	res, err := printnode.Get(context.Background(), "/computers", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	mustClose(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	seen, method, url := captured()
	if method != http.MethodGet {
		t.Errorf("method = %q, want GET", method)
	}
	if got := seen.Get("x-knoxcall-route"); got != "r_1" {
		t.Errorf("route header = %q, want r_1", got)
	}
	if got := seen.Get("x-knoxcall-environment"); got != "production" {
		t.Errorf("environment header = %q, want the bound default", got)
	}
	if got := seen.Get("X-A"); got != "bound" {
		t.Errorf("X-A = %q, want the bound header injected", got)
	}
	if !strings.HasSuffix(url, "/computers") {
		t.Errorf("url = %q, want suffix /computers", url)
	}
}

func TestBoundRoutePerCallValuesBeatBoundDefaults(t *testing.T) {
	ts, captured := captureProxyServer(t)
	defer ts.Close()
	c := newTestClient(t, ts.URL, nil)

	bound := c.Route("r_1", &BoundRouteOptions{
		Environment: "production",
		Headers:     map[string]string{"X-A": "bound", "X-B": "kept"},
	})
	res, err := bound.Post(context.Background(), "/printjobs", &CallOptions{
		Body:        map[string]int{"a": 1},
		Environment: "staging",
		Headers:     map[string]string{"X-A": "call"},
	})
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	mustClose(t, res)

	seen, method, _ := captured()
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if got := seen.Get("x-knoxcall-environment"); got != "staging" {
		t.Errorf("environment header = %q, want the per-call value to win", got)
	}
	if got := seen.Get("X-A"); got != "call" {
		t.Errorf("X-A = %q, want the per-call header to win the merge", got)
	}
	if got := seen.Get("X-B"); got != "kept" {
		t.Errorf("X-B = %q, want unconflicted bound headers to survive the merge", got)
	}
}

func TestBoundRouteGenericRequestMethod(t *testing.T) {
	ts, captured := captureProxyServer(t)
	defer ts.Close()
	c := newTestClient(t, ts.URL, nil)

	res, err := c.Route("r_1", nil).Request(context.Background(), http.MethodDelete, "/printjobs/42", nil)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	mustClose(t, res)

	seen, method, url := captured()
	if method != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", method)
	}
	if !strings.HasSuffix(url, "/printjobs/42") {
		t.Errorf("url = %q, want suffix /printjobs/42", url)
	}
	if got := seen.Get("x-knoxcall-route"); got != "r_1" {
		t.Errorf("route header = %q, want r_1", got)
	}
}

// ── Default environment (PARITY §2) ───────────────────────────────────────────

func TestClientDefaultEnvironmentAppliesToCalls(t *testing.T) {
	clearConstructionEnv(t)
	ts, captured := captureProxyServer(t)
	defer ts.Close()

	c, err := New(Options{
		Tenant: "acme", Environment: "production", APIKey: "kc_live_x",
		BaseURL: ts.URL, ProxyBaseURL: ts.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	res.Body.Close()
	if h, _, _ := captured(); h.Get("x-knoxcall-environment") != "production" {
		t.Fatalf("environment header = %q, want production", h.Get("x-knoxcall-environment"))
	}
}

func TestEnvironmentResolutionPerCallBeatsBoundBeatsClient(t *testing.T) {
	clearConstructionEnv(t)
	ts, captured := captureProxyServer(t)
	defer ts.Close()

	c, err := New(Options{
		Tenant: "acme", Environment: "client-env", APIKey: "kc_live_x",
		BaseURL: ts.URL, ProxyBaseURL: ts.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	res, err := c.Route("r_1", nil).Get(ctx, "/x", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
	if h, _, _ := captured(); h.Get("x-knoxcall-environment") != "client-env" {
		t.Fatalf("unbound route: environment = %q, want client-env", h.Get("x-knoxcall-environment"))
	}

	res, err = c.Route("r_1", &BoundRouteOptions{Environment: "bound-env"}).Get(ctx, "/x", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
	if h, _, _ := captured(); h.Get("x-knoxcall-environment") != "bound-env" {
		t.Fatalf("bound route: environment = %q, want bound-env", h.Get("x-knoxcall-environment"))
	}

	res, err = c.Route("r_1", &BoundRouteOptions{Environment: "bound-env"}).
		Get(ctx, "/x", &CallOptions{Environment: "call-env"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
	if h, _, _ := captured(); h.Get("x-knoxcall-environment") != "call-env" {
		t.Fatalf("per-call: environment = %q, want call-env", h.Get("x-knoxcall-environment"))
	}
}

func TestEnvironmentFromEnvVarWithExplicitWinning(t *testing.T) {
	clearConstructionEnv(t)
	t.Setenv("KNOXCALL_ENVIRONMENT", "staging")

	c, err := New(Options{Tenant: "acme", APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Environment != "staging" {
		t.Fatalf("env-var fallback: Environment = %q, want staging", c.opts.Environment)
	}

	c, err = New(Options{Tenant: "acme", Environment: "production", APIKey: "kc_live_x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Environment != "production" {
		t.Fatalf("explicit: Environment = %q, want production", c.opts.Environment)
	}
}
