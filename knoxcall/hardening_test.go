package knoxcall

// Tests for the hardened request pipeline — the Go port of the shapes in
// knoxcall-python/tests/test_hardening.py (see ../../PARITY.md).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newTestClient(t *testing.T, baseURL string, mod func(*Options)) *Client {
	t.Helper()
	opts := Options{
		Tenant:         "acme",
		BaseURL:        baseURL,
		ProxyBaseURL:   baseURL,
		Credentials:    ClientCredentials{ClientID: "tk_x", ClientSecret: "sec"},
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  5 * time.Millisecond,
	}
	if mod != nil {
		mod(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func writeToken(w http.ResponseWriter, token string, expiresIn any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
}

func mustClose(t *testing.T, res *http.Response) {
	t.Helper()
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

// failNTransport fails the first N requests matching match with err, then
// delegates to the real transport. Used to simulate transport-level failures
// that httptest handlers can't produce.
type failNTransport struct {
	base     http.RoundTripper
	match    func(*http.Request) bool
	err      error
	mu       sync.Mutex
	failures int
	attempts int
}

func (tr *failNTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if tr.match(req) {
		tr.mu.Lock()
		tr.attempts++
		shouldFail := tr.failures > 0
		if shouldFail {
			tr.failures--
		}
		tr.mu.Unlock()
		if shouldFail {
			return nil, tr.err
		}
	}
	return tr.base.RoundTrip(req)
}

// ── call() hardening ──────────────────────────────────────────────────────────

func TestCallPurgesTokenAndRemintsOnceOn401(t *testing.T) {
	var mu sync.Mutex
	var minted []string
	seq := []string{"kc_live_revoked", "kc_live_fresh"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tok := seq[len(minted)]
			minted = append(minted, tok)
			mu.Unlock()
			writeToken(w, tok, 3600)
			return
		}
		if r.Header.Get("Authorization") == "Bearer kc_live_revoked" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(minted) != 2 || minted[0] != "kc_live_revoked" || minted[1] != "kc_live_fresh" {
		t.Fatalf("minted = %v, want [kc_live_revoked kc_live_fresh]", minted)
	}
}

func TestCallSecond401IsReturnedNotLooped(t *testing.T) {
	var mu sync.Mutex
	tokenCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			writeToken(w, "kc_live_bad", 3600)
			return
		}
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	if res.StatusCode != 401 {
		t.Fatalf("status = %d, want 401 returned as-is", res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 2 {
		t.Fatalf("tokenCalls = %d, want 2 (original + single re-mint, no loop)", tokenCalls)
	}
}

func TestCallDoesNotReplayPostOnLateTransportFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	tr := &failNTransport{
		base:     http.DefaultTransport,
		match:    func(r *http.Request) bool { return r.URL.Path == "/x" },
		err:      errors.New("read: connection reset by peer"), // NOT a dial error
		failures: 1,
	}
	c := newTestClient(t, ts.URL, func(o *Options) {
		o.HTTPClient = &http.Client{Transport: tr}
	})

	_, err := c.Call(context.Background(), "r_1", &CallOptions{
		Method: "POST", Path: "/x", Body: map[string]int{"a": 1},
	})
	var ce *ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v (%T), want *ConnectionError", err, err)
	}
	if tr.attempts != 1 {
		t.Fatalf("attempts = %d, want 1 — a mutating request must never be replayed", tr.attempts)
	}
}

func TestCallRetriesLateTransportFailureForGet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	tr := &failNTransport{
		base:     http.DefaultTransport,
		match:    func(r *http.Request) bool { return r.URL.Path == "/x" },
		err:      errors.New("read: connection reset by peer"),
		failures: 1,
	}
	c := newTestClient(t, ts.URL, func(o *Options) {
		o.HTTPClient = &http.Client{Transport: tr}
	})

	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	if res.StatusCode != 200 || tr.attempts != 2 {
		t.Fatalf("status = %d, attempts = %d; want 200 after one transparent GET retry", res.StatusCode, tr.attempts)
	}
}

func TestCallRetriesConnectRefusedEvenForPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	dialRefused := &net.OpError{
		Op: "dial", Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	}
	tr := &failNTransport{
		base:     http.DefaultTransport,
		match:    func(r *http.Request) bool { return r.URL.Path == "/x" },
		err:      dialRefused,
		failures: 1,
	}
	c := newTestClient(t, ts.URL, func(o *Options) {
		o.HTTPClient = &http.Client{Transport: tr}
	})

	res, err := c.Call(context.Background(), "r_1", &CallOptions{
		Method: "POST", Path: "/x", Body: map[string]int{"a": 1},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	if res.StatusCode != 200 || tr.attempts != 2 {
		t.Fatalf("status = %d, attempts = %d; want 200 — request never left the machine, so replay is safe", res.StatusCode, tr.attempts)
	}
}

func TestCallPerCallTimeoutViaContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	// Prime the token cache so only the proxied call hits the deadline.
	if _, err := c.getToken(context.Background()); err != nil {
		t.Fatalf("getToken: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := c.Call(ctx, "r_1", &CallOptions{Path: "/x"})
	var cte *ConnectionTimeoutError
	if !errors.As(err, &cte) {
		t.Fatalf("err = %v (%T), want *ConnectionTimeoutError", err, err)
	}
}

func TestCallExplicitArgsBeatCallerHeaders(t *testing.T) {
	var mu sync.Mutex
	seen := http.Header{}
	seenURL := ""

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_real", 3600)
			return
		}
		mu.Lock()
		seen = r.Header.Clone()
		seenURL = r.URL.String()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	res, err := c.Call(context.Background(), "r_1", &CallOptions{
		Path:        "/x",
		Environment: "production",
		Query:       url.Values{"page": {"2"}},
		Headers: map[string]string{
			"x-knoxcall-route":       "spoofed",
			"x-knoxcall-environment": "spoof-env",
			"Authorization":          "Bearer attacker",
			"X-Custom":               "1",
		},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	if got := seen.Get("x-knoxcall-route"); got != "r_1" {
		t.Errorf("route header = %q, want explicit argument to win", got)
	}
	if got := seen.Get("x-knoxcall-environment"); got != "production" {
		t.Errorf("environment header = %q, want explicit argument to win", got)
	}
	if got := seen.Get("Authorization"); got != "Bearer kc_live_real" {
		t.Errorf("authorization = %q, want the SDK-minted token to win", got)
	}
	if got := seen.Get("X-Custom"); got != "1" {
		t.Errorf("custom header = %q, want passthrough", got)
	}
	if !strings.Contains(seenURL, "page=2") {
		t.Errorf("url = %q, want query page=2", seenURL)
	}
}

// SECURITY (PARITY §5): the SDK is the only source of proxy auth. Any
// caller-supplied proxy-consumed auth header (x-knoxcall-agent-id /
// -agent-token / -key, Authorization, DPoP) must be stripped before dispatch,
// so a caller can neither impersonate another agent nor smuggle a credential
// the proxy would honor. Covers both the kc_ (SDK sets Authorization: Bearer)
// and the legacy tk_ (SDK sets x-knoxcall-key, leaving Authorization unset —
// the caller's Authorization must NOT survive) transmission paths.
func TestCallStripsCallerSuppliedProxyAuthHeaders(t *testing.T) {
	cases := []struct {
		name     string
		token    string
		wantAuth string
		wantKey  string
	}{
		{"kc token → Bearer", "kc_live_real", "Bearer kc_live_real", ""},
		{"legacy tk token → x-knoxcall-key", "tk_live_legacy", "", "tk_live_legacy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen http.Header
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					writeToken(w, tc.token, 3600)
					return
				}
				mu.Lock()
				seen = r.Header.Clone()
				mu.Unlock()
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer ts.Close()

			c := newTestClient(t, ts.URL, nil)
			res, err := c.Call(context.Background(), "r_1", &CallOptions{
				Path: "/x",
				Headers: map[string]string{
					"x-knoxcall-agent-id":    "victim-agent",
					"x-knoxcall-agent-token": "stolen",
					"x-knoxcall-key":         "attacker-key",
					"Authorization":          "Bearer attacker",
					"DPoP":                   "attacker-proof",
					// The interceptors' reroute marker (PARITY §21.2) is SDK-owned
					// too: a caller must not relabel its own direct Calls as
					// intercepted. A direct Call never sets it, so a survivor here
					// could only be this injected copy.
					"x-knoxcall-origin": "sdk-intercept",
					"X-Custom":          "keep",
				},
			})
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			mustClose(t, res)

			mu.Lock()
			defer mu.Unlock()
			for _, h := range []string{"x-knoxcall-agent-id", "x-knoxcall-agent-token", "DPoP", "x-knoxcall-origin"} {
				if got := seen.Get(h); got != "" {
					t.Errorf("%s = %q, want stripped", h, got)
				}
			}
			if got := seen.Get("Authorization"); got != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q (SDK credential authoritative)", got, tc.wantAuth)
			}
			if got := seen.Get("x-knoxcall-key"); got != tc.wantKey {
				t.Errorf("x-knoxcall-key = %q, want %q", got, tc.wantKey)
			}
			if got := seen.Get("X-Custom"); got != "keep" {
				t.Errorf("X-Custom = %q, want non-auth caller headers preserved", got)
			}
		})
	}
}

// Ephemeral targets /v1/proxy and legitimately sends the credential as Bearer,
// but must still strip caller-supplied agent headers (and the caller's own
// Authorization, which the SDK-set Bearer overrides).
func TestEphemeralStripsCallerAgentHeadersButSetsSDKAuthorization(t *testing.T) {
	var mu sync.Mutex
	var seen http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_real", 3600)
			return
		}
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	res, err := c.Ephemeral(context.Background(), "https://upstream.example.test/v1/x", &EphemeralOptions{
		Headers: map[string]string{
			"x-knoxcall-agent-id":    "victim-agent",
			"x-knoxcall-agent-token": "stolen",
			"Authorization":          "Bearer attacker",
		},
	})
	if err != nil {
		t.Fatalf("Ephemeral: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	if got := seen.Get("x-knoxcall-agent-id"); got != "" {
		t.Errorf("x-knoxcall-agent-id = %q, want stripped on the ephemeral path", got)
	}
	if got := seen.Get("x-knoxcall-agent-token"); got != "" {
		t.Errorf("x-knoxcall-agent-token = %q, want stripped on the ephemeral path", got)
	}
	if got := seen.Get("Authorization"); got != "Bearer kc_live_real" {
		t.Errorf("Authorization = %q, want the SDK-set Bearer to win over the caller's", got)
	}
}

// Wrap-support (PR2): mode "transparent" and upstreamAuthorization thread two
// optional SDK headers onto the ephemeral path without touching the KnoxCall
// auth path or body encoding. Both are additive — omitting them must leave the
// existing behaviour byte-for-byte unchanged.
func TestEphemeralWrapSupportHeaders(t *testing.T) {
	t.Run("both set emit their headers", func(t *testing.T) {
		var mu sync.Mutex
		var seen http.Header
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(w, "kc_live_real", 3600)
				return
			}
			mu.Lock()
			seen = r.Header.Clone()
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer ts.Close()

		c := newTestClient(t, ts.URL, nil)
		res, err := c.Ephemeral(context.Background(), "https://upstream.example.test/charge", &EphemeralOptions{
			Method:                "POST",
			Mode:                  "transparent",
			UpstreamAuthorization: "Bearer sk_test_provider",
			UpstreamAuthSecret:    "stripe-secret",
			UpstreamAuthScheme:    "Bearer",
		})
		if err != nil {
			t.Fatalf("Ephemeral: %v", err)
		}
		mustClose(t, res)

		mu.Lock()
		defer mu.Unlock()
		if got := seen.Get("X-Knox-Proxy-Mode"); got != "transparent" {
			t.Errorf("X-Knox-Proxy-Mode = %q, want %q", got, "transparent")
		}
		if got := seen.Get("X-Knox-Upstream-Authorization"); got != "Bearer sk_test_provider" {
			t.Errorf("X-Knox-Upstream-Authorization = %q, want the opaque upstream credential", got)
		}
		if got := seen.Get("X-Knox-Upstream-Auth-Secret"); got != "stripe-secret" {
			t.Errorf("X-Knox-Upstream-Auth-Secret = %q, want the escrowed wrap-credential name", got)
		}
		if got := seen.Get("X-Knox-Upstream-Auth-Scheme"); got != "Bearer" {
			t.Errorf("X-Knox-Upstream-Auth-Scheme = %q, want the resolved-secret auth scheme", got)
		}
		// The SDK's own KnoxCall auth is unaffected by upstreamAuthorization.
		if got := seen.Get("Authorization"); got != "Bearer kc_live_real" {
			t.Errorf("Authorization = %q, want the SDK-minted KnoxCall token untouched", got)
		}
	})

	t.Run("unset omits both headers", func(t *testing.T) {
		var mu sync.Mutex
		var seen http.Header
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/oauth/token" {
				writeToken(w, "kc_live_real", 3600)
				return
			}
			mu.Lock()
			seen = r.Header.Clone()
			mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer ts.Close()

		c := newTestClient(t, ts.URL, nil)
		res, err := c.Ephemeral(context.Background(), "https://upstream.example.test/x", &EphemeralOptions{})
		if err != nil {
			t.Fatalf("Ephemeral: %v", err)
		}
		mustClose(t, res)

		mu.Lock()
		defer mu.Unlock()
		if _, ok := seen["X-Knox-Proxy-Mode"]; ok {
			t.Errorf("X-Knox-Proxy-Mode present = %q, want omitted by default", seen.Get("X-Knox-Proxy-Mode"))
		}
		if _, ok := seen["X-Knox-Upstream-Authorization"]; ok {
			t.Errorf("X-Knox-Upstream-Authorization present, want omitted by default")
		}
		if _, ok := seen["X-Knox-Upstream-Auth-Secret"]; ok {
			t.Errorf("X-Knox-Upstream-Auth-Secret present, want omitted by default")
		}
		if _, ok := seen["X-Knox-Upstream-Auth-Scheme"]; ok {
			t.Errorf("X-Knox-Upstream-Auth-Scheme present, want omitted by default")
		}
	})
}

// ── Concurrency (run with -race) ──────────────────────────────────────────────

func TestConcurrentGoroutinesShareOneClientSingleTokenMint(t *testing.T) {
	var mu sync.Mutex
	tokenCalls, proxyCalls := 0, 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			time.Sleep(5 * time.Millisecond) // widen the single-flight window
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		proxyCalls++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	var wg sync.WaitGroup
	statuses := make(chan int, 32)
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/things"})
			if err != nil {
				errs <- err
				return
			}
			statuses <- res.StatusCode
			mustClose(t, res)
		}()
	}
	wg.Wait()
	close(statuses)
	close(errs)

	for err := range errs {
		t.Fatalf("Call: %v", err)
	}
	for s := range statuses {
		if s != 200 {
			t.Fatalf("status = %d, want 200", s)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if proxyCalls != 32 {
		t.Fatalf("proxyCalls = %d, want 32", proxyCalls)
	}
	if tokenCalls != 1 {
		t.Fatalf("tokenCalls = %d, want 1 — single-flight must hold across goroutines", tokenCalls)
	}
}

// ── Token lifecycle ───────────────────────────────────────────────────────────

// A static AccessToken gets a ~1h synthetic expiry and NO synthetic lifetime
// (the references use 1h, not 24h, and leave lifetime unset — there is nothing
// to refresh). fetchToken makes no HTTP for the AccessToken case.
func TestStaticAccessTokenGetsOneHourSyntheticExpiryNoLifetime(t *testing.T) {
	c := newTestClient(t, "https://api.example.test", func(o *Options) {
		o.Credentials = AccessToken{Token: "kc_live_static"}
	})
	tok, err := c.fetchToken(context.Background())
	if err != nil {
		t.Fatalf("fetchToken: %v", err)
	}
	if tok.accessToken != "kc_live_static" || tok.tokenType != "Bearer" {
		t.Fatalf("token = %+v, want the static token attached as Bearer", tok)
	}
	if ttl := time.Until(tok.expiresAt); ttl < 55*time.Minute || ttl > 65*time.Minute {
		t.Fatalf("synthetic expiry ttl = %v, want ~1h (not the old 24h)", ttl)
	}
	if tok.lifetime != 0 {
		t.Fatalf("lifetime = %v, want 0 — a static access token has nothing to refresh", tok.lifetime)
	}
}

func TestShortLivedTokensNotRefetchedEveryRequest(t *testing.T) {
	var mu sync.Mutex
	tokenCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			writeToken(w, "kc_live_aaaa", 60) // shorter than the 5-min window
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	for i := 0; i < 5; i++ {
		res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
		if err != nil {
			t.Fatalf("Call %d: %v", i, err)
		}
		mustClose(t, res)
	}
	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 1 {
		t.Fatalf("tokenCalls = %d, want 1 — refresh-ahead must be min(300s, lifetime/2)", tokenCalls)
	}
}

func TestStaleButValidTokenUsedWhenTokenEndpointDown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"auth": r.Header.Get("Authorization")})
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	// Inside the refresh-ahead window (lifetime 1h → window 5m, 60s left),
	// but still genuinely valid.
	c.mu.Lock()
	c.tokenCache = &cachedToken{
		accessToken: "kc_live_stale",
		tokenType:   "Bearer",
		expiresAt:   time.Now().Add(60 * time.Second),
		lifetime:    time.Hour,
	}
	c.mu.Unlock()

	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	defer res.Body.Close()
	var body struct{ Auth string }
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Auth != "Bearer kc_live_stale" {
		t.Fatalf("auth = %q, want the stale-but-valid token", body.Auth)
	}
}

func TestTokenResponseParsingSurvivesStringExpiresIn(t *testing.T) {
	var mu sync.Mutex
	tokenCalls := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tokenCalls++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"kc_live_aaaa","token_type":"Bearer","expires_in":"120"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	for i := 0; i < 2; i++ {
		res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
		if err != nil {
			t.Fatalf("Call: %v", err)
		}
		mustClose(t, res)
	}
	mu.Lock()
	defer mu.Unlock()
	if tokenCalls != 1 {
		t.Fatalf("tokenCalls = %d, want 1 — string expires_in must parse as a real lifetime", tokenCalls)
	}
}

func TestTokenResponseNonJSON200IsTypedError(t *testing.T) {
	for name, payload := range map[string]string{
		"html body":            "<html>edge proxy says hi</html>",
		"missing access_token": `{"token_type":"Bearer","expires_in":3600}`,
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(payload))
			}))
			defer ts.Close()

			c := newTestClient(t, ts.URL, nil)
			_, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
			var ae *APIError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v (%T), want a typed *APIError, never a raw decode error", err, err)
			}
			if !strings.Contains(err.Error(), "unexpected response") {
				t.Fatalf("err = %v, want 'unexpected response'", err)
			}
		})
	}
}

// ── DPoP (PARITY §7) ──────────────────────────────────────────────────────────

func decodeJWTPart(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode JWT part: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal JWT part: %v", err)
	}
	return m
}

func TestDPoPTokenTypeWithoutKeypairIsClearError(t *testing.T) {
	// The server hands back a DPoP-bound token without ever challenging
	// (no invalid_dpop_proof), so no keypair exists in either mode — the
	// SDK must fail loudly, never send "Authorization: DPoP" proofless.
	for _, mode := range []string{"never", "auto"} {
		t.Run(mode, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				payload := map[string]any{"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(payload)
			}))
			defer ts.Close()

			c := newTestClient(t, ts.URL, func(o *Options) { o.DPoP = mode })
			_, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
			if err == nil || !strings.Contains(err.Error(), "DPoP") {
				t.Fatalf("err = %v, want a clear DPoP error (never Authorization: DPoP without a proof)", err)
			}
		})
	}
}

func TestDPoPInvalidModeRejectedAtConstruction(t *testing.T) {
	_, err := New(Options{Tenant: "acme", APIKey: "tk_x", DPoP: "sometimes"})
	if err == nil || !strings.Contains(err.Error(), "invalid DPoP mode") {
		t.Fatalf("err = %v, want a construction error for an unknown DPoP mode", err)
	}
}

func TestDPoPAutoUpgradesWhenClientRequiresIt(t *testing.T) {
	var mu sync.Mutex
	var tokenProofs []string
	var dataAuth, dataProof string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			proof := r.Header.Get("DPoP")
			mu.Lock()
			tokenProofs = append(tokenProofs, proof)
			mu.Unlock()
			if proof == "" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"DPoP proof required"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600,
			})
			return
		}
		mu.Lock()
		dataAuth = r.Header.Get("Authorization")
		dataProof = r.Header.Get("DPoP")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil) // default mode: "auto"
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: "/x"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	if len(tokenProofs) != 2 || tokenProofs[0] != "" || tokenProofs[1] == "" {
		t.Fatalf("tokenProofs = %q, want exactly one proofless attempt then one retry with a proof", tokenProofs)
	}
	if !strings.HasPrefix(dataAuth, "DPoP kc_live_dpop") {
		t.Fatalf("Authorization = %q, want DPoP scheme after upgrade", dataAuth)
	}
	if len(strings.Split(dataProof, ".")) != 3 {
		t.Fatalf("data-plane DPoP header = %q, want a 3-part JWT", dataProof)
	}
}

func TestDPoPAlwaysSendsProofOnTokenAndDataPlane(t *testing.T) {
	var mu sync.Mutex
	var tokenProof, dataAuth, dataProof string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			tokenProof = r.Header.Get("DPoP")
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "kc_live_dpop", "token_type": "DPoP", "expires_in": 3600,
			})
			return
		}
		mu.Lock()
		dataAuth = r.Header.Get("Authorization")
		dataProof = r.Header.Get("DPoP")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) { o.DPoP = "always" })
	res, err := c.Call(context.Background(), "r_1",
		&CallOptions{Path: "/x", Query: url.Values{"a": {"1"}}})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)

	mu.Lock()
	defer mu.Unlock()
	// Token request itself carries a proof (POST, no ath — no token yet).
	tokenParts := strings.Split(tokenProof, ".")
	if len(tokenParts) != 3 {
		t.Fatalf("token DPoP header = %q, want a 3-part JWT", tokenProof)
	}
	tokenClaims := decodeJWTPart(t, tokenParts[1])
	if tokenClaims["htm"] != "POST" || tokenClaims["htu"] != ts.URL+"/oauth/token" {
		t.Fatalf("token proof claims = %v, want htm POST / htu %s/oauth/token", tokenClaims, ts.URL)
	}
	if _, hasAth := tokenClaims["ath"]; hasAth {
		t.Fatalf("token proof must not carry ath (no token presented yet): %v", tokenClaims)
	}

	if dataAuth != "DPoP kc_live_dpop" {
		t.Fatalf("Authorization = %q, want %q", dataAuth, "DPoP kc_live_dpop")
	}
	dataParts := strings.Split(dataProof, ".")
	if len(dataParts) != 3 {
		t.Fatalf("data-plane DPoP header = %q, want a 3-part JWT", dataProof)
	}
	header := decodeJWTPart(t, dataParts[0])
	if header["alg"] != "ES256" || header["typ"] != "dpop+jwt" {
		t.Fatalf("proof header = %v, want alg ES256 / typ dpop+jwt", header)
	}
	claims := decodeJWTPart(t, dataParts[1])
	if claims["htm"] != "GET" {
		t.Fatalf("htm = %v, want GET", claims["htm"])
	}
	if claims["htu"] != ts.URL+"/x" {
		t.Fatalf("htu = %v, want %s/x (query string stripped)", claims["htu"], ts.URL)
	}
	if ath, _ := claims["ath"].(string); ath == "" {
		t.Fatalf("data-plane proof missing ath binding: %v", claims)
	}
}

func TestDPoPProofShapeAndThumbprint(t *testing.T) {
	kp, err := generateDpopKeyPair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	tp1, err := kp.thumbprint()
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	tp2, _ := kp.thumbprint()
	if tp1 == "" || tp1 != tp2 {
		t.Fatalf("thumbprint = %q / %q, want stable non-empty value", tp1, tp2)
	}

	proof1, err := kp.sign("get", "https://x.example/path?q=1#frag", "kc_live_tok", "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(proof1, ".")
	if len(parts) != 3 {
		t.Fatalf("proof = %q, want 3 parts", proof1)
	}
	claims := decodeJWTPart(t, parts[1])
	if claims["htm"] != "GET" || claims["htu"] != "https://x.example/path" {
		t.Fatalf("claims = %v, want htm GET / htu without query+fragment", claims)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatalf("claims = %v, want a jti", claims)
	}

	proof2, _ := kp.sign("get", "https://x.example/path?q=1#frag", "kc_live_tok", "")
	claims2 := decodeJWTPart(t, strings.Split(proof2, ".")[1])
	if claims["jti"] == claims2["jti"] {
		t.Fatalf("jti reused across proofs — every proof must be fresh")
	}
}

// ── Management API retry pipeline ─────────────────────────────────────────────

func TestManagementRetries503ThenSucceeds(t *testing.T) {
	var mu sync.Mutex
	hits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		hits++
		n := hits
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[],"meta":{"total":0,"page":1,"per_page":20,"total_pages":0,"request_id":"req_mock"}}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("List: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (one retry on 503)", hits)
	}
}

func TestManagementDoesNotRetry409(t *testing.T) {
	var mu sync.Mutex
	hits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"error":"conflict","message":"route already exists"}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	_, err := c.Routes.Create(context.Background(), CreateRouteInput{Name: "r", TargetBaseURL: "https://x"})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v (%T), want *ConflictError", err, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 — a real conflict does not resolve by replaying", hits)
	}
}

func TestIdempotencyKeyStableAcrossRetriesAndAbsentOnGet(t *testing.T) {
	var mu sync.Mutex
	var postKeys []string
	getKey := "unset"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		if r.Method == http.MethodPost {
			mu.Lock()
			postKeys = append(postKeys, r.Header.Get("X-Idempotency-Key"))
			n := len(postKeys)
			mu.Unlock()
			if n == 1 {
				w.WriteHeader(503)
				_, _ = w.Write([]byte(`{"error":"unavailable"}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"id":"r_1","name":"r"},"meta":{"request_id":"req_mock"}}`))
			return
		}
		mu.Lock()
		getKey = r.Header.Get("X-Idempotency-Key")
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":[],"meta":{"total":0,"page":1,"per_page":20,"total_pages":0,"request_id":"req_mock"}}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	if _, err := c.Routes.Create(context.Background(), CreateRouteInput{Name: "r", TargetBaseURL: "https://x"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("List: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(postKeys) != 2 || postKeys[0] == "" || postKeys[0] != postKeys[1] {
		t.Fatalf("postKeys = %v, want one non-empty ULID stable across both attempts", postKeys)
	}
	if len(postKeys[0]) != 26 {
		t.Fatalf("idempotency key %q has length %d, want a 26-char ULID", postKeys[0], len(postKeys[0]))
	}
	if getKey != "" {
		t.Fatalf("GET idempotency key = %q, want none", getKey)
	}
}

func TestManagementTransparentReauthOn401(t *testing.T) {
	var mu sync.Mutex
	minted := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			mu.Lock()
			minted++
			tok := fmt.Sprintf("kc_live_%d", minted)
			mu.Unlock()
			writeToken(w, tok, 3600)
			return
		}
		if r.Header.Get("Authorization") == "Bearer kc_live_1" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[],"meta":{"total":0,"page":1,"per_page":20,"total_pages":0,"request_id":"req_mock"}}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("List: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if minted != 2 {
		t.Fatalf("minted = %d, want 2 (one transparent re-auth)", minted)
	}
}

func TestRetryDelayHonorsRetryAfterCapped(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	c := newTestClient(t, ts.URL, nil)

	mkErr := func(retryAfter string) error {
		h := http.Header{}
		h.Set("Retry-After", retryAfter)
		return errorFromResponse(429, []byte(`{"error":"rate_limited"}`), h)
	}
	if d := c.retryDelay(mkErr("2"), 1); d != 2*time.Second {
		t.Errorf("retryDelay(Retry-After: 2) = %v, want 2s", d)
	}
	if d := c.retryDelay(mkErr("600"), 1); d != 30*time.Second {
		t.Errorf("retryDelay(Retry-After: 600) = %v, want capped at 30s", d)
	}
}

// ── Body encoding ─────────────────────────────────────────────────────────────

func TestRawBytesBodyPassesThroughWithCallerContentType(t *testing.T) {
	var mu sync.Mutex
	var seenBody []byte
	seenCT := ""

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenBody = b
		seenCT = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	res, err := c.Call(context.Background(), "r_1", &CallOptions{
		Method:  "POST",
		Path:    "/x",
		Body:    []byte("%PDF-1.4 raw"),
		Headers: map[string]string{"Content-Type": "application/pdf"},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	mu.Lock()
	defer mu.Unlock()
	if string(seenBody) != "%PDF-1.4 raw" {
		t.Errorf("body = %q, want raw passthrough", seenBody)
	}
	if seenCT != "application/pdf" {
		t.Errorf("content-type = %q, want caller's value respected", seenCT)
	}
}

func TestStructBodyEncodesTimeTimeAndDefaultsJSONContentType(t *testing.T) {
	var mu sync.Mutex
	var seenBody []byte
	seenCT := ""

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenBody = b
		seenCT = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	when := time.Date(2026, 6, 10, 12, 30, 0, 0, time.UTC)
	c := newTestClient(t, ts.URL, nil)
	res, err := c.Call(context.Background(), "r_1", &CallOptions{
		Method: "POST", Path: "/x",
		Body: map[string]any{"when": when},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	mu.Lock()
	defer mu.Unlock()
	if seenCT != "application/json" {
		t.Errorf("content-type = %q, want application/json default", seenCT)
	}
	var decoded struct{ When time.Time }
	if err := json.Unmarshal(seenBody, &decoded); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if !decoded.When.Equal(when) {
		t.Errorf("when = %v, want %v (encoding/json must cover time.Time)", decoded.When, when)
	}
}

func TestCallerSuppliedMarshalHook(t *testing.T) {
	var mu sync.Mutex
	var seenBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenBody = b
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.JSONMarshal = func(v any) ([]byte, error) {
			return []byte(`{"hooked":true}`), nil
		}
	})
	res, err := c.Call(context.Background(), "r_1", &CallOptions{
		Method: "POST", Path: "/x", Body: map[string]int{"a": 1},
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	mustClose(t, res)
	mu.Lock()
	defer mu.Unlock()
	if string(seenBody) != `{"hooked":true}` {
		t.Errorf("body = %q, want output of the caller-supplied marshal hook", seenBody)
	}
}

// ── Secret hygiene + error names ──────────────────────────────────────────────

func TestCredentialFmtOutputNeverLeaksSecrets(t *testing.T) {
	cc := ClientCredentials{ClientID: "tk_x", ClientSecret: "supersecret"}
	at := AccessToken{Token: "kc_live_topsecret"}
	oidc := OIDCTokenExchange{SubjectToken: "jwt_secret_token", Issuer: "https://oidc.vercel.com"}
	opts := Options{Tenant: "acme", APIKey: "kc_key_secret", ClientID: "tk_x", ClientSecret: "supersecret"}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for name, v := range map[string]any{
			"ClientCredentials":  cc,
			"&ClientCredentials": &cc,
			"AccessToken":        at,
			"OIDCTokenExchange":  oidc,
			"Options":            opts,
		} {
			out := fmt.Sprintf(verb, v)
			for _, secret := range []string{"supersecret", "kc_live_topsecret", "jwt_secret_token", "kc_key_secret"} {
				if strings.Contains(out, secret) {
					t.Errorf("%s via %s leaked a secret: %s", name, verb, out)
				}
			}
		}
	}
	// Non-sensitive fields stay visible for debuggability.
	if out := fmt.Sprintf("%+v", cc); !strings.Contains(out, "tk_x") {
		t.Errorf("ClientCredentials output hides ClientID (not sensitive): %s", out)
	}
	if out := fmt.Sprintf("%+v", oidc); !strings.Contains(out, "https://oidc.vercel.com") {
		t.Errorf("OIDCTokenExchange output hides Issuer (not sensitive): %s", out)
	}
}

func TestClientFmtOutputNeverLeaksSecretsOrTokens(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeToken(w, "kc_live_cached_secret", 3600)
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, func(o *Options) {
		o.Credentials = ClientCredentials{ClientID: "tk_x", ClientSecret: "client_secret_value"}
	})
	if _, err := c.getToken(context.Background()); err != nil {
		t.Fatalf("getToken: %v", err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, c)
		if strings.Contains(out, "client_secret_value") {
			t.Errorf("Client via %s leaked credentials: %s", verb, out)
		}
		if strings.Contains(out, "kc_live_cached_secret") {
			t.Errorf("Client via %s leaked the cached token: %s", verb, out)
		}
	}
}

func Test403MapsToPermissionDeniedError(t *testing.T) {
	var mu sync.Mutex
	hits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	_, err := c.Routes.List(context.Background(), nil)

	var pde *PermissionDeniedError
	if !errors.As(err, &pde) {
		t.Fatalf("err = %v (%T), want *PermissionDeniedError", err, err)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 403 {
		t.Fatalf("err must also unwrap to *APIError with status 403, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 — 403 is not retryable", hits)
	}
}

func Test402MapsToPaymentRequiredError(t *testing.T) {
	var mu sync.Mutex
	hits := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set("X-Request-Id", "req_402")
		w.WriteHeader(402)
		_, _ = w.Write([]byte(`{"error":{"type":"plan_limit","message":"upgrade required","request_id":"req_402"}}`))
	}))
	defer ts.Close()

	c := newTestClient(t, ts.URL, nil)
	_, err := c.Routes.List(context.Background(), nil)

	// 402 maps to its own typed error, distinct from 403's PermissionDenied.
	var pre *PaymentRequiredError
	if !errors.As(err, &pre) {
		t.Fatalf("err = %v (%T), want *PaymentRequiredError", err, err)
	}
	var pde *PermissionDeniedError
	if errors.As(err, &pde) {
		t.Fatalf("err = %v (%T), 402 must NOT be a *PermissionDeniedError (403)", err, err)
	}
	// Carries the same code/message/request_id the other typed errors do.
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 402 {
		t.Fatalf("err must unwrap to *APIError with status 402, got %v", err)
	}
	if ae.Message != "plan_limit" {
		t.Fatalf("code = %q, want %q", ae.Message, "plan_limit")
	}
	if ae.Detail != "upgrade required" {
		t.Fatalf("message = %q, want %q", ae.Detail, "upgrade required")
	}
	if ae.RequestID != "req_402" {
		t.Fatalf("request id = %q, want %q", ae.RequestID, "req_402")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 — 402 is not retryable", hits)
	}
}

func TestManagementRequestSendsKnoxCallVersionHeader(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":[],"meta":{"request_id":"req_1","total":0,"total_pages":0,"page":1,"per_page":20}}`)
	})
	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("Routes.List: %v", err)
	}
	reqs := requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(reqs))
	}
	if got := reqs[0].Header.Get("KnoxCall-Version"); got != "2026-08-05" {
		t.Fatalf("KnoxCall-Version = %q, want %q", got, "2026-08-05")
	}
	// The legacy header name must NOT be sent — the server no longer reads it.
	if got := reqs[0].Header.Get("X-KnoxCall-Api-Version"); got != "" {
		t.Fatalf("X-KnoxCall-Api-Version = %q, want it unset (renamed to KnoxCall-Version)", got)
	}
}

func TestULIDShape(t *testing.T) {
	a, b := newULID(), newULID()
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("ULID lengths = %d, %d; want 26", len(a), len(b))
	}
	if a == b {
		t.Fatalf("two ULIDs collided: %s", a)
	}
	for _, ch := range a {
		if !strings.ContainsRune(ulidAlphabet, ch) {
			t.Fatalf("ULID %q contains non-Crockford char %q", a, ch)
		}
	}
}
