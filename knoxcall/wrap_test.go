package knoxcall

// Coverage for the wrap-credential escrow resource: POST /v1/wrap/credentials
// carries the provider/name/value/hosts body, and the metadata envelope
// unwraps without ever echoing the raw value back. Captured at the HTTP
// boundary via envelopeServer, exactly like the secrets.Create coverage.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestWrapEscrow(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"secret_id":"sec_1","name":"stripe-live","provider":"stripe","allowed_hosts":["api.stripe.com"],"sandbox":false},"meta":{"request_id":"req_1"}}`)
	})

	res, err := c.Wrap.Escrow(context.Background(), WrapCredentialInput{
		Provider: "stripe",
		Name:     "stripe-live",
		Value:    "sk_live_supersecret",
		Hosts:    []string{"api.stripe.com"},
	})
	if err != nil {
		t.Fatalf("Escrow: %v", err)
	}
	if res.SecretID != "sec_1" || res.Name != "stripe-live" || res.Provider != "stripe" || res.Sandbox {
		t.Fatalf("Escrow = %+v, want the escrow metadata unwrapped", res)
	}
	if len(res.AllowedHosts) != 1 || res.AllowedHosts[0] != "api.stripe.com" {
		t.Fatalf("AllowedHosts = %v, want the pinned host echoed back", res.AllowedHosts)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/wrap/credentials" {
		t.Fatalf("request = %s %s, want POST /v1/wrap/credentials", req.Method, req.Path)
	}
	// Every mutating management request carries a stable idempotency key.
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Errorf("missing X-Idempotency-Key on the escrow POST")
	}
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal escrow body: %v", err)
	}
	if body["provider"] != "stripe" || body["name"] != "stripe-live" || body["value"] != "sk_live_supersecret" {
		t.Fatalf("body = %v, want the provider/name/value fields", body)
	}
	hosts, ok := body["hosts"].([]any)
	if !ok || len(hosts) != 1 || hosts[0] != "api.stripe.com" {
		t.Fatalf("body hosts = %v, want the load-bearing host pin", body["hosts"])
	}
}

func TestWrapGatewayURL(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"wtok_1","token":"kcg_secretbearer","base_url":"https://api-gw.knoxcall.com/wrap/kcg_secretbearer","host":"api.stripe.com","secret_id":"sec_1","sandbox":false,"expires_at":"2026-09-01T00:00:00Z"},"meta":{"request_id":"req_1"}}`)
	})

	res, err := c.Wrap.GatewayURL(context.Background(), GatewayURLInput{
		Secret:     "stripe-live",
		Host:       "api.stripe.com",
		TTLSeconds: 3600,
		Label:      "checkout worker",
	})
	if err != nil {
		t.Fatalf("GatewayURL: %v", err)
	}
	if res.ID != "wtok_1" || res.Token != "kcg_secretbearer" || res.Host != "api.stripe.com" || res.SecretID != "sec_1" || res.Sandbox {
		t.Fatalf("GatewayURL = %+v, want the minted gateway token unwrapped", res)
	}
	if res.BaseURL != "https://api-gw.knoxcall.com/wrap/kcg_secretbearer" {
		t.Fatalf("BaseURL = %q, want the gateway base URL echoed back", res.BaseURL)
	}
	if res.ExpiresAt == nil || *res.ExpiresAt != "2026-09-01T00:00:00Z" {
		t.Fatalf("ExpiresAt = %v, want the expiry decoded", res.ExpiresAt)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/wrap/tokens" {
		t.Fatalf("request = %s %s, want POST /v1/wrap/tokens", req.Method, req.Path)
	}
	// Every mutating management request carries a stable idempotency key.
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Errorf("missing X-Idempotency-Key on the mint POST")
	}
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal mint body: %v", err)
	}
	if body["secret"] != "stripe-live" || body["host"] != "api.stripe.com" {
		t.Fatalf("body = %v, want the secret + pinned host", body)
	}
	if body["ttl_seconds"] != float64(3600) || body["label"] != "checkout worker" {
		t.Fatalf("body = %v, want the snake_case ttl_seconds + label", body)
	}
}

func TestWrapGatewayURLOmitsEmptyOptionals(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"wtok_2","token":"kcg_x","base_url":"https://api-gw.knoxcall.com/wrap/kcg_x","host":"api.stripe.com","secret_id":"sec_1","sandbox":false,"expires_at":null},"meta":{"request_id":"req_2"}}`)
	})

	res, err := c.Wrap.GatewayURL(context.Background(), GatewayURLInput{Secret: "stripe-live"})
	if err != nil {
		t.Fatalf("GatewayURL: %v", err)
	}
	// A non-expiring token comes back with a null expiry.
	if res.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil for a non-expiring token", res.ExpiresAt)
	}

	var body map[string]any
	if err := json.Unmarshal(requests()[0].Body, &body); err != nil {
		t.Fatalf("unmarshal mint body: %v", err)
	}
	// Only `secret` is sent; the zero-value host/ttl_seconds/label/style are omitted.
	if body["secret"] != "stripe-live" {
		t.Fatalf("body = %v, want the secret sent", body)
	}
	for _, k := range []string{"host", "ttl_seconds", "label", "style"} {
		if _, present := body[k]; present {
			t.Errorf("body = %v, empty %q must be omitted", body, k)
		}
	}
}

// The optional base_url `style` selector (sdk-wrapping, 2026-08-22 wildcard-
// subdomain gateway): when set it is forwarded verbatim in the POST body, and
// the response's base_url_style is decoded onto the token. base_url stays
// opaque — the SDK passes it through unchanged.
func TestWrapGatewayURLStyle(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"wtok_3","token":"kcg_y","base_url":"https://ab12cd.wrap.knoxcall.com","base_url_style":"subdomain","host":"api.stripe.com","secret_id":"sec_1","sandbox":false,"expires_at":null},"meta":{"request_id":"req_3"}}`)
	})

	res, err := c.Wrap.GatewayURL(context.Background(), GatewayURLInput{
		Secret: "stripe-live",
		Host:   "api.stripe.com",
		Style:  "subdomain",
	})
	if err != nil {
		t.Fatalf("GatewayURL: %v", err)
	}
	// The server-selected form is surfaced on the token, and base_url is passed
	// through opaque.
	if res.BaseURLStyle != "subdomain" {
		t.Fatalf("BaseURLStyle = %q, want the returned base_url form decoded", res.BaseURLStyle)
	}
	if res.BaseURL != "https://ab12cd.wrap.knoxcall.com" {
		t.Fatalf("BaseURL = %q, want the subdomain gateway URL echoed back opaque", res.BaseURL)
	}

	var body map[string]any
	if err := json.Unmarshal(requests()[0].Body, &body); err != nil {
		t.Fatalf("unmarshal mint body: %v", err)
	}
	if body["style"] != "subdomain" {
		t.Fatalf("body = %v, want the style selector forwarded verbatim", body)
	}
}

func TestWrapListGatewayTokens(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		// The endpoint nests the slice under data.tokens (not a bare array).
		writeJSON(w, 200, `{"data":{"tokens":[{"id":"wtok_1","secret_id":"sec_1","host":"api.stripe.com","label":"checkout worker","created_at":"2026-08-01T00:00:00Z","expires_at":"2026-09-01T00:00:00Z","revoked_at":null,"last_used_at":null}]},"meta":{"request_id":"req_1"}}`)
	})

	tokens, err := c.Wrap.ListGatewayTokens(context.Background())
	if err != nil {
		t.Fatalf("ListGatewayTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("ListGatewayTokens returned %d rows, want 1", len(tokens))
	}
	tk := tokens[0]
	if tk.ID != "wtok_1" || tk.SecretID != "sec_1" || tk.Host != "api.stripe.com" {
		t.Fatalf("token = %+v, want the nested token metadata unwrapped", tk)
	}
	if tk.Label == nil || *tk.Label != "checkout worker" {
		t.Fatalf("Label = %v, want the label decoded", tk.Label)
	}
	if tk.CreatedAt == nil || tk.ExpiresAt == nil {
		t.Fatalf("token = %+v, want created_at/expires_at decoded", tk)
	}
	// An active, never-used token has null revoked_at/last_used_at.
	if tk.RevokedAt != nil || tk.LastUsedAt != nil {
		t.Fatalf("token = %+v, want nil revoked_at/last_used_at for an active token", tk)
	}

	req := requests()[0]
	if req.Method != http.MethodGet || req.Path != "/v1/wrap/tokens" {
		t.Fatalf("request = %s %s, want GET /v1/wrap/tokens", req.Method, req.Path)
	}
}

func TestWrapRevokeGatewayToken(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"wtok 1","revoked":true},"meta":{"request_id":"req_1"}}`)
	})

	// An id with a space proves the path is escaped, not concatenated raw.
	res, err := c.Wrap.RevokeGatewayToken(context.Background(), "wtok 1")
	if err != nil {
		t.Fatalf("RevokeGatewayToken: %v", err)
	}
	if res.ID != "wtok 1" || !res.Revoked {
		t.Fatalf("RevokeGatewayToken = %+v, want the revoked result unwrapped", res)
	}

	req := requests()[0]
	if req.Method != http.MethodDelete || req.Path != "/v1/wrap/tokens/wtok 1" {
		t.Fatalf("request = %s %s, want DELETE /v1/wrap/tokens/wtok%%201", req.Method, req.Path)
	}
	// Every mutating management request carries a stable idempotency key.
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Errorf("missing X-Idempotency-Key on the revoke DELETE")
	}
}

// ── Wrap RoundTripper (data-plane transport, sdk-wrapping PR4) ──────────────────
//
// The Go analog of the Node wrap.fetch() tests
// (sdk/knoxcall-node/test/wrap-transport.test.ts): capture is at the SDK's HTTP
// boundary (the /v1/proxy request the mock server records, or the injected base
// transport for route-around), never by mocking the RoundTripper itself.

const stripeForm = "amount=2000&currency=usd&source=tok_visa"

// recordingTransport is a base http.RoundTripper stub for route-around: it
// records the direct-to-provider request and answers 200 without any network.
type recordingTransport struct {
	got   *http.Request
	calls int
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.got = req
	rt.calls++
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"id":"tok_1"}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// Transit mode (default): the wrapped SDK's request is re-targeted to /v1/proxy
// in transparent mode, its own Authorization is lifted out-of-band (never a raw
// header), and the method / body bytes / Content-Type are forwarded verbatim.
func TestWrapRoundTripperTransitLiftsAuthorization(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"ok":true}`)
	})

	hc := &http.Client{Transport: c.Wrap.RoundTripper()}
	req, err := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(stripeForm))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer sk_live_provider")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Idempotency-Key", "idem-1")

	res, err := hc.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()

	reqs := requests()
	if len(reqs) != 1 {
		t.Fatalf("recorded %d requests, want exactly 1 to /v1/proxy", len(reqs))
	}
	got := reqs[0]
	if got.Method != http.MethodPost || got.Path != "/v1/proxy" {
		t.Fatalf("request = %s %s, want POST /v1/proxy", got.Method, got.Path)
	}
	// Re-targeted to KnoxCall's proxy in transparent mode.
	if u := got.Header.Get("X-Knox-Proxy-URL"); u != "https://api.stripe.com/v1/charges" {
		t.Errorf("X-Knox-Proxy-URL = %q, want the full upstream URL", u)
	}
	if m := got.Header.Get("X-Knox-Proxy-Mode"); m != "transparent" {
		t.Errorf("X-Knox-Proxy-Mode = %q, want transparent", m)
	}
	// Provider credential lifted out-of-band; the raw key is NOT forwarded.
	if a := got.Header.Get("X-Knox-Upstream-Authorization"); a != "Bearer sk_live_provider" {
		t.Errorf("X-Knox-Upstream-Authorization = %q, want the lifted provider key", a)
	}
	// KnoxCall's own credential authenticates the proxy call — never the sk_ key.
	if a := got.Header.Get("Authorization"); a != "Bearer kc_live_aaaa" {
		t.Errorf("Authorization = %q, want the SDK-minted KnoxCall token", a)
	}
	// SDK headers preserved; Content-Type verbatim; body byte-identical.
	if k := got.Header.Get("Idempotency-Key"); k != "idem-1" {
		t.Errorf("Idempotency-Key = %q, want the SDK header preserved", k)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want the SDK Content-Type forwarded verbatim", ct)
	}
	if string(got.Body) != stripeForm {
		t.Errorf("body = %q, want the form bytes forwarded verbatim", string(got.Body))
	}
}

// Escrow mode: the escrowed secret NAME is sent (X-Knox-Upstream-Auth-Secret)
// and the SDK's own (placeholder) key never travels out-of-band. An optional
// scheme threads through, and there is no Test/Live assertion (the SDK key is
// ignored).
func TestWrapRoundTripperEscrowUsesSecretRef(t *testing.T) {
	t.Run("secret ref sent, raw key never forwarded", func(t *testing.T) {
		c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"ok":true}`)
		})
		hc := &http.Client{Transport: c.Wrap.RoundTripper(WithEscrow("wrap-stripe-live"))}
		req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(stripeForm))
		req.Header.Set("Authorization", "Bearer sk_managed_by_knoxcall")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()

		got := requests()[0]
		if s := got.Header.Get("X-Knox-Upstream-Auth-Secret"); s != "wrap-stripe-live" {
			t.Errorf("X-Knox-Upstream-Auth-Secret = %q, want the escrowed credential name", s)
		}
		// The placeholder key the SDK set is NOT forwarded out-of-band.
		if a := got.Header.Get("X-Knox-Upstream-Authorization"); a != "" {
			t.Errorf("X-Knox-Upstream-Authorization = %q, want omitted in escrow mode", a)
		}
		if string(got.Body) != stripeForm {
			t.Errorf("body = %q, want the form bytes forwarded verbatim", string(got.Body))
		}
	})

	t.Run("custom scheme threads through", func(t *testing.T) {
		c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"ok":true}`)
		})
		hc := &http.Client{Transport: c.Wrap.RoundTripper(WithEscrow("wrap-x", "none"))}
		req, _ := http.NewRequest(http.MethodPost, "https://api.example.com/x", strings.NewReader("x"))
		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()
		if s := requests()[0].Header.Get("X-Knox-Upstream-Auth-Scheme"); s != "none" {
			t.Errorf("X-Knox-Upstream-Auth-Scheme = %q, want the custom scheme", s)
		}
	})
}

// Route-around: a raw-card endpoint (default rule) goes DIRECTLY to the provider
// via the base transport, untouched — KnoxCall is never contacted. A trailing-dot
// host still routes around (it can't dodge the exact-match rule).
func TestWrapRoundTripperRouteAroundBypasses(t *testing.T) {
	t.Run("default raw-card rule sends direct", func(t *testing.T) {
		c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("KnoxCall was contacted at %s, want the request routed around", r.URL.Path)
			writeJSON(w, 200, `{}`)
		})
		base := &recordingTransport{}
		var info RouteAroundInfo
		hc := &http.Client{Transport: c.Wrap.RoundTripper(
			WithBaseTransport(base),
			WithOnRouteAround(func(i RouteAroundInfo) { info = i }),
		)}
		req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/tokens", strings.NewReader("card[number]=4242424242424242"))
		req.Header.Set("Authorization", "Bearer sk_live_x")

		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()

		if base.calls != 1 {
			t.Fatalf("base transport calls = %d, want 1 (routed around)", base.calls)
		}
		// The ORIGINAL request goes direct, untouched (still targets the provider).
		if base.got.URL.Host != "api.stripe.com" || base.got.Header.Get("Authorization") != "Bearer sk_live_x" {
			t.Errorf("direct request = %s (auth %q), want the untouched provider request",
				base.got.URL, base.got.Header.Get("Authorization"))
		}
		if len(requests()) != 0 {
			t.Errorf("KnoxCall recorded %d requests, want 0 (routed around)", len(requests()))
		}
		if info.Host != "api.stripe.com" || info.Reason == "" {
			t.Errorf("onRouteAround info = %+v, want the host + reason surfaced", info)
		}
	})

	t.Run("trailing-dot host still routes around", func(t *testing.T) {
		c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("KnoxCall was contacted, want the trailing-dot host routed around")
			writeJSON(w, 200, `{}`)
		})
		base := &recordingTransport{}
		hc := &http.Client{Transport: c.Wrap.RoundTripper(WithBaseTransport(base))}
		req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com./v1/tokens", strings.NewReader("card[number]=4242"))
		req.Header.Set("Authorization", "Bearer sk_live_x")
		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()
		if base.calls != 1 {
			t.Fatalf("base transport calls = %d, want 1 (trailing-dot routed around)", base.calls)
		}
	})

	t.Run("a normal endpoint is NOT routed around", func(t *testing.T) {
		c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, `{"ok":true}`)
		})
		base := &recordingTransport{}
		hc := &http.Client{Transport: c.Wrap.RoundTripper(WithBaseTransport(base))}
		req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(stripeForm))
		req.Header.Set("Authorization", "Bearer sk_live_x")
		res, err := hc.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = res.Body.Close()
		if base.calls != 0 {
			t.Errorf("base transport calls = %d, want 0 (charges go through KnoxCall)", base.calls)
		}
		if len(requests()) != 1 {
			t.Errorf("KnoxCall recorded %d requests, want 1 (proxied)", len(requests()))
		}
	})
}

// Both-must-agree: a provider key whose Test/Live prefix disagrees with the
// client's Sandbox flag (or a publishable pk_ key) is rejected PRE-SEND — the
// error is a *WrapSandboxMismatchError and KnoxCall is never contacted.
func TestWrapRoundTripperSandboxMismatchErrors(t *testing.T) {
	cases := []struct {
		name    string
		sandbox bool
		auth    string
	}{
		{"test key on a live client", false, "Bearer sk_test_x"},
		{"live key on a sandbox client", true, "Bearer sk_live_x"},
		{"publishable key rejected outright", false, "Bearer pk_live_x"},
		{"leading space before Bearer is not a bypass", true, " Bearer sk_live_x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					writeToken(w, "kc_live_aaaa", 3600)
					return
				}
				atomic.AddInt32(&hits, 1)
				writeJSON(w, 200, `{"ok":true}`)
			}))
			defer ts.Close()

			c := newTestClient(t, ts.URL, func(o *Options) { o.Sandbox = tc.sandbox })
			hc := &http.Client{Transport: c.Wrap.RoundTripper()}
			req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(""))
			req.Header.Set("Authorization", tc.auth)

			res, err := hc.Do(req)
			if err == nil {
				_ = res.Body.Close()
				t.Fatalf("Do = nil error, want a sandbox-mismatch rejection")
			}
			var mism *WrapSandboxMismatchError
			if !errors.As(err, &mism) {
				t.Fatalf("err = %v (%T), want *WrapSandboxMismatchError", err, err)
			}
			if n := atomic.LoadInt32(&hits); n != 0 {
				t.Errorf("KnoxCall received %d proxy requests, want 0 (rejected pre-send)", n)
			}
		})
	}
}

// A restricted key (rk_) matching the Sandbox flag is accepted and lifted.
func TestWrapRoundTripperAcceptsRestrictedKey(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"ok":true}`)
	})
	hc := &http.Client{Transport: c.Wrap.RoundTripper()} // sandbox=false
	req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer rk_live_restricted")
	res, err := hc.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = res.Body.Close()
	if a := requests()[0].Header.Get("X-Knox-Upstream-Authorization"); a != "Bearer rk_live_restricted" {
		t.Errorf("X-Knox-Upstream-Authorization = %q, want the restricted key lifted", a)
	}
}

// A misconfigured escrow (empty secret) fails CLOSED on every RoundTrip rather
// than silently falling through to transit and leaking the SDK's raw key.
func TestWrapRoundTripperEmptyEscrowFailsClosed(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("KnoxCall was contacted, want the misconfigured transport to fail closed")
		writeJSON(w, 200, `{}`)
	})
	hc := &http.Client{Transport: c.Wrap.RoundTripper(WithEscrow(""))}
	req, _ := http.NewRequest(http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer sk_live_provider")
	res, err := hc.Do(req)
	if err == nil {
		_ = res.Body.Close()
		t.Fatalf("Do = nil error, want a WrapConfigError")
	}
	var cfgErr *WrapConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %v (%T), want *WrapConfigError", err, err)
	}
	if len(requests()) != 0 {
		t.Errorf("KnoxCall recorded %d requests, want 0 (failed closed)", len(requests()))
	}
}

// A non-bare route-around host (scheme/port/path) fails closed rather than
// silently never matching.
func TestWrapRoundTripperInvalidRouteAroundHostFailsClosed(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"ok":true}`)
	})
	hc := &http.Client{Transport: c.Wrap.RoundTripper(
		WithRouteAround(RouteAroundRule{Host: "https://api.stripe.com", Reason: "x"}),
	)}
	req, _ := http.NewRequest(http.MethodGet, "https://api.stripe.com/v1/charges", nil)
	res, err := hc.Do(req)
	if err == nil {
		_ = res.Body.Close()
		t.Fatalf("Do = nil error, want a WrapConfigError for the non-bare host")
	}
	var cfgErr *WrapConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err = %v (%T), want *WrapConfigError", err, err)
	}
}

// The request's context is honored: a cancelled context aborts the proxied call
// instead of hanging.
func TestWrapRoundTripperHonorsContext(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"ok":true}`)
	})
	hc := &http.Client{Transport: c.Wrap.RoundTripper()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the call
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.stripe.com/v1/charges", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer sk_live_x")
	res, err := hc.Do(req)
	if err == nil {
		_ = res.Body.Close()
		t.Fatalf("Do = nil error, want the cancelled context to abort the call")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled propagated", err)
	}
}

func TestWrapInterceptManifest(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		env := r.URL.Query().Get("environment")
		if env == "" {
			env = "production"
		}
		writeJSON(w, 200, `{"data":{"version":"sha256:abc","ttl_seconds":60,"environment":"`+env+`","sandbox":false,"routes":[{"host":"api.hubapi.com","base_path":"/crm/v3","slug":"hubspot","route_id":"r-1","requires_clients":false,"allowed_methods":null,"updated_at":"2026-09-25T00:00:00.000Z"}]},"meta":{"request_id":"req_1"}}`)
	})

	m, err := c.Wrap.InterceptManifest(context.Background())
	if err != nil {
		t.Fatalf("InterceptManifest: %v", err)
	}
	if m.Version != "sha256:abc" || m.TTLSeconds != 60 || m.Environment != "production" {
		t.Fatalf("manifest = %+v, want the envelope unwrapped", m)
	}
	if len(m.Routes) != 1 || m.Routes[0].Host != "api.hubapi.com" || m.Routes[0].Slug != "hubspot" || m.Routes[0].BasePath != "/crm/v3" {
		t.Fatalf("routes = %+v, want the hubspot entry", m.Routes)
	}
	if m.Routes[0].AllowedMethods != nil || m.Routes[0].Ambiguous {
		t.Fatalf("routes[0] = %+v, want nil AllowedMethods and Ambiguous false", m.Routes[0])
	}
	if got := requests()[0]; got.Method != "GET" || got.Path != "/v1/wrap/intercept-manifest" || got.Query["environment"] != "" {
		t.Fatalf("request = %s %s %v, want GET /v1/wrap/intercept-manifest with no environment query", got.Method, got.Path, got.Query)
	}

	staging, err := c.Wrap.InterceptManifest(context.Background(), InterceptManifestOptions{Environment: "staging"})
	if err != nil {
		t.Fatalf("InterceptManifest(staging): %v", err)
	}
	if staging.Environment != "staging" {
		t.Fatalf("Environment = %q, want the query forwarded", staging.Environment)
	}
	if got := requests()[1]; got.Query["environment"] != "staging" {
		t.Fatalf("request query = %v, want environment=staging", got.Query)
	}
}
