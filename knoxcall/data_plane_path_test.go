package knoxcall

// PARITY §5 — where the data plane lives under a proxy base.
//
// On a KnoxCall cloud tenant host the proxy is served ONLY under /api
// (server.ts strips the prefix; every other path on that host is the
// dashboard). Until 2026-09-25 Call sent proxyBase + path, so every documented
// Path: "/users" example answered the dashboard HTML on a real tenant host, and
// the five live smokes passed only because each hard-coded Path: "/api/get".
// Measured on a local server that day: GET /api/get → 200 with
// X-Knox-Upstream-Status; GET /get → the SPA branch, no upstream call. These
// pin the URL Call builds for every base shape.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDataPlanePathPrefixRule(t *testing.T) {
	cases := []struct{ base, want string }{
		{"https://acme.knoxcall.com", "/api"},
		{"https://acme.knoxcall.com/", "/api"},
		{"https://sandbox-acme.knoxcall.com", "/api"},
		{"http://sandbox-acme.knoxcall.com:3100", "/api"},
		{"https://ACME.KnoxCall.com", "/api"},
		{"https://acme.knoxcall.com/api", ""},
		{"https://acme.knoxcall.com/proxy", ""},
		{"https://api.knoxcall.com", ""},
		{"https://sandbox.knoxcall.com", ""},
		{"https://api-staging.knoxcall.com", ""},
		{"https://sandbox-staging.knoxcall.com", ""},
		{"https://www.knoxcall.com", ""},
		{"https://staging.knoxcall.com", ""},
		{"https://admin.knoxcall.com", ""},
		{"https://a.b.knoxcall.com", ""},
		{"https://knoxcall.com", ""},
		{"https://acme.knoxcall.com.evil.test", ""},
		{"http://localhost:3000", ""},
		{"https://knox.example.com", ""},
		{"not a url", ""},
	}
	for _, c := range cases {
		if got := dataPlanePathPrefix(c.base); got != c.want {
			t.Errorf("dataPlanePathPrefix(%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

// callURL builds a client with a token credential (no token round trip) and a
// transport that records the one URL Call sends to.
func callURL(t *testing.T, path string, mod func(*Options)) string {
	t.Helper()
	for _, v := range []string{"KNOXCALL_PROXY_BASE_URL", "KNOXCALL_BASE_URL", "KNOXCALL_TENANT", "KNOXCALL_ENVIRONMENT"} {
		t.Setenv(v, "")
	}
	seen := []string{}
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.String())
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			Request:    r,
		}, nil
	})}
	opts := Options{Tenant: "acme", Credentials: AccessToken{Token: "kc_live_pre"}, HTTPClient: hc}
	if mod != nil {
		mod(&opts)
	}
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Call(context.Background(), "r_1", &CallOptions{Path: path})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	res.Body.Close()
	if len(seen) != 1 {
		t.Fatalf("saw %d requests, want 1: %v", len(seen), seen)
	}
	return seen[0]
}

func TestCallPlacesTheUpstreamPathUnderTheTenantHostEntryPoint(t *testing.T) {
	cases := []struct {
		name, path, want string
		mod              func(*Options)
	}{
		{"derived sandbox shape", "/users", "https://sandbox-acme.knoxcall.com/api/users",
			func(o *Options) { o.BaseURL = "https://sandbox.knoxcall.com" }},
		{"derived plain shape", "/users", "https://acme.knoxcall.com/api/users",
			func(o *Options) { o.BaseURL = "https://api.knoxcall.com" }},
		{"explicit override naming a tenant host, any port (the live smoke harness)", "/get", "http://sandbox-acme.knoxcall.com:3100/api/get",
			func(o *Options) {
				o.BaseURL = "http://sandbox.knoxcall.com:3100"
				o.ProxyBaseURL = "http://sandbox-acme.knoxcall.com:3100"
			}},
		{"override carrying the entry point is verbatim, never doubled", "/get", "https://sandbox-acme.knoxcall.com/api/get",
			func(o *Options) {
				o.BaseURL = "https://sandbox.knoxcall.com"
				o.ProxyBaseURL = "https://sandbox-acme.knoxcall.com/api"
			}},
		{"loopback override is verbatim", "/get", "http://localhost:3000/get",
			func(o *Options) { o.BaseURL = "http://localhost:3000"; o.ProxyBaseURL = "http://localhost:3000" }},
		{"self-hosted base is verbatim", "/get", "https://knox.example.com/get",
			func(o *Options) { o.BaseURL = "https://knox.example.com" }},
		{"path without a leading slash", "users", "https://acme.knoxcall.com/api/users",
			func(o *Options) { o.BaseURL = "https://api.knoxcall.com" }},
		{"an upstream path that itself starts with /api", "/api/v2/tickets", "https://acme.knoxcall.com/api/api/v2/tickets",
			func(o *Options) { o.BaseURL = "https://api.knoxcall.com" }},
		{"the bare route path", "/", "https://acme.knoxcall.com/api/",
			func(o *Options) { o.BaseURL = "https://api.knoxcall.com" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := callURL(t, c.path, c.mod); got != c.want {
				t.Fatalf("Call sent %q, want %q", got, c.want)
			}
		})
	}
}

func TestBoundRoutesInheritTheEntryPoint(t *testing.T) {
	t.Setenv("KNOXCALL_PROXY_BASE_URL", "")
	seen := ""
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Request: r}, nil
	})}
	c, err := New(Options{Tenant: "acme", BaseURL: "https://api.knoxcall.com", Credentials: AccessToken{Token: "kc_live_pre"}, HTTPClient: hc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := c.Route("r_1", nil).Get(context.Background(), "/users", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	res.Body.Close()
	if seen != "https://acme.knoxcall.com/api/users" {
		t.Fatalf("bound route sent %q", seen)
	}
}
