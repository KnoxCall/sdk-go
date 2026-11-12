package knoxcall

// Tenant-slug validation (PARITY §2): because the tenant slug becomes a
// data-plane hostname (https://<slug>.knoxcall.com), a hostile slug adopted
// from an explicit option, a token response, /v1/account, or the credentials
// file must be rejected with a typed *BootstrapError BEFORE it can misdirect
// the bearer token to another host.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostileTenantSlugRejectedAtConstruction(t *testing.T) {
	clearConstructionEnv(t)
	hostile := []string{
		"evil.com#",             // '#' would truncate the host in a URL parser
		"evil.com",              // an embedded dot escapes the .knoxcall.com label
		"a.b",                   // dotted → not a bare label
		"-lead",                 // leading hyphen
		"trail-",                // trailing hyphen
		"under_score",           // underscore not in a DNS label
		"has space",             // whitespace
		"tenant/../other",       // path traversal
		strings.Repeat("a", 64), // 64 chars — one past the 63-char label cap
		// NB: "" is NOT hostile — an empty tenant means "not set" (like node/
		// python), so no host is derived at construction and it is not rejected.
	}
	for _, slug := range hostile {
		_, err := New(Options{Tenant: slug, APIKey: "kc_live_x", BaseURL: "https://api.knoxcall.com"})
		var be *BootstrapError
		if !errors.As(err, &be) {
			t.Errorf("slug %q: err = %v (%T), want a *BootstrapError refusing to derive a host", slug, err, err)
			continue
		}
		if !strings.Contains(err.Error(), "tenant slug") {
			t.Errorf("slug %q: err = %v, want a message naming the tenant slug", slug, err)
		}
	}
}

func TestValidTenantSlugsAcceptedAndDeriveHost(t *testing.T) {
	clearConstructionEnv(t)
	for _, slug := range []string{"acme", "a", "a1", "my-tenant", "ABC123", strings.Repeat("a", 63)} {
		c, err := New(Options{Tenant: slug, APIKey: "kc_live_x", BaseURL: "https://api.knoxcall.com"})
		if err != nil {
			t.Errorf("slug %q rejected: %v", slug, err)
			continue
		}
		if want := "https://" + slug + ".knoxcall.com"; c.proxyBaseURL != want {
			t.Errorf("slug %q: proxyBaseURL = %q, want %q", slug, c.proxyBaseURL, want)
		}
	}
}

// The sandbox shape derives sandbox-<slug>.knoxcall.com and must validate too.
func TestHostileTenantSlugRejectedForSandboxShape(t *testing.T) {
	clearConstructionEnv(t)
	_, err := New(Options{Tenant: "evil.com#", APIKey: "kc_live_x", BaseURL: "https://sandbox.knoxcall.com"})
	var be *BootstrapError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v (%T), want a *BootstrapError refusing the sandbox host", err, err)
	}
}

// A hostile slug adopted from /v1/account during lazy discovery is rejected
// before it becomes a data-plane host.
func TestHostileTenantSlugFromDiscoveryRejected(t *testing.T) {
	clearConstructionEnv(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"slug":"evil.com#"}}`))
	}))
	defer ts.Close()

	// Cloud-shaped base URL, static token, no tenant → discovery via /v1/account.
	c, err := New(Options{APIKey: "kc_live_pre", BaseURL: "https://api.knoxcall.com"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.baseURL = ts.URL // discovery endpoint reachable; proxy never derived from the hostile slug

	_, err = c.ensureProxyBaseURL(context.Background())
	var be *BootstrapError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v (%T), want a *BootstrapError refusing the discovered hostile slug", err, err)
	}
}
