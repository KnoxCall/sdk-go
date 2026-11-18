package knoxcall

// Tests for the plaintext-transport hardening warning (PARITY §15) — the Go
// port of the shapes in the node warn.ts / core.ts coverage.

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

// captureWarnings swaps the package warn writer for a buffer and clears the
// once-per-process dedup, restoring both when the test ends.
// syncBuffer is a bytes.Buffer safe for a writer on another goroutine: the
// store's refresh goroutine warns from its hooks while a test reads the capture.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

func captureWarnings(t *testing.T) *syncBuffer {
	t.Helper()
	orig := warnWriter
	buf := &syncBuffer{}
	warnWriter = buf
	resetWarnedForTests()
	t.Cleanup(func() {
		warnWriter = orig
		resetWarnedForTests()
	})
	return buf
}

func TestIsInsecureRemoteURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		// http:// to a non-loopback host → insecure.
		{"http://api.knoxcall.com", true},
		{"http://api.knoxcall.com:8080/v1", true},
		{"http://198.51.100.7:3000", true},
		{"http://internal-gateway:8080", true},
		{"HTTP://API.KNOXCALL.COM", true}, // scheme match is case-insensitive
		// https:// (or any non-http scheme) is never flagged.
		{"https://api.knoxcall.com", false},
		{"ftp://api.knoxcall.com", false},
		{"", false},
		{"not a url", false},
		// Loopback hosts are the normal dev case — never flagged.
		{"http://localhost", false},
		{"http://localhost:3000", false},
		{"http://foo.localhost:5173", false},
		{"http://127.0.0.1:3000", false},
		{"http://127.5.6.7", false},
		{"http://0.0.0.0:3000", false},
		{"http://[::1]:3000", false},
	}
	for _, tc := range cases {
		if got := isInsecureRemoteURL(tc.url); got != tc.want {
			t.Errorf("isInsecureRemoteURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestWarnOnceDedupsByCode(t *testing.T) {
	buf := captureWarnings(t)

	warnOnce("CODE_A", "first message")
	warnOnce("CODE_A", "second message must be suppressed")
	warnOnce("CODE_B", "different code fires")

	out := buf.String()
	if n := strings.Count(out, "CODE_A"); n != 1 {
		t.Errorf("CODE_A appeared %d times, want exactly 1 (deduped)", n)
	}
	if !strings.Contains(out, "first message") {
		t.Errorf("first warning missing: %q", out)
	}
	if strings.Contains(out, "second message must be suppressed") {
		t.Errorf("duplicate CODE_A warning was not suppressed: %q", out)
	}
	if !strings.Contains(out, "CODE_B") || !strings.Contains(out, "different code fires") {
		t.Errorf("a distinct code must still warn: %q", out)
	}
}

// An http:// non-loopback management base URL (and the proxy URL derived from
// it) must emit the plaintext-transport warning at construction.
func TestConstructionWarnsOnInsecureBaseAndProxyURL(t *testing.T) {
	clearConstructionEnv(t)
	buf := captureWarnings(t)

	// A non-cloud, non-loopback base URL: the proxy URL is derived as the same
	// self-hosted host, so both the base and proxy checks fire.
	if _, err := New(Options{Tenant: "acme", APIKey: "kc_live_x", BaseURL: "http://gateway.internal:8080"}); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "KNOXCALL_INSECURE_BASE_URL") {
		t.Errorf("missing base-URL warning: %q", out)
	}
	if !strings.Contains(out, "KNOXCALL_INSECURE_PROXY_URL") {
		t.Errorf("missing proxy-URL warning: %q", out)
	}
}

// An explicit http:// non-loopback proxy override warns even when the base URL
// is https:// — the proxy carries the SDK credential too.
func TestConstructionWarnsOnInsecureProxyOnly(t *testing.T) {
	clearConstructionEnv(t)
	buf := captureWarnings(t)

	if _, err := New(Options{
		Tenant:       "acme",
		APIKey:       "kc_live_x",
		BaseURL:      "https://api.knoxcall.com",
		ProxyBaseURL: "http://proxy.internal:9000",
	}); err != nil {
		t.Fatalf("New: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "KNOXCALL_INSECURE_BASE_URL") {
		t.Errorf("https base URL must not warn: %q", out)
	}
	if !strings.Contains(out, "KNOXCALL_INSECURE_PROXY_URL") {
		t.Errorf("missing proxy-URL warning for an http:// proxy override: %q", out)
	}
}

// http://localhost is the normal local-dev case and must never warn — for the
// base URL or the proxy URL derived from it.
func TestConstructionDoesNotWarnOnLocalhost(t *testing.T) {
	clearConstructionEnv(t)
	buf := captureWarnings(t)

	if _, err := New(Options{Tenant: "acme", APIKey: "kc_live_x", BaseURL: "http://localhost:3000"}); err != nil {
		t.Fatalf("New: %v", err)
	}
	if out := buf.String(); strings.Contains(out, "KNOXCALL_INSECURE") {
		t.Errorf("http://localhost must not warn, got: %q", out)
	}
}
