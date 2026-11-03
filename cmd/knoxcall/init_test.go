package main

// `knoxcall init` coverage — the Go port of the Node init tests
// (sdk/knoxcall-node/test/cli.test.ts, describe('init command')): scaffold mode
// prints the quickstart and writes nothing, escrow mode hits the wrap endpoints
// and prints the base_url without ever printing the raw key, a missing
// KNOXCALL_WRAP_SECRET errors, and not-logged-in errors with a re-login hint.
//
// Auth uses the seeded credentials-file profile (fast-path stored access token,
// no /oauth/token round-trip); the test server serves /v1/account plus the wrap
// escrow/token endpoints and records every request path.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// initServer serves a seeded tenant's endpoints and records every request path,
// so a test can assert which endpoints were (not) hit — the Go analog of the
// Node init tests' stubFetch path capture.
func initServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	seen := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
	return srv, seen
}

func writeInitJSON(w http.ResponseWriter, payload string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, payload)
}

func writeAccount(w http.ResponseWriter) {
	writeInitJSON(w, `{"data":{"id":"t_1","slug":"acme","name":"Acme Inc"},"meta":{"request_id":"req_acct"}}`)
}

func TestInitScaffoldPrintsQuickstartAndMakesNoWrites(t *testing.T) {
	path := isolateEnv(t)
	srv, paths := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/account" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		writeAccount(w)
	})
	seedProfiles(t, path, srv.URL)

	a, tio := newTestApp(t)
	if rc := a.run(context.Background(), []string{"init"}); rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}
	out := tio.out.String()
	for _, want := range []string{
		"Signed in as Acme Inc",
		"Wrap a provider SDK through KnoxCall",
		"knoxcall init --provider stripe",
		"RoundTripper", // the Go transport-wrap seam
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, out)
		}
	}
	// Scaffold writes nothing: the wrap endpoints are never hit.
	for _, p := range paths() {
		if strings.HasPrefix(p, "/v1/wrap/") {
			t.Errorf("scaffold mode hit %q, want no wrap writes", p)
		}
	}
}

func TestInitEscrowMovesKeyIntoCustodyAndPrintsBaseURL(t *testing.T) {
	path := isolateEnv(t)
	const baseURL = "https://api.knoxcall.com/wg/wkt_x/api.stripe.com"
	var escrowBody, tokenBody []byte
	srv, paths := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/wrap/credentials":
			escrowBody, _ = io.ReadAll(r.Body)
			writeInitJSON(w, `{"data":{"secret_id":"sec_1","name":"wrap-stripe","provider":"stripe","allowed_hosts":["api.stripe.com"],"sandbox":false},"meta":{"request_id":"req_esc"}}`)
		case "/v1/wrap/tokens":
			tokenBody, _ = io.ReadAll(r.Body)
			writeInitJSON(w, `{"data":{"id":"tok_1","token":"wkt_x","base_url":"`+baseURL+`","base_url_style":"path","host":"api.stripe.com","secret_id":"sec_1","sandbox":false,"expires_at":null},"meta":{"request_id":"req_tok"}}`)
		default:
			writeAccount(w)
		}
	})
	seedProfiles(t, path, srv.URL)
	// The raw key is delivered via the env var, NEVER a flag/argv.
	t.Setenv("KNOXCALL_WRAP_SECRET", "sk_live_SECRET")

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"init", "--provider", "stripe", "--secret-name", "wrap-stripe", "--host", "api.stripe.com"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}

	got := paths()
	if !slices.Contains(got, "/v1/wrap/credentials") || !slices.Contains(got, "/v1/wrap/tokens") {
		t.Fatalf("paths = %v, want BOTH wrap endpoints hit", got)
	}
	out := tio.out.String()
	if !strings.Contains(out, "in KnoxCall custody") {
		t.Errorf("stdout = %q, want the custody confirmation", out)
	}
	if !strings.Contains(out, baseURL) {
		t.Errorf("stdout missing the gateway base_url %q; got:\n%s", baseURL, out)
	}
	if strings.Contains(out, "sk_live_SECRET") {
		t.Error("the raw provider key leaked to stdout")
	}

	// The escrow body carries the flag-supplied provider/name/host and the
	// env-supplied value (the load-bearing "never a flag" property).
	var eb map[string]any
	if err := json.Unmarshal(escrowBody, &eb); err != nil {
		t.Fatalf("escrow body: %v", err)
	}
	if eb["provider"] != "stripe" || eb["name"] != "wrap-stripe" || eb["value"] != "sk_live_SECRET" {
		t.Errorf("escrow body = %v, want provider/name/value from flags+env", eb)
	}
	if hosts, _ := eb["hosts"].([]any); len(hosts) != 1 || hosts[0] != "api.stripe.com" {
		t.Errorf("escrow hosts = %v, want the single pinned host", eb["hosts"])
	}
	var tb map[string]any
	if err := json.Unmarshal(tokenBody, &tb); err != nil {
		t.Fatalf("token body: %v", err)
	}
	if tb["secret"] != "wrap-stripe" || tb["host"] != "api.stripe.com" {
		t.Errorf("token body = %v, want the escrowed secret + pinned host", tb)
	}
}

func TestInitEscrowRequiresWrapSecretEnv(t *testing.T) {
	path := isolateEnv(t)
	srv, paths := initServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/wrap/") {
			t.Errorf("wrap endpoint %q hit despite the missing key", r.URL.Path)
		}
		writeAccount(w)
	})
	seedProfiles(t, path, srv.URL)
	t.Setenv("KNOXCALL_WRAP_SECRET", "") // explicitly unset — the key is missing

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"init", "--provider", "stripe", "--secret-name", "wrap-stripe", "--host", "api.stripe.com"})
	if rc != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", rc, tio.err.String())
	}
	errOut := tio.err.String()
	if !strings.HasPrefix(errOut, "error: ") || !strings.Contains(errOut, "KNOXCALL_WRAP_SECRET") {
		t.Errorf("stderr = %q, want a clear KNOXCALL_WRAP_SECRET error", errOut)
	}
	// The key is checked before any escrow write — no wrap endpoint is contacted.
	for _, p := range paths() {
		if strings.HasPrefix(p, "/v1/wrap/") {
			t.Errorf("wrap endpoint %q hit, want none before the env check", p)
		}
	}
}

func TestInitNotLoggedIn(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"init", "--profile", "staging"})
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	errOut := tio.err.String()
	if !strings.HasPrefix(errOut, "error: ") {
		t.Errorf("stderr = %q, want the error: prefix", errOut)
	}
	if !strings.Contains(errOut, "staging") || !strings.Contains(errOut, "knoxcall login") {
		t.Errorf("stderr = %q, want the profile name and the re-login hint", errOut)
	}
}
