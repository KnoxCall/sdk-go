package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knoxcall/sdk-go/internal/clilogin"
	"github.com/knoxcall/sdk-go/internal/credfile"
)

// -- PKCE ---------------------------------------------------------------------------

func TestPKCEPairIsS256AndURLSafe(t *testing.T) {
	verifier, challenge, err := generatePKCEPair()
	if err != nil {
		t.Fatalf("generatePKCEPair: %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 { // RFC 7636 §4.1
		t.Errorf("verifier length = %d, want 43..128", len(verifier))
	}
	for _, r := range verifier {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
			t.Errorf("verifier contains non-base64url rune %q", r)
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Errorf("challenge = %q, want S256 of the verifier %q", challenge, want)
	}
	if strings.Contains(challenge, "=") {
		t.Error("challenge is padded — must be unpadded base64url")
	}
	v2, _, err := generatePKCEPair()
	if err != nil {
		t.Fatalf("generatePKCEPair: %v", err)
	}
	if v2 == verifier {
		t.Error("verifier repeated — no fresh entropy per call")
	}
}

func TestAuthorizeURLUsesCLIAliasAndS256(t *testing.T) {
	raw := buildAuthorizeURL("https://api.example.test",
		"http://127.0.0.1:51234/callback", "st_1", "chal", "acme")
	if !strings.HasPrefix(raw, "https://api.example.test/oauth/authorize?") {
		t.Fatalf("url = %q, want the /oauth/authorize endpoint", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	q := u.Query()
	for key, want := range map[string]string{
		"client_id":             "knoxcall-cli",
		"response_type":         "code",
		"code_challenge_method": "S256",
		"code_challenge":        "chal",
		"redirect_uri":          "http://127.0.0.1:51234/callback",
		"state":                 "st_1",
		"tenant":                "acme",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// -- Loopback callback server ---------------------------------------------------------

func hitCallback(t *testing.T, port int, query string) {
	t.Helper()
	res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?%s", port, query))
	if err != nil {
		t.Fatalf("GET callback: %v", err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

func TestLoopbackCallbackSuccess(t *testing.T) {
	s, err := clilogin.NewLoopbackServer()
	if err != nil {
		t.Fatalf("newLoopbackServer: %v", err)
	}
	defer s.Close()

	hitCallback(t, s.Port, "code=abc123&state=st1")
	code, err := s.WaitForCode(context.Background(), "st1", 5*time.Second)
	if err != nil {
		t.Fatalf("waitForCode: %v", err)
	}
	if code != "abc123" {
		t.Errorf("code = %q, want abc123", code)
	}
}

func TestLoopbackCallbackErrorParam(t *testing.T) {
	s, err := clilogin.NewLoopbackServer()
	if err != nil {
		t.Fatalf("newLoopbackServer: %v", err)
	}
	defer s.Close()

	hitCallback(t, s.Port, "error=access_denied&error_description=nope&state=st1")
	_, err = s.WaitForCode(context.Background(), "st1", 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v, want the error_description surfaced", err)
	}
}

func TestLoopbackCallbackStateMismatch(t *testing.T) {
	s, err := clilogin.NewLoopbackServer()
	if err != nil {
		t.Fatalf("newLoopbackServer: %v", err)
	}
	defer s.Close()

	hitCallback(t, s.Port, "code=abc123&state=EVIL")
	_, err = s.WaitForCode(context.Background(), "st1", 5*time.Second)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "state") {
		t.Fatalf("err = %v, want a state-mismatch error", err)
	}
}

// -- Auth-code flow end-to-end (fake browser, httptest token endpoint) ---------------

func TestAuthCodeFlowExchangesCodeWithVerifier(t *testing.T) {
	var mu sync.Mutex
	var exchanged url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("path = %q, want /oauth/token", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		mu.Lock()
		exchanged = r.PostForm
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "kc_ac",
			"refresh_token": "rt_ac",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"tenant":        "acme",
			"client_id":     "kc_cli_real",
		})
	}))
	defer srv.Close()

	a, tio := newTestApp(t)
	var wg sync.WaitGroup
	a.openBrowser = func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			t.Errorf("authorize URL did not parse: %v", err)
			return err
		}
		q := u.Query()
		if q.Get("client_id") != "knoxcall-cli" {
			t.Errorf("authorize client_id = %q, want knoxcall-cli", q.Get("client_id"))
		}
		redirect := q.Get("redirect_uri")
		state := q.Get("state")
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := http.Get(redirect + "?code=authcode1&state=" + url.QueryEscape(state))
			if err == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}()
		return nil
	}

	body, err := a.authCodeFlow(context.Background(), srv.URL, "", 10*time.Second)
	wg.Wait()
	if err != nil {
		t.Fatalf("authCodeFlow: %v", err)
	}
	if strVal(body, "access_token") != "kc_ac" {
		t.Errorf("access_token = %q, want kc_ac", strVal(body, "access_token"))
	}

	mu.Lock()
	form := exchanged
	mu.Unlock()
	if form.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("code") != "authcode1" {
		t.Errorf("code = %q, want authcode1", form.Get("code"))
	}
	if form.Get("client_id") != "knoxcall-cli" {
		t.Errorf("client_id = %q, want knoxcall-cli", form.Get("client_id"))
	}
	if len(form.Get("code_verifier")) < 43 {
		t.Errorf("code_verifier = %q, want the PKCE verifier", form.Get("code_verifier"))
	}
	// The URL is ALWAYS printed; the token never is.
	out := tio.out.String()
	if !strings.Contains(out, "/oauth/authorize?") {
		t.Error("authorize URL was not printed")
	}
	if strings.Contains(out, "kc_ac") || strings.Contains(out, "rt_ac") {
		t.Error("token leaked to stdout")
	}
}

// -- Device flow polling ---------------------------------------------------------------

func TestDevicePollHonorsIntervalAndSlowDown(t *testing.T) {
	responses := []struct {
		status int
		body   string
	}{
		{400, `{"error":"authorization_pending"}`},
		{400, `{"error":"slow_down"}`},
		{400, `{"error":"authorization_pending"}`},
		{200, `{"access_token":"kc_dev","refresh_token":"rt","expires_in":3600}`},
	}
	var mu sync.Mutex
	var forms []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		i := len(forms)
		forms = append(forms, string(raw))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(responses[i].status)
		_, _ = io.WriteString(w, responses[i].body)
	}))
	defer srv.Close()

	a, tio := newTestApp(t)
	body, err := a.pollDeviceToken(context.Background(), srv.URL, "dev_code_1",
		5*time.Second, 900*time.Second)
	if err != nil {
		t.Fatalf("pollDeviceToken: %v", err)
	}
	if strVal(body, "access_token") != "kc_dev" {
		t.Errorf("access_token = %q, want kc_dev", strVal(body, "access_token"))
	}

	// 5s until slow_down (sleep BEFORE the first poll), then bumped by +5
	// per RFC 8628 §3.5.
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if len(tio.sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", tio.sleeps, want)
	}
	for i := range want {
		if tio.sleeps[i] != want[i] {
			t.Errorf("sleeps[%d] = %v, want %v", i, tio.sleeps[i], want[i])
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for i, form := range forms {
		if !strings.Contains(form, "device_code=dev_code_1") {
			t.Errorf("poll %d missing device_code: %q", i, form)
		}
	}
	if !strings.Contains(forms[0], "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code") {
		t.Errorf("poll 0 missing the device grant type: %q", forms[0])
	}
}

func TestDevicePollTerminalErrors(t *testing.T) {
	for _, tc := range []struct{ oauthError, fragment string }{
		{"access_denied", "denied"},
		{"expired_token", "knoxcall login"},
	} {
		t.Run(tc.oauthError, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"error":"`+tc.oauthError+`"}`)
			}))
			defer srv.Close()

			a, _ := newTestApp(t)
			_, err := a.pollDeviceToken(context.Background(), srv.URL, "dev_code_1",
				5*time.Second, 900*time.Second)
			if err == nil || !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("err = %v, want %q in the message", err, tc.fragment)
			}
		})
	}
}

// -- Profile write / merge / persist ---------------------------------------------------

func TestPersistLoginRecordsExtensionMembers(t *testing.T) {
	path := isolateEnv(t)
	_, err := persistLogin(context.Background(), path, "default", "https://api.example.test",
		map[string]any{
			"access_token":  "kc_a",
			"refresh_token": "rt_a",
			"expires_in":    float64(3600),
			"scope":         "routes:read",
			"tenant":        "acme",
			"client_id":     "kc_cli_real", // extension member: real per-tenant client
		}, "")
	if err != nil {
		t.Fatalf("persistLogin: %v", err)
	}
	onDisk := credfile.ReadProfile(path, "default")
	if onDisk == nil {
		t.Fatal("profile not written")
	}
	if got := strVal(onDisk, "client_id"); got != "kc_cli_real" {
		t.Errorf("client_id = %q, want the real per-tenant client id", got)
	}
	if got := strVal(onDisk, "tenant"); got != "acme" {
		t.Errorf("tenant = %q, want acme", got)
	}
	if got := strVal(onDisk, "base_url"); got != "https://api.example.test" {
		t.Errorf("base_url = %q", got)
	}
	if got := strVal(onDisk, "refresh_token"); got != "rt_a" {
		t.Errorf("refresh_token = %q, want rt_a", got)
	}
	if !strings.HasSuffix(strVal(onDisk, "access_token_expires_at"), "Z") {
		t.Errorf("access_token_expires_at = %q, want the UTC wire format", strVal(onDisk, "access_token_expires_at"))
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Error("lock file left behind after persistLogin")
	}
}

func TestPersistLoginMergesProfiles(t *testing.T) {
	path := isolateEnv(t)
	for _, p := range []struct{ profile, rt string }{{"default", "rt1"}, {"work", "rt2"}} {
		if _, err := persistLogin(context.Background(), path, p.profile, "https://api.example.test",
			map[string]any{"access_token": "kc_a", "refresh_token": p.rt, "tenant": "acme"}, ""); err != nil {
			t.Fatalf("persistLogin(%s): %v", p.profile, err)
		}
	}
	// Overwriting one profile leaves the other intact.
	if _, err := persistLogin(context.Background(), path, "default", "https://api.example.test",
		map[string]any{"access_token": "kc_b", "refresh_token": "rt3", "tenant": "acme"}, ""); err != nil {
		t.Fatalf("persistLogin overwrite: %v", err)
	}
	if got := strVal(credfile.ReadProfile(path, "default"), "refresh_token"); got != "rt3" {
		t.Errorf("default refresh_token = %q, want rt3", got)
	}
	if got := strVal(credfile.ReadProfile(path, "work"), "refresh_token"); got != "rt2" {
		t.Errorf("work refresh_token = %q, want rt2 (merge must keep other profiles)", got)
	}
}

func TestPersistLoginWaitsForHeldLock(t *testing.T) {
	path := isolateEnv(t)
	lock := credfile.NewLock(path)
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(150 * time.Millisecond)
		lock.Release()
		close(released)
	}()

	start := time.Now()
	if _, err := persistLogin(context.Background(), path, "default", "https://api.example.test",
		map[string]any{"access_token": "kc_a", "tenant": "acme"}, ""); err != nil {
		t.Fatalf("persistLogin: %v", err)
	}
	<-released
	if time.Since(start) < 100*time.Millisecond {
		t.Error("persistLogin wrote without waiting for the held lock")
	}
	if credfile.ReadProfile(path, "default") == nil {
		t.Error("profile not written after the lock was released")
	}
}

// -- login command (device path, fully mocked) ------------------------------------------

func newDeviceServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device_authorization":
			raw, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(raw), "client_id=knoxcall-cli") {
				t.Errorf("device authorization missing the CLI alias: %q", raw)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "dc1",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          srv.URL + "/oauth/activate",
				"verification_uri_complete": srv.URL + "/oauth/activate?user_code=ABCD-EFGH",
				"expires_in":                900,
				"interval":                  5,
			})
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "kc_dev",
				"refresh_token": "rt_dev",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "routes:read",
				"tenant":        "acme",
				"client_id":     "kc_cli_real",
			})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	return srv
}

func TestLoginDeviceFlowWritesProfile(t *testing.T) {
	for _, flagName := range []string{"--device", "--no-browser"} {
		t.Run(flagName, func(t *testing.T) {
			path := isolateEnv(t)
			srv := newDeviceServer(t)
			defer srv.Close()

			a, tio := newTestApp(t)
			rc := a.run(context.Background(), []string{"login", flagName, "--base-url", srv.URL})
			if rc != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
			}

			record := credfile.ReadProfile(path, "default")
			if record == nil {
				t.Fatal("profile not written")
			}
			if got := strVal(record, "client_id"); got != "kc_cli_real" {
				t.Errorf("client_id = %q, want kc_cli_real", got)
			}
			if got := strVal(record, "refresh_token"); got != "rt_dev" {
				t.Errorf("refresh_token = %q, want rt_dev", got)
			}
			if got := strVal(record, "tenant"); got != "acme" {
				t.Errorf("tenant = %q, want acme", got)
			}
			if got := strVal(record, "base_url"); got != srv.URL {
				t.Errorf("base_url = %q, want %q", got, srv.URL)
			}

			out := tio.out.String()
			if !strings.Contains(out, "ABCD-EFGH") {
				t.Error("user code not shown prominently")
			}
			if !strings.Contains(out, "acme") {
				t.Error("tenant not reported on success")
			}
			if strings.Contains(out, "kc_dev") || strings.Contains(out, "rt_dev") {
				t.Error("tokens leaked to stdout")
			}
		})
	}
}

func TestLoginRespectsProfileFlag(t *testing.T) {
	path := isolateEnv(t)
	srv := newDeviceServer(t)
	defer srv.Close()

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"login", "--device", "--base-url", srv.URL, "--profile", "staging"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}
	if got := strVal(credfile.ReadProfile(path, "staging"), "access_token"); got != "kc_dev" {
		t.Errorf("staging access_token = %q, want kc_dev", got)
	}
	if credfile.ReadProfile(path, "default") != nil {
		t.Error("default profile written despite --profile staging")
	}
}
