package knoxcall

// Credentials-file provider tests — StoredCredentials (PARITY §2/§10), the Go
// port of knoxcall-python/tests/test_credentials_file.py. Every test routes
// KNOXCALL_CREDENTIALS_FILE at a t.TempDir() path via clearConstructionEnv so
// the real ~/.knoxcall is never touched (or even read).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// credsRecord returns a fully-populated profile record; mut tweaks it.
func credsRecord(baseURL string, mut func(map[string]any)) map[string]any {
	rec := map[string]any{
		"tenant":                  "acme",
		"base_url":                baseURL,
		"client_id":               "kc_cli_real",
		"refresh_token":           "rt_old",
		"access_token":            "kc_stored_fresh",
		"access_token_expires_at": formatCredentialsExpiry(time.Now().Add(time.Hour)),
		"scope":                   "routes:read",
	}
	if mut != nil {
		mut(rec)
	}
	return rec
}

func writeTestCreds(t *testing.T, path, profile string, rec map[string]any) {
	t.Helper()
	if err := writeCredentialsProfile(path, profile, rec); err != nil {
		t.Fatalf("writeCredentialsProfile: %v", err)
	}
}

// tokenAndPingServer serves /oauth/token with the given handler and answers
// everything else with an enveloped 200, recording the Authorization header.
func tokenAndPingServer(t *testing.T, token http.HandlerFunc) (*httptest.Server, func() (tokenForms []string, lastAuth string)) {
	t.Helper()
	var mu sync.Mutex
	var forms []string
	lastAuth := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			forms = append(forms, string(b))
			mu.Unlock()
			token(w, r)
			return
		}
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	captured := func() ([]string, string) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), forms...), lastAuth
	}
	return ts, captured
}

func writeRefreshedToken(w http.ResponseWriter, access, refresh string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         "routes:read secrets:read",
		"tenant":        "acme",
		"client_id":     "kc_cli_real",
	})
}

// ── Chain position (env token > file > env client-credentials) ────────────────

func TestCredentialsFilePickedUpInZeroConfigConstruction(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.creds.(StoredCredentials); !ok {
		t.Fatalf("creds = %v, want StoredCredentials from the login file", c.creds)
	}
}

func TestEnvAccessTokenBeatsCredentialsFile(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))
	t.Setenv("KNOXCALL_ACCESS_TOKEN", "kc_env_token")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	at, ok := c.creds.(AccessToken)
	if !ok || at.Token != "kc_env_token" {
		t.Fatalf("creds = %v, want the pre-acquired env token to beat the file", c.creds)
	}
}

func TestCredentialsFileBeatsEnvClientCredentials(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.creds.(StoredCredentials); !ok {
		t.Fatalf("creds = %v, want the file to beat env client-credentials (chain order)", c.creds)
	}
}

func TestMissingFileSkipsProvider(t *testing.T) {
	clearConstructionEnv(t) // points at a path that was never written
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cc, ok := c.creds.(ClientCredentials)
	if !ok || cc.ClientID != "tk_env" {
		t.Fatalf("creds = %v, want the chain to continue to env client-credentials", c.creds)
	}
}

func TestMissingProfileSkipsProvider(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil)) // only "default" exists
	t.Setenv("KNOXCALL_PROFILE", "work")
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.creds.(ClientCredentials); !ok {
		t.Fatalf("creds = %v, want the unknown profile to skip the provider", c.creds)
	}
}

func TestMalformedFileSkipsProviderNotCrash(t *testing.T) {
	path := clearConstructionEnv(t)
	if err := os.WriteFile(path, []byte("{this is not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("KNOXCALL_CLIENT_ID", "tk_env")
	t.Setenv("KNOXCALL_CLIENT_SECRET", "sec")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v — a malformed file must skip the provider, never crash", err)
	}
	if _, ok := c.creds.(ClientCredentials); !ok {
		t.Fatalf("creds = %v, want the malformed file to skip the provider", c.creds)
	}
}

// ── Fresh-token fast path ─────────────────────────────────────────────────────

func TestFreshStoredTokenUsedWithoutRefresh(t *testing.T) {
	path := clearConstructionEnv(t)
	ts, captured := tokenAndPingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // must never be hit
	})
	defer ts.Close()
	writeTestCreds(t, path, "default", credsRecord(ts.URL, nil))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.do(context.Background(), requestOpts{method: http.MethodGet, path: "/v1/ping"}, nil); err != nil {
		t.Fatalf("do: %v", err)
	}

	forms, auth := captured()
	if len(forms) != 0 {
		t.Fatalf("token endpoint hit %d times, want 0 (fresh stored token, no refresh)", len(forms))
	}
	if auth != "Bearer kc_stored_fresh" {
		t.Fatalf("Authorization = %q, want the stored access token used directly", auth)
	}
}

// ── Refresh + rotated write-back ──────────────────────────────────────────────

func TestExpiredStoredTokenRefreshesAndWritesBackRotatedToken(t *testing.T) {
	path := clearConstructionEnv(t)
	ts, captured := tokenAndPingServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeRefreshedToken(w, "kc_new", "rt_new")
	})
	defer ts.Close()
	writeTestCreds(t, path, "default", credsRecord(ts.URL, func(rec map[string]any) {
		rec["access_token"] = "kc_old"
		// inside the 60s freshness window → must refresh
		rec["access_token_expires_at"] = formatCredentialsExpiry(time.Now().Add(10 * time.Second))
	}))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.do(context.Background(), requestOpts{method: http.MethodGet, path: "/v1/ping"}, nil); err != nil {
		t.Fatalf("do: %v", err)
	}

	forms, auth := captured()
	if len(forms) != 1 {
		t.Fatalf("token endpoint hit %d times, want exactly 1", len(forms))
	}
	form := forms[0]
	if !strings.Contains(form, "grant_type=refresh_token") || !strings.Contains(form, "refresh_token=rt_old") {
		t.Errorf("form = %q, want a refresh_token grant with the stored token", form)
	}
	if !strings.Contains(form, "client_id=kc_cli_real") {
		t.Errorf("form = %q, want the file's REAL client id", form)
	}
	if strings.Contains(form, "client_secret") {
		t.Errorf("form = %q, want no client_secret (public client)", form)
	}
	if auth != "Bearer kc_new" {
		t.Errorf("Authorization = %q, want the freshly minted token", auth)
	}

	onDisk := readCredentialsProfile(path, "default")
	if onDisk == nil {
		t.Fatal("credentials file unreadable after write-back")
	}
	if got := strField(onDisk, "refresh_token"); got != "rt_new" {
		t.Errorf("on-disk refresh_token = %q, want the rotated rt_new persisted", got)
	}
	if got := strField(onDisk, "access_token"); got != "kc_new" {
		t.Errorf("on-disk access_token = %q, want kc_new", got)
	}
	if got := strField(onDisk, "scope"); got != "routes:read secrets:read" {
		t.Errorf("on-disk scope = %q, want the refreshed scope", got)
	}

	// Atomic write: no temp-file or lock litter left behind.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "credentials.json" {
		t.Errorf("directory contents = %v, want only credentials.json", names)
	}
}

func TestConcurrentDoubleRefreshSerializedByLock(t *testing.T) {
	// Two clients race an expired token: exactly ONE refresh POST happens —
	// the loser re-reads the file under the lock and adopts the rotated token
	// (single-use refresh tokens make a second POST a family revocation).
	// Two SEPARATE clients so the in-process single-flight mutex can't mask
	// the cross-process file lock. Run with -race.
	path := clearConstructionEnv(t)
	ts, captured := tokenAndPingServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // hold the refresh so the other client queues on the file lock
		writeRefreshedToken(w, "kc_new", "rt_rotated")
	})
	defer ts.Close()
	writeTestCreds(t, path, "default", credsRecord(ts.URL, func(rec map[string]any) {
		rec["access_token"] = "kc_old"
		rec["refresh_token"] = "rt_only"
		rec["access_token_expires_at"] = formatCredentialsExpiry(time.Now().Add(-time.Minute))
	}))

	tokens := make([]string, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := New(Options{})
			if err != nil {
				errs[i] = err
				return
			}
			tok, err := c.getToken(context.Background())
			if err != nil {
				errs[i] = err
				return
			}
			tokens[i] = tok.accessToken
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
	}
	forms, _ := captured()
	if len(forms) != 1 {
		t.Fatalf("token endpoint hit %d times, want exactly 1 (lock-serialized)", len(forms))
	}
	for i, tok := range tokens {
		if tok != "kc_new" {
			t.Errorf("client %d token = %q, want both clients to end on kc_new", i, tok)
		}
	}
	if got := strField(readCredentialsProfile(path, "default"), "refresh_token"); got != "rt_rotated" {
		t.Errorf("on-disk refresh_token = %q, want rt_rotated", got)
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock file left behind (stat err = %v)", err)
	}
}

func TestInvalidGrantReturnsTypedErrorWithReloginHint(t *testing.T) {
	path := clearConstructionEnv(t)
	ts, _ := tokenAndPingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"family revoked"}`))
	})
	defer ts.Close()
	writeTestCreds(t, path, "default", credsRecord(ts.URL, func(rec map[string]any) {
		rec["access_token"] = "kc_old"
		rec["access_token_expires_at"] = formatCredentialsExpiry(time.Now().Add(-time.Minute))
	}))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.getToken(context.Background())
	var ae *AuthenticationError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want *AuthenticationError", err, err)
	}
	if !strings.Contains(err.Error(), "knoxcall login") {
		t.Errorf("err = %q, want the re-login hint", err.Error())
	}
	if ae.Message != "invalid_grant" {
		t.Errorf("Message = %q, want the invalid_grant code preserved", ae.Message)
	}
	// Secret hygiene: token values never appear in error strings.
	for _, secret := range []string{"rt_old", "kc_old"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("err = %q leaks %q", err.Error(), secret)
		}
	}
}

func TestExpiredTokenWithoutRefreshTokenReturnsReloginHint(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", func(rec map[string]any) {
		delete(rec, "refresh_token")
		rec["access_token"] = "kc_dead"
		rec["access_token_expires_at"] = formatCredentialsExpiry(time.Now().Add(-10 * time.Second))
	}))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.getToken(context.Background())
	var ae *AuthenticationError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want *AuthenticationError", err, err)
	}
	if !strings.Contains(err.Error(), "knoxcall login") {
		t.Errorf("err = %q, want the re-login hint", err.Error())
	}
}

// ── Lock: staleness + timeout ─────────────────────────────────────────────────

func TestStaleLockIsBroken(t *testing.T) {
	target := filepath.Join(t.TempDir(), "credentials.json")
	lockPath := target + ".lock"
	if err := os.WriteFile(lockPath, []byte("999 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	old := time.Now().Add(-120 * time.Second) // well past the 60s staleness threshold
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	lock := newCredentialsFileLock(target)
	start := time.Now()
	if err := lock.Acquire(context.Background()); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("acquire waited instead of breaking the stale lock")
	}
	lock.Release()
	if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file left behind (stat err = %v)", err)
	}
}

func TestLiveLockTimesOut(t *testing.T) {
	target := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(target+".lock", []byte("123 now\n"), 0o600); err != nil { // fresh, not stale
		t.Fatalf("WriteFile: %v", err)
	}

	lock := newCredentialsFileLock(target)
	lock.Timeout = 300 * time.Millisecond
	lock.RetryInterval = 50 * time.Millisecond
	err := lock.Acquire(context.Background())
	if err == nil || !strings.Contains(err.Error(), "credentials file lock") {
		t.Fatalf("err = %v, want a lock-timeout error", err)
	}
}

// ── Client seeding: file tenant/base_url, explicit always wins ────────────────

func TestFileSeedsTenantAndBaseURLWhenNotExplicit(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme seeded from the file", c.opts.Tenant)
	}
	if c.baseURL != "https://api.example.test" {
		t.Errorf("baseURL = %q, want the file's base_url", c.baseURL)
	}
	// Non-cloud base URL → self-hosted shape: the data plane shares the host.
	if c.proxyBaseURL != "https://api.example.test" {
		t.Errorf("proxyBaseURL = %q, want derived from the seeded base_url", c.proxyBaseURL)
	}
}

func TestExplicitTenantAndBaseURLBeatFile(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))

	c, err := New(Options{Tenant: "zeta", BaseURL: "https://explicit.example.test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.creds.(StoredCredentials); !ok {
		t.Fatalf("creds = %v, want StoredCredentials (tenant/base_url are not credentials)", c.creds)
	}
	if c.opts.Tenant != "zeta" {
		t.Errorf("tenant = %q, want the explicit option to win", c.opts.Tenant)
	}
	if c.baseURL != "https://explicit.example.test" {
		t.Errorf("baseURL = %q, want the explicit option to win", c.baseURL)
	}
}

func TestEnvTenantAndBaseURLBeatFile(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))
	t.Setenv("KNOXCALL_TENANT", "envcorp")
	t.Setenv("KNOXCALL_BASE_URL", "https://env.example.test")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "envcorp" {
		t.Errorf("tenant = %q, want the env var to win over the file", c.opts.Tenant)
	}
	if c.baseURL != "https://env.example.test" {
		t.Errorf("baseURL = %q, want the env var to win over the file", c.baseURL)
	}
}

// ── Path + profile overrides ──────────────────────────────────────────────────

func TestCredentialsFileEnvOverrideHonored(t *testing.T) {
	clearConstructionEnv(t)
	custom := filepath.Join(t.TempDir(), "elsewhere", "creds.json")
	writeTestCreds(t, custom, "default", credsRecord("https://api.example.test", func(rec map[string]any) {
		rec["access_token"] = "kc_custom_path"
	}))
	t.Setenv("KNOXCALL_CREDENTIALS_FILE", custom)

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := c.creds.(StoredCredentials); !ok {
		t.Fatalf("creds = %v, want StoredCredentials from the overridden path", c.creds)
	}
	tok, err := c.getToken(context.Background())
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if tok.accessToken != "kc_custom_path" {
		t.Fatalf("token = %q, want the token from KNOXCALL_CREDENTIALS_FILE", tok.accessToken)
	}
}

func TestProfileEnvOverrideSelectsProfile(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", func(rec map[string]any) {
		rec["access_token"] = "kc_default"
	}))
	writeTestCreds(t, path, "work", credsRecord("https://api.example.test", func(rec map[string]any) {
		rec["tenant"] = "globex"
		rec["access_token"] = "kc_work"
	}))
	t.Setenv("KNOXCALL_PROFILE", "work")

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "globex" {
		t.Errorf("tenant = %q, want globex from the selected profile", c.opts.Tenant)
	}
	tok, err := c.getToken(context.Background())
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if tok.accessToken != "kc_work" {
		t.Fatalf("token = %q, want the work profile's token", tok.accessToken)
	}
}

func TestExplicitStoredCredentialsPathAndProfile(t *testing.T) {
	clearConstructionEnv(t)
	custom := filepath.Join(t.TempDir(), "custom.json")
	writeTestCreds(t, custom, "staging", credsRecord("https://api.example.test", func(rec map[string]any) {
		rec["tenant"] = "stagecorp"
		rec["access_token"] = "kc_staging"
	}))

	c, err := New(Options{Credentials: StoredCredentials{Path: custom, Profile: "staging"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.opts.Tenant != "stagecorp" {
		t.Errorf("tenant = %q, want seeded from the explicit path+profile", c.opts.Tenant)
	}
	tok, err := c.getToken(context.Background())
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if tok.accessToken != "kc_staging" {
		t.Fatalf("token = %q, want kc_staging", tok.accessToken)
	}
}

// ── Secret hygiene ────────────────────────────────────────────────────────────

func TestStoredCredentialsFmtOutputNeverContainsFileTokens(t *testing.T) {
	path := clearConstructionEnv(t)
	writeTestCreds(t, path, "default", credsRecord("https://api.example.test", nil))

	c, err := New(Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.getToken(context.Background()); err != nil {
		t.Fatalf("getToken: %v", err)
	}
	for _, dump := range []string{
		fmt.Sprintf("%v", c.creds),
		fmt.Sprintf("%+v", c.creds),
		fmt.Sprintf("%#v", c.creds),
		fmt.Sprintf("%v", c.opts),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
	} {
		for _, secret := range []string{"kc_stored_fresh", "rt_old"} {
			if strings.Contains(dump, secret) {
				t.Errorf("fmt output %q leaks %q", dump, secret)
			}
		}
	}
}
