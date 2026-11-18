// Shared test plumbing — isolated env, injectable app, profile seeding.
//
// All HTTP is served by httptest; the loopback callback server binds
// 127.0.0.1:0 and is hit locally. Credentials files live under t.TempDir()
// only (pinned via KNOXCALL_CREDENTIALS_FILE).
package main

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

var envVars = []string{
	"KNOXCALL_TENANT",
	"KNOXCALL_BASE_URL",
	"KNOXCALL_API_BASE_URL",
	"KNOXCALL_PROXY_BASE_URL",
	"KNOXCALL_ACCESS_TOKEN",
	"KNOXCALL_API_KEY",
	"KNOXCALL_CLIENT_ID",
	"KNOXCALL_CLIENT_SECRET",
	"KNOXCALL_PROFILE",
	"KNOXCALL_ENVIRONMENT",
}

// isolateEnv pins every credential-related env var to empty (treated as
// unset) and points the credentials file at a per-test temp path.
func isolateEnv(t *testing.T) string {
	t.Helper()
	for _, v := range envVars {
		t.Setenv(v, "")
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("KNOXCALL_CREDENTIALS_FILE", path)
	return path
}

// testIO captures the app's output streams and recorded poll sleeps.
type testIO struct {
	out    bytes.Buffer
	err    bytes.Buffer
	sleeps []time.Duration
}

// newTestApp builds an app with captured output, a recording (non-blocking)
// sleeper, and a no-op browser launcher.
func newTestApp(t *testing.T) (*app, *testIO) {
	t.Helper()
	tio := &testIO{}
	a := &app{
		stdout: &tio.out,
		stderr: &tio.err,
		http:   &http.Client{Timeout: 10 * time.Second},
		sleep: func(ctx context.Context, d time.Duration) error {
			tio.sleeps = append(tio.sleeps, d)
			return ctx.Err()
		},
		openBrowser: func(string) error { return nil },
	}
	return a, tio
}

// seedProfiles writes the "default" and "work" profiles used by the logout
// tests.
func seedProfiles(t *testing.T, path, baseURL string) {
	t.Helper()
	for _, p := range []struct{ name, rt string }{
		{"default", "rt_default"},
		{"work", "rt_work"},
	} {
		record := map[string]any{
			"tenant":                  "acme",
			"base_url":                baseURL,
			"client_id":               "kc_cli_real",
			"refresh_token":           p.rt,
			"access_token":            "kc_x",
			"access_token_expires_at": credfile.FormatExpiry(time.Now().Add(time.Hour)),
		}
		if err := credfile.WriteProfile(path, p.name, record); err != nil {
			t.Fatalf("WriteProfile(%s): %v", p.name, err)
		}
	}
}
