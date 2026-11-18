package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

func TestWhoamiPrintsTenantViaSDKClient(t *testing.T) {
	path := isolateEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/account" || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer kc_stored" {
			t.Errorf("Authorization = %q, want the stored access token as Bearer", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"id":                "t_1",
				"slug":              "acme",
				"name":              "Acme Corp",
				"subscription_plan": "pro",
			},
		})
	}))
	defer srv.Close()

	record := map[string]any{
		"tenant":                  "acme",
		"base_url":                srv.URL,
		"client_id":               "kc_cli_real",
		"refresh_token":           "rt_x",
		"access_token":            "kc_stored",
		"access_token_expires_at": credfile.FormatExpiry(time.Now().Add(time.Hour)),
	}
	if err := credfile.WriteProfile(path, "default", record); err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"whoami"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}
	out := tio.out.String()
	for _, want := range []string{
		"Tenant: Acme Corp",
		"Slug:   acme",
		"Plan:   pro",
		"Profile: default (" + path + ")",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q; got:\n%s", want, out)
		}
	}
	if strings.Contains(out, "kc_stored") || strings.Contains(out, "rt_x") {
		t.Error("tokens leaked to stdout")
	}
}

func TestWhoamiNotLoggedIn(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"whoami", "--profile", "staging"})
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
