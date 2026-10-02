package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

func TestLogoutRevokesAndRemovesProfile(t *testing.T) {
	path := isolateEnv(t)
	var mu sync.Mutex
	type call struct{ path, form string }
	var seen []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, call{r.URL.Path, string(raw)})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}")
	}))
	defer srv.Close()
	seedProfiles(t, path, srv.URL)

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"logout", "--profile", "work"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}

	mu.Lock()
	if len(seen) != 1 || seen[0].path != "/oauth/revoke" {
		t.Fatalf("revoke calls = %+v, want one POST /oauth/revoke", seen)
	}
	form := seen[0].form
	mu.Unlock()
	if !strings.Contains(form, "token=rt_work") {
		t.Errorf("revoke form missing the profile's refresh token: %q", form)
	}
	if !strings.Contains(form, "token_type_hint=refresh_token") {
		t.Errorf("revoke form missing token_type_hint: %q", form)
	}
	if !strings.Contains(form, "client_id=kc_cli_real") {
		t.Errorf("revoke form must use the stored real client id: %q", form)
	}
	if credfile.ReadProfile(path, "work") != nil {
		t.Error("work profile still present after logout")
	}
	if credfile.ReadProfile(path, "default") == nil {
		t.Error("default profile removed — other profiles must be kept")
	}
	if !strings.Contains(tio.out.String(), "removed profile 'work'") {
		t.Errorf("stdout = %q, want the removal confirmation", tio.out.String())
	}

	// Removing the last profile deletes the file.
	a2, tio2 := newTestApp(t)
	if rc := a2.run(context.Background(), []string{"logout"}); rc != 0 {
		t.Fatalf("second logout exit = %d, want 0 (stderr: %s)", rc, tio2.err.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("credentials file still exists after the last profile was removed (stat err = %v)", err)
	}
}

func TestLogoutRemovesProfileEvenWhenRevokeFails(t *testing.T) {
	path := isolateEnv(t)
	// A closed server: connection refused → revocation is best-effort.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := srv.URL
	srv.Close()
	seedProfiles(t, path, deadURL)

	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"logout", "--profile", "work"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", rc, tio.err.String())
	}
	if credfile.ReadProfile(path, "work") != nil {
		t.Error("profile still present — removal must proceed when revocation is unreachable")
	}
}

func TestLogoutWithoutCredentialsIsANoop(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	rc := a.run(context.Background(), []string{"logout"})
	if rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if !strings.Contains(tio.out.String(), "nothing to do") {
		t.Errorf("stdout = %q, want the nothing-to-do notice", tio.out.String())
	}
}
