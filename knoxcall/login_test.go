package knoxcall

// Tests for the library-level interactive login helpers (PARITY §14):
// EnsureLogin returns a client from a stored profile with no prompt/network,
// and the interactive guard refuses (with *NotAuthenticatedError) when it is
// unsafe to prompt.

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

// EnsureLogin returns a client bound to an existing profile without prompting
// or any network I/O, seeded (tenant/base URL) from the credentials file.
func TestEnsureLoginReturnsClientFromStoredProfileNoPrompt(t *testing.T) {
	path := clearConstructionEnv(t) // KNOXCALL_CREDENTIALS_FILE → temp path
	record := map[string]any{
		"tenant":                  "acme",
		"base_url":                "https://api.example.test",
		"client_id":               "kc_cli_real",
		"refresh_token":           "rt_x",
		"access_token":            "kc_stored",
		"access_token_expires_at": credfile.FormatExpiry(time.Now().Add(time.Hour)),
	}
	if err := credfile.WriteProfile(path, "default", record); err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}

	c, err := EnsureLogin(context.Background(), LoginOptions{})
	if err != nil {
		t.Fatalf("EnsureLogin: %v", err)
	}
	if c == nil {
		t.Fatal("EnsureLogin returned a nil client")
	}
	if _, ok := c.creds.(StoredCredentials); !ok {
		t.Fatalf("creds = %T, want StoredCredentials bound to the profile", c.creds)
	}
	if c.opts.Tenant != "acme" {
		t.Fatalf("tenant = %q, want acme seeded from the credentials file", c.opts.Tenant)
	}
}

// The interactive guard refuses to prompt in a non-interactive context,
// raising *NotAuthenticatedError so the caller can branch on it.
func TestLoginInteractiveGuardRefuses(t *testing.T) {
	clearConstructionEnv(t)

	t.Run("KNOXCALL_NO_INTERACTIVE", func(t *testing.T) {
		t.Setenv("KNOXCALL_NO_INTERACTIVE", "1")
		_, err := Login(context.Background(), LoginOptions{Tenant: "acme"})
		var nae *NotAuthenticatedError
		if !errors.As(err, &nae) {
			t.Fatalf("err = %v (%T), want *NotAuthenticatedError under KNOXCALL_NO_INTERACTIVE", err, err)
		}
	})

	t.Run("CI", func(t *testing.T) {
		t.Setenv("KNOXCALL_NO_INTERACTIVE", "")
		t.Setenv("CI", "true")
		_, err := Login(context.Background(), LoginOptions{Tenant: "acme"})
		var nae *NotAuthenticatedError
		if !errors.As(err, &nae) {
			t.Fatalf("err = %v (%T), want *NotAuthenticatedError under CI", err, err)
		}
	})

	t.Run("no-tty", func(t *testing.T) {
		t.Setenv("KNOXCALL_NO_INTERACTIVE", "")
		t.Setenv("CI", "")
		if isTerminal(os.Stdin) && isTerminal(os.Stdout) {
			t.Skip("stdin/stdout are terminals in this runner; the no-TTY guard is not exercised")
		}
		_, err := Login(context.Background(), LoginOptions{Tenant: "acme"})
		var nae *NotAuthenticatedError
		if !errors.As(err, &nae) {
			t.Fatalf("err = %v (%T), want *NotAuthenticatedError with no TTY", err, err)
		}
	})
}
