package knoxcall

// Tests for the NotAuthenticatedError raised when credential auto-detection
// finds nothing (PARITY §1). Distinctly typed so callers can branch on
// "not logged in — offer Login()", yet still an errors.As match for the base
// bootstrap error so existing catches keep working.

import (
	"context"
	"errors"
	"testing"
)

// The detect ladder gives up with a *NotAuthenticatedError when no credential
// is configured anywhere — and it stays LAZY: New() succeeds, the error only
// surfaces at the first token fetch.
func TestNoCredentialYieldsNotAuthenticatedErrorLazily(t *testing.T) {
	clearConstructionEnv(t) // no env creds; credentials file points at an unwritten temp path

	c, err := New(Options{Tenant: "acme", BaseURL: "https://api.example.test"})
	if err != nil {
		t.Fatalf("New must not fail when no credential is configured (auto-detect is lazy): %v", err)
	}

	_, err = c.getToken(context.Background())
	var nae *NotAuthenticatedError
	if !errors.As(err, &nae) {
		t.Fatalf("err = %v (%T), want *NotAuthenticatedError from the exhausted detect ladder", err, err)
	}
	if err.Error() == "" {
		t.Fatalf("err carries no message: %v", err)
	}
}

// NotAuthenticatedError embeds/unwraps to *BootstrapError, so a generic
// errors.As(err, &bootErr) still catches it while a specific
// errors.As(err, &notAuth) branch also matches.
func TestNotAuthenticatedErrorIsABootstrapError(t *testing.T) {
	var err error = notAuthenticated("no credential found")

	var be *BootstrapError
	if !errors.As(err, &be) {
		t.Fatalf("errors.As(&BootstrapError) = false, want NotAuthenticatedError to unwrap to *BootstrapError")
	}
	if be.Error() == "" {
		t.Fatalf("bootstrap error message empty")
	}
	var nae *NotAuthenticatedError
	if !errors.As(err, &nae) {
		t.Fatalf("errors.As(&NotAuthenticatedError) = false, want the concrete type to match")
	}
}
