package knoxcall

// Shared credentials file (~/.knoxcall/credentials.json) — read, write, lock,
// refresh. The file is written by `knoxcall login` and consumed by every SDK
// through the StoredCredentials credential. Format, lock protocol, and refresh
// rules are cross-SDK identical (see ../../PARITY.md §2); the Python SDK's
// auth/credentials_file.py is the reference implementation.
//
// The server's refresh tokens are SINGLE-USE with family revocation on reuse,
// so any refresh MUST:
//
//  1. hold the sibling credentials.json.lock file (exclusive-create, 100ms
//     retry up to 10s, locks older than the stale window are broken — but
//     only ownership-aware, see credfile.FileLock; the window sits safely
//     above the token-endpoint HTTP timeout so a live refresh is never
//     broken),
//  2. RE-READ the file after acquiring the lock (another process may have
//     already refreshed), and
//  3. atomically (temp file + rename) write back the rotated refresh token
//     before releasing the lock.
//
// The file primitives (resolution, tolerant reads, atomic writes, the lock,
// expiry formatting) live in internal/credfile so the cmd/knoxcall CLI can
// share them without widening this package's public API; the unexported
// wrappers below keep this package's call sites unchanged.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

const (
	// A stored access token is "fresh" while it has more than this much
	// validity left; below the threshold the provider refreshes under the
	// file lock.
	credentialsFreshWindow = 60 * time.Second

	reloginMessage = "stored CLI credentials are no longer valid — run `knoxcall login` again"
)

// StoredCredentials authenticates with the credentials file written by
// `knoxcall login`. It holds no secrets itself — tokens are read from the
// file at token-fetch time. The file is the cross-process cache and refresh
// authority: fresh stored access tokens are used directly, and expired ones
// are refreshed under the sibling .lock file with the rotated (single-use)
// refresh token written back atomically before the lock is released.
type StoredCredentials struct {
	// Path to the credentials file. Empty resolves KNOXCALL_CREDENTIALS_FILE,
	// then ~/.knoxcall/credentials.json.
	Path string
	// Profile selects a named profile within the file. Empty resolves
	// KNOXCALL_PROFILE, then "default".
	Profile string
}

func (StoredCredentials) isCredentials() {}

// String implements fmt.Stringer. StoredCredentials carries no secrets (the
// tokens live in the file), so the path and profile are shown as-is.
func (s StoredCredentials) String() string {
	return fmt.Sprintf("knoxcall.StoredCredentials{Path:%q, Profile:%q}", s.Path, s.Profile)
}

// GoString implements fmt.GoStringer for %#v.
func (s StoredCredentials) GoString() string { return s.String() }

// -- Delegating wrappers over internal/credfile ------------------------------------

// resolveCredentialsPath resolves the credentials file path: explicit
// override > KNOXCALL_CREDENTIALS_FILE > ~/.knoxcall/credentials.json.
// An unresolvable home directory yields "" — readers treat it as a missing
// file, so the provider is skipped silently.
func resolveCredentialsPath(override string) string { return credfile.ResolvePath(override) }

// resolveProfile resolves the profile name: explicit override >
// KNOXCALL_PROFILE > "default".
func resolveProfile(override string) string { return credfile.ResolveProfile(override) }

// readCredentialsProfile returns one profile's record, or nil (missing file,
// malformed JSON, unknown profile).
func readCredentialsProfile(path, profile string) map[string]any {
	return credfile.ReadProfile(path, profile)
}

// credentialsProfileAvailable is the construction-time presence check:
// file exists AND the selected profile parses.
func credentialsProfileAvailable(path, profile string) bool {
	return credfile.ProfileAvailable(path, profile)
}

// writeCredentialsProfile merges one profile into the file (other profiles
// and unknown top-level keys untouched), atomically. Nil values are dropped
// from the record.
func writeCredentialsProfile(path, profile string, record map[string]any) error {
	return credfile.WriteProfile(path, profile, record)
}

// formatCredentialsExpiry renders an expiry as the cross-SDK wire format
// (UTC, RFC 3339, second precision — e.g. "2026-07-04T10:00:00Z").
func formatCredentialsExpiry(t time.Time) string { return credfile.FormatExpiry(t) }

// parseCredentialsExpiry tolerates RFC 3339 (Z or numeric offsets) and
// zone-less ISO timestamps (assumed UTC, matching the Python reference).
func parseCredentialsExpiry(v any) (time.Time, bool) { return credfile.ParseExpiry(v) }

// newCredentialsFileLock builds the sibling ".lock" file lock (see
// credfile.FileLock for the cross-SDK protocol).
func newCredentialsFileLock(target string) *credfile.FileLock { return credfile.NewLock(target) }

// -- Client seeding -----------------------------------------------------------------

// seedFromStoredCredentials seeds tenant/base URL from the credentials file
// when the caller did not set them explicitly — explicit Options values and
// env vars always win, and Sandbox counts as an explicit base-URL choice.
// Malformed/missing file → no-op (the chain already vetted presence).
func seedFromStoredCredentials(opts *Options, sc StoredCredentials) {
	record := readCredentialsProfile(resolveCredentialsPath(sc.Path), resolveProfile(sc.Profile))
	if record == nil {
		return
	}
	if opts.Tenant == "" {
		// KNOXCALL_TENANT was already consulted by New() before this point,
		// so an env-provided tenant lands in opts.Tenant first and wins.
		opts.Tenant = strField(record, "tenant")
	}
	if opts.BaseURL == "" && !opts.Sandbox &&
		os.Getenv("KNOXCALL_BASE_URL") == "" && os.Getenv("KNOXCALL_API_BASE_URL") == "" {
		opts.BaseURL = strings.TrimRight(strField(record, "base_url"), "/")
	}
}

func strField(record map[string]any, key string) string {
	s, _ := record[key].(string)
	return s
}

// -- Token fetch (fast path + locked refresh) -----------------------------------------

// storedCredentialsReloginError builds the typed auth error for unrecoverable
// stored-credential states. Only Detail carries the re-login hint — the
// server's error_description is deliberately not copied so the hint is what
// prints, and no token value can ever reach the message.
func storedCredentialsReloginError(from *APIError) error {
	ae := APIError{Detail: reloginMessage}
	if from != nil {
		ae.StatusCode = from.StatusCode
		ae.Message = from.Message
		ae.RequestID = from.RequestID
	}
	return &AuthenticationError{ae}
}

// storedTokenFastPath returns a usable cache entry when the stored access
// token still has more than 60s of validity — no HTTP, no lock.
//
// The entry deliberately carries no refresh token (cachedToken cannot hold
// one): the file is the sole refresh authority, so no in-process fallback —
// including getToken's stale-but-valid path — can ever replay a consumed
// (rotated) refresh token. Lifetime is left zero so the refresh-ahead window
// re-consults the file instead of trusting a stale in-process copy.
func storedTokenFastPath(record map[string]any) *cachedToken {
	token := strField(record, "access_token")
	expiresAt, ok := parseCredentialsExpiry(record["access_token_expires_at"])
	if token == "" || !ok {
		return nil
	}
	if time.Until(expiresAt) <= credentialsFreshWindow {
		return nil
	}
	return &cachedToken{
		accessToken: token,
		tokenType:   "Bearer",
		expiresAt:   expiresAt,
		tenant:      strField(record, "tenant"),
	}
}

// fetchStoredToken produces a usable access token from the credentials file.
//
// Fast path: stored access token with >60s validity, no HTTP. Otherwise
// lock → re-read → re-check → refresh-token grant → atomic write-back of the
// rotated refresh token before the lock is released.
func (c *Client) fetchStoredToken(ctx context.Context, sc StoredCredentials) (*cachedToken, error) {
	path := resolveCredentialsPath(sc.Path)
	profile := resolveProfile(sc.Profile)

	record := readCredentialsProfile(path, profile)
	if record == nil {
		// Detection saw the profile but it has since vanished/corrupted.
		return nil, storedCredentialsReloginError(nil)
	}
	if tok := storedTokenFastPath(record); tok != nil {
		return tok, nil
	}

	lock := newCredentialsFileLock(path)
	if err := lock.Acquire(ctx); err != nil {
		return nil, err
	}
	defer lock.Release()

	record = readCredentialsProfile(path, profile)
	if record == nil {
		return nil, storedCredentialsReloginError(nil)
	}
	if tok := storedTokenFastPath(record); tok != nil {
		return tok, nil // another process refreshed while we waited on the lock
	}
	return c.refreshStoredToken(ctx, path, profile, record)
}

// refreshStoredToken runs the refresh_token grant with the file's client_id
// (the tenant's real CLI client — public, no secret) and persists the rotated
// refresh token. The caller MUST hold the credentials file lock.
func (c *Client) refreshStoredToken(ctx context.Context, path, profile string, record map[string]any) (*cachedToken, error) {
	refreshToken := strField(record, "refresh_token")
	clientID := strField(record, "client_id")
	if refreshToken == "" || clientID == "" {
		return nil, storedCredentialsReloginError(nil)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	if resp.StatusCode >= 400 {
		err := errorFromResponse(resp.StatusCode, body, resp.Header)
		var ae *APIError
		if errors.As(err, &ae) && ae.Message == "invalid_grant" {
			// Revoked family or expired refresh token — unrecoverable here.
			return nil, storedCredentialsReloginError(ae)
		}
		return nil, err
	}

	var tr struct {
		AccessToken  string      `json:"access_token"`
		ExpiresIn    flexSeconds `json:"expires_in"`
		RefreshToken string      `json:"refresh_token"`
		Scope        string      `json:"scope"`
		Tenant       string      `json:"tenant"`    // extension member (RFC 6749 §5.1)
		ClientID     string      `json:"client_id"` // extension member: the real per-tenant client id
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Detail:     fmt.Sprintf("token endpoint returned an unexpected response (status %d)", resp.StatusCode),
		}
	}

	ttl := time.Duration(float64(tr.ExpiresIn) * float64(time.Second))
	if ttl <= 0 {
		ttl = time.Hour
	}
	now := time.Now()

	// Write back the rotated refresh token BEFORE the caller releases the
	// lock — the old one is already consumed server-side.
	updated := make(map[string]any, len(record)+2)
	for k, v := range record {
		updated[k] = v
	}
	updated["access_token"] = tr.AccessToken
	updated["access_token_expires_at"] = formatCredentialsExpiry(now.Add(ttl))
	if tr.RefreshToken != "" {
		updated["refresh_token"] = tr.RefreshToken
	}
	if tr.Scope != "" {
		updated["scope"] = tr.Scope
	}
	if tr.Tenant != "" {
		updated["tenant"] = tr.Tenant
	}
	if tr.ClientID != "" {
		updated["client_id"] = tr.ClientID
	}
	if err := writeCredentialsProfile(path, profile, updated); err != nil {
		return nil, fmt.Errorf("knoxcall: persist rotated credentials: %w", err)
	}

	return &cachedToken{
		accessToken: tr.AccessToken,
		tokenType:   "Bearer",
		expiresAt:   now.Add(ttl),
		lifetime:    ttl,
		tenant:      strField(updated, "tenant"),
	}, nil
}
