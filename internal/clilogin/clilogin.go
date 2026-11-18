// Package clilogin implements the interactive `knoxcall login` OAuth flows —
// authorization-code + PKCE over a loopback redirect (RFC 7636 / RFC 8252) and
// the RFC 8628 device-code flow — plus profile persistence. It is the single
// source of truth for that flow, shared by BOTH the cmd/knoxcall CLI (package
// main) and the SDK's library-level knoxcall.Login / knoxcall.EnsureLogin
// helpers (PARITY §13/§14). Being under internal/ it is invisible outside this
// module, so it widens no public API.
//
// The Python SDK's knoxcall.cli is the cross-SDK reference implementation.
package clilogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

const (
	// CLIClientID is the reserved alias accepted by /oauth/authorize and the
	// device endpoints; the server lazily provisions the tenant's real CLI
	// client and returns its id as the `client_id` extension member on the
	// token response.
	CLIClientID = "knoxcall-cli"

	// DeviceGrant is the RFC 8628 device-code grant type.
	DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

	// DefaultBrowserTimeout is how long the loopback flow waits for the
	// browser redirect before giving up.
	DefaultBrowserTimeout = 300 * time.Second
)

// Flow carries the injectable dependencies for a login flow: where prompts are
// written, the HTTP client for token exchange, a context-aware sleeper (device
// poll cadence), and the browser launcher. Both the CLI and the library login
// helpers build a Flow so they share one implementation.
type Flow struct {
	Stdout      io.Writer
	HTTP        *http.Client
	Sleep       func(ctx context.Context, d time.Duration) error
	OpenBrowser func(url string) error
}

// -- PKCE (RFC 7636, S256 only) ---------------------------------------------------

// GeneratePKCEPair returns (code_verifier, code_challenge) — S256, unpadded
// base64url.
func GeneratePKCEPair() (verifier, challenge string, err error) {
	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge, nil
}

// BuildAuthorizeURL constructs the /oauth/authorize URL for the auth-code flow.
func BuildAuthorizeURL(baseURL, redirectURI, state, codeChallenge, tenant string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {CLIClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	if tenant != "" {
		params.Set("tenant", tenant)
	}
	return baseURL + "/oauth/authorize?" + params.Encode()
}

// -- Loopback redirect receiver (RFC 8252 §7.3) -------------------------------------

// LoopbackServer is a one-shot loopback HTTP server on 127.0.0.1:0 for the
// authorize redirect.
type LoopbackServer struct {
	srv    *http.Server
	Port   int
	result chan map[string]string
}

// NewLoopbackServer starts a one-shot loopback listener on 127.0.0.1:0.
func NewLoopbackServer() (*LoopbackServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not start the loopback listener: %w", err)
	}
	s := &LoopbackServer{
		Port:   ln.Addr().(*net.TCPAddr).Port,
		result: make(chan map[string]string, 1),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", s.handleCallback) // anything else 404s
	s.srv = &http.Server{Handler: mux}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

func (s *LoopbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	result := make(map[string]string, len(query))
	for k, vs := range query {
		if len(vs) > 0 && vs[0] != "" {
			result[k] = vs[0]
		}
	}
	failed := result["error"] != "" || result["code"] == ""
	outcome := "<h1>Signed in</h1><p>You can close this window and return to your terminal.</p>"
	if failed {
		outcome = "<h1>Sign-in failed</h1><p>Return to your terminal for details.</p>"
	}
	page := "<!doctype html><meta charset='utf-8'><title>KnoxCall CLI</title>" +
		"<body style='font-family:system-ui;margin:4rem auto;max-width:28rem'>" +
		outcome + "</body>"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, page)
	select {
	case s.result <- result:
	default: // one-shot: only the first callback counts
	}
}

// WaitForCode blocks until the browser hits /callback; validates state
// (constant-time), returns the authorization code.
func (s *LoopbackServer) WaitForCode(ctx context.Context, expectedState string, timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		return "", errors.New("timed out waiting for the browser sign-in to complete")
	case <-ctx.Done():
		return "", ctx.Err()
	case result := <-s.result:
		if e := result["error"]; e != "" {
			detail := result["error_description"]
			if detail == "" {
				detail = e
			}
			return "", fmt.Errorf("authorization failed: %s", detail)
		}
		if subtle.ConstantTimeCompare([]byte(result["state"]), []byte(expectedState)) != 1 {
			return "", errors.New("state mismatch in the OAuth callback — possible CSRF, aborting")
		}
		if result["code"] == "" {
			return "", errors.New("no authorization code in the OAuth callback")
		}
		return result["code"], nil
	}
}

// Close shuts down the loopback server.
func (s *LoopbackServer) Close() { _ = s.srv.Close() }

// -- Flows --------------------------------------------------------------------------

// AuthCode runs the authorization-code + PKCE loopback flow and returns the
// parsed token response body. The authorize URL is ALWAYS printed; a broken
// browser launcher is never fatal.
func (f *Flow) AuthCode(ctx context.Context, baseURL, tenant string, timeout time.Duration) (map[string]any, error) {
	verifier, challenge, err := GeneratePKCEPair()
	if err != nil {
		return nil, err
	}
	stateBuf := make([]byte, 24)
	if _, err := rand.Read(stateBuf); err != nil {
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(stateBuf)

	server, err := NewLoopbackServer()
	if err != nil {
		return nil, err
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", server.Port)
	authURL := BuildAuthorizeURL(baseURL, redirectURI, state, challenge, tenant)
	// ALWAYS print the URL — never rely on the browser opening.
	fmt.Fprintf(f.Stdout, "Opening your browser to sign in. If it does not open, visit:\n\n  %s\n\n", authURL)
	if f.OpenBrowser != nil {
		_ = f.OpenBrowser(authURL) // URL is printed; a broken browser launcher is not fatal
	}
	code, err := server.WaitForCode(ctx, state, timeout)
	server.Close()
	if err != nil {
		return nil, err
	}

	status, body, err := f.PostForm(ctx, baseURL+"/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {CLIClientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return nil, err
	}
	if status >= 400 || StrVal(body, "access_token") == "" {
		return nil, errors.New(tokenErrorMessage(status, body))
	}
	return body, nil
}

// PollDeviceToken polls the token endpoint per RFC 8628 §3.5, honoring
// interval + slow_down (+5s). The sleep runs BEFORE the first poll.
func (f *Flow) PollDeviceToken(ctx context.Context, baseURL, deviceCode string, interval, expiresIn time.Duration) (map[string]any, error) {
	deadline := time.Now().Add(expiresIn)
	for {
		if time.Now().After(deadline) {
			return nil, errors.New("device authorization expired — run `knoxcall login` again")
		}
		if err := f.Sleep(ctx, interval); err != nil {
			return nil, err
		}
		status, body, err := f.PostForm(ctx, baseURL+"/oauth/token", url.Values{
			"grant_type":  {DeviceGrant},
			"device_code": {deviceCode},
			"client_id":   {CLIClientID},
		})
		if err != nil {
			return nil, err
		}
		if status < 400 && StrVal(body, "access_token") != "" {
			return body, nil
		}
		switch StrVal(body, "error") {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "expired_token":
			return nil, errors.New("the device code expired — run `knoxcall login` again")
		case "access_denied":
			return nil, errors.New("sign-in was denied")
		}
		return nil, errors.New(tokenErrorMessage(status, body))
	}
}

// Device runs the RFC 8628 device-code flow end-to-end and returns the parsed
// token response body.
func (f *Flow) Device(ctx context.Context, baseURL string) (map[string]any, error) {
	status, body, err := f.PostForm(ctx, baseURL+"/oauth/device_authorization",
		url.Values{"client_id": {CLIClientID}})
	if err != nil {
		return nil, err
	}
	if status >= 400 || StrVal(body, "device_code") == "" {
		return nil, errors.New(tokenErrorMessage(status, body))
	}

	fmt.Fprintf(f.Stdout, "To sign in, open:\n\n  %s\n\nand enter the code:\n\n  %s\n\n",
		StrVal(body, "verification_uri"), StrVal(body, "user_code"))
	if complete := StrVal(body, "verification_uri_complete"); complete != "" {
		fmt.Fprintf(f.Stdout, "(or open %s directly)\n\n", complete)
	}
	fmt.Fprintln(f.Stdout, "Waiting for approval…")

	interval := time.Duration(numVal(body, "interval", 5)) * time.Second
	expiresIn := time.Duration(numVal(body, "expires_in", 900) * float64(time.Second))
	return f.PollDeviceToken(ctx, baseURL, StrVal(body, "device_code"), interval, expiresIn)
}

// PostForm POSTs a urlencoded form; returns (status, parsed-JSON-or-empty-map).
//
// Connection failures return an error with a human message. HTTP error
// statuses are returned, not raised — device polling needs the error codes.
func (f *Flow) PostForm(ctx context.Context, urlStr string, form url.Values) (int, map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := f.HTTP.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("could not reach %s: %w", urlStr, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("could not reach %s: %w", urlStr, err)
	}
	body := map[string]any{}
	_ = json.Unmarshal(raw, &body) // non-JSON / non-object body → empty map
	if body == nil {
		body = map[string]any{} // a literal JSON null unmarshals to a nil map
	}
	return res.StatusCode, body, nil
}

// -- Persistence + helpers ----------------------------------------------------------

// PersistLogin stores a successful token response as a credentials-file
// profile UNDER THE FILE LOCK — a login racing a concurrent refresh must not
// lose a rotation. It persists the `tenant` and `client_id` extension members:
// refreshes must use the REAL per-tenant client id, not the `knoxcall-cli`
// alias.
func PersistLogin(ctx context.Context, path, profile, baseURL string, tokenBody map[string]any, fallbackTenant string) (map[string]any, error) {
	expiresIn := numVal(tokenBody, "expires_in", 3600)
	tenant := StrVal(tokenBody, "tenant")
	if tenant == "" {
		tenant = fallbackTenant
	}
	clientID := StrVal(tokenBody, "client_id")
	if clientID == "" {
		clientID = CLIClientID
	}
	record := map[string]any{
		"tenant":                  nilIfEmpty(tenant),
		"base_url":                baseURL,
		"client_id":               clientID,
		"refresh_token":           nilIfEmpty(StrVal(tokenBody, "refresh_token")),
		"access_token":            nilIfEmpty(StrVal(tokenBody, "access_token")),
		"access_token_expires_at": credfile.FormatExpiry(time.Now().Add(time.Duration(expiresIn * float64(time.Second)))),
		"scope":                   StrVal(tokenBody, "scope"),
	}
	lock := credfile.NewLock(path)
	if err := lock.Acquire(ctx); err != nil {
		return nil, err
	}
	defer lock.Release()
	if err := credfile.WriteProfile(path, profile, record); err != nil {
		return nil, err
	}
	return record, nil
}

// DefaultBaseURL resolves the management API base URL:
// flagValue > KNOXCALL_BASE_URL env > sandbox/production default.
func DefaultBaseURL(flagValue string, sandbox bool) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("KNOXCALL_BASE_URL"); env != "" {
		return env
	}
	if sandbox {
		return "https://sandbox.knoxcall.com"
	}
	return "https://api.knoxcall.com"
}

// StrVal returns m[key] as a string ("" for missing / non-string values).
func StrVal(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// numVal returns m[key] as a number, tolerating string values; missing,
// malformed, and non-positive values yield def (matching the Python
// reference's `int(body.get(...) or default)` semantics).
func numVal(m map[string]any, key string, def float64) float64 {
	var v float64
	switch n := m[key].(type) {
	case float64:
		v = n
	case string:
		val, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return def
		}
		v = val
	default:
		return def
	}
	if v <= 0 {
		return def
	}
	return v
}

// nilIfEmpty maps "" to nil so credfile.WriteProfile drops the key, mirroring
// the Python reference (None values are not persisted).
func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func tokenErrorMessage(status int, body map[string]any) string {
	detail := StrVal(body, "error_description")
	if detail == "" {
		detail = StrVal(body, "error")
	}
	if detail == "" {
		detail = fmt.Sprintf("HTTP %d", status)
	}
	return "sign-in failed: " + detail
}

// -- Browser launcher ---------------------------------------------------------------

// OpenBrowser launches the platform's URL opener (`start` / `open` /
// `xdg-open` by GOOS). Callers ALWAYS print the URL before invoking it — a
// broken or headless launcher is never fatal.
func OpenBrowser(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		// cmd's `start` treats & as a command separator; escape it. The
		// empty "" is start's window-title argument.
		cmd = exec.Command("cmd", "/c", "start", "", strings.ReplaceAll(rawURL, "&", "^&"))
	case "darwin":
		cmd = exec.Command("open", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}
