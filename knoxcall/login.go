package knoxcall

// Interactive first-run authentication — OPT-IN, and NEVER on the request path.
//
// The persistent credential (`knoxcall login` → ~/.knoxcall/credentials.json,
// rotating refresh token) already survives restarts; these helpers just let an
// embedding program *initiate* that login programmatically. Because an SDK runs
// inside someone else's process (production servers, CI, background agents,
// serverless), a browser/device flow must be an explicit, TTY-gated call —
// never a silent side effect of a normal API call. New() and Call() never
// trigger this; they return *NotAuthenticatedError when no credential is found.
//
// The flow itself is the SAME code the `knoxcall` CLI uses
// (internal/clilogin), so there is one tested implementation. Node's
// src/login.ts is the cross-SDK reference (PARITY §14).

import (
	"context"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/knoxcall/sdk-go/internal/clilogin"
)

// LoginOptions configures the interactive Login / EnsureLogin helpers.
type LoginOptions struct {
	// Tenant hint for the authorize URL (optional; discovered otherwise).
	Tenant string
	// Sandbox targets the sandbox host / Test data plane.
	Sandbox bool
	// BaseURL overrides the management base URL (default: prod, or sandbox
	// when Sandbox is set; KNOXCALL_BASE_URL is consulted when empty).
	BaseURL string
	// Profile selects the credentials-file profile to write/read
	// (default: KNOXCALL_PROFILE, then "default").
	Profile string
	// Mode is "auto" (browser on a desktop with a display, else device) |
	// "browser" | "device". Empty means "auto".
	Mode string
	// Timeout bounds the loopback wait for the browser flow
	// (default clilogin.DefaultBrowserTimeout, 300s).
	Timeout time.Duration
	// AllowNonInteractive bypasses the TTY / CI / KNOXCALL_NO_INTERACTIVE guard.
	AllowNonInteractive bool
	// HTTPClient runs the OAuth flow (default: a 30s client). Not forwarded to
	// the returned client — set ClientOptions.HTTPClient for that.
	HTTPClient *http.Client
	// Stdout receives the flow's prompts (authorize URL / device code)
	// (default os.Stdout).
	Stdout io.Writer
	// OpenBrowser overrides the OS browser launcher (default the platform opener).
	OpenBrowser func(url string) error
	// ClientOptions are forwarded to the returned client; its Credentials and
	// Sandbox are overridden to bind the freshly written profile.
	ClientOptions Options
}

// isTerminal reports whether f is attached to a character device (a real
// terminal). Dependency-free stand-in for term.IsTerminal: a pipe, file, or
// /dev/null lacks os.ModeCharDevice, so redirected or non-interactive stdio is
// correctly treated as "not a terminal" on both POSIX and Windows.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// interactiveGuard refuses to pop a browser or block on a device code where
// doing so is unsafe: a non-interactive process (no TTY), CI, or an explicit
// opt-out. The caller overrides with AllowNonInteractive when they know it is
// safe. Refusal is a *NotAuthenticatedError (PARITY §14).
func interactiveGuard(opts LoginOptions) error {
	if opts.AllowNonInteractive {
		return nil
	}
	if os.Getenv("KNOXCALL_NO_INTERACTIVE") != "" || os.Getenv("CI") != "" {
		return notAuthenticated(
			"knoxcall: interactive login is disabled here (KNOXCALL_NO_INTERACTIVE or CI is set) — " +
				"provision a non-interactive credential (client_id/secret or workload OIDC) instead",
		)
	}
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		return notAuthenticated(
			"knoxcall: no interactive terminal detected — run `knoxcall login` in a terminal, " +
				"or provision a non-interactive credential (client_id/secret or workload OIDC)",
		)
	}
	return nil
}

// hasDesktopBrowser chooses browser-vs-device for mode "auto". Headless CI is
// already blocked by interactiveGuard, so this only runs on a real TTY; on
// Linux, require a display server.
func hasDesktopBrowser() bool {
	if runtime.GOOS == "linux" {
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	}
	return true
}

// clientFromProfile builds a client bound to a written credentials-file
// profile, forwarding ClientOptions but overriding the credential + sandbox.
func clientFromProfile(profile string, opts LoginOptions) (*Client, error) {
	co := opts.ClientOptions
	// The profile is the credential; drop any conflicting flat options the
	// caller left on ClientOptions so New()'s mutual-exclusion check passes.
	co.APIKey = ""
	co.ClientID = ""
	co.ClientSecret = ""
	co.Credentials = StoredCredentials{Profile: profile}
	co.Sandbox = opts.Sandbox
	return New(co)
}

// flowFor builds a clilogin.Flow from the options' (defaulted) dependencies.
func flowFor(opts LoginOptions) *clilogin.Flow {
	out := opts.Stdout
	if out == nil {
		out = os.Stdout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	open := opts.OpenBrowser
	if open == nil {
		open = clilogin.OpenBrowser
	}
	return &clilogin.Flow{Stdout: out, HTTP: hc, Sleep: sleepCtx, OpenBrowser: open}
}

// Login runs the interactive browser (loopback) or device-code login, persists
// the credential to the credentials file, and returns a ready client bound to
// the written profile. The caller explicitly asked to log in, so blocking +
// browser is expected. It refuses (with *NotAuthenticatedError) in a
// non-interactive context unless AllowNonInteractive is set.
func Login(ctx context.Context, opts LoginOptions) (*Client, error) {
	if err := interactiveGuard(opts); err != nil {
		return nil, err
	}
	baseURL := strings.TrimRight(clilogin.DefaultBaseURL(opts.BaseURL, opts.Sandbox), "/")
	profile := resolveProfile(opts.Profile)
	mode := opts.Mode
	if mode == "" {
		mode = "auto"
	}
	useDevice := mode == "device" || (mode == "auto" && !hasDesktopBrowser())

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = clilogin.DefaultBrowserTimeout
	}

	flow := flowFor(opts)
	var tokenBody map[string]any
	var err error
	if useDevice {
		tokenBody, err = flow.Device(ctx, baseURL)
	} else {
		tokenBody, err = flow.AuthCode(ctx, baseURL, opts.Tenant, timeout)
	}
	if err != nil {
		return nil, err
	}

	if _, err := clilogin.PersistLogin(ctx, resolveCredentialsPath(""), profile, baseURL, tokenBody, opts.Tenant); err != nil {
		return nil, err
	}
	return clientFromProfile(profile, opts)
}

// EnsureLogin returns a client from an already-stored credential for the
// profile when one is present (no prompt, no network), otherwise runs Login
// once. The ergonomic "make sure I'm authenticated, then give me a client"
// entry point.
func EnsureLogin(ctx context.Context, opts LoginOptions) (*Client, error) {
	profile := resolveProfile(opts.Profile)
	if credentialsProfileAvailable(resolveCredentialsPath(""), profile) {
		return clientFromProfile(profile, opts)
	}
	return Login(ctx, opts)
}
