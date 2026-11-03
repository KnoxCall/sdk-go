package knoxcall

// One-time, deduplicated warnings for security-relevant misconfigurations
// (plaintext transport). Non-blocking and behavior-preserving: a warning never
// returns an error, never panics, and never changes what the client does — it
// only writes once to stderr. Mirrors node src/warn.ts and PARITY §15.
//
// Idiomatic Go avoids stderr spam, so each distinct code fires at most once per
// process. warnWriter is a package variable so tests can capture the output;
// production writes to os.Stderr. (The credentials-file permission warning
// lives in internal/credfile, which cannot import this package — knoxcall
// imports credfile — so it carries its own once-per-process helper.)

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
)

// warnWriter receives one-time security warnings. Swappable in tests.
var warnWriter io.Writer = os.Stderr

// warnedCodes deduplicates by code — LoadOrStore gives the once-per-code guard
// without a dedicated mutex.
var warnedCodes sync.Map

// warnOnce writes a one-time, non-blocking security warning. The same code
// never warns twice in a process.
func warnOnce(code, message string) {
	if _, loaded := warnedCodes.LoadOrStore(code, struct{}{}); loaded {
		return
	}
	fmt.Fprintf(warnWriter, "knoxcall: warning: %s (%s)\n", message, code)
}

// resetWarnedForTests clears the once-per-process dedup so warnings can be
// re-asserted. Test-only.
func resetWarnedForTests() {
	warnedCodes.Range(func(k, _ any) bool {
		warnedCodes.Delete(k)
		return true
	})
}

// isInsecureRemoteURL reports whether raw is a plaintext http:// URL whose host
// is NOT loopback. Plain http:// to localhost / *.localhost / 127.0.0.0/8 /
// ::1 / 0.0.0.0 is the normal dev case and returns false; any other host over
// http:// returns true (credentials and tokens would travel unencrypted).
// https:// and non-http schemes always return false. Mirrors node warn.ts
// isInsecureRemoteUrl / PARITY §15.
func isInsecureRemoteURL(raw string) bool {
	if raw == "" || !strings.HasPrefix(strings.ToLower(raw), "http://") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname()) // strips the port and IPv6 brackets
	switch {
	case host == "localhost",
		strings.HasSuffix(host, ".localhost"),
		host == "0.0.0.0",
		host == "::1",
		strings.HasPrefix(host, "127."):
		return false
	}
	return true
}
