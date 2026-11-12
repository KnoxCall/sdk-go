package knoxcall

// The DPoP server nonce (RFC 9449 section 8) -- PARITY 7.1, client Phase 4.3.
//
// KnoxCall answers EVERY request that carried a `DPoP` proof header with
// `DPoP-Nonce: <value>`: mints, refusals and successful calls alike, on
// POST /oauth/token, /v1, the tenant data plane, the self-hosted proxy and the
// AI gateway. The value is stateless, changes every minute, and the server
// accepts the current and the previous minute's -- so a nonce is good for
// 60-120 s.
//
// The server's rule is VERIFY-IF-PRESENT: a proof carrying a `nonce` claim must
// carry one the server would issue now, and a proof carrying none is still
// accepted. So sending one is an optimisation and a readiness step, never a
// requirement, and a client that never learned a nonce keeps working.
//
// WHAT THIS FILE IS. A per-origin memory of the last nonce seen, plus the
// predicate that recognises the server's "use a nonce" refusal. Both are
// deliberately tiny and have no I/O.
//
//   - Keyed by ORIGIN (scheme + host + port), because that is what the nonce is
//     scoped to: the management API and a tenant's data plane are different
//     origins and issue different values. Keyed coarser and a cross-origin
//     nonce would be sent and refused; keyed finer (a path) and almost every
//     request would start without one.
//   - Last-write-wins, no expiry. A nonce is not a secret and needs no storage
//     beyond the process. It need not be fresh either: the worst a stale one
//     costs is the single documented retry, and the server deliberately refuses
//     a stale nonce BEFORE claiming the proof's jti, so that retry is not then
//     refused for an unrelated reason.
//   - Guarded by a mutex: one *Client is shared across goroutines by design.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	// nonceHeader is the response header the server sends on every
	// DPoP-carrying request.
	nonceHeader = "DPoP-Nonce"

	// useDpopNonce is the RFC 9449 section 8 error code: in the OAuth body on
	// the authorization server, in WWW-Authenticate on a resource server.
	useDpopNonce = "use_dpop_nonce"
)

// originOf returns scheme://host[:port] -- the scope a nonce belongs to -- or
// "" when the URL has no host, which simply means "do not remember this one".
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// dpopNonceStore holds the last DPoP-Nonce seen per origin. See the file comment.
type dpopNonceStore struct {
	mu       sync.Mutex
	byOrigin map[string]string
}

func newDpopNonceStore() *dpopNonceStore {
	return &dpopNonceStore{byOrigin: map[string]string{}}
}

// remember records the nonce on a response, if it carried one, and returns it.
func (s *dpopNonceStore) remember(rawURL string, header http.Header) string {
	if s == nil || header == nil {
		return ""
	}
	value := strings.TrimSpace(header.Get(nonceHeader))
	if value == "" {
		return ""
	}
	origin := originOf(rawURL)
	if origin == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byOrigin[origin] = value
	return value
}

// get returns the nonce to put in a proof for rawURL, or "" when this origin has
// not answered yet (which is fine -- the server accepts a proof with no nonce
// claim, and sign() omits the claim for "").
func (s *dpopNonceStore) get(rawURL string) string {
	if s == nil {
		return ""
	}
	origin := originOf(rawURL)
	if origin == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byOrigin[origin]
}

// snapshot copies the map, for tests and debugging.
func (s *dpopNonceStore) snapshot() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.byOrigin))
	for k, v := range s.byOrigin {
		out[k] = v
	}
	return out
}

// isUseDpopNonce reports whether a refusal is the server asking for a (fresh)
// nonce.
//
// RFC 9449 splits the two surfaces and so does KnoxCall, which is why this takes
// all three inputs rather than just a status:
//
//   - POST /oauth/token (authorization server, section 8.1) answers 400 with the
//     OAuth body {"error": "use_dpop_nonce", ...};
//   - /v1, the tenant data plane, the self-hosted proxy and the AI gateway
//     (resource server, section 8.2) answer 401 with
//     WWW-Authenticate: DPoP error="use_dpop_nonce". On /v1 the body's error type
//     says it too, but the tenant data plane keeps its deliberately opaque
//     Unauthorized body, SO THE HEADER IS THE ONLY SIGNAL THERE. Reading the body
//     alone would make this work on /v1 and silently not on the data plane.
func isUseDpopNonce(status int, code string, header http.Header) bool {
	if status != 400 && status != 401 {
		return false
	}
	if code == useDpopNonce {
		return true
	}
	if header == nil {
		return false
	}
	return strings.Contains(strings.ToLower(header.Get("WWW-Authenticate")), useDpopNonce)
}

// isUseDpopNonceErr is the error-shaped form the retry loops use. It unwraps
// with errors.As exactly as statusOf does, so it sees through every typed
// wrapper (AuthenticationError and friends all embed APIError). The headers come
// off that error, which is why APIError carries them.
func isUseDpopNonceErr(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return isUseDpopNonce(ae.StatusCode, ae.Message, ae.Headers)
}

// apiErrorCode extracts just the machine-readable error code from a response
// body, without constructing (and discarding) a typed error. Used by the token
// path, where the nonce decision is made BEFORE the error is built -- the body
// may yet be re-read after a successful re-sign.
func apiErrorCode(status int, body []byte, header http.Header) string {
	ae := asAPIErrorValue(errorFromResponse(status, body, header))
	if ae == nil {
		return ""
	}
	return ae.Message
}

func asAPIErrorValue(err error) *APIError {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae
	}
	return nil
}
