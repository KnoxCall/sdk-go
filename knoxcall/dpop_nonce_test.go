package knoxcall

// The DPoP server nonce (RFC 9449 section 8) -- PARITY 7.1, client Phase 4.3.
//
// Four behaviours, and the fourth is the one that is easy to get wrong:
//
//  1. remember the most recent DPoP-Nonce per ORIGIN;
//  2. send it as the proof's nonce claim on every later request there;
//  3. on the server's "use a nonce" refusal, re-sign ONCE with the nonce that
//     refusal carried, with a new jti, and never loop;
//  4. that refusal is NOT an authentication failure. A 401 normally purges the
//     cached token and spends the one re-auth; a use_dpop_nonce 401 must do
//     neither, or every nonce rotation costs a token mint -- and the retry would
//     then succeed anyway, which is what would hide it.
//
// Capture is at the HTTP boundary (an httptest server that records the proofs it
// is sent), so these drive the real signer, the real store and the real loops.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func proofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a JWT: %q", proof)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode proof payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("parse proof payload: %v", err)
	}
	return claims
}

// nonceHdr builds a header the way a real response does. A RAW MAP KEY would
// bypass net/http's canonicalisation, which Get() applies -- so
// http.Header{"DPoP-Nonce": ...} is unreadable by Get("DPoP-Nonce"), while a
// real server response is fine. Worth a helper rather than a comment at five
// call sites.
func nonceHdr(value string) http.Header {
	h := http.Header{}
	h.Set(nonceHeader, value)
	return h
}

// -- the store ---------------------------------------------------------------

func TestOriginOf(t *testing.T) {
	cases := map[string]string{
		"https://api.knoxcall.com/v1/routes":       "https://api.knoxcall.com",
		"https://api.knoxcall.com/v1/routes?a=1#f": "https://api.knoxcall.com",
		"https://API.KnoxCall.com/v1":              "https://api.knoxcall.com",
		"http://localhost:3000/v1":                 "http://localhost:3000",
		"https://api.knoxcall.com:8443/v1":         "https://api.knoxcall.com:8443",
		"/just/a/path":                             "",
		"":                                         "",
	}
	for in, want := range cases {
		if got := originOf(in); got != want {
			t.Errorf("originOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNonceStoreIsKeyedByOrigin(t *testing.T) {
	s := newDpopNonceStore()
	s.remember("https://api.knoxcall.com/oauth/token", nonceHdr("A"))
	if got := s.get("https://api.knoxcall.com/v1/routes?x=1"); got != "A" {
		t.Fatalf("same origin, different path: got %q want A", got)
	}
	// A DIFFERENT origin has not answered yet. The management API and a tenant's
	// data plane issue different values; sending one to the other is refused.
	if got := s.get("https://acme.knoxcall.com/api/anything"); got != "" {
		t.Fatalf("cross-origin leak: got %q want empty", got)
	}
	s.remember("https://acme.knoxcall.com/api/x", nonceHdr("B"))
	if got := s.get("https://acme.knoxcall.com/api/y"); got != "B" {
		t.Fatalf("second origin: got %q want B", got)
	}
	if got := s.get("https://api.knoxcall.com/v1/routes"); got != "A" {
		t.Fatalf("first origin was clobbered: got %q want A", got)
	}
}

func TestNonceStoreLastWriteWinsAndBlanksAreIgnored(t *testing.T) {
	s := newDpopNonceStore()
	s.remember("https://api.test/x", nonceHdr("first"))
	s.remember("https://api.test/x", nonceHdr("second"))
	for _, h := range []http.Header{{}, nonceHdr(""), nonceHdr("   "), nil} {
		if got := s.remember("https://api.test/x", h); got != "" {
			t.Fatalf("blank remembered: %q", got)
		}
		if got := s.get("https://api.test/x"); got != "second" {
			t.Fatalf("a blank erased what we held: %q", got)
		}
	}
}

func TestNonceStoreIgnoresHostlessURL(t *testing.T) {
	s := newDpopNonceStore()
	if got := s.remember("/just/a/path", nonceHdr("x")); got != "" {
		t.Fatalf("remembered a hostless URL: %q", got)
	}
	if len(s.snapshot()) != 0 {
		t.Fatalf("snapshot not empty: %v", s.snapshot())
	}
}

func TestNonceStoreIsConcurrencySafe(t *testing.T) {
	// One *Client is shared across goroutines by design, so the map is locked.
	// Run under -race in CI.
	s := newDpopNonceStore()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.remember("https://api.test/x", nonceHdr("n"))
			_ = s.get("https://api.test/x")
			_ = s.snapshot()
		}()
	}
	wg.Wait()
}

// -- the refusal predicate ---------------------------------------------------

func TestIsUseDpopNonce(t *testing.T) {
	challenge := http.Header{"Www-Authenticate": []string{`DPoP error="use_dpop_nonce"`}}
	shouty := http.Header{"Www-Authenticate": []string{`DPoP realm="knoxcall", ERROR="USE_DPOP_NONCE"`}}

	if !isUseDpopNonce(400, useDpopNonce, nil) {
		t.Error("the authorization server's 400 + OAuth body must match")
	}
	// The tenant data plane keeps its deliberately opaque body, so the header is
	// the ONLY signal there.
	if !isUseDpopNonce(401, "", challenge) {
		t.Error("a resource server's challenge header alone must match")
	}
	if !isUseDpopNonce(401, "", shouty) {
		t.Error("case must not matter")
	}
	for _, c := range []struct {
		status int
		code   string
		header http.Header
	}{
		{401, "invalid_token", nil},
		{401, "", http.Header{"Www-Authenticate": []string{`DPoP error="invalid_token"`}}},
		{403, useDpopNonce, nil},
		{500, useDpopNonce, nil},
		{200, "", nil},
	} {
		if isUseDpopNonce(c.status, c.code, c.header) {
			t.Errorf("false positive: status=%d code=%q", c.status, c.code)
		}
	}
}

// -- end to end --------------------------------------------------------------

type nonceServer struct {
	mu       sync.Mutex
	seen     []seenReq
	tokenQ   []func(w http.ResponseWriter)
	apiQ     []func(w http.ResponseWriter)
	fallback func(w http.ResponseWriter)
}

type seenReq struct {
	path  string
	proof string
}

func (s *nonceServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, seenReq{path: r.URL.Path, proof: r.Header.Get("DPoP")})
		isToken := strings.Contains(r.URL.Path, "/oauth/token")
		var next func(w http.ResponseWriter)
		if isToken && len(s.tokenQ) > 0 {
			next, s.tokenQ = s.tokenQ[0], s.tokenQ[1:]
		} else if !isToken && len(s.apiQ) > 0 {
			next, s.apiQ = s.apiQ[0], s.apiQ[1:]
		} else {
			next = s.fallback
		}
		s.mu.Unlock()
		if next == nil {
			http.Error(w, "unscripted request: "+r.URL.Path, 599)
			return
		}
		next(w)
	}
}

func (s *nonceServer) proofs(t *testing.T, pathContains string) []map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, r := range s.seen {
		if pathContains != "" && !strings.Contains(r.path, pathContains) {
			continue
		}
		if r.proof != "" {
			out = append(out, proofClaims(t, r.proof))
		}
	}
	return out
}

func (s *nonceServer) mintCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.seen {
		if strings.Contains(r.path, "/oauth/token") {
			n++
		}
	}
	return n
}

func tokenOK(nonce string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		if nonce != "" {
			w.Header().Set(nonceHeader, nonce)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"access_token":"kc_at_x","token_type":"DPoP","expires_in":3600}`))
	}
}

func jsonOK(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(body))
	}
}

func nonceRefusal401(nonce string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.Header().Set(nonceHeader, nonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"error":{"type":"use_dpop_nonce","message":"nonce required"}}`))
	}
}

func clientForNonce(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(Options{
		Tenant:       "acme",
		BaseURL:      srv.URL,
		ProxyBaseURL: srv.URL,
		ClientID:     "tk_id",
		ClientSecret: "shh",
		DPoP:         "always",
		HTTPClient:   srv.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNonceFromMintIsSentOnTheNextCall(t *testing.T) {
	ns := &nonceServer{
		tokenQ: []func(http.ResponseWriter){tokenOK("NONCE-1")},
		apiQ: []func(http.ResponseWriter){
			func(w http.ResponseWriter) {
				w.Header().Set(nonceHeader, "NONCE-2")
				jsonOK(`{"data":[],"meta":{}}`)(w)
			},
			jsonOK(`{"data":[],"meta":{}}`),
		},
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("first list: %v", err)
	}
	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("second list: %v", err)
	}

	proofs := ns.proofs(t, "")
	if len(proofs) < 3 {
		t.Fatalf("expected 3 proofs (mint + 2 calls), got %d", len(proofs))
	}
	// The very first proof -- the mint -- has no nonce to send, and the server
	// accepts that.
	if _, ok := proofs[0]["nonce"]; ok {
		t.Errorf("the first mint carried a nonce: %v", proofs[0]["nonce"])
	}
	if proofs[1]["nonce"] != "NONCE-1" {
		t.Errorf("first call nonce = %v, want NONCE-1", proofs[1]["nonce"])
	}
	if proofs[2]["nonce"] != "NONCE-2" {
		t.Errorf("second call nonce = %v, want NONCE-2", proofs[2]["nonce"])
	}
}

func TestResourceServerRefusalReSignsOnceAndDoesNotReMint(t *testing.T) {
	ns := &nonceServer{
		tokenQ: []func(http.ResponseWriter){tokenOK("STALE")},
		apiQ:   []func(http.ResponseWriter){nonceRefusal401("FRESH"), jsonOK(`{"data":[],"meta":{}}`)},
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("list: %v", err)
	}

	calls := ns.proofs(t, "/v1/routes")
	if len(calls) != 2 {
		t.Fatalf("expected exactly one retry, saw %d attempts", len(calls))
	}
	if calls[0]["nonce"] != "STALE" || calls[1]["nonce"] != "FRESH" {
		t.Errorf("nonces = %v then %v, want STALE then FRESH", calls[0]["nonce"], calls[1]["nonce"])
	}
	if calls[0]["jti"] == calls[1]["jti"] {
		t.Error("the retry reused the jti; the refused proof's may have been spent")
	}
	// The whole point of behaviour 4.
	if n := ns.mintCount(); n != 1 {
		t.Errorf("the nonce refusal spent a token mint: %d mints", n)
	}
}

func TestRealUnauthorizedStillReMints(t *testing.T) {
	ns := &nonceServer{
		tokenQ: []func(http.ResponseWriter){tokenOK("N1"), tokenOK("N2")},
		apiQ: []func(http.ResponseWriter){
			func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":{"type":"invalid_token","message":"nope"}}`))
			},
			jsonOK(`{"data":[],"meta":{}}`),
		},
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	if _, err := c.Routes.List(context.Background(), nil); err != nil {
		t.Fatalf("list: %v", err)
	}
	if n := ns.mintCount(); n != 2 {
		t.Errorf("a real 401 must still purge and re-mint once: %d mints", n)
	}
}

func TestNonceRetryNeverLoops(t *testing.T) {
	ns := &nonceServer{
		tokenQ:   []func(http.ResponseWriter){tokenOK("N")},
		fallback: nonceRefusal401("N"),
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	if _, err := c.Routes.List(context.Background(), nil); err == nil {
		t.Fatal("a server refusing every proof must surface the error")
	}
	// ONE nonce re-sign, then the error surfaces. It must not also spend the
	// re-auth: the token was deliberately not purged, so that retry would
	// resend an identical request.
	if calls := ns.proofs(t, "/v1/routes"); len(calls) != 2 {
		t.Errorf("expected 1 retry, saw %d attempts", len(calls))
	}
	if n := ns.mintCount(); n != 1 {
		t.Errorf("a nonce refusal must never cost a mint: %d mints", n)
	}
}

func TestMintReSignsInPlaceWithNoOuterLoop(t *testing.T) {
	// Isolates the mint-level retry. getToken drives the token fetch directly,
	// with no request loop to fall back on -- so if the mint did not retry
	// itself, this 400 would reach the caller. A test that went through a normal
	// request could NOT show that: the request loop's own nonce branch also
	// matches a 400 and would mask a missing mint-level retry entirely. (Go has
	// no exported Authenticate; this test is in-package, which is the point of
	// keeping it there.)
	ns := &nonceServer{
		tokenQ: []func(http.ResponseWriter){
			func(w http.ResponseWriter) {
				w.Header().Set(nonceHeader, "FRESH")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"nonce required"}`))
			},
			tokenOK("FRESH"),
		},
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	if _, err := c.getToken(context.Background()); err != nil {
		t.Fatalf("getToken: %v", err)
	}
	mints := ns.proofs(t, "/oauth/token")
	if len(mints) != 2 {
		t.Fatalf("expected exactly one re-sign of the mint, saw %d", len(mints))
	}
	if _, ok := mints[0]["nonce"]; ok {
		t.Error("the first mint carried a nonce")
	}
	if mints[1]["nonce"] != "FRESH" {
		t.Errorf("the re-signed mint nonce = %v, want FRESH", mints[1]["nonce"])
	}
	if mints[0]["jti"] == mints[1]["jti"] {
		t.Error("the re-signed mint reused the jti")
	}
}

func TestUpstreamAnsweredIsNotANonceRefusal(t *testing.T) {
	// A stamped response is the upstream's answer, not KnoxCall's: it must not
	// trigger a re-sign even if it somehow carries the challenge.
	ns := &nonceServer{
		tokenQ: []func(http.ResponseWriter){tokenOK("N")},
		apiQ: []func(http.ResponseWriter){
			func(w http.ResponseWriter) {
				w.Header().Set("X-Knox-Upstream-Status", "401")
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				w.WriteHeader(401)
				_, _ = w.Write([]byte("upstream says no"))
			},
		},
	}
	srv := httptest.NewServer(ns.handler())
	defer srv.Close()
	c := clientForNonce(t, srv)

	res, err := c.Call(context.Background(), "my-route", &CallOptions{Path: "/v1/things"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", res.StatusCode)
	}
	// One proof for the data-plane call; no retry.
	dataPlane := 0
	ns.mu.Lock()
	for _, r := range ns.seen {
		if !strings.Contains(r.path, "/oauth/token") && r.proof != "" {
			dataPlane++
		}
	}
	ns.mu.Unlock()
	if dataPlane != 1 {
		t.Errorf("no retry expected on an upstream answer, saw %d data-plane proofs", dataPlane)
	}
}
