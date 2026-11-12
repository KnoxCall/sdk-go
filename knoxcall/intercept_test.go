package knoxcall

// Route-aware interception at the SDK's HTTP boundary
// (route-aware-interception-plan.md §2, PARITY §21.1). Capture is what the mock
// KnoxCall server records — the manifest poll, the /v1/proxy request, the
// route data-plane request — or what the injected base transport received for
// direct traffic; never a mocked RoundTripper. The decision table itself is
// pinned by the shared fixtures (intercept_resolver_test.go); these tests
// prove the WIRE: what leaves the process, with which headers, and when.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
)

const manifestNone = `{"version":"sha256:none","ttl_seconds":60,"environment":"production","sandbox":false,"routes":[]}`

const manifestHubspot = `{"version":"sha256:hubspot","ttl_seconds":60,"environment":"production","sandbox":false,"routes":[` +
	`{"host":"api.hubapi.com","base_path":"/crm/v3","slug":"hubspot-crm","route_id":"r-crm","requires_clients":false,"allowed_methods":null,"updated_at":null}]}`

const manifestWarnings = `{"version":"sha256:warn","ttl_seconds":60,"environment":"production","sandbox":false,"routes":[` +
	`{"host":"api.openai.com","base_path":"/v1","slug":"openai","route_id":"r-oai","requires_clients":true,"allowed_methods":["GET","POST"],"updated_at":null},` +
	`{"host":"dup.example","base_path":"/","slug":"a-first","route_id":"r-d1","requires_clients":false,"allowed_methods":null,"ambiguous":true,"updated_at":null},` +
	`{"host":"dup.example","base_path":"/","slug":"b-second","route_id":"r-d2","requires_clients":false,"allowed_methods":null,"ambiguous":true,"updated_at":null}]}`

// interceptServer is the mock KnoxCall: the manifest endpoint (served in
// order, the last body repeating), the ephemeral proxy, and — because
// newTestClient sets ProxyBaseURL = BaseURL — the route data plane for every
// other path.
type interceptServer struct {
	mu            sync.Mutex
	manifests     []string
	manifestCalls int
	// manifestStatusAt answers the Nth manifest call (1-based) with this
	// status and an error body instead of the manifest — a 401 to prove the
	// re-auth path, for instance.
	manifestStatusAt map[int]int
	tokenCalls       int
	routeStatus      int
	routeHeader      http.Header
	routeBody        string // when set, the route data plane answers exactly this body
	proxyHeader      http.Header
	// obsStatus answers POST /v1/wrap/egress-observations (0 → 202 accepting everything).
	obsStatus int
}

func (s *interceptServer) setManifestStatusAt(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manifestStatusAt == nil {
		s.manifestStatusAt = map[int]int{}
	}
	s.manifestStatusAt[n] = status
}

// manifestVersion reads the `version` of a manifest body the server serves.
func manifestVersion(body string) string {
	var m struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal([]byte(body), &m)
	return m.Version
}

func (s *interceptServer) setManifests(bodies ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.manifests = bodies
}

func (s *interceptServer) setRoute(status int, header http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routeStatus = status
	s.routeHeader = header
	s.routeBody = ""
}

func (s *interceptServer) setRouteResponse(status int, header http.Header, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routeStatus = status
	s.routeHeader = header
	s.routeBody = body
}

func (s *interceptServer) setProxyHeader(header http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proxyHeader = header
}

func (s *interceptServer) manifestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifestCalls
}

func (s *interceptServer) tokenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

func newInterceptHarness(t *testing.T, mod func(*Options)) (*Client, func() []recordedRequest, *interceptServer) {
	t.Helper()
	srv := &interceptServer{manifests: []string{manifestNone}, routeStatus: 200}
	var mu sync.Mutex
	var seen []recordedRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			srv.mu.Lock()
			srv.tokenCalls++
			srv.mu.Unlock()
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		mu.Lock()
		seen = append(seen, recordedRequest{Method: r.Method, Path: r.URL.Path, Query: q, Body: body, Header: r.Header.Clone()})
		mu.Unlock()

		switch r.URL.Path {
		case "/v1/wrap/egress-observations":
			srv.mu.Lock()
			status := srv.obsStatus
			srv.mu.Unlock()
			if status == 403 {
				writeJSON(w, 403, `{"error":{"type":"forbidden","message":"insufficient scope","request_id":"r"}}`)
				return
			}
			var report struct {
				Observations []json.RawMessage `json:"observations"`
			}
			_ = json.Unmarshal(body, &report)
			writeJSON(w, 202, fmt.Sprintf(`{"data":{"accepted":%d,"dropped":0,"reasons":{}},"meta":{"request_id":"o"}}`, len(report.Observations)))
		case "/v1/wrap/intercept-manifest":
			// As the server does (src/client-api/wrap.ts): ETag W/"<version>"
			// on every answer, 304 with no body when If-None-Match carries it.
			srv.mu.Lock()
			i := srv.manifestCalls
			srv.manifestCalls++
			status, overridden := srv.manifestStatusAt[srv.manifestCalls]
			if i >= len(srv.manifests) {
				i = len(srv.manifests) - 1
			}
			m := srv.manifests[i]
			srv.mu.Unlock()
			if overridden {
				writeJSON(w, status, `{"error":{"type":"error","message":"canned","request_id":"req_m"}}`)
				return
			}
			etag := ManifestETag(manifestVersion(m))
			w.Header().Set("ETag", etag)
			for _, tag := range strings.Split(r.Header.Get("If-None-Match"), ",") {
				if strings.TrimSpace(tag) == etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			writeJSON(w, 200, `{"data":`+m+`,"meta":{"request_id":"req_m"}}`)
		case "/v1/proxy":
			srv.mu.Lock()
			for k, v := range srv.proxyHeader {
				w.Header()[k] = v
			}
			srv.mu.Unlock()
			writeJSON(w, 200, `{"ok":true}`)
		default: // the route data plane
			srv.mu.Lock()
			status := srv.routeStatus
			routeBody := srv.routeBody
			for k, v := range srv.routeHeader {
				w.Header()[k] = v
			}
			srv.mu.Unlock()
			if routeBody != "" {
				writeJSON(w, status, routeBody)
				return
			}
			if status == 401 {
				writeJSON(w, 401, `{"error":"Unauthorized"}`)
				return
			}
			writeJSON(w, status, `{"routed":true}`)
		}
	}))
	t.Cleanup(ts.Close)
	requests := func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), seen...)
	}
	return newTestClient(t, ts.URL, mod), requests, srv
}

func byPath(reqs []recordedRequest, path string) []recordedRequest {
	var out []recordedRequest
	for _, r := range reqs {
		if r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// routeCalls are the requests that went through the route data plane.
func routeCalls(reqs []recordedRequest) []recordedRequest {
	var out []recordedRequest
	for _, r := range reqs {
		if r.Header.Get("x-knoxcall-route") != "" {
			out = append(out, r)
		}
	}
	return out
}

func mustWait(t *testing.T, rt *WrapRoundTripper) {
	t.Helper()
	if err := rt.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func doOK(t *testing.T, hc *http.Client, req *http.Request) *http.Response {
	t.Helper()
	res, err := hc.Do(req)
	if err != nil {
		t.Fatalf("Do %s: %v", req.URL, err)
	}
	mustClose(t, res)
	return res
}

// ── the conditional poll on the wire (PARITY §21.1 "Conditional poll") ────────
// The store-level walk of sdk/fixtures/intercept-store-conditional.json lives in
// intercept_store_test.go; here the same contract is proven at the SDK's HTTP
// boundary — which header leaves, in which form, and what a 304 becomes —
// through the real InterceptManifest and the real store.

func TestInterceptManifestWireFormMatchesEveryFixtureStep(t *testing.T) {
	f := loadConditionalFixture(t)
	for _, step := range f.Steps {
		if step.Expect.FetchIfNoneMatch == nil {
			if step.Expect.WireIfNoneMatch != nil {
				t.Fatalf("%s: nothing held must send no header, fixture says %q", step.Name, *step.Expect.WireIfNoneMatch)
			}
			continue
		}
		if got := ManifestETag(*step.Expect.FetchIfNoneMatch); step.Expect.WireIfNoneMatch == nil || got != *step.Expect.WireIfNoneMatch {
			t.Fatalf("%s: ManifestETag(%q) = %q, fixture wire form %v", step.Name, *step.Expect.FetchIfNoneMatch, got, step.Expect.WireIfNoneMatch)
		}
	}
}

func TestInterceptManifestConditionalSendsTheWeakETagAndReturnsNilNilOn304(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	ctx := context.Background()

	first, err := c.Wrap.InterceptManifest(ctx)
	if err != nil || first == nil || first.Version != "sha256:hubspot" {
		t.Fatalf("unconditional = (%+v, %v)", first, err)
	}
	unchanged, err := c.Wrap.InterceptManifest(ctx, InterceptManifestOptions{IfNoneMatch: first.Version})
	if err != nil || unchanged != nil {
		t.Fatalf("conditional with the held version = (%+v, %v), want (nil, nil)", unchanged, err)
	}
	stale, err := c.Wrap.InterceptManifest(ctx, InterceptManifestOptions{IfNoneMatch: "sha256:stale"})
	if err != nil || stale == nil || stale.Version != first.Version {
		t.Fatalf("conditional with a stale version = (%+v, %v), want the current manifest", stale, err)
	}

	polls := byPath(requests(), "/v1/wrap/intercept-manifest")
	if len(polls) != 3 {
		t.Fatalf("manifest calls = %d, want 3", len(polls))
	}
	want := []string{"", `W/"sha256:hubspot"`, `W/"sha256:stale"`}
	for i, p := range polls {
		if got := p.Header.Get("If-None-Match"); got != want[i] {
			t.Fatalf("call %d If-None-Match = %q, want %q", i+1, got, want[i])
		}
	}
}

func TestInterceptManifest401OnTheConditionalPollReauthsOnceAndTheRetryCarriesTheHeader(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	srv.setManifestStatusAt(2, 401)
	ctx := context.Background()

	first, err := c.Wrap.InterceptManifest(ctx)
	if err != nil || first == nil {
		t.Fatalf("unconditional = (%+v, %v)", first, err)
	}
	tokensBefore := srv.tokenCount()
	res, err := c.Wrap.InterceptManifest(ctx, InterceptManifestOptions{IfNoneMatch: first.Version})
	if err != nil || res != nil {
		t.Fatalf("after the re-auth the 304 must come back as (nil, nil): (%+v, %v)", res, err)
	}
	polls := byPath(requests(), "/v1/wrap/intercept-manifest")
	if len(polls) != 3 { // unconditional, the 401, the re-authed retry
		t.Fatalf("manifest calls = %d, want 3", len(polls))
	}
	for _, p := range polls[1:] {
		if got := p.Header.Get("If-None-Match"); got != `W/"sha256:hubspot"` {
			t.Fatalf("the header must ride on the retry too: got %q", got)
		}
	}
	if srv.tokenCount() != tokensBefore+1 {
		t.Fatalf("token mints = %d → %d, want exactly one re-mint", tokensBefore, srv.tokenCount())
	}
}

func TestInterceptRoundTripperPollsConditionally(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	var mu sync.Mutex
	var refreshes []ManifestRefreshInfo
	rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefresh(func(i ManifestRefreshInfo) {
		mu.Lock()
		refreshes = append(refreshes, i)
		mu.Unlock()
	}))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	ctx := context.Background()
	hookCalls := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(refreshes)
	}

	// A forced refresh (what a routing refusal triggers) is conditional too:
	// the server's 304 keeps the manifest and fires no hook.
	if err := rt.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m := rt.Manifest(); m == nil || m.Version != "sha256:hubspot" || hookCalls() != 1 {
		t.Fatalf("after a 304: manifest %+v, hook calls %d — want the held manifest and one (the initial) hook", m, hookCalls())
	}

	// A change replaces the manifest and fires the diff; the next poll carries the NEW version.
	srv.setManifests(manifestWarnings)
	_ = captureWarnings(t) // the warnings manifest warns once per entry; keep it out of the output
	if err := rt.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m := rt.Manifest(); m == nil || m.Version != "sha256:warn" || hookCalls() != 2 {
		t.Fatalf("after a change: manifest %+v, hook calls %d", m, hookCalls())
	}
	if err := rt.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if m := rt.Manifest(); m == nil || m.Version != "sha256:warn" || hookCalls() != 2 {
		t.Fatalf("after the second 304: manifest %+v, hook calls %d", m, hookCalls())
	}

	polls := byPath(requests(), "/v1/wrap/intercept-manifest")
	want := []string{"", `W/"sha256:hubspot"`, `W/"sha256:hubspot"`, `W/"sha256:warn"`}
	if len(polls) != len(want) {
		t.Fatalf("manifest polls = %d, want %d", len(polls), len(want))
	}
	for i, p := range polls {
		if got := p.Header.Get("If-None-Match"); got != want[i] {
			t.Fatalf("poll %d If-None-Match = %q, want %q", i+1, got, want[i])
		}
	}
	if srv.manifestCount() != len(want) {
		t.Fatalf("server counted %d manifest calls, want %d", srv.manifestCount(), len(want))
	}
}

// ── the explicit transport ────────────────────────────────────────────────────

// A request whose host + path the manifest covers goes through the Route: the
// existing Call pipeline (x-knoxcall-route, the client's environment, the
// SDK's own token), the path rebased under base_path with the query kept, the
// wrapped SDK's headers and body forwarded verbatim — and its Authorization
// dropped: the Route injects the stored secret, no provider credential travels.
func TestInterceptRoundTripperRoutesThroughTheCoveringRoute(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, func(o *Options) { o.Environment = "staging" })
	srv.setManifests(manifestHubspot)
	var reroutes []RerouteInfo
	rt := c.Wrap.RoundTripper(WithRoutes(), WithOnReroute(func(i RerouteInfo) { reroutes = append(reroutes, i) }))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	if m := rt.Manifest(); m == nil || m.Version != "sha256:hubspot" {
		t.Fatalf("Manifest = %+v, want the polled manifest", m)
	}

	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodPost, "https://api.hubapi.com/crm/v3/objects/contacts?limit=1&after=x", strings.NewReader(`{"properties":{}}`))
	req.Header.Set("Authorization", "Bearer pat-provider-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "1")
	if res := doOK(t, hc, req); res.StatusCode != 200 {
		t.Fatalf("status = %d, want the route's 200", res.StatusCode)
	}

	reqs := requests()
	manifest := byPath(reqs, "/v1/wrap/intercept-manifest")
	if len(manifest) != 1 || manifest[0].Query["environment"] != "staging" {
		t.Fatalf("manifest polls = %+v, want one for the client's environment", manifest)
	}
	routed := routeCalls(reqs)
	if len(routed) != 1 {
		t.Fatalf("route calls = %d, want exactly 1", len(routed))
	}
	got := routed[0]
	if got.Method != http.MethodPost || got.Path != "/objects/contacts" || got.Query["limit"] != "1" || got.Query["after"] != "x" {
		t.Fatalf("route request = %s %s %v, want the path rebased under /crm/v3 with the query kept", got.Method, got.Path, got.Query)
	}
	if s := got.Header.Get("x-knoxcall-route"); s != "hubspot-crm" {
		t.Errorf("x-knoxcall-route = %q, want the manifest slug", s)
	}
	// The reroute marker the API Log renders as "SDK intercept" (PARITY §21.2).
	if o := got.Header.Get("x-knoxcall-origin"); o != "sdk-intercept" {
		t.Errorf("x-knoxcall-origin = %q, want the interceptor's reroute marker", o)
	}
	if e := got.Header.Get("x-knoxcall-environment"); e != "staging" {
		t.Errorf("x-knoxcall-environment = %q, want the client's environment", e)
	}
	if a := got.Header.Get("Authorization"); a != "Bearer kc_live_aaaa" {
		t.Errorf("Authorization = %q, want the SDK's own KnoxCall token", a)
	}
	if got.Header.Get("X-Knox-Upstream-Authorization") != "" || got.Header.Get("X-Knox-Proxy-URL") != "" {
		t.Errorf("route mode must never lift the SDK's key or target the proxy: %v", got.Header)
	}
	if got.Header.Get("X-Custom") != "1" || got.Header.Get("Content-Type") != "application/json" || string(got.Body) != `{"properties":{}}` {
		t.Errorf("headers/body not forwarded verbatim: %v %q", got.Header, got.Body)
	}
	if len(byPath(reqs, "/v1/proxy")) != 0 {
		t.Errorf("the ephemeral proxy was contacted for a route-covered host")
	}
	if len(reroutes) != 1 || reroutes[0].Mode != InterceptRoute || reroutes[0].Slug != "hubspot-crm" || reroutes[0].Reason != ReasonManifest || reroutes[0].Host != "api.hubapi.com" {
		t.Errorf("onReroute = %+v, want route/hubspot-crm/manifest", reroutes)
	}
}

// A host no Route covers goes through the ephemeral proxy exactly as before
// (transit: the SDK's own key lifted out-of-band). A host that HAS routes but
// none covering this path also goes ephemeral, and the unmatched-path hook
// fires once per host + first path segment.
func TestInterceptRoundTripperListedHostWithoutRouteGoesEphemeral(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	var unmatched []UnmatchedPathInfo
	var reroutes []RerouteInfo
	rt := c.Wrap.RoundTripper(WithRoutes(),
		WithOnUnmatchedPath(func(i UnmatchedPathInfo) { unmatched = append(unmatched, i) }),
		WithOnReroute(func(i RerouteInfo) { reroutes = append(reroutes, i) }))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	hc := &http.Client{Transport: rt}

	req, _ := http.NewRequest(http.MethodGet, "https://api.resend.com/emails", nil)
	req.Header.Set("Authorization", "Bearer re_secret")
	doOK(t, hc, req)
	proxy := byPath(requests(), "/v1/proxy")
	if len(proxy) != 1 {
		t.Fatalf("proxy calls = %d, want 1", len(proxy))
	}
	if u := proxy[0].Header.Get("X-Knox-Proxy-URL"); u != "https://api.resend.com/emails" {
		t.Errorf("X-Knox-Proxy-URL = %q", u)
	}
	if proxy[0].Header.Get("X-Knox-Proxy-Mode") != "transparent" || proxy[0].Header.Get("X-Knox-Upstream-Authorization") != "Bearer re_secret" {
		t.Errorf("ephemeral request = %v, want transparent mode with the key lifted", proxy[0].Header)
	}
	// The reroute marker is a ROUTE-mode fact (PARITY §21.2); an ephemeral hop
	// is a different log and carries nothing.
	if o := proxy[0].Header.Get("x-knoxcall-origin"); o != "" {
		t.Errorf("x-knoxcall-origin = %q on the ephemeral hop, want absent", o)
	}
	if len(reroutes) != 1 || reroutes[0].Mode != InterceptEphemeral || reroutes[0].Reason != ReasonNoRoute {
		t.Errorf("onReroute = %+v, want ephemeral/no_route", reroutes)
	}

	for _, u := range []string{"https://api.hubapi.com/oauth/v1/token", "https://api.hubapi.com/oauth/v1/token", "https://api.hubapi.com/oauth/v2/x"} {
		r, _ := http.NewRequest(http.MethodPost, u, strings.NewReader("grant_type=refresh_token"))
		doOK(t, hc, r)
	}
	reqs := requests()
	if n := len(byPath(reqs, "/v1/proxy")); n != 4 {
		t.Fatalf("proxy calls = %d, want the three outside-base requests to go ephemeral", n)
	}
	if len(routeCalls(reqs)) != 0 {
		t.Fatalf("a path outside every base must not go through the route")
	}
	if len(unmatched) != 1 || unmatched[0].Host != "api.hubapi.com" {
		t.Errorf("onUnmatchedPath = %+v, want exactly once for api.hubapi.com /oauth", unmatched)
	}
	if last := reroutes[len(reroutes)-1]; last.Reason != ReasonNoBasePathMatch {
		t.Errorf("last reroute reason = %q, want no_base_path_match", last.Reason)
	}
}

// Without WithRoutes an explicit transport keeps its pre-manifest behaviour:
// no poll, every request through the ephemeral proxy.
func TestInterceptRoundTripperRoutesOffNeverPollsTheManifest(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	rt := c.Wrap.RoundTripper()
	if !isClosed(rt.Ready()) || rt.Manifest() != nil {
		t.Fatalf("routes off: Ready is immediate and there is no manifest")
	}
	if err := rt.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh without a store is a no-op: %v", err)
	}
	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
	req.Header.Set("Authorization", "Bearer pat")
	doOK(t, hc, req)
	reqs := requests()
	if len(byPath(reqs, "/v1/wrap/intercept-manifest")) != 0 || len(routeCalls(reqs)) != 0 || len(byPath(reqs, "/v1/proxy")) != 1 {
		t.Fatalf("routes off must be ephemeral-only with no manifest poll: %+v", reqs)
	}
}

// The client's own hosts and any knoxcall.com host are never intercepted —
// whatever the list or manifest says — so the SDK can never recurse into itself.
func TestInterceptRoundTripperOwnAndPlatformHostsGoDirect(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestNone)
	base := &recordingTransport{}
	rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	hc := &http.Client{Transport: rt}
	for i, u := range []string{c.baseURL + "/v1/anything", "https://acme.knoxcall.com/x", "https://KNOXCALL.COM./y"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer x")
		doOK(t, hc, req)
		if base.calls != i+1 {
			t.Fatalf("%s: base calls = %d, want %d (sent direct)", u, base.calls, i+1)
		}
	}
	reqs := requests()
	if len(byPath(reqs, "/v1/anything")) != 0 || len(byPath(reqs, "/v1/proxy")) != 0 {
		t.Fatalf("an own-host request must never reach KnoxCall through the transport: %+v", reqs)
	}
}

// KNOXCALL_INTERCEPT=off turns the transport into pass-through per request,
// with no deploy — the original request goes to the base transport untouched.
func TestInterceptRoundTripperKillSwitch(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	base := &recordingTransport{}
	rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	t.Setenv("KNOXCALL_INTERCEPT", "off")
	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodPost, "https://api.hubapi.com/crm/v3/objects", strings.NewReader("x"))
	req.Header.Set("Authorization", "Bearer sk_provider")
	doOK(t, hc, req)
	if base.calls != 1 || base.got.URL.Host != "api.hubapi.com" || base.got.Header.Get("Authorization") != "Bearer sk_provider" {
		t.Fatalf("kill switch: want the untouched request on the base transport, got calls=%d %v", base.calls, base.got)
	}
	reqs := requests()
	if len(routeCalls(reqs)) != 0 || len(byPath(reqs, "/v1/proxy")) != 0 {
		t.Fatalf("kill switch: KnoxCall must not be contacted: %+v", reqs)
	}
	t.Setenv("KNOXCALL_INTERCEPT", "on")
	doOK(t, hc, req)
	if len(routeCalls(requests())) != 1 {
		t.Fatalf("with the switch back on the next request goes through the route again")
	}
}

// A KnoxCall-origin 401 in route mode (no upstream-status header; Call's own
// re-mint already spent) means a stale manifest or a refused credential. ONE
// forced refresh, ONE re-decision: resent through the new mode when the
// decision changed; returned as-is otherwise. Never a loop.
func TestInterceptRoundTripperRefusalRefreshesOnceAndRedecides(t *testing.T) {
	t.Run("the refresh changes the decision: resent once via the new mode", func(t *testing.T) {
		c, requests, srv := newInterceptHarness(t, nil)
		srv.setManifests(manifestHubspot, manifestNone) // the start poll sees the route; the refusal refresh sees it gone
		srv.setRoute(401, nil)
		var refused []RefusedInfo
		rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)

		hc := &http.Client{Transport: rt}
		req, _ := http.NewRequest(http.MethodPost, "https://api.hubapi.com/crm/v3/objects", strings.NewReader(`{"a":1}`))
		req.Header.Set("Authorization", "Bearer pat")
		if res := doOK(t, hc, req); res.StatusCode != 200 {
			t.Fatalf("status = %d, want the resend's 200 from the ephemeral proxy", res.StatusCode)
		}
		reqs := requests()
		if n := len(routeCalls(reqs)); n != 2 {
			t.Fatalf("route calls = %d, want 2 (the refusal + Call's own one re-mint), never a third", n)
		}
		if srv.tokenCount() != 2 {
			t.Fatalf("token mints = %d, want the start mint + the one re-mint", srv.tokenCount())
		}
		if srv.manifestCount() != 2 {
			t.Fatalf("manifest polls = %d, want start + exactly one refusal refresh", srv.manifestCount())
		}
		proxy := byPath(reqs, "/v1/proxy")
		if len(proxy) != 1 || string(proxy[0].Body) != `{"a":1}` || proxy[0].Header.Get("X-Knox-Upstream-Authorization") != "Bearer pat" {
			t.Fatalf("resend = %+v, want the same body through the ephemeral proxy with the key lifted", proxy)
		}
		if len(refused) != 1 || refused[0].Status != 401 || refused[0].Slug != "hubspot-crm" || refused[0].Redecided != InterceptEphemeral {
			t.Fatalf("onRefused = %+v, want 401/hubspot-crm redecided ephemeral", refused)
		}
	})

	t.Run("the refresh changes nothing: the refusal is returned after exactly one refresh", func(t *testing.T) {
		c, requests, srv := newInterceptHarness(t, nil)
		srv.setManifests(manifestHubspot)
		srv.setRoute(401, nil)
		var refused []RefusedInfo
		rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)

		hc := &http.Client{Transport: rt}
		req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
		if res := doOK(t, hc, req); res.StatusCode != 401 {
			t.Fatalf("status = %d, want the refusal surfaced", res.StatusCode)
		}
		reqs := requests()
		if n := len(routeCalls(reqs)); n != 2 {
			t.Fatalf("route calls = %d, want 2 (refusal + one re-mint) and no replay", n)
		}
		if srv.manifestCount() != 2 || len(byPath(reqs, "/v1/proxy")) != 0 {
			t.Fatalf("manifest polls = %d, proxy = %d; want one refresh and no fallback", srv.manifestCount(), len(byPath(reqs, "/v1/proxy")))
		}
		if len(refused) != 1 || refused[0].Redecided != "" {
			t.Fatalf("onRefused = %+v, want the unchanged decision reported", refused)
		}
	})
}

const routeNotFoundEnvelope = `{"error":{"type":"route_not_found","message":"Route 'hubspot-crm' not found.","request_id":"req_x"}}`

// Founder decision 2026-09-26: an AUTHENTICATED key gets a real 404 for a
// route that does not resolve. A stale manifest naming a Route deleted since
// the poll is exactly that, so the 404 route_not_found envelope is a refresh
// trigger too (PARITY §21.1). No re-mint is spent on it — Call's rule is
// 401-only — so the Route is called ONCE.
func TestInterceptRoundTripper404RouteNotFoundRefreshesOnceAndRedecides(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot, manifestNone)
	srv.setRouteResponse(404, http.Header{"X-Knox-Origin": {"knoxcall"}, "X-Knox-Error": {"route_not_found"}, "X-Knox-Plane": {"route"}}, routeNotFoundEnvelope)
	var refused []RefusedInfo
	rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)

	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodPost, "https://api.hubapi.com/crm/v3/objects", strings.NewReader(`{"a":1}`))
	req.Header.Set("Authorization", "Bearer pat")
	if res := doOK(t, hc, req); res.StatusCode != 200 {
		t.Fatalf("status = %d, want the resend's 200 from the ephemeral proxy", res.StatusCode)
	}
	reqs := requests()
	if n := len(routeCalls(reqs)); n != 1 {
		t.Fatalf("route calls = %d, want 1 — a 404 spends no re-mint", n)
	}
	if srv.tokenCount() != 1 {
		t.Fatalf("token mints = %d, want the start mint only", srv.tokenCount())
	}
	if srv.manifestCount() != 2 {
		t.Fatalf("manifest polls = %d, want start + exactly one refusal refresh", srv.manifestCount())
	}
	proxy := byPath(reqs, "/v1/proxy")
	if len(proxy) != 1 || string(proxy[0].Body) != `{"a":1}` {
		t.Fatalf("resend = %+v, want the same body through the ephemeral proxy", proxy)
	}
	if len(refused) != 1 || refused[0].Status != 404 || refused[0].Slug != "hubspot-crm" || refused[0].Redecided != InterceptEphemeral {
		t.Fatalf("onRefused = %+v, want 404/hubspot-crm redecided ephemeral", refused)
	}
}

// A 404 of an environment_* type is refused as-is: a refresh cannot fix an
// environment.
func TestInterceptRoundTripper404EnvironmentTypeIsNotARefusal(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	srv.setRouteResponse(404, http.Header{"X-Knox-Origin": {"knoxcall"}, "X-Knox-Error": {"environment_not_configured"}},
		`{"error":{"type":"environment_not_configured","message":"Environment 'staging' is not configured for this route.","request_id":"r"}}`)
	var refused []RefusedInfo
	rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)

	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
	res, err := hc.Do(req) // not doOK: it drains the body, and the body is the assertion
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("status = %d, want the 404 surfaced", res.StatusCode)
	}
	if !strings.Contains(string(body), `"environment_not_configured"`) {
		t.Fatalf("body = %s, want the envelope returned intact", body)
	}
	if n := len(routeCalls(requests())); n != 1 || srv.manifestCount() != 1 || len(refused) != 0 {
		t.Fatalf("route calls = %d, manifest polls = %d, refused = %v; want one call, no refresh, no hook", n, srv.manifestCount(), refused)
	}
}

// An UPSTREAM 404 relayed by the data plane is the caller's, even when its
// body imitates the envelope: the stamp wins, no refresh, body intact.
func TestInterceptRoundTripperUpstream404IsNotARefusal(t *testing.T) {
	for _, header := range []string{"X-Knox-Upstream-Status", "X-Knox-Destination-Status"} {
		t.Run(header, func(t *testing.T) {
			c, requests, srv := newInterceptHarness(t, nil)
			srv.setManifests(manifestHubspot)
			srv.setRouteResponse(404, http.Header{header: {"404"}}, routeNotFoundEnvelope)
			var refused []RefusedInfo
			rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
			t.Cleanup(rt.Stop)
			mustWait(t, rt)

			hc := &http.Client{Transport: rt}
			req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
			res, err := hc.Do(req) // not doOK: it drains the body, and the body is the assertion
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			_ = res.Body.Close()
			if res.StatusCode != 404 || res.Header.Get(header) != "404" {
				t.Fatalf("status = %d %s=%q, want the upstream's 404 returned raw", res.StatusCode, header, res.Header.Get(header))
			}
			if string(body) != routeNotFoundEnvelope {
				t.Fatalf("body = %s, want the upstream's body intact", body)
			}
			if n := len(routeCalls(requests())); n != 1 || srv.manifestCount() != 1 || len(refused) != 0 {
				t.Fatalf("route calls = %d, manifest polls = %d, refused = %v; an upstream 404 is not a routing refusal", n, srv.manifestCount(), refused)
			}
		})
	}
}

// A 401 the UPSTREAM answered and the data plane relayed is the caller's: no
// token re-mint (the client.go fix), no manifest refresh (not a refusal).
func TestProxySendDoesNotRemintOrRefreshOnAnUpstream401(t *testing.T) {
	for _, header := range []string{"X-Knox-Upstream-Status", "X-Knox-Destination-Status"} {
		t.Run(header, func(t *testing.T) {
			c, requests, srv := newInterceptHarness(t, nil)
			srv.setManifests(manifestHubspot)
			srv.setRoute(401, http.Header{header: {"401"}})
			var refused []RefusedInfo
			rt := c.Wrap.RoundTripper(WithRoutes(), WithOnRefused(func(i RefusedInfo) { refused = append(refused, i) }))
			t.Cleanup(rt.Stop)
			mustWait(t, rt)

			hc := &http.Client{Transport: rt}
			req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
			if res := doOK(t, hc, req); res.StatusCode != 401 {
				t.Fatalf("status = %d, want the upstream's 401 returned raw", res.StatusCode)
			}
			if n := len(routeCalls(requests())); n != 1 {
				t.Fatalf("route calls = %d, want 1 — an upstream 401 must not spend the re-mint", n)
			}
			if srv.tokenCount() != 1 {
				t.Fatalf("token mints = %d, want the start mint only", srv.tokenCount())
			}
			if srv.manifestCount() != 1 || len(refused) != 0 {
				t.Fatalf("manifest polls = %d, refused = %v; an upstream 401 is not a routing refusal", srv.manifestCount(), refused)
			}
		})
	}
}

// X-Knox-Promoted-Route on an ephemeral response is a signal: the manifest is
// refreshed in the background (rate-limited) and the hook fires.
func TestInterceptRoundTripperPromotedHintRefreshesTheManifest(t *testing.T) {
	c, _, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestNone)
	srv.setProxyHeader(http.Header{"X-Knox-Promoted-Route": {"resend"}})
	var mu sync.Mutex
	var promoted []PromotedInfo
	rt := c.Wrap.RoundTripper(WithRoutes(), WithOnPromoted(func(i PromotedInfo) {
		mu.Lock()
		promoted = append(promoted, i)
		mu.Unlock()
	}))
	t.Cleanup(rt.Stop)
	rt.store.minGap = 0 // the hint would otherwise sit inside the start poll's rate-limit gap
	mustWait(t, rt)

	hc := &http.Client{Transport: rt}
	req, _ := http.NewRequest(http.MethodGet, "https://api.resend.com/emails", nil)
	doOK(t, hc, req)
	mu.Lock()
	if len(promoted) != 1 || promoted[0].Host != "api.resend.com" || promoted[0].Slug != "resend" {
		mu.Unlock()
		t.Fatalf("onPromoted = %+v", promoted)
	}
	mu.Unlock()
	eventually(t, func() bool { return srv.manifestCount() == 2 }, "the hint to refresh the manifest")
}

// D4. KnoxCall unreachable: route mode and escrow fail CLOSED (the SDK's typed
// connection error; the base transport is never touched). Transit may opt into
// going direct, transport-wide or per host; the ORIGINAL request then goes to
// the base transport untouched and onFallback fires.
func TestInterceptRoundTripperFailsClosedWhenKnoxCallIsUnreachable(t *testing.T) {
	dialRefused := &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	unreachable := func(t *testing.T, match func(*http.Request) bool) (*Client, func() []recordedRequest, *interceptServer) {
		t.Helper()
		return newInterceptHarness(t, func(o *Options) {
			o.HTTPClient = &http.Client{Transport: &failNTransport{base: http.DefaultTransport, match: match, err: dialRefused, failures: 100}}
		})
	}
	proxyPath := func(r *http.Request) bool { return r.URL.Path == "/v1/proxy" }
	routePath := func(r *http.Request) bool { return r.Header.Get("x-knoxcall-route") != "" }
	newReq := func() *http.Request {
		req, _ := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", strings.NewReader("x=1"))
		req.Header.Set("Authorization", "Bearer re_secret")
		return req
	}

	t.Run("transit fails closed by default", func(t *testing.T) {
		c, _, _ := unreachable(t, proxyPath)
		base := &recordingTransport{}
		rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)
		_, err := (&http.Client{Transport: rt}).Do(newReq())
		var ce *ConnectionError
		if err == nil || !errors.As(err, &ce) {
			t.Fatalf("err = %v, want the SDK's ConnectionError", err)
		}
		if base.calls != 0 {
			t.Fatalf("base transport called %d times, want 0 — never 'try KnoxCall then send the key direct' by default", base.calls)
		}
	})

	t.Run("transit may opt into direct: the original request goes untouched and onFallback fires", func(t *testing.T) {
		c, _, _ := unreachable(t, proxyPath)
		base := &recordingTransport{}
		var fallbacks []FallbackInfo
		rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base), WithUnavailableDirect(),
			WithOnFallback(func(i FallbackInfo) { fallbacks = append(fallbacks, i) }))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)
		res := doOK(t, &http.Client{Transport: rt}, newReq())
		if res.StatusCode != 200 || base.calls != 1 {
			t.Fatalf("status=%d base calls=%d, want the base transport's answer", res.StatusCode, base.calls)
		}
		body, _ := io.ReadAll(base.got.Body)
		if base.got.URL.Host != "api.resend.com" || base.got.Header.Get("Authorization") != "Bearer re_secret" || string(body) != "x=1" {
			t.Fatalf("direct request = %s auth=%q body=%q, want the original request untouched", base.got.URL, base.got.Header.Get("Authorization"), body)
		}
		var ce *ConnectionError
		if len(fallbacks) != 1 || fallbacks[0].Host != "api.resend.com" || !errors.As(fallbacks[0].Err, &ce) {
			t.Fatalf("onFallback = %+v", fallbacks)
		}
	})

	t.Run("per-host opt-in covers only that host", func(t *testing.T) {
		c, _, _ := unreachable(t, proxyPath)
		base := &recordingTransport{}
		rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base), WithHost("api.resend.com", HostUnavailableDirect()))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)
		hc := &http.Client{Transport: rt}
		doOK(t, hc, newReq())
		if base.calls != 1 {
			t.Fatalf("the opted-in host goes direct: base calls = %d", base.calls)
		}
		other, _ := http.NewRequest(http.MethodGet, "https://api.other.example/x", nil)
		if _, err := hc.Do(other); err == nil || base.calls != 1 {
			t.Fatalf("a host without the opt-in still fails closed: err=%v base calls=%d", err, base.calls)
		}
	})

	t.Run("escrow never goes direct, even with both opt-ins", func(t *testing.T) {
		c, _, _ := unreachable(t, proxyPath)
		base := &recordingTransport{}
		rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base), WithUnavailableDirect(),
			WithHost("api.resend.com", HostEscrow("resend-key"), HostUnavailableDirect()))
		t.Cleanup(rt.Stop)
		mustWait(t, rt)
		_, err := (&http.Client{Transport: rt}).Do(newReq())
		var ce *ConnectionError
		if err == nil || !errors.As(err, &ce) || base.calls != 0 {
			t.Fatalf("escrow: err=%v base calls=%d, want fail-closed (there is no credential to go direct with)", err, base.calls)
		}
	})

	t.Run("route mode never goes direct", func(t *testing.T) {
		c, _, srv := unreachable(t, routePath)
		srv.setManifests(manifestHubspot)
		base := &recordingTransport{}
		rt := c.Wrap.RoundTripper(WithRoutes(), WithBaseTransport(base), WithUnavailableDirect())
		t.Cleanup(rt.Stop)
		mustWait(t, rt)
		req, _ := http.NewRequest(http.MethodGet, "https://api.hubapi.com/crm/v3/objects", nil)
		_, err := (&http.Client{Transport: rt}).Do(req)
		var ce *ConnectionError
		if err == nil || !errors.As(err, &ce) || base.calls != 0 {
			t.Fatalf("route: err=%v base calls=%d, want fail-closed", err, base.calls)
		}
	})
}

// requires_clients and an ambiguous pair are warned ONCE, at the refresh that
// added them — not per request, and not again on an unchanged manifest.
func TestInterceptRoundTripperWarnsOnceForRequiresClientsAndAmbiguousEntries(t *testing.T) {
	buf := captureWarnings(t)
	c, _, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestWarnings)
	rt := c.Wrap.RoundTripper(WithRoutes())
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	if err := rt.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	out := buf.String()
	if n := strings.Count(out, "KNOXCALL_INTERCEPT_REQUIRES_CLIENTS:openai"); n != 1 {
		t.Errorf("requires_clients warned %d times, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "KNOXCALL_INTERCEPT_AMBIGUOUS:dup.example/"); n != 1 {
		t.Errorf("ambiguous warned %d times, want 1:\n%s", n, out)
	}
}

// Per-host escrow: the named credential travels for that host; a host without
// one stays in transit.
func TestInterceptRoundTripperPerHostEscrow(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestNone)
	rt := c.Wrap.RoundTripper(WithRoutes(), WithHost("api.resend.com", HostEscrow("resend-key", "none")))
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	hc := &http.Client{Transport: rt}

	req, _ := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer placeholder")
	doOK(t, hc, req)
	other, _ := http.NewRequest(http.MethodGet, "https://api.other.example/x", nil)
	other.Header.Set("Authorization", "Bearer other_secret")
	doOK(t, hc, other)

	proxy := byPath(requests(), "/v1/proxy")
	if len(proxy) != 2 {
		t.Fatalf("proxy calls = %d", len(proxy))
	}
	if proxy[0].Header.Get("X-Knox-Upstream-Auth-Secret") != "resend-key" || proxy[0].Header.Get("X-Knox-Upstream-Auth-Scheme") != "none" || proxy[0].Header.Get("X-Knox-Upstream-Authorization") != "" {
		t.Errorf("escrow host = %v, want the secret ref + scheme and no lifted key", proxy[0].Header)
	}
	if proxy[1].Header.Get("X-Knox-Upstream-Authorization") != "Bearer other_secret" || proxy[1].Header.Get("X-Knox-Upstream-Auth-Secret") != "" {
		t.Errorf("transit host = %v, want the key lifted", proxy[1].Header)
	}
}

// A misconfiguration fails closed: every RoundTrip returns a WrapConfigError;
// Intercept refuses at install and leaves http.DefaultTransport alone.
func TestInterceptMisconfigurationFailsClosed(t *testing.T) {
	c, _, _ := newInterceptHarness(t, nil)
	for name, opts := range map[string][]WrapOption{
		"non-bare listed host":   {WithHost("https://x.example/path")},
		"empty per-host escrow":  {WithHost("h.example", HostEscrow(""))},
		"empty transport escrow": {WithEscrow("")},
		"non-bare route-around":  {WithRouteAround(RouteAroundRule{Host: "https://x.example"})},
	} {
		t.Run(name, func(t *testing.T) {
			rt := c.Wrap.RoundTripper(opts...)
			req, _ := http.NewRequest(http.MethodGet, "https://api.resend.com/x", nil)
			_, err := (&http.Client{Transport: rt}).Do(req)
			var ce *WrapConfigError
			if err == nil || !errors.As(err, &ce) {
				t.Fatalf("err = %v, want *WrapConfigError", err)
			}
			prev := http.DefaultTransport
			h, err := c.Wrap.Intercept(context.Background(), opts...)
			if h != nil || err == nil || !errors.As(err, &ce) {
				t.Fatalf("Intercept = (%v, %v), want the config error at install", h, err)
			}
			if http.DefaultTransport != prev {
				t.Fatalf("a refused install must not touch http.DefaultTransport")
			}
		})
	}
}

// ── the process-wide form ─────────────────────────────────────────────────────

// Intercept swaps http.DefaultTransport: an untouched client on the default
// transport reaches the Route for a covered host, the ephemeral proxy for a
// listed host, and the previous transport for everything else. One handle per
// process; Stop restores.
func TestInterceptSwapsDefaultTransportAndRestores(t *testing.T) {
	prev := http.DefaultTransport
	// The SDK's own management/data-plane calls bypass the swap so what the
	// mock records is the wrapped SDK's traffic only.
	c, requests, srv := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	srv.setManifests(manifestHubspot)
	base := &recordingTransport{}

	h, err := c.Wrap.Intercept(context.Background(), WithHosts("api.resend.com"), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	if _, ok := http.DefaultTransport.(*WrapRoundTripper); !ok {
		t.Fatalf("http.DefaultTransport = %T, want the route-aware RoundTripper installed", http.DefaultTransport)
	}
	if err := h.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if h.Manifest() == nil || h.Transport() != http.DefaultTransport {
		t.Fatalf("handle exposes the installed transport and its manifest")
	}

	get := func(u string) {
		t.Helper()
		res, err := http.DefaultClient.Get(u) // an untouched client on the default transport
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		mustClose(t, res)
	}
	get("https://api.hubapi.com/crm/v3/objects")
	get("https://api.resend.com/emails")
	get("https://unlisted.example/x")

	reqs := requests()
	if routed := routeCalls(reqs); len(routed) != 1 || routed[0].Path != "/objects" {
		t.Fatalf("route calls = %+v, want the covered host through its Route", routed)
	}
	if len(byPath(reqs, "/v1/proxy")) != 1 {
		t.Fatalf("proxy calls = %d, want the listed host through the ephemeral proxy", len(byPath(reqs, "/v1/proxy")))
	}
	if base.calls != 1 || base.got.URL.Host != "unlisted.example" {
		t.Fatalf("base calls = %d (%v), want the unlisted host on the previous transport, untouched", base.calls, base.got)
	}

	if _, err := c.Wrap.Intercept(context.Background()); !errors.Is(err, ErrInterceptInstalled) {
		t.Fatalf("second Intercept = %v, want ErrInterceptInstalled", err)
	}

	h.Stop()
	if http.DefaultTransport != prev {
		t.Fatalf("Stop must restore the previous http.DefaultTransport")
	}
	h.Stop() // idempotent
	h2, err := c.Wrap.Intercept(context.Background(), WithoutRoutes())
	if err != nil {
		t.Fatalf("Intercept after Stop: %v", err)
	}
	h2.Stop()
	if http.DefaultTransport != prev {
		t.Fatalf("the second handle restores too")
	}
}

// Stop never clobbers a transport something else installed after us.
func TestInterceptStopNeverClobbersALaterTransport(t *testing.T) {
	prev := http.DefaultTransport
	c, _, _ := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	h, err := c.Wrap.Intercept(context.Background(), WithoutRoutes(), WithHosts("api.resend.com"))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	later := &recordingTransport{}
	http.DefaultTransport = later
	t.Cleanup(func() { http.DefaultTransport = prev })
	buf := captureWarnings(t)
	h.Stop()
	if http.DefaultTransport != http.RoundTripper(later) {
		t.Fatalf("Stop replaced a later installer's transport")
	}
	if !strings.Contains(buf.String(), "KNOXCALL_INTERCEPT_NOT_RESTORED") {
		t.Fatalf("want a one-time warning, got %q", buf.String())
	}
	// The slot is free again: a new install works.
	h2, err := c.Wrap.Intercept(context.Background(), WithoutRoutes())
	if err != nil {
		t.Fatalf("Intercept after a clobbered Stop: %v", err)
	}
	h2.Stop()
}

// WithRequireContext: only a request whose context descends from Routed(ctx)
// is intercepted — the call site is marked, not the SDK.
func TestInterceptRequireContextHonoursRouted(t *testing.T) {
	prev := http.DefaultTransport
	c, requests, _ := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	base := &recordingTransport{}
	h, err := c.Wrap.Intercept(context.Background(), WithoutRoutes(), WithHosts("api.resend.com"), WithRequireContext(), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)

	plain, _ := http.NewRequest(http.MethodGet, "https://api.resend.com/emails", nil)
	doOK(t, http.DefaultClient, plain)
	if base.calls != 1 || len(byPath(requests(), "/v1/proxy")) != 0 {
		t.Fatalf("outside Routed: base calls=%d proxy=%d, want direct", base.calls, len(byPath(requests(), "/v1/proxy")))
	}
	routed, _ := http.NewRequestWithContext(c.Wrap.Routed(context.Background()), http.MethodGet, "https://api.resend.com/emails", nil)
	doOK(t, http.DefaultClient, routed)
	if base.calls != 1 || len(byPath(requests(), "/v1/proxy")) != 1 {
		t.Fatalf("inside Routed: base calls=%d proxy=%d, want the ephemeral proxy", base.calls, len(byPath(requests(), "/v1/proxy")))
	}
}

// The transport is documented as safe for concurrent use: many goroutines
// mixing route and ephemeral traffic all get answers, every one accounted for.
func TestInterceptRoundTripperConcurrentUse(t *testing.T) {
	c, requests, srv := newInterceptHarness(t, nil)
	srv.setManifests(manifestHubspot)
	rt := c.Wrap.RoundTripper(WithRoutes())
	t.Cleanup(rt.Stop)
	mustWait(t, rt)
	hc := &http.Client{Transport: rt}

	const workers, perWorker = 16, 4
	errs := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				u := "https://api.hubapi.com/crm/v3/objects"
				if (i+j)%2 == 1 {
					u = "https://api.resend.com/emails"
				}
				req, _ := http.NewRequest(http.MethodGet, u, nil)
				res, err := hc.Do(req)
				if err != nil {
					errs <- err
					continue
				}
				mustClose(t, res)
				if res.StatusCode != 200 {
					errs <- errors.New("non-200 under concurrency")
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent request: %v", err)
	}
	reqs := requests()
	if n := len(routeCalls(reqs)); n != workers*perWorker/2 {
		t.Errorf("route calls = %d, want %d", n, workers*perWorker/2)
	}
	if n := len(byPath(reqs, "/v1/proxy")); n != workers*perWorker/2 {
		t.Errorf("proxy calls = %d, want %d", n, workers*perWorker/2)
	}
}
