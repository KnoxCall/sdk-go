package knoxcall

// Uncovered-egress observations (PARITY §21.3) — the Go mirror of
// sdk/knoxcall-node/test/egress-observations.test.ts. Three layers: the
// classifier, driven by the CROSS-LANGUAGE fixture
// sdk/fixtures/egress-observation.json; the observer against an injected
// report function; and the seams (Intercept / RoundTripper) with the mock
// KnoxCall recording what LEAVES the process — so the wire body is asserted
// to carry the credential header's NAME and never its VALUE, never the query.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type egressFixture struct {
	CredentialHeaders struct {
		Allowlist []string `json:"allowlist"`
		Suffixes  []string `json:"suffixes"`
	} `json:"credential_headers"`
	HeaderCases []struct {
		Name   string `json:"name"`
		Counts bool   `json:"counts"`
	} `json:"header_cases"`
	PickCases []struct {
		Headers []string `json:"headers"`
		Expect  *string  `json:"expect"`
	} `json:"pick_cases"`
	FirstSegmentCases []struct {
		URL    string `json:"url"`
		Expect string `json:"expect"`
	} `json:"first_segment_cases"`
	SegmentRedactionCases []struct {
		Segment  string `json:"segment"`
		Redacted bool   `json:"redacted"`
	} `json:"segment_redaction_cases"`
	HostCases []struct {
		URL    string `json:"url"`
		Expect string `json:"expect"`
	} `json:"host_cases"`
	ObservationCases []struct {
		Name    string            `json:"name"`
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Expect  *struct {
			Host         string `json:"host"`
			FirstSegment string `json:"first_segment"`
			Method       string `json:"method"`
			HeaderName   string `json:"header_name"`
		} `json:"expect"`
	} `json:"cases"`
}

func loadEgressFixture(t *testing.T) egressFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "egress-observation.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f egressFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

// ── 1. the classifier: shared fixtures ───────────────────────────────────────

func TestEgressObservationSharedFixtures(t *testing.T) {
	f := loadEgressFixture(t)
	if len(f.HeaderCases) <= 20 || len(f.ObservationCases) <= 3 {
		t.Fatalf("fixture is trivial: %d header cases, %d observation cases", len(f.HeaderCases), len(f.ObservationCases))
	}
	if strings.Join(CredentialHeaderAllowlist, ",") != strings.Join(f.CredentialHeaders.Allowlist, ",") {
		t.Fatalf("allowlist drifted from the fixture")
	}
	if strings.Join(CredentialHeaderSuffixes, ",") != strings.Join(f.CredentialHeaders.Suffixes, ",") {
		t.Fatalf("suffixes drifted from the fixture")
	}
	for _, c := range f.HeaderCases {
		if got := IsCredentialHeaderName(c.Name); got != c.Counts {
			t.Errorf("IsCredentialHeaderName(%q) = %v, want %v", c.Name, got, c.Counts)
		}
	}
	for _, c := range f.PickCases {
		h := http.Header{}
		for _, name := range c.Headers {
			h[name] = []string{"value"} // raw key: the classifier must lower-case, not rely on canonicalisation
		}
		got := CredentialHeaderName(h)
		want := ""
		if c.Expect != nil {
			want = *c.Expect
		}
		if got != want {
			t.Errorf("CredentialHeaderName(%v) = %q, want %q", c.Headers, got, want)
		}
	}
	for _, c := range f.FirstSegmentCases {
		u, err := url.Parse(c.URL)
		if err != nil {
			t.Fatalf("parse %s: %v", c.URL, err)
		}
		if got := observationFirstSegment(u); got != c.Expect {
			t.Errorf("first segment of %s = %q, want %q", c.URL, got, c.Expect)
		}
	}
	if len(f.SegmentRedactionCases) < 20 {
		t.Fatalf("segment_redaction_cases is trivial: %d", len(f.SegmentRedactionCases))
	}
	for _, c := range f.SegmentRedactionCases {
		if got := FirstSegmentLooksLikeCredential(c.Segment); got != c.Redacted {
			t.Errorf("FirstSegmentLooksLikeCredential(%q) = %v, want %v", c.Segment, got, c.Redacted)
		}
	}
	for _, c := range f.HostCases {
		u, _ := url.Parse(c.URL)
		if got := normalizeHost(u.Hostname()); got != c.Expect {
			t.Errorf("host of %s = %q, want %q", c.URL, got, c.Expect)
		}
	}
	for _, c := range f.ObservationCases {
		req, err := http.NewRequest(strings.ToUpper(c.Method), c.URL, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		req.Method = c.Method // the fixture's casing, as a caller could set it
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		got, ok := observationFor(req)
		if c.Expect == nil {
			if ok {
				t.Errorf("%s: recorded %+v, want nothing", c.Name, got)
			}
			continue
		}
		want := observationKey{host: c.Expect.Host, segment: c.Expect.FirstSegment, method: c.Expect.Method, header: c.Expect.HeaderName}
		if !ok || got != want {
			t.Errorf("%s: got %+v (ok=%v), want %+v", c.Name, got, ok, want)
		}
		for _, v := range c.Headers { // names, never values
			if strings.TrimSpace(v) != "" && strings.Contains(got.host+got.segment+got.method+got.header, v) {
				t.Errorf("%s: a header value leaked into the observation", c.Name)
			}
		}
	}
}

// ── 2. the observer ──────────────────────────────────────────────────────────

type obsSink struct {
	mu    sync.Mutex
	calls [][]EgressObservation
	err   error
	minus int
}

func (s *obsSink) report(_ context.Context, obs []EgressObservation) (*EgressObservationsReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.calls = append(s.calls, obs)
	return &EgressObservationsReport{Accepted: len(obs) - s.minus, Dropped: s.minus, Reasons: map[string]int{}}, nil
}

func (s *obsSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *obsSink) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func key(i int) observationKey {
	return observationKey{host: "h" + itoa(i) + ".example", segment: "/v1", method: "GET", header: "authorization"}
}

func itoa(i int) string { return strconv.Itoa(i) }

// observerFlags reads the reporter's forbidden / warned-failed flags under its
// lock. The flush goroutine writes them under o.mu; reading them bare from the
// test goroutine is a data race that `go test -race` (sdk-ci) reports.
func observerFlags(o *egressObserver) (forbidden, warnedFailed bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.forbidden, o.warnedFailed
}

func waitUntil(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func captureObsWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := warnWriter
	buf := &bytes.Buffer{}
	warnWriter = buf
	resetWarnedForTests()
	t.Cleanup(func() {
		warnWriter = orig
		resetWarnedForTests()
	})
	return buf
}

func TestEgressObserverAggregatesWithCountsAndISOTimestamps(t *testing.T) {
	sink := &obsSink{}
	o := newEgressObserver(sink.report, nil)
	now := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)
	o.now = func() time.Time { return now }
	o.rand = func() float64 { return 0.5 }
	o.record(key(1))
	now = now.Add(time.Second)
	o.record(key(1))
	now = now.Add(time.Second)
	o.record(key(1))
	o.record(observationKey{host: "h1.example", segment: "/v1", method: "POST", header: "authorization"})
	o.record(observationKey{host: "h1.example", segment: "/v2", method: "GET", header: "authorization"})
	o.record(observationKey{host: "h1.example", segment: "/v1", method: "GET", header: "x-api-key"})
	if o.size() != 4 {
		t.Fatalf("size = %d, want 4", o.size())
	}
	o.flush(context.Background())
	if sink.count() != 1 {
		t.Fatalf("report calls = %d, want 1", sink.count())
	}
	first := sink.calls[0][0]
	want := EgressObservation{Host: "h1.example", FirstSegment: "/v1", Method: "GET", HeaderName: "authorization", Count: 3, FirstSeen: "2023-11-14T22:13:20.000Z", LastSeen: "2023-11-14T22:13:22.000Z"}
	if first != want {
		t.Fatalf("first observation = %+v, want %+v", first, want)
	}
	if o.size() != 0 {
		t.Fatalf("buffer not drained")
	}
}

func TestEgressObserverFlushesAt200AndChunksAt200PerRequest(t *testing.T) {
	sink := &obsSink{}
	o := newEgressObserver(sink.report, nil)
	for i := 0; i < 199; i++ {
		o.record(key(i))
	}
	if sink.count() != 0 {
		t.Fatalf("flushed early")
	}
	o.record(key(199))
	waitUntil(t, func() bool { return sink.count() == 1 }, "the immediate flush")
	if len(sink.calls[0]) != 200 {
		t.Fatalf("flushed %d, want 200", len(sink.calls[0]))
	}
	o.stop()

	big := &obsSink{}
	ob := newEgressObserver(big.report, nil)
	ob.flushAt = 10_000
	for i := 0; i < 450; i++ {
		ob.record(key(i))
	}
	ob.flush(context.Background())
	if big.count() != 3 || len(big.calls[0]) != 200 || len(big.calls[1]) != 200 || len(big.calls[2]) != 50 {
		t.Fatalf("chunks = %d (%v), want 200,200,50", big.count(), big.calls)
	}
}

func TestEgressObserverTimerFlush(t *testing.T) {
	sink := &obsSink{}
	o := newEgressObserver(sink.report, nil)
	o.interval = 30 * time.Millisecond
	o.rand = func() float64 { return 0.5 }
	o.record(key(1))
	if sink.count() != 0 {
		t.Fatalf("flushed before the timer")
	}
	waitUntil(t, func() bool { return sink.count() == 1 }, "the timer flush")
	o.mu.Lock()
	armed := o.timer != nil
	o.mu.Unlock()
	if armed {
		t.Fatalf("timer re-armed with nothing pending")
	}
	o.record(key(2))
	waitUntil(t, func() bool { return sink.count() == 2 }, "the second timer flush")
	o.stop()
}

func TestEgressObserverCapsAt1000WithOneWarning(t *testing.T) {
	buf := captureObsWarnings(t)
	sink := &obsSink{}
	o := newEgressObserver(sink.report, nil)
	o.flushAt = 10_000
	for i := 0; i < 1005; i++ {
		o.record(key(i))
	}
	o.record(key(3)) // an EXISTING key still counts
	if o.size() != 1000 {
		t.Fatalf("size = %d, want 1000", o.size())
	}
	for _, p := range o.pending() {
		if p.Host == "h3.example" && p.Count != 2 {
			t.Fatalf("existing key count = %d, want 2", p.Count)
		}
	}
	if n := strings.Count(buf.String(), "KNOXCALL_EGRESS_OBSERVATIONS_OVERFLOW"); n != 1 {
		t.Fatalf("overflow warnings = %d, want 1: %s", n, buf.String())
	}
}

func TestEgressObserver403StopsForGoodWithOneWarning(t *testing.T) {
	buf := captureObsWarnings(t)
	sink := &obsSink{err: &PermissionDeniedError{}}
	o := newEgressObserver(sink.report, nil)
	o.record(key(1))
	o.flush(context.Background())
	if !o.forbidden {
		t.Fatalf("not forbidden after a 403")
	}
	o.record(key(2))
	if o.size() != 0 {
		t.Fatalf("a record after 403 was kept")
	}
	o.flush(context.Background())
	o.stop()
	if sink.count() != 0 {
		t.Fatalf("a report succeeded after 403")
	}
	if n := strings.Count(buf.String(), "KNOXCALL_EGRESS_OBSERVATIONS_FORBIDDEN"); n != 1 || !strings.Contains(buf.String(), "routes:read") {
		t.Fatalf("forbidden warnings = %d: %s", n, buf.String())
	}
}

func TestEgressObserverOtherFailureDropsTheBatchWithOneWarningAndKeepsGoing(t *testing.T) {
	buf := captureObsWarnings(t)
	sink := &obsSink{err: errors.New("dial tcp: connection refused")}
	o := newEgressObserver(sink.report, nil)
	o.record(key(1))
	o.flush(context.Background())
	if o.size() != 0 || o.forbidden {
		t.Fatalf("batch should be dropped (not retried) and reporting should stay on")
	}
	sink.setErr(nil)
	o.record(key(2))
	o.flush(context.Background())
	if sink.count() != 1 || sink.calls[0][0].Host != "h2.example" {
		t.Fatalf("later flush = %v, want only h2.example", sink.calls)
	}
	sink.setErr(errors.New("again"))
	o.record(key(3))
	o.flush(context.Background())
	if n := strings.Count(buf.String(), "KNOXCALL_EGRESS_OBSERVATIONS_FAILED"); n != 1 {
		t.Fatalf("failed warnings = %d, want 1: %s", n, buf.String())
	}
}

func TestEgressObserverOnFlushAndStop(t *testing.T) {
	var infos []ObservationFlushInfo
	sink := &obsSink{minus: 1}
	o := newEgressObserver(sink.report, func(i ObservationFlushInfo) {
		infos = append(infos, i)
		panic("hook bug") // must never break the observer
	})
	o.record(key(1))
	o.record(key(2))
	o.flush(context.Background())
	if len(infos) != 1 || infos[0] != (ObservationFlushInfo{Accepted: 1, Dropped: 1}) {
		t.Fatalf("onFlush = %+v", infos)
	}
	o.record(key(3))
	o.stop()
	if sink.count() != 2 {
		t.Fatalf("stop did not flush once more: %d", sink.count())
	}
	o.record(key(4))
	if o.size() != 0 {
		t.Fatalf("a record after stop was kept")
	}
	o.stop() // idempotent
}

// ── 3. the seams ─────────────────────────────────────────────────────────────

// splitTransport sends the SDK's own host to the real network (the httptest
// server) and everything else to a recording fake, so an unlisted host never
// reaches the network while the SDK's own calls still do.
type splitTransport struct {
	ownHost string
	real    http.RoundTripper
	fake    *recordingTransport
}

func (s *splitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == s.ownHost {
		return s.real.RoundTrip(req)
	}
	return s.fake.RoundTrip(req)
}

func hostOf(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

func obsCalls(reqs []recordedRequest) []recordedRequest {
	return byPath(reqs, "/v1/wrap/egress-observations")
}

func decodeReport(t *testing.T, r recordedRequest) (string, []EgressObservation) {
	t.Helper()
	var body egressObservationsBody
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("report body: %v (%s)", err, r.Body)
	}
	return body.SDK, body.Observations
}

func TestInterceptObservesUnlistedCredentialedCallsNamesNeverValues(t *testing.T) {
	prev := http.DefaultTransport
	// The SDK's own client is pinned to the pre-install transport, as in
	// TestInterceptSwapsDefaultTransportAndRestores: getToken holds c.mu across
	// the mint, and the route-aware RoundTrip reads c.mu for its own-host set.
	c, requests, srv := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} }) // the SDK's own client rides http.DefaultTransport
	srv.setManifests(manifestHubspot)
	fake := &recordingTransport{}
	base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
	var flushes []ObservationFlushInfo
	h, err := c.Wrap.Intercept(context.Background(), WithHosts("api.resend.com"), WithBaseTransport(base),
		WithOnObservationFlush(func(i ObservationFlushInfo) { flushes = append(flushes, i) }))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	mustWait(t, h.Transport())

	req, _ := http.NewRequest("post", "https://a.klaviyo.com/api/profiles/?x=1&token=leak-in-query", strings.NewReader(`{"email":"never-appears@example.com"}`))
	req.Header.Set("Authorization", "Klaviyo-API-Key pk_live_should_never_appear")
	req.Header.Set("Content-Type", "application/json")
	res := doOK(t, http.DefaultClient, req) // an untouched client on the default transport
	if res.StatusCode != 200 || fake.calls != 1 || fake.got.URL.Host != "a.klaviyo.com" {
		t.Fatalf("the application's request must go direct, untouched: %d %v", fake.calls, fake.got)
	}
	req2, _ := http.NewRequest(http.MethodPost, "https://a.klaviyo.com/api/profiles/?x=2", nil)
	req2.Header.Set("authorization", "Klaviyo-API-Key pk_live_2")
	doOK(t, http.DefaultClient, req2)
	if len(obsCalls(requests())) != 0 {
		t.Fatalf("nothing may leave the process on the request's own path")
	}

	h.Transport().observer.flush(context.Background())
	calls := obsCalls(requests())
	if len(calls) != 1 {
		t.Fatalf("report calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.Method != http.MethodPost || call.Header.Get("Authorization") != "Bearer kc_live_aaaa" {
		t.Fatalf("the report must ride the SDK's OWN credential through request(): %s %v", call.Method, call.Header)
	}
	if call.Header.Get("X-Idempotency-Key") == "" {
		t.Fatalf("the report must go through the shared request pipeline (idempotency key)")
	}
	sdk, obs := decodeReport(t, call)
	if sdk != "go/"+sdkVersion {
		t.Fatalf("sdk = %q", sdk)
	}
	if len(obs) != 1 || obs[0].Host != "a.klaviyo.com" || obs[0].FirstSegment != "/api" || obs[0].Method != "POST" || obs[0].HeaderName != "authorization" || obs[0].Count != 2 {
		t.Fatalf("observations = %+v", obs)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", obs[0].FirstSeen); err != nil || !strings.HasSuffix(obs[0].LastSeen, "Z") {
		t.Fatalf("timestamps must be ISO-8601 UTC: %q %q", obs[0].FirstSeen, obs[0].LastSeen)
	}
	for _, leak := range []string{"pk_live", "x=1", "x=2", "leak-in-query", "never-appears", "profiles"} {
		if bytes.Contains(call.Body, []byte(leak)) {
			t.Fatalf("the wire body carries %q — names, never values", leak)
		}
	}
	if len(flushes) != 1 || flushes[0] != (ObservationFlushInfo{Accepted: 1, Dropped: 0}) {
		t.Fatalf("onObservationFlush = %+v", flushes)
	}
	// The report itself, and the SDK's own manifest poll (both credentialed,
	// both to the SDK's own host), were never observed.
	if h.Transport().observer.size() != 0 {
		t.Fatalf("the SDK's own traffic was observed: %+v", h.Transport().observer.pending())
	}
}

func TestInterceptObservesNothingForOtherDecisions(t *testing.T) {
	prev := http.DefaultTransport
	// The SDK's own client is pinned to the pre-install transport, as in
	// TestInterceptSwapsDefaultTransportAndRestores: getToken holds c.mu across
	// the mint, and the route-aware RoundTrip reads c.mu for its own-host set.
	c, requests, srv := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	srv.setManifests(manifestHubspot)
	fake := &recordingTransport{}
	base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
	h, err := c.Wrap.Intercept(context.Background(), WithHosts("api.resend.com", "api.stripe.com"), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	mustWait(t, h.Transport())

	do := func(method, u string, hdr map[string]string) {
		t.Helper()
		req, _ := http.NewRequest(method, u, strings.NewReader("body"))
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		doOK(t, http.DefaultClient, req)
	}
	do("GET", "https://unlisted.example/x", map[string]string{"Accept": "*/*", "X-Request-Id": "1"})       // no credential
	do("GET", c.baseURL+"/v1/anything", map[string]string{"Authorization": "Bearer kc"})                   // own_host
	do("GET", "https://acme.knoxcall.com/x", map[string]string{"Authorization": "Bearer kc"})              // platform host
	do("POST", "https://api.stripe.com/v1/tokens", map[string]string{"Authorization": "Bearer sk_live_x"}) // route_around
	do("GET", "https://api.hubapi.com/crm/v3/objects", map[string]string{"Authorization": "Bearer t"})     // route
	do("POST", "https://api.resend.com/emails", map[string]string{"Authorization": "Bearer re"})           // ephemeral
	t.Setenv("KNOXCALL_INTERCEPT", "off")
	do("GET", "https://unlisted.example/x", map[string]string{"Authorization": "Bearer u"}) // kill_switch
	t.Setenv("KNOXCALL_INTERCEPT", "")

	if h.Transport().observer.size() != 0 {
		t.Fatalf("observed: %+v", h.Transport().observer.pending())
	}
	h.Stop()
	if len(obsCalls(requests())) != 0 {
		t.Fatalf("a report was sent with nothing to report")
	}
}

func TestInterceptObservationOptOuts(t *testing.T) {
	run := func(t *testing.T, env string, opts ...WrapOption) (hasObserver bool, reports int) {
		t.Helper()
		t.Setenv("KNOXCALL_OBSERVE_UNCOVERED", env) // "" = unset for this run (t.Setenv persists to the end of the test)
		prev := http.DefaultTransport
		c, requests, _ := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
		fake := &recordingTransport{}
		base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
		h, err := c.Wrap.Intercept(context.Background(), append([]WrapOption{WithBaseTransport(base)}, opts...)...)
		if err != nil {
			t.Fatalf("Intercept: %v", err)
		}
		mustWait(t, h.Transport())
		req, _ := http.NewRequest(http.MethodGet, "https://h.example/v1/x", nil)
		req.Header.Set("Authorization", "Bearer x")
		doOK(t, http.DefaultClient, req)
		h.Stop()
		return h.Transport().observer != nil, len(obsCalls(requests()))
	}
	if has, n := run(t, "", WithObserveUncovered(false)); has || n != 0 {
		t.Fatalf("WithObserveUncovered(false): observer=%v reports=%d", has, n)
	}
	for _, v := range []string{"off", "FALSE", "0"} {
		if has, n := run(t, v); has || n != 0 {
			t.Fatalf("KNOXCALL_OBSERVE_UNCOVERED=%s: observer=%v reports=%d", v, has, n)
		}
	}
	t.Setenv("KNOXCALL_INTERCEPT", "off")
	if has, n := run(t, ""); !has || n != 0 {
		t.Fatalf("KNOXCALL_INTERCEPT=off: observer=%v reports=%d (everything is direct; nothing is worth reporting)", has, n)
	}
	t.Setenv("KNOXCALL_INTERCEPT", "")
	if has, n := run(t, ""); !has || n != 1 {
		t.Fatalf("the control (on by default): observer=%v reports=%d", has, n)
	}
}

func TestInterceptObservation403StopsWithOneWarning(t *testing.T) {
	buf := captureObsWarnings(t)
	prev := http.DefaultTransport
	// The SDK's own client is pinned to the pre-install transport, as in
	// TestInterceptSwapsDefaultTransportAndRestores: getToken holds c.mu across
	// the mint, and the route-aware RoundTrip reads c.mu for its own-host set.
	c, requests, srv := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	srv.mu.Lock()
	srv.obsStatus = 403
	srv.mu.Unlock()
	fake := &recordingTransport{}
	base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
	h, err := c.Wrap.Intercept(context.Background(), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	mustWait(t, h.Transport())
	get := func(u string) {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer x")
		doOK(t, http.DefaultClient, req)
	}
	for i := 0; i < 200; i++ {
		get("https://h" + itoa(i) + ".example/v1/x")
	}
	waitUntil(t, func() bool { f, _ := observerFlags(h.Transport().observer); return f }, "the 403 to be seen")
	for i := 0; i < 200; i++ {
		get("https://k" + itoa(i) + ".example/v1/x")
	}
	if fake.calls != 400 {
		t.Fatalf("the application never notices: %d direct calls, want 400", fake.calls)
	}
	h.Stop()
	if n := len(obsCalls(requests())); n != 1 {
		t.Fatalf("report attempts = %d, want exactly the one that was refused", n)
	}
	if n := strings.Count(buf.String(), "KNOXCALL_EGRESS_OBSERVATIONS_FORBIDDEN"); n != 1 || !strings.Contains(buf.String(), "routes:read") {
		t.Fatalf("warnings: %s", buf.String())
	}
}

func TestInterceptObservationNetworkErrorDroppedWithOneWarning(t *testing.T) {
	buf := captureObsWarnings(t)
	prev := http.DefaultTransport
	failing := &failNTransport{
		base:     prev,
		match:    func(r *http.Request) bool { return r.URL.Path == "/v1/wrap/egress-observations" },
		err:      errors.New("dial tcp: connection refused"),
		failures: 1000,
	}
	c, requests, _ := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: failing} })
	fake := &recordingTransport{}
	base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
	h, err := c.Wrap.Intercept(context.Background(), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	mustWait(t, h.Transport())
	get := func(u string) {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer x")
		res := doOK(t, http.DefaultClient, req)
		if res.StatusCode != 200 {
			t.Fatalf("the application's request must be unaffected")
		}
	}
	for i := 0; i < 200; i++ {
		get("https://h" + itoa(i) + ".example/v1/x")
	}
	waitUntil(t, func() bool { _, w := observerFlags(h.Transport().observer); return w }, "the failed flush")
	failing.mu.Lock()
	failing.failures = 0
	failing.mu.Unlock()
	get("https://later.example/v1/x")
	h.Stop()
	calls := obsCalls(requests())
	if len(calls) != 1 {
		t.Fatalf("successful reports = %d, want 1 (the failed batch is never retried)", len(calls))
	}
	if _, obs := decodeReport(t, calls[0]); len(obs) != 1 || obs[0].Host != "later.example" {
		t.Fatalf("later report = %+v", obs)
	}
	if n := strings.Count(buf.String(), "KNOXCALL_EGRESS_OBSERVATIONS_FAILED"); n != 1 {
		t.Fatalf("failed warnings = %d: %s", n, buf.String())
	}
}

func TestInterceptObservationTimerFlush(t *testing.T) {
	prev := http.DefaultTransport
	c, requests, _ := newInterceptHarness(t, func(o *Options) { o.HTTPClient = &http.Client{Transport: prev} })
	fake := &recordingTransport{}
	base := &splitTransport{ownHost: hostOf(c.baseURL), real: prev, fake: fake}
	h, err := c.Wrap.Intercept(context.Background(), WithBaseTransport(base))
	if err != nil {
		t.Fatalf("Intercept: %v", err)
	}
	t.Cleanup(h.Stop)
	mustWait(t, h.Transport())
	h.Transport().observer.interval = 30 * time.Millisecond
	req, _ := http.NewRequest(http.MethodGet, "https://h.example/v1/x", nil)
	req.Header.Set("Authorization", "Bearer x")
	doOK(t, http.DefaultClient, req)
	if len(obsCalls(requests())) != 0 {
		t.Fatalf("flushed on the request's own path")
	}
	waitUntil(t, func() bool { return len(obsCalls(requests())) == 1 }, "the timer flush")
}

func TestRoundTripperObservationDefaults(t *testing.T) {
	c, requests, _ := newInterceptHarness(t, nil)
	off := c.Wrap.RoundTripper()
	t.Cleanup(off.Stop)
	if off.observer != nil {
		t.Fatalf("an explicit transport without WithRoutes must not report")
	}
	on := c.Wrap.RoundTripper(WithRoutes())
	t.Cleanup(on.Stop)
	mustWait(t, on)
	if on.observer == nil {
		t.Fatalf("WithRoutes builds the observer")
	}
	hc := &http.Client{Transport: on}
	req, _ := http.NewRequest(http.MethodGet, "https://anything.example/v1/x", nil)
	req.Header.Set("Authorization", "Bearer x")
	doOK(t, hc, req) // every host is listed → ephemeral, never `unlisted`
	if len(byPath(requests(), "/v1/proxy")) != 1 || on.observer.size() != 0 {
		t.Fatalf("an explicit transport observes nothing by construction")
	}
	forced := c.Wrap.RoundTripper(WithRoutes(), WithObserveUncovered(false))
	t.Cleanup(forced.Stop)
	if forced.observer != nil {
		t.Fatalf("WithObserveUncovered(false) wins")
	}
}

func TestWrapReportEgressObservations(t *testing.T) {
	c, requests, _ := newInterceptHarness(t, nil)
	obs := []EgressObservation{{Host: "h.example", FirstSegment: "/v1", Method: "GET", HeaderName: "authorization", Count: 3, FirstSeen: "2026-09-26T00:00:00.000Z", LastSeen: "2026-09-26T00:01:00.000Z"}}
	res, err := c.Wrap.ReportEgressObservations(context.Background(), obs)
	if err != nil {
		t.Fatalf("ReportEgressObservations: %v", err)
	}
	if res.Accepted != 1 || res.Dropped != 0 || res.Reasons == nil {
		t.Fatalf("result = %+v", res)
	}
	call := obsCalls(requests())[0]
	if call.Method != http.MethodPost || call.Header.Get("Authorization") != "Bearer kc_live_aaaa" {
		t.Fatalf("request = %s %v", call.Method, call.Header)
	}
	sdk, got := decodeReport(t, call)
	if sdk != "go/"+sdkVersion || len(got) != 1 || got[0] != obs[0] {
		t.Fatalf("body = %s", call.Body)
	}
	if _, err := c.Wrap.ReportEgressObservations(context.Background(), nil, ReportEgressObservationsOptions{SDK: "custom/9.9.9"}); err != nil {
		t.Fatalf("custom sdk: %v", err)
	}
	sdk2, got2 := decodeReport(t, obsCalls(requests())[1])
	if sdk2 != "custom/9.9.9" || got2 == nil || len(got2) != 0 {
		t.Fatalf("nil observations must serialise as [] with the custom sdk: %s", obsCalls(requests())[1].Body)
	}
}

// The report runs under the SDK's suppressed context; a route-aware
// RoundTripper hands such a request straight to its base transport — an
// unlisted, credentialed request that would otherwise be observed is neither
// intercepted nor recorded.
func TestRoundTripperSuppressedContextBypassesInterceptionAndObservation(t *testing.T) {
	c, _, _ := newInterceptHarness(t, nil)
	base := &recordingTransport{}
	rt := c.Wrap.newRoundTripper([]WrapOption{WithBaseTransport(base)}, false, false)
	if rt.observer == nil {
		t.Fatalf("the process-wide form reports by default")
	}
	req, _ := http.NewRequestWithContext(withSuppressed(context.Background()), http.MethodPost, "https://unlisted.example/v1/x", nil)
	req.Header.Set("Authorization", "Bearer x")
	res, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	mustClose(t, res)
	if base.calls != 1 || rt.observer.size() != 0 {
		t.Fatalf("suppressed request: base calls = %d, observed = %d; want 1, 0", base.calls, rt.observer.size())
	}
	plain, _ := http.NewRequest(http.MethodPost, "https://unlisted.example/v1/x", nil)
	plain.Header.Set("Authorization", "Bearer x")
	res, err = rt.RoundTrip(plain)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	mustClose(t, res)
	if rt.observer.size() != 1 {
		t.Fatalf("the control: an unsuppressed unlisted credentialed request is observed")
	}
}
