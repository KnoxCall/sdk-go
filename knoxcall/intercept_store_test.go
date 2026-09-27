package knoxcall

// The SDK-side manifest store (route-aware-interception-plan.md §2.5, PARITY
// §21.1): poll at the TTL, single-flight, stale-keep with backoff, permission
// refusals as "no manifest" with one warning, rate-limited out-of-cycle
// refreshes, Stop. Timers and the clock are injected so every schedule is
// asserted as a value, never waited for.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeTimers records every scheduled poll instead of arming a real timer.
type fakeTimers struct {
	mu        sync.Mutex
	delays    []time.Duration
	fns       []func()
	cancelled int
}

func (f *fakeTimers) schedule(d time.Duration, fn func()) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays = append(f.delays, d)
	f.fns = append(f.fns, fn)
	return func() {
		f.mu.Lock()
		f.cancelled++
		f.mu.Unlock()
	}
}

func (f *fakeTimers) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.delays)
}

func (f *fakeTimers) lastDelay() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.delays) == 0 {
		return -1
	}
	return f.delays[len(f.delays)-1]
}

func (f *fakeTimers) cancels() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cancelled
}

// fireLast runs the most recently scheduled poll synchronously.
func (f *fakeTimers) fireLast() {
	f.mu.Lock()
	fn := f.fns[len(f.fns)-1]
	f.mu.Unlock()
	fn()
}

func storeEntry(host, slug, base string) InterceptManifestRoute {
	return InterceptManifestRoute{Host: host, BasePath: base, Slug: slug, RouteID: "id-" + slug}
}

func manifestOf(version string, routes ...InterceptManifestRoute) *InterceptManifest {
	if routes == nil {
		routes = []InterceptManifestRoute{}
	}
	return &InterceptManifest{Version: version, TTLSeconds: 60, Environment: "production", Routes: routes}
}

func testStore(fetch func(ctx context.Context, ifNoneMatch string) (*InterceptManifest, error)) (*manifestStore, *fakeClock, *fakeTimers) {
	s := newManifestStore(fetch)
	clock := &fakeClock{t: time.Unix(1_000_000, 0)}
	timers := &fakeTimers{}
	s.now = clock.now
	s.random = func() float64 { return 0.5 } // jitter factor exactly 1.0
	s.schedule = timers.schedule
	return s, clock, timers
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// eventually polls cond until it holds or the deadline passes.
func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ── the conditional poll (PARITY §21.1 "Conditional poll") ───────────────────
// Driven by the CROSS-LANGUAGE fixture sdk/fixtures/intercept-store-conditional.json;
// node (sdk/knoxcall-node/test/intercept-manifest-store.test.ts) is the reference.

type conditionalStep struct {
	Name    string `json:"name"`
	Forced  bool   `json:"forced"`
	Respond struct {
		Status   int    `json:"status"`
		Manifest string `json:"manifest"`
	} `json:"respond"`
	Expect struct {
		FetchIfNoneMatch *string  `json:"fetch_if_none_match"`
		WireIfNoneMatch  *string  `json:"wire_if_none_match"`
		Version          string   `json:"version"`
		RefreshFired     bool     `json:"refresh_fired"`
		Added            []string `json:"added"`
		Removed          []string `json:"removed"`
	} `json:"expect"`
}

type conditionalFixture struct {
	Manifests map[string]*InterceptManifest `json:"manifests"`
	Steps     []conditionalStep             `json:"steps"`
}

func loadConditionalFixture(t *testing.T) conditionalFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "intercept-store-conditional.json"))
	if err != nil {
		t.Fatalf("read the shared fixture: %v", err)
	}
	var f conditionalFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse the shared fixture: %v", err)
	}
	if len(f.Steps) < 4 || f.Steps[0].Expect.FetchIfNoneMatch != nil {
		t.Fatalf("fixture shape: %d steps, first fetch_if_none_match=%v", len(f.Steps), f.Steps[0].Expect.FetchIfNoneMatch)
	}
	sawNotModified, sawForced := false, false
	for _, s := range f.Steps {
		sawNotModified = sawNotModified || s.Respond.Status == 304
		sawForced = sawForced || s.Forced
	}
	if !sawNotModified || !sawForced {
		t.Fatalf("fixture must carry a 304 step and a forced step")
	}
	return f
}

func slugsOf(entries []InterceptManifestRoute) []string {
	out := []string{}
	for _, e := range entries {
		out = append(out, e.Slug)
	}
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Every Refresh here runs on the test goroutine (no Start, no Hint), so the
// fetch and the hooks run inline and nothing needs to be waited for.
func TestManifestStoreConditionalPollWalksTheSharedFixture(t *testing.T) {
	f := loadConditionalFixture(t)
	var sent []string
	var refreshes []ManifestRefreshInfo
	respond := struct {
		status   int
		manifest string
	}{}
	s, _, timers := testStore(func(_ context.Context, ifNoneMatch string) (*InterceptManifest, error) {
		sent = append(sent, ifNoneMatch)
		if respond.status == 304 {
			return nil, nil
		}
		m := *f.Manifests[respond.manifest]
		return &m, nil
	})
	s.onRefresh = func(i ManifestRefreshInfo) { refreshes = append(refreshes, i) }
	ctx := context.Background()

	for i, step := range f.Steps {
		respond.status, respond.manifest = step.Respond.Status, step.Respond.Manifest
		refreshes = nil
		switch {
		case i == 0:
			_, _ = s.Refresh(ctx, "start", true)
		case step.Forced:
			_, _ = s.Refresh(ctx, "route_refused", true)
		default:
			// The scheduled poll: run the last timer the store armed.
			timers.mu.Lock()
			fn := timers.fns[len(timers.fns)-1]
			timers.mu.Unlock()
			fn()
		}
		want := ""
		if step.Expect.FetchIfNoneMatch != nil {
			want = *step.Expect.FetchIfNoneMatch
		}
		if len(sent) != i+1 || sent[i] != want {
			t.Fatalf("%s: the fetch saw %q, want %q as call %d", step.Name, sent, want, i+1)
		}
		if got := s.Get(); s.Version() != step.Expect.Version || got == nil || got.Version != step.Expect.Version {
			t.Fatalf("%s: store holds version %q / %+v, want %q", step.Name, s.Version(), got, step.Expect.Version)
		}
		if s.LastError() != nil {
			t.Fatalf("%s: LastError = %v, want nil", step.Name, s.LastError())
		}
		if d := timers.lastDelay(); d != 60*time.Second {
			t.Fatalf("%s: next poll armed at %v, want one TTL (every answer, a 304 included, restarts the clock)", step.Name, d)
		}
		if step.Expect.RefreshFired {
			if len(refreshes) != 1 || refreshes[0].Version != step.Expect.Version ||
				!sameStrings(slugsOf(refreshes[0].Added), step.Expect.Added) ||
				!sameStrings(slugsOf(refreshes[0].Removed), step.Expect.Removed) {
				t.Fatalf("%s: onRefresh = %+v, want one call with version %q added %v removed %v",
					step.Name, refreshes, step.Expect.Version, step.Expect.Added, step.Expect.Removed)
			}
		} else if len(refreshes) != 0 {
			t.Fatalf("%s: onRefresh fired %+v, want none (nothing changed)", step.Name, refreshes)
		}
	}
}

func TestManifestStoreA304ClearsTheBackoffARunOfFaultsBuiltUp(t *testing.T) {
	mode := "ok"
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		switch mode {
		case "fault":
			return nil, errors.New("network error: ECONNRESET")
		case "not_modified":
			return nil, nil
		}
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	ctx := context.Background()
	_, _ = s.Refresh(ctx, "start", true)
	mode = "fault"
	_, _ = s.Refresh(ctx, "poll", true) // fault #1 → next at TTL
	_, _ = s.Refresh(ctx, "poll", true) // fault #2 → next at 2×TTL
	if d := timers.lastDelay(); d != 120*time.Second {
		t.Fatalf("after two faults the poll is armed at %v, want 2×TTL", d)
	}
	mode = "not_modified"
	_, _ = s.Refresh(ctx, "poll", true)
	if m := s.Get(); m == nil || len(m.Routes) != 1 || s.LastError() != nil {
		t.Fatalf("a 304 keeps the manifest and clears the error: %+v / %v", m, s.LastError())
	}
	if d := timers.lastDelay(); d != 60*time.Second {
		t.Fatalf("after a 304 the poll is armed at %v, want one TTL (backoff cleared)", d)
	}
}

func TestManifestStoreAfterAPermissionRefusalTheRecoveryPollIsUnconditional(t *testing.T) {
	denied := false
	var sent []string
	s, _, _ := testStore(func(_ context.Context, ifNoneMatch string) (*InterceptManifest, error) {
		sent = append(sent, ifNoneMatch)
		if denied {
			return nil, &APIError{StatusCode: 403, Message: "insufficient scope"}
		}
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	_ = captureWarnings(t) // the refusal warns once; keep it out of the test output
	ctx := context.Background()
	_, _ = s.Refresh(ctx, "start", true)
	denied = true
	_, _ = s.Refresh(ctx, "manual", true)
	if !sameStrings(sent, []string{"", "v:a"}) || s.Version() != "" {
		t.Fatalf("sent %q, version %q: the refusal drops the held version", sent, s.Version())
	}
	denied = false
	_, _ = s.Refresh(ctx, "manual", true)
	if len(sent) != 3 || sent[2] != "" || s.Version() != "v:a" {
		t.Fatalf("sent %q, version %q: the recovery poll must be unconditional", sent, s.Version())
	}
}

func TestManifestStoreFirstRefreshReportsEveryEntryAdded(t *testing.T) {
	calls := 0
	var refreshes []ManifestRefreshInfo
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		calls++
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	s.onRefresh = func(i ManifestRefreshInfo) { refreshes = append(refreshes, i) }

	if s.Get() != nil || isClosed(s.Ready()) {
		t.Fatalf("a fresh store holds nothing and is not ready")
	}
	m, err := s.Refresh(context.Background(), "start", true)
	if err != nil || m == nil || calls != 1 {
		t.Fatalf("Refresh = (%v, %v) calls=%d, want one fetch", m, err, calls)
	}
	if s.Version() != "v:a" || len(s.Get().Routes) != 1 {
		t.Fatalf("store = %q %+v, want the fetched manifest", s.Version(), s.Get())
	}
	if len(refreshes) != 1 || refreshes[0].Reason != "start" || len(refreshes[0].Added) != 1 || refreshes[0].Added[0].Slug != "a" || len(refreshes[0].Removed) != 0 {
		t.Fatalf("onRefresh = %+v, want every entry reported as added", refreshes)
	}
	if !isClosed(s.Ready()) {
		t.Fatalf("Ready must close after the first attempt")
	}
	if d := timers.lastDelay(); d != 60*time.Second {
		t.Fatalf("next poll = %v, want the manifest TTL", d)
	}
}

func TestManifestStoreStartPollsAndReportsOnlyTheDiff(t *testing.T) {
	var mu sync.Mutex
	routes := []InterceptManifestRoute{storeEntry("a.example", "a", "/")}
	version := "v:a"
	var refreshes []ManifestRefreshInfo
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		mu.Lock()
		defer mu.Unlock()
		return manifestOf(version, routes...), nil
	})
	s.onRefresh = func(i ManifestRefreshInfo) {
		mu.Lock()
		refreshes = append(refreshes, i)
		mu.Unlock()
	}

	s.Start(context.Background())
	s.Start(context.Background()) // idempotent
	<-s.Ready()
	eventually(t, func() bool { return timers.count() == 1 }, "the first poll to be scheduled")

	mu.Lock()
	routes = []InterceptManifestRoute{storeEntry("b.example", "b", "/")}
	version = "v:b"
	mu.Unlock()
	timers.fireLast()

	mu.Lock()
	defer mu.Unlock()
	if len(refreshes) != 2 {
		t.Fatalf("refreshes = %d, want start + poll", len(refreshes))
	}
	last := refreshes[1]
	if last.Reason != "poll" || len(last.Added) != 1 || last.Added[0].Slug != "b" || len(last.Removed) != 1 || last.Removed[0].Slug != "a" {
		t.Fatalf("poll diff = %+v, want +b -a", last)
	}
	if timers.count() != 2 {
		t.Fatalf("polls scheduled = %d, want the loop to continue", timers.count())
	}
}

func TestManifestStoreUnchangedVersionFiresNoHook(t *testing.T) {
	hooks := 0
	s, _, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	s.onRefresh = func(ManifestRefreshInfo) { hooks++ }
	_, _ = s.Refresh(context.Background(), "start", true)
	_, _ = s.Refresh(context.Background(), "poll", true)
	if hooks != 1 {
		t.Fatalf("hooks = %d, want 1 (same version = nothing changed)", hooks)
	}
}

func TestManifestStoreFaultKeepsLastGoodManifestAndBacksOff(t *testing.T) {
	fail := false
	var errs []error
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		if fail {
			return nil, &ConnectionError{Err: errors.New("read: connection reset")}
		}
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	s.onError = func(err error) { errs = append(errs, err) }
	_, _ = s.Refresh(context.Background(), "start", true)

	fail = true
	m, err := s.Refresh(context.Background(), "poll", true)
	if err == nil || m == nil || len(m.Routes) != 1 {
		t.Fatalf("a failed refresh returns the error AND keeps the last good manifest: (%v, %v)", m, err)
	}
	if len(errs) != 1 || s.LastError() == nil {
		t.Fatalf("onError = %v, LastError = %v, want the fault reported once", errs, s.LastError())
	}
	// One transient failure keeps the TTL; from the second the delay doubles, capped at 8×TTL.
	want := []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second, 480 * time.Second, 480 * time.Second}
	if d := timers.lastDelay(); d != want[0] {
		t.Fatalf("after 1 failure next poll = %v, want %v", d, want[0])
	}
	for i := 1; i < len(want); i++ {
		_, _ = s.Refresh(context.Background(), "poll", true)
		if d := timers.lastDelay(); d != want[i] {
			t.Fatalf("after %d failures next poll = %v, want %v", i+1, d, want[i])
		}
	}
	if len(s.Get().Routes) != 1 {
		t.Fatalf("the last good manifest survives every failure")
	}

	fail = false
	_, _ = s.Refresh(context.Background(), "poll", true)
	if d := timers.lastDelay(); d != 60*time.Second || s.LastError() != nil {
		t.Fatalf("a success resets the backoff: delay %v, err %v", d, s.LastError())
	}
}

func TestManifestStorePermissionRefusalIsNoManifestWarnsOnceRechecksSlowly(t *testing.T) {
	buf := captureWarnings(t)
	denied := true
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		if denied {
			return nil, &PermissionDeniedError{APIError{StatusCode: 403, Message: "insufficient_scope"}}
		}
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	_, err := s.Refresh(context.Background(), "start", true)
	if err == nil || s.Get() != nil || !s.PermissionDenied() {
		t.Fatalf("a 403 is 'no manifest': err=%v manifest=%v denied=%v", err, s.Get(), s.PermissionDenied())
	}
	if d := timers.lastDelay(); d != 600*time.Second {
		t.Fatalf("re-check after a refusal = %v, want 10×TTL", d)
	}
	_, _ = s.Refresh(context.Background(), "poll", true) // a second refusal
	if n := strings.Count(buf.String(), "routes:read"); n != 1 {
		t.Fatalf("warned %d times, want exactly once:\n%s", n, buf.String())
	}

	denied = false
	_, _ = s.Refresh(context.Background(), "poll", true)
	if s.PermissionDenied() || s.Get() == nil || len(s.Get().Routes) != 1 {
		t.Fatalf("a later success clears the refusal: denied=%v manifest=%v", s.PermissionDenied(), s.Get())
	}
}

func TestManifestStoreNotFoundFromAnOlderServerIsAlsoNoManifest(t *testing.T) {
	captureWarnings(t)
	s, _, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		return nil, &NotFoundError{APIError{StatusCode: 404}}
	})
	_, _ = s.Refresh(context.Background(), "start", true)
	if !s.PermissionDenied() || s.Get() != nil {
		t.Fatalf("a 404 (server predates the manifest) behaves as no manifest")
	}
}

func TestManifestStoreRefreshIsSingleFlight(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	entered := make(chan struct{})
	gate := make(chan struct{})
	s, _, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		close(entered)
		<-gate
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})

	var wg sync.WaitGroup
	results := make([]*InterceptManifest, 2)
	wg.Add(1)
	go func() { defer wg.Done(); results[0], _ = s.Refresh(context.Background(), "a", true) }()
	<-entered // the first caller is inside fetch, so the second must join it
	wg.Add(1)
	go func() { defer wg.Done(); results[1], _ = s.Refresh(context.Background(), "b", true) }()
	// Spawned is not waiting: release the gate only once the second caller has
	// actually joined the in-flight refresh, or it could arrive after the first
	// completed and start a fetch of its own.
	eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.joined == 1
	}, "the second caller to join the in-flight refresh")
	close(gate)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("fetches = %d, want 1 shared by both callers", calls)
	}
	if results[0] == nil || results[1] == nil || results[0].Version != results[1].Version {
		t.Fatalf("both callers take the shared answer: %+v %+v", results[0], results[1])
	}
}

func TestManifestStoreOutOfCycleRefreshIsRateLimitedAndForceBypasses(t *testing.T) {
	calls := 0
	s, clock, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		calls++
		return manifestOf("v:a"), nil
	})
	_, _ = s.Refresh(context.Background(), "start", true)
	_, _ = s.Refresh(context.Background(), "hint", false) // inside the 5 s gap
	if calls != 1 {
		t.Fatalf("calls = %d, want the hint inside the gap to cost nothing", calls)
	}
	clock.advance(6 * time.Second)
	_, _ = s.Refresh(context.Background(), "hint", false)
	if calls != 2 {
		t.Fatalf("calls = %d, want the hint after the gap to fetch", calls)
	}
	_, _ = s.Refresh(context.Background(), "manual", true)
	if calls != 3 {
		t.Fatalf("calls = %d, want force to bypass the gap", calls)
	}
}

func TestManifestStoreHintRefreshesInTheBackground(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s, _, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return manifestOf("v:a"), nil
	})
	s.minGap = 0
	_, _ = s.Refresh(context.Background(), "start", true)
	s.Hint()
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return calls == 2
	}, "the hint to refresh")
}

func TestManifestStoreStopDropsTheManifestAndRefusesToRefresh(t *testing.T) {
	calls := 0
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		calls++
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	_, _ = s.Refresh(context.Background(), "start", true)
	s.Stop()
	if s.Get() != nil || s.Version() != "" {
		t.Fatalf("Stop drops the manifest")
	}
	if timers.cancels() != 1 {
		t.Fatalf("Stop cancels the armed poll: cancels = %d", timers.cancels())
	}
	if m, err := s.Refresh(context.Background(), "manual", true); m != nil || err != nil || calls != 1 {
		t.Fatalf("a stopped store never fetches: (%v, %v) calls=%d", m, err, calls)
	}
	if !isClosed(s.Ready()) {
		t.Fatalf("Stop releases Ready")
	}
}

func TestManifestStoreFirstFailureNeverPanicsAndReleasesReady(t *testing.T) {
	s, _, _ := testStore(func(context.Context, string) (*InterceptManifest, error) {
		return nil, errors.New("boom")
	})
	m, err := s.Refresh(context.Background(), "start", true)
	if m != nil || err == nil || s.LastError() == nil {
		t.Fatalf("(%v, %v)", m, err)
	}
	if !isClosed(s.Ready()) {
		t.Fatalf("Ready closes on failure too")
	}
}

func TestManifestStorePollContextEndStopsPollingButKeepsTheManifest(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	s, _, timers := testStore(func(context.Context, string) (*InterceptManifest, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return manifestOf("v:a", storeEntry("a.example", "a", "/")), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	<-s.Ready()
	eventually(t, func() bool { return timers.count() == 1 }, "the first poll")
	cancel()
	eventually(t, func() bool { return timers.cancels() == 1 }, "the poll to be cancelled")

	if s.Get() == nil {
		t.Fatalf("the manifest is kept when the poll context ends")
	}
	// An explicit refresh still works, and arms no further poll.
	if _, err := s.Refresh(context.Background(), "manual", true); err != nil {
		t.Fatalf("Refresh after the poll ended: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 || timers.count() != 1 {
		t.Fatalf("calls=%d polls=%d, want a fetch and no new poll", calls, timers.count())
	}
}
