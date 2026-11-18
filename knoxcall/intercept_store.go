package knoxcall

// The SDK-side copy of the intercept manifest — fetched, held, refreshed
// (route-aware-interception-plan.md §2.5; PARITY §21.1). One per route-aware
// RoundTripper; process memory only; dropped on Stop.
//
//   - polls at the manifest's ttl_seconds (±10% jitter) on a time.AfterFunc
//     timer, single-flight — never more than one refresh in flight;
//   - keeps the last GOOD manifest when a refresh fails (stale-but-valid, the
//     same posture the token cache takes) and backs off exponentially from the
//     second consecutive failure (cap 8×TTL);
//   - a 401/403/404 from the manifest endpoint — the credential lacks
//     routes:read, or an older server — is NOT a routing failure: the store
//     warns once, behaves as "no manifest" (so every listed host stays on the
//     ephemeral path exactly as before this feature), and re-checks at 10×TTL;
//   - out-of-cycle refreshes (a route-mode refusal, a promoted-route hint, an
//     explicit Refresh) are rate-limited so a burst costs one management call.
//
// Discovery failing open is deliberate and bounded: it can only leave a host on
// the path it was on before the manifest existed. The DATA-PLANE hop is where
// fail-closed lives (D4), and that is in intercept.go.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	defaultManifestTTL              = 60 * time.Second
	defaultManifestRefreshGap       = 5 * time.Second
	manifestMaxBackoffFactor        = 8
	manifestPermissionRecheckFactor = 10
)

// ManifestRefreshInfo is passed to WithOnRefresh after every refresh whose
// entries changed: which hosts became route-covered and which stopped being.
type ManifestRefreshInfo struct {
	// Reason: "start", "poll", "route_refused", "promoted_hint" or "manual".
	Reason  string
	Version string
	Added   []InterceptManifestRoute
	Removed []InterceptManifestRoute
}

// manifestEntryKey identifies one manifest entry across versions.
type manifestEntryKey struct{ host, basePath, slug string }

func keyOf(e InterceptManifestRoute) manifestEntryKey {
	return manifestEntryKey{host: e.Host, basePath: e.BasePath, slug: e.Slug}
}

// manifestStore holds the manifest and decides when it is stale. Safe for
// concurrent use.
type manifestStore struct {
	// fetch performs GET /v1/wrap/intercept-manifest. ifNoneMatch is the
	// version the store holds ("" on the first poll): send it as
	// `If-None-Match: W/"<version>"` and return (nil, nil) on the server's 304
	// — the store then keeps its manifest, re-arms at one TTL and fires no
	// onRefresh (PARITY §21.1 "Conditional poll").
	fetch     func(ctx context.Context, ifNoneMatch string) (*InterceptManifest, error)
	onRefresh func(ManifestRefreshInfo)
	onError   func(error)
	minGap    time.Duration
	// Test seams: the clock, the jitter source in [0,1), the timer factory.
	now      func() time.Time
	random   func() float64
	schedule func(d time.Duration, fn func()) (cancel func())

	mu               sync.Mutex
	started          bool
	stopped          bool
	manifest         *InterceptManifest
	version          string
	inflight         chan struct{} // non-nil while a fetch is running; closed when it settles
	cancelTimer      func()
	failures         int
	joined           int // callers that waited on an in-flight refresh (test seam)
	permissionDenied bool
	lastRefreshAt    time.Time
	lastErr          error
	pollCtx          context.Context

	ready     chan struct{}
	readyOnce sync.Once
}

func newManifestStore(fetch func(ctx context.Context, ifNoneMatch string) (*InterceptManifest, error)) *manifestStore {
	s := &manifestStore{
		fetch:   fetch,
		minGap:  defaultManifestRefreshGap,
		now:     time.Now,
		random:  rand.Float64,
		pollCtx: context.Background(),
		ready:   make(chan struct{}),
	}
	s.schedule = func(d time.Duration, fn func()) func() {
		t := time.AfterFunc(d, fn)
		return func() { t.Stop() }
	}
	return s
}

// Ready is closed after the FIRST refresh attempt settles — success or failure
// — or on Stop. It never signals an error; read LastError for that.
func (s *manifestStore) Ready() <-chan struct{} { return s.ready }

func (s *manifestStore) markReady() { s.readyOnce.Do(func() { close(s.ready) }) }

// Get returns the last good manifest, or nil before the first success / after
// a permission refusal / after Stop.
func (s *manifestStore) Get() *InterceptManifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.manifest
}

func (s *manifestStore) Version() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// PermissionDenied is true once the manifest endpoint refused the credential
// (warned once; re-checked slowly).
func (s *manifestStore) PermissionDenied() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.permissionDenied
}

func (s *manifestStore) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Start kicks off the first refresh and the poll loop. Idempotent. ctx bounds
// the BACKGROUND polling only: when it is done no further poll is scheduled
// and the last manifest is kept; explicit refreshes still work, and Stop is
// what drops the store.
func (s *manifestStore) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.pollCtx = ctx
	s.mu.Unlock()
	go func() { _, _ = s.Refresh(ctx, "start", true) }()
	if done := ctx.Done(); done != nil {
		go func() {
			<-done
			s.mu.Lock()
			if s.cancelTimer != nil {
				s.cancelTimer()
				s.cancelTimer = nil
			}
			s.mu.Unlock()
		}()
	}
}

// Stop cancels polling and drops the manifest. The store cannot be restarted.
func (s *manifestStore) Stop() {
	s.mu.Lock()
	s.stopped = true
	if s.cancelTimer != nil {
		s.cancelTimer()
		s.cancelTimer = nil
	}
	s.manifest = nil
	s.version = ""
	s.mu.Unlock()
	s.markReady()
}

// Hint: a promoted-route hint arrived on an ephemeral response — refresh in the
// background, rate-limited (the hint is a signal; the manifest is the truth).
func (s *manifestStore) Hint() {
	s.mu.Lock()
	ctx := s.pollCtx
	s.mu.Unlock()
	go func() { _, _ = s.Refresh(ctx, "promoted_hint", false) }()
}

// Refresh fetches now. Single-flight: concurrent callers share one fetch and
// its outcome. Rate-limited unless force: an out-of-cycle refresh inside minGap
// of the last one returns the current manifest without a call. Returns the
// manifest the store holds afterwards (nil after a permission refusal) and the
// fetch error, if any — the store has already applied stale-keep / backoff.
func (s *manifestStore) Refresh(ctx context.Context, reason string, force bool) (*InterceptManifest, error) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil, nil
	}
	if ch := s.inflight; ch != nil {
		s.joined++
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return s.Get(), ctx.Err()
		}
		s.mu.Lock()
		m, err := s.manifest, s.lastErr
		s.mu.Unlock()
		return m, err
	}
	if !force && s.now().Sub(s.lastRefreshAt) < s.minGap {
		m := s.manifest
		s.mu.Unlock()
		return m, nil
	}
	ch := make(chan struct{})
	s.inflight = ch
	s.lastRefreshAt = s.now()
	// Every poll after the first is conditional on the held version; the
	// server answers 304 (→ nil, nil) when nothing changed, and that is a
	// success: keep the manifest, re-arm at one TTL, fire no hook.
	held := s.version
	s.mu.Unlock()

	next, err := s.fetch(ctx, held)

	s.mu.Lock()
	var info *ManifestRefreshInfo
	var delay time.Duration
	shutdown := s.pollCtx.Err() != nil && errors.Is(err, context.Canceled)
	switch {
	case s.stopped:
		// Dropped while fetching: discard the answer.
	case shutdown:
		// The poll context ended mid-fetch: not a failure, nothing to schedule.
	case err != nil:
		s.lastErr = err
		status := 0
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			status = apiErr.StatusCode
		}
		if status == 401 || status == 403 || status == 404 {
			// Not a routing failure: the credential cannot read routes, or the
			// server predates the manifest. Every listed host stays ephemeral,
			// as it was before this feature existed. Warn once, re-check slowly.
			s.permissionDenied = true
			s.manifest = nil
			s.version = ""
			warnOnce("KNOXCALL_INTERCEPT_MANIFEST_UNAVAILABLE", fmt.Sprintf(
				"KnoxCall intercept manifest unavailable (HTTP %d): route-aware interception is off for this client — "+
					"listed hosts use the ephemeral proxy. Grant the credential `routes:read` (or upgrade the server) to enable it.", status))
			delay = defaultManifestTTL * manifestPermissionRecheckFactor
		} else {
			// Transport or server fault: keep the last good manifest, back off
			// from the second consecutive failure.
			s.failures = min(s.failures+1, 30)
			factor := min(1<<(s.failures-1), manifestMaxBackoffFactor)
			base := ttlOf(s.manifest)
			delay = min(base*time.Duration(factor), base*manifestMaxBackoffFactor)
		}
	default:
		prev := s.manifest
		s.failures = 0
		s.permissionDenied = false
		s.lastErr = nil
		if next == nil {
			// Not modified: the held manifest stands for another TTL.
			delay = ttlOf(prev)
			break
		}
		if prev == nil || prev.Version != next.Version {
			before := map[manifestEntryKey]struct{}{}
			if prev != nil {
				for _, e := range prev.Routes {
					before[keyOf(e)] = struct{}{}
				}
			}
			after := map[manifestEntryKey]struct{}{}
			for _, e := range next.Routes {
				after[keyOf(e)] = struct{}{}
			}
			var added, removed []InterceptManifestRoute
			for _, e := range next.Routes {
				if _, ok := before[keyOf(e)]; !ok {
					added = append(added, e)
				}
			}
			if prev != nil {
				for _, e := range prev.Routes {
					if _, ok := after[keyOf(e)]; !ok {
						removed = append(removed, e)
					}
				}
			}
			s.manifest = next
			s.version = next.Version
			if len(added) > 0 || len(removed) > 0 || prev == nil {
				info = &ManifestRefreshInfo{Reason: reason, Version: next.Version, Added: added, Removed: removed}
			}
		}
		delay = ttlOf(next)
	}
	if !s.stopped && !shutdown && delay > 0 {
		s.scheduleLocked(delay)
	}
	m := s.manifest
	s.inflight = nil
	close(ch)
	s.mu.Unlock()

	// Hooks run outside the lock: one that calls back into the store must not deadlock.
	if err != nil && !shutdown && s.onError != nil {
		s.onError(err)
	}
	if info != nil && s.onRefresh != nil {
		s.onRefresh(*info)
	}
	// Ready is signalled only AFTER the first attempt's hooks have run. Signalling
	// before them let a caller that returned from Wait() read state the hooks were
	// still producing on this goroutine — the -race report on 2026-09-25 was the
	// once-per-code warnings landing in a test's buffer while the test read it.
	// A hook that calls Refresh is unaffected (Refresh never waits on ready).
	s.markReady()
	return m, err
}

// scheduleLocked arms the next poll at base ±10% (never under a second). The
// caller holds s.mu. A done poll context arms nothing.
func (s *manifestStore) scheduleLocked(base time.Duration) {
	if s.cancelTimer != nil {
		s.cancelTimer()
		s.cancelTimer = nil
	}
	if s.pollCtx.Err() != nil {
		return
	}
	jitter := 1 + (s.random()*0.2 - 0.1)
	d := time.Duration(float64(base) * jitter)
	if d < time.Second {
		d = time.Second
	}
	ctx := s.pollCtx
	s.cancelTimer = s.schedule(d, func() { _, _ = s.Refresh(ctx, "poll", true) })
}

func ttlOf(m *InterceptManifest) time.Duration {
	if m == nil || m.TTLSeconds <= 0 {
		return defaultManifestTTL
	}
	return time.Duration(m.TTLSeconds) * time.Second
}
