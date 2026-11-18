package knoxcall

// Uncovered-egress observations (PARITY §21.3; founder decisions 2026-09-26).
// Go mirror of sdk/knoxcall-node/src/egress-observations.ts.
//
// A route-aware RoundTripper sees every outbound request the process makes
// and sends only the covered ones through KnoxCall. The rest go direct — and
// among them are calls that carry a credential the platform does not hold:
// "uncovered egress". This file records those (host, first path segment,
// method, credential header NAME) in memory and reports the aggregate to
// POST /v1/wrap/egress-observations (WrapResource.ReportEgressObservations),
// so the dashboard can show a tenant which credentials are still leaving
// their process un-custodied.
//
// What is recorded is bounded on purpose, and the bound is the feature:
//   - names, never values — the credential header's NAME, never its value;
//   - the FIRST path segment only — never the query string, never the body,
//     never a deeper path;
//   - counts per (host, segment, method, header) with first/last seen.
//
// Only a DIRECT decision with reason `unlisted` is observed. own_host,
// route_around, kill_switch, outside_context and unparseable never are.
//
// Nothing here may add latency to, throw into, or alter the application's
// request: record is synchronous and cheap, the flush runs on a time.AfterFunc
// (which never keeps a process alive) or a goroutine, and every failure is
// swallowed after one warning. The observer is process memory only.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// CredentialHeaderAllowlist is the exact (case-insensitive) set of header
// names that carry a credential. The shared fixture
// sdk/fixtures/egress-observation.json pins it.
var CredentialHeaderAllowlist = []string{
	"authorization",
	"proxy-authorization",
	"x-api-key",
	"api-key",
	"apikey",
	"x-apikey",
	"x-auth-token",
	"x-access-token",
	"x-token",
	"token",
	"x-secret",
	"x-secret-key",
	"x-client-secret",
	"ocp-apim-subscription-key",
	"x-goog-api-key",
	"x-amz-security-token",
	"x-shopify-access-token",
	"klaviyo-api-key",
	"x-hubspot-api-key",
}

// CredentialHeaderSuffixes: a lower-cased header name ending in one of these
// also counts.
var CredentialHeaderSuffixes = []string{"-api-key", "-token", "-secret", "-auth"}

// ObservationMethods are the methods the server accepts (upper-case); any
// other would be dropped as invalid_method, so it is never recorded.
var ObservationMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"}

// The server's shape checks (src/wrap/egress-observations.ts).
var (
	headerNameRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	firstSegmentRE   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%-]{0,255}$`)
	maxHeaderNameLen = 64
)

var credentialHeaderRank = func() map[string]int {
	m := make(map[string]int, len(CredentialHeaderAllowlist))
	for i, n := range CredentialHeaderAllowlist {
		m[n] = i
	}
	return m
}()

// IsCredentialHeaderName reports whether a header NAME (any casing) is
// credential-bearing.
func IsCredentialHeaderName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || len(n) > maxHeaderNameLen || !headerNameRE.MatchString(n) {
		return false
	}
	if _, ok := credentialHeaderRank[n]; ok {
		return true
	}
	for _, s := range CredentialHeaderSuffixes {
		if len(n) > len(s) && strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// CredentialHeaderName is the credential header NAME to report for a request,
// or "" when none is present. Allowlist entries win in allowlist order; then
// the lexicographically smallest suffix match. A header whose value is empty
// after trimming never counts. Only names are read — values are looked at
// solely to discard empties and are never returned.
func CredentialHeaderName(h http.Header) string {
	best, bestRank, bestSuffix := "", len(CredentialHeaderAllowlist)+1, ""
	for rawName, values := range h {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		nonEmpty := false
		for _, v := range values {
			if strings.TrimSpace(v) != "" {
				nonEmpty = true
				break
			}
		}
		if !nonEmpty {
			continue
		}
		if rank, ok := credentialHeaderRank[name]; ok {
			if rank < bestRank {
				bestRank, best = rank, name
			}
			continue
		}
		if IsCredentialHeaderName(name) && (bestSuffix == "" || name < bestSuffix) {
			bestSuffix = name
		}
	}
	if best != "" {
		return best
	}
	return bestSuffix
}

// A credential in the first path segment (server #1022). Some APIs put one in
// the path (Telegram's /bot<id>:<secret>/...). The server stores such a
// segment as "/"; the SDK applies the SAME rule before sending, so the value
// never leaves the process.

// MaxPlainFirstSegmentLength: longer than this and a segment is not a resource name.
const MaxPlainFirstSegmentLength = 64

var (
	credentialSegmentPrefixes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^bot\d+:`),
		regexp.MustCompile(`(?i)^(sk|pk|rk)_(live|test)_`),
		regexp.MustCompile(`^sk-`),
		regexp.MustCompile(`^xox[abposr]-`),
		regexp.MustCompile(`^gh[pousr]_`),
		regexp.MustCompile(`^github_pat_`),
		regexp.MustCompile(`^glpat-`),
		regexp.MustCompile(`^shp(at|ca|pa|ss)_`),
		regexp.MustCompile(`^(AKIA|ASIA)[0-9A-Z]{12,}`),
		regexp.MustCompile(`^AIza[0-9A-Za-z_-]{20,}`),
		regexp.MustCompile(`^eyJ[A-Za-z0-9_-]{8,}`),
		regexp.MustCompile(`^SG\.`),
	}
	highEntropyRunRE = regexp.MustCompile(`[A-Za-z0-9_-]{24,}`)
	lowerRE          = regexp.MustCompile(`[a-z]`)
	upperRE          = regexp.MustCompile(`[A-Z]`)
	digitRE          = regexp.MustCompile(`[0-9]`)
)

// FirstSegmentLooksLikeCredential reports whether a first segment ("/" + one
// segment) looks like it carries a credential — the server's rule, applied to
// the raw and the percent-decoded form.
func FirstSegmentLooksLikeCredential(firstSegment string) bool {
	raw := strings.TrimPrefix(firstSegment, "/")
	if raw == "" {
		return false
	}
	forms := []string{raw}
	if decoded, err := url.PathUnescape(raw); err == nil && decoded != raw {
		forms = append(forms, decoded)
	}
	for _, s := range forms {
		if len(s) > MaxPlainFirstSegmentLength {
			return true
		}
		for _, re := range credentialSegmentPrefixes {
			if re.MatchString(s) {
				return true
			}
		}
		for _, run := range highEntropyRunRE.FindAllString(s, -1) {
			n := 0
			for _, re := range []*regexp.Regexp{lowerRE, upperRE, digitRE} {
				if re.MatchString(run) {
					n++
				}
			}
			if n >= 2 {
				return true
			}
		}
	}
	return false
}

// observationFirstSegment is "/" or "/<first path segment>" of the URL's
// escaped path — never the query, never deeper. Exactly one leading slash is
// consumed, so "//double" reports "/".
func observationFirstSegment(u *url.URL) string {
	if u == nil {
		return "/"
	}
	p := u.EscapedPath()
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return "/" + p
}

// observationKey identifies one aggregated observation.
type observationKey struct {
	host, segment, method, header string
}

// observationFor is the whole classifier, pure: the identifying tuple for this
// request, or false when it carries no credential-bearing header. The caller
// has ALREADY decided the request is direct + unlisted.
func observationFor(req *http.Request) (observationKey, bool) {
	if req == nil || req.URL == nil {
		return observationKey{}, false
	}
	host := normalizeHost(req.URL.Hostname())
	// An IP literal is never a Route target; the server drops it (ip_literal).
	if host == "" || net.ParseIP(host) != nil {
		return observationKey{}, false
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	if !slices.Contains(ObservationMethods, method) {
		return observationKey{}, false
	}
	segment := observationFirstSegment(req.URL)
	if FirstSegmentLooksLikeCredential(segment) {
		segment = "/" // reported as "/"; the entry is kept
	}
	if !firstSegmentRE.MatchString(segment) {
		return observationKey{}, false
	}
	name := CredentialHeaderName(req.Header)
	if name == "" {
		return observationKey{}, false
	}
	return observationKey{host: host, segment: segment, method: method, header: name}, true
}

// observeUncoveredDisabledByEnv: KNOXCALL_OBSERVE_UNCOVERED=off|false|0 turns
// the reporter off (read when a transport is built).
func observeUncoveredDisabledByEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KNOXCALL_OBSERVE_UNCOVERED"))) {
	case "off", "0", "false":
		return true
	}
	return false
}

// ObservationFlushInfo is passed to WithOnObservationFlush after each accepted
// observation report — never per observation.
type ObservationFlushInfo struct {
	Accepted int
	Dropped  int
}

// WithObserveUncovered turns uncovered-egress reporting (PARITY §21.3) on or
// off for this transport. It is ON by default for Intercept and for a
// RoundTripper built WithRoutes: calls sent DIRECT because their host was
// `unlisted` (no Route covers it, nobody listed it) while carrying a
// credential-bearing header are counted — host, first path segment, method
// and the header NAME, never its value; never the query string; never the
// body — and posted to POST /v1/wrap/egress-observations about once a
// minute. KNOXCALL_OBSERVE_UNCOVERED=off in the environment (read when the
// transport is built) also turns it off; nothing is reported while
// KNOXCALL_INTERCEPT=off. A 403 from the endpoint stops reporting for the
// life of the handle (warned once).
func WithObserveUncovered(on bool) WrapOption {
	return func(c *wrapConfig) { v := on; c.observeUncovered = &v }
}

// WithOnObservationFlush registers a hook fired after each accepted
// uncovered-egress report with the server's counts.
func WithOnObservationFlush(fn func(ObservationFlushInfo)) WrapOption {
	return func(c *wrapConfig) { c.onObservationFlush = fn }
}

// suppressedKey marks a context as the SDK's OWN traffic (the observation
// report): a route-aware RoundTripper sends such a request straight to its
// base transport, so the report is never itself intercepted or observed.
type suppressedKey struct{}

func withSuppressed(ctx context.Context) context.Context {
	return context.WithValue(ctx, suppressedKey{}, true)
}

func inSuppressedContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(suppressedKey{}).(bool)
	return v
}

const (
	defaultObservationFlushInterval = 60 * time.Second
	defaultObservationFlushAtKeys   = 200
	defaultObservationMaxKeys       = 1000
	defaultObservationMaxPerRequest = 200
	defaultObservationFlushTimeout  = 10 * time.Second
)

type observationEntry struct {
	key         observationKey
	count       int
	first, last time.Time
}

// egressObserver aggregates uncovered-egress observations for ONE transport /
// handle and flushes them in the background. Safe for concurrent use;
// bounded; never panics into a caller.
type egressObserver struct {
	report       func(ctx context.Context, obs []EgressObservation) (*EgressObservationsReport, error)
	onFlush      func(ObservationFlushInfo)
	interval     time.Duration
	flushAt      int
	maxKeys      int
	maxPer       int
	flushTimeout time.Duration
	now          func() time.Time
	rand         func() float64

	mu             sync.Mutex
	entries        map[observationKey]*observationEntry
	order          []observationKey
	timer          *time.Timer
	flushing       bool
	stopped        bool
	forbidden      bool
	warnedOverflow bool
	warnedFailed   bool
	inflight       sync.WaitGroup
}

func newEgressObserver(
	report func(ctx context.Context, obs []EgressObservation) (*EgressObservationsReport, error),
	onFlush func(ObservationFlushInfo),
) *egressObserver {
	return &egressObserver{
		report:       report,
		onFlush:      onFlush,
		interval:     defaultObservationFlushInterval,
		flushAt:      defaultObservationFlushAtKeys,
		maxKeys:      defaultObservationMaxKeys,
		maxPer:       defaultObservationMaxPerRequest,
		flushTimeout: defaultObservationFlushTimeout,
		now:          time.Now,
		rand:         rand.Float64,
		entries:      map[observationKey]*observationEntry{},
	}
}

// observe records req when — and only when — it carries a credential-bearing
// header. The RoundTripper calls it after a DIRECT + unlisted decision and
// before the direct send; it can never panic into that request.
func (o *egressObserver) observe(req *http.Request) {
	defer func() {
		// best-effort: telemetry must never reach the application's request.
		_ = recover()
	}()
	if k, ok := observationFor(req); ok {
		o.record(k)
	}
}

func (o *egressObserver) record(k observationKey) {
	o.mu.Lock()
	if o.stopped || o.forbidden {
		o.mu.Unlock()
		return
	}
	now := o.now()
	if e, ok := o.entries[k]; ok {
		e.count++
		e.last = now
		o.mu.Unlock()
		return
	}
	if len(o.entries) >= o.maxKeys {
		warn := !o.warnedOverflow
		o.warnedOverflow = true
		o.mu.Unlock()
		if warn {
			warnOnce("KNOXCALL_EGRESS_OBSERVATIONS_OVERFLOW", fmt.Sprintf(
				"more than %d distinct uncovered-egress observations are pending; new ones are dropped until the next flush", o.maxKeys))
		}
		return
	}
	o.entries[k] = &observationEntry{key: k, count: 1, first: now, last: now}
	o.order = append(o.order, k)
	flushNow := len(o.entries) >= o.flushAt
	if !flushNow && o.timer == nil {
		jitter := 1 + (o.rand()*0.2 - 0.1) // ±10 %
		o.timer = time.AfterFunc(time.Duration(float64(o.interval)*jitter), o.timerFired)
	}
	o.mu.Unlock()
	if flushNow {
		o.flushAsync()
	}
}

func (o *egressObserver) timerFired() {
	o.mu.Lock()
	o.timer = nil
	o.mu.Unlock()
	o.flush(context.Background())
}

func (o *egressObserver) flushAsync() {
	o.inflight.Add(1)
	go func() {
		defer o.inflight.Done()
		o.flush(context.Background())
	}()
}

// size is the number of distinct keys currently held.
func (o *egressObserver) size() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

// pending is what would be sent now (a copy, in first-seen order).
func (o *egressObserver) pending() []EgressObservation {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]EgressObservation, 0, len(o.order))
	for _, k := range o.order {
		if e, ok := o.entries[k]; ok {
			out = append(out, toWireObservation(e))
		}
	}
	return out
}

func (o *egressObserver) drainLocked() []EgressObservation {
	batch := make([]EgressObservation, 0, len(o.order))
	for _, k := range o.order {
		if e, ok := o.entries[k]; ok {
			batch = append(batch, toWireObservation(e))
		}
	}
	o.entries = map[observationKey]*observationEntry{}
	o.order = nil
	return batch
}

// flush sends what is pending now, in chunks of at most maxPer, inside the
// SDK's own suppressed context. A concurrent flush returns immediately. Never
// returns an error: a 403 ends reporting for good (warned once); any other
// failure drops the batch (warned once) and is never retried in a loop.
func (o *egressObserver) flush(ctx context.Context) {
	o.mu.Lock()
	if o.flushing || o.forbidden || len(o.entries) == 0 {
		o.mu.Unlock()
		return
	}
	o.flushing = true
	if o.timer != nil {
		o.timer.Stop()
		o.timer = nil
	}
	batch := o.drainLocked()
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.flushing = false
		o.mu.Unlock()
	}()

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(withSuppressed(ctx), o.flushTimeout)
	defer cancel()
	for i := 0; i < len(batch); i += o.maxPer {
		chunk := batch[i:min(i+o.maxPer, len(batch))]
		res, err := o.report(ctx, chunk)
		if err != nil {
			var pd *PermissionDeniedError
			if errors.As(err, &pd) {
				// The key lacks routes:read: reporting is off for good. Anything
				// recorded from here on is dropped at the door.
				o.mu.Lock()
				o.forbidden = true
				o.entries = map[observationKey]*observationEntry{}
				o.order = nil
				o.mu.Unlock()
				warnOnce("KNOXCALL_EGRESS_OBSERVATIONS_FORBIDDEN",
					"the credential cannot report uncovered-egress observations (HTTP 403 — it lacks routes:read); "+
						"reporting is off for this interceptor. Grant the scope, or pass WithObserveUncovered(false) to silence this")
				return
			}
			// best-effort: the batch is dropped, never retried in a loop, never
			// surfaced into the application's own request.
			o.mu.Lock()
			warn := !o.warnedFailed
			o.warnedFailed = true
			o.mu.Unlock()
			if warn {
				warnOnce("KNOXCALL_EGRESS_OBSERVATIONS_FAILED",
					fmt.Sprintf("reporting uncovered-egress observations failed (%v); the batch was dropped", err))
			}
			return
		}
		if o.onFlush != nil && res != nil {
			func() {
				defer func() { _ = recover() }() // a caller's hook must never break the reporter
				o.onFlush(ObservationFlushInfo{Accepted: res.Accepted, Dropped: res.Dropped})
			}()
		}
	}
}

// stop ends the timer, waits for any background flush, and flushes once more
// (synchronously, bounded by flushTimeout). Idempotent.
func (o *egressObserver) stop() {
	o.mu.Lock()
	if o.stopped {
		o.mu.Unlock()
		return
	}
	o.stopped = true
	if o.timer != nil {
		o.timer.Stop()
		o.timer = nil
	}
	o.mu.Unlock()
	o.inflight.Wait()
	o.flush(context.Background())
}

func toWireObservation(e *observationEntry) EgressObservation {
	return EgressObservation{
		Host:         e.key.host,
		FirstSegment: e.key.segment,
		Method:       e.key.method,
		HeaderName:   e.key.header,
		Count:        e.count,
		FirstSeen:    isoUTC(e.first),
		LastSeen:     isoUTC(e.last),
	}
}

func isoUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
