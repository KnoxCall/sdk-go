package knoxcall

// Route-aware interception — the Go seam
// (docs/internal/sdk-wrapping/route-aware-interception-plan.md §2–§3, PARITY
// §21.1; founder decisions D2–D4 and D7 of 2026-09-25).
//
// Two forms share one pipeline:
//
//   - Wrap.RoundTripper(WithRoutes(), …) — the explicit transport. Hand it to
//     any SDK that accepts an *http.Client. Every request the wrapped SDK makes
//     is one the caller chose to send through KnoxCall, so a host with no Route
//     goes through the ephemeral proxy exactly as before; a host the intercept
//     manifest covers goes through that Route instead.
//   - Wrap.Intercept(ctx, …) — the process-wide form. It swaps
//     http.DefaultTransport for a route-aware RoundTripper wrapping the previous
//     one (idiomatic Go: otelhttp / oauth2.Transport do the same; nothing is
//     monkeypatched), so http.DefaultClient and every &http.Client{} with a nil
//     Transport — most SDK defaults — are reached. Only hosts a Route covers, or
//     hosts the caller lists, are touched (D2); everything else goes to the
//     previous transport untouched. Stop() restores it.
//
// Per request, first match wins (intercept_resolver.go, pinned by the shared
// fixtures): KNOXCALL_INTERCEPT=off → direct · unparseable → direct · the
// client's own hosts and any knoxcall.com host → direct · route-around rule →
// direct · WithRequireContext outside Routed(ctx) → direct · a manifest entry
// covering host + path → ROUTE (the Route injects the stored secret; no
// provider credential travels) · a listed host → EPHEMERAL · otherwise direct.
//
// Unavailability (D4): route mode and escrow fail CLOSED — the credential is
// only in KnoxCall, there is nothing to go direct with. Transit may opt into
// going direct (WithUnavailableDirect / HostUnavailableDirect), because the key
// is in the process there.
//
// Route mode is the custody path — the key never enters your process. The
// process-wide form is a convenience, not a security boundary: it is a
// process global, it does not reach a client built with its own Transport, and
// it composes with APM transports in install order.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ── options ──────────────────────────────────────────────────────────────────

// hostConfig is the per-host configuration WithHost accumulates.
type hostConfig struct {
	credential        *escrowCredential
	unavailableDirect bool
}

// HostOption configures one host listed with WithHost.
type HostOption func(*hostConfig)

// HostEscrow selects escrow mode for this host's EPHEMERAL traffic: the named
// escrowed credential (WrapResource.Escrow) is resolved server-side; the
// wrapped SDK's own key is an ignored placeholder. Omit for transit mode. An
// empty secret is a WrapConfigError (fail-closed), never a fall-through to transit.
func HostEscrow(secret string, scheme ...string) HostOption {
	return func(h *hostConfig) {
		h.credential = &escrowCredential{secret: secret}
		if len(scheme) > 0 {
			h.credential.scheme = scheme[0]
		}
	}
}

// HostUnavailableDirect opts this host's TRANSIT traffic out of fail-closed:
// when KnoxCall is unreachable the original request is sent untouched via the
// base transport and WithOnFallback fires. Escrow and route mode never go
// direct — there is no credential to go direct with (D4).
func HostUnavailableDirect() HostOption {
	return func(h *hostConfig) { h.unavailableDirect = true }
}

// WithRoutes turns route discovery on for an explicit RoundTripper: the
// intercept manifest (GET /v1/wrap/intercept-manifest, the client's
// Environment) is polled at its TTL and a request whose host + path an
// intercept-enabled Route covers goes through that Route. Off by default on
// RoundTripper — an explicit transport keeps its ephemeral-only behaviour
// unless asked; ON by default on Intercept.
func WithRoutes() WrapOption {
	return func(c *wrapConfig) { v := true; c.routes = &v }
}

// WithoutRoutes turns route discovery off (the static, ephemeral-only form of
// Intercept: only listed hosts, always through the ephemeral proxy).
func WithoutRoutes() WrapOption {
	return func(c *wrapConfig) { v := false; c.routes = &v }
}

// WithHosts lists bare DNS hostnames to cover even when NO Route does — they go
// through the ephemeral proxy in transit mode. Hosts a Route covers are added
// from the manifest automatically, so Intercept needs no list at all. Never
// widened to "all egress" (D2). A non-bare host is a WrapConfigError.
func WithHosts(hosts ...string) WrapOption {
	return func(c *wrapConfig) {
		for _, h := range hosts {
			c.host(h)
		}
	}
}

// WithHost lists one host with per-host options (HostEscrow, HostUnavailableDirect).
func WithHost(host string, opts ...HostOption) WrapOption {
	return func(c *wrapConfig) {
		hc := c.host(host)
		for _, o := range opts {
			o(hc)
		}
	}
}

// WithUnavailableDirect opts EVERY transit host out of fail-closed (see
// HostUnavailableDirect). Route mode and escrow are unaffected.
func WithUnavailableDirect() WrapOption {
	return func(c *wrapConfig) { c.unavailableDirect = true }
}

// WithRequireContext limits interception to requests whose context descends
// from Wrap.Routed(ctx): you mark the CALL SITE, not the SDK. Off by default.
func WithRequireContext() WrapOption {
	return func(c *wrapConfig) { c.requireContext = true }
}

// RerouteInfo is passed to WithOnReroute before a request is sent through
// KnoxCall (route or ephemeral mode).
type RerouteInfo struct {
	Host   string
	URL    string
	Mode   InterceptMode
	Slug   string // route mode only
	Reason InterceptReason
}

// UnmatchedPathInfo is passed to WithOnUnmatchedPath — once per host + first
// path segment — when a host HAS intercept routes but none covers this path,
// so a misconfigured base path is visible rather than silent.
type UnmatchedPathInfo struct {
	Host string
	URL  string
}

// RefusedInfo is passed to WithOnRefused when a route-mode request came back
// as a KnoxCall refusal and the manifest was refreshed once. Redecided is the
// mode the request was resent in, or "" when the refresh changed nothing (the
// refusal is returned as-is).
type RefusedInfo struct {
	Host      string
	URL       string
	Slug      string
	Status    int
	Redecided InterceptMode
}

// FallbackInfo is passed to WithOnFallback when KnoxCall was unreachable and a
// transit request was sent direct under an unavailable-direct opt-in.
type FallbackInfo struct {
	Host string
	URL  string
	Err  error
}

// PromotedInfo is passed to WithOnPromoted when an ephemeral response carried
// X-Knox-Promoted-Route: a Route now covers this host (the manifest is refreshed).
type PromotedInfo struct {
	Host string
	Slug string
}

// WithOnReroute registers an observability hook fired before a request is sent
// through KnoxCall, with the mode and reason the decision table chose.
func WithOnReroute(fn func(RerouteInfo)) WrapOption {
	return func(c *wrapConfig) { c.onReroute = fn }
}

// WithOnRefresh fires after every manifest refresh whose entries changed.
func WithOnRefresh(fn func(ManifestRefreshInfo)) WrapOption {
	return func(c *wrapConfig) { c.onRefresh = fn }
}

// WithOnManifestError fires when a manifest refresh failed (the last good
// manifest is kept).
func WithOnManifestError(fn func(error)) WrapOption {
	return func(c *wrapConfig) { c.onManifestError = fn }
}

// WithOnUnmatchedPath fires once per host + first path segment when the host
// has intercept routes but none covers the path (the request went ephemeral).
func WithOnUnmatchedPath(fn func(UnmatchedPathInfo)) WrapOption {
	return func(c *wrapConfig) { c.onUnmatchedPath = fn }
}

// WithOnRefused fires when a route-mode request was refused by KnoxCall and the
// manifest was refreshed once in response.
func WithOnRefused(fn func(RefusedInfo)) WrapOption {
	return func(c *wrapConfig) { c.onRefused = fn }
}

// WithOnFallback fires when a transit request went direct because KnoxCall was
// unreachable (only under WithUnavailableDirect / HostUnavailableDirect).
func WithOnFallback(fn func(FallbackInfo)) WrapOption {
	return func(c *wrapConfig) { c.onFallback = fn }
}

// WithOnPromoted fires when an ephemeral response says a Route now covers the host.
func WithOnPromoted(fn func(PromotedInfo)) WrapOption {
	return func(c *wrapConfig) { c.onPromoted = fn }
}

// ── the route-aware RoundTripper ─────────────────────────────────────────────

// WrapRoundTripper is the http.RoundTripper WrapResource.RoundTripper returns
// and Intercept installs. Safe for concurrent use. Beyond RoundTrip it exposes
// the route-aware controls: Ready / Wait (the first manifest attempt settled),
// Refresh, Manifest and Stop.
type WrapRoundTripper struct {
	c       *Client
	cfg     wrapConfig
	rules   []RouteAroundRule
	initErr error // set when misconfigured; every RoundTrip fails closed

	// allHosts is the explicit-transport form: every request is "listed".
	allHosts bool
	hosts    map[string]struct{}
	hostCfg  map[string]*hostConfig
	store    *manifestStore // nil when route discovery is off
	ready    <-chan struct{}
	// observer reports uncovered egress (PARITY §21.3); nil when reporting is off.
	observer *egressObserver

	unmatched sync.Map // host + first path segment → warned
}

func (r *WrapResource) newRoundTripper(opts []WrapOption, allHosts, routesDefault bool) *WrapRoundTripper {
	cfg := wrapConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.base == nil {
		cfg.base = http.DefaultTransport
	}
	rt := &WrapRoundTripper{
		c:        r.c,
		cfg:      cfg,
		allHosts: allHosts,
		hosts:    map[string]struct{}{},
		hostCfg:  map[string]*hostConfig{},
	}

	// Escrow-vs-transit is decided by the credential presence; a WithEscrow("")
	// must NOT silently fall through to transit and leak the SDK's raw key.
	if cfg.credential != nil && cfg.credential.secret == "" {
		rt.initErr = &WrapConfigError{Message: "knoxcall: WithEscrow requires a non-empty secret name; " +
			"omit WithEscrow entirely for transit mode"}
	}
	for h, hc := range cfg.hosts {
		if err := assertInterceptHost(h); err != nil && rt.initErr == nil {
			rt.initErr = err
		}
		if hc.credential != nil && hc.credential.secret == "" && rt.initErr == nil {
			rt.initErr = &WrapConfigError{Message: fmt.Sprintf("knoxcall: WithHost(%q, HostEscrow(...)) requires a non-empty secret name; "+
				"omit HostEscrow entirely for transit mode", h)}
		}
		n := normalizeHost(h)
		rt.hosts[n] = struct{}{}
		rt.hostCfg[n] = hc
	}

	// Merge default + caller route-around rules, and validate the caller's
	// hosts up front so a non-bare host fails loud instead of never matching.
	if !cfg.disableDefaultRA {
		rt.rules = append(rt.rules, DefaultRouteAround...)
	}
	rt.rules = append(rt.rules, cfg.routeAround...)
	if err := assertRouteAroundRules(cfg.routeAround); err != nil && rt.initErr == nil {
		rt.initErr = err
	}

	routes := routesDefault
	if cfg.routes != nil {
		routes = *cfg.routes
	}
	if routes {
		rt.store = newManifestStore(rt.fetchManifest)
		rt.store.onError = cfg.onManifestError
		rt.store.onRefresh = rt.onRefresh
		rt.ready = rt.store.Ready()
	} else {
		ch := make(chan struct{})
		close(ch)
		rt.ready = ch
	}

	// Uncovered-egress observations (PARITY §21.3). ON by default (founder
	// decision 2026-09-26) for the process-wide form and for an explicit
	// RoundTripper WithRoutes; WithObserveUncovered(false) or the environment
	// turns it off. An explicit transport treats every host as listed, so
	// `unlisted` never occurs there by construction — the observer exists so
	// the contract (and the opt-out) reads the same in every form. The report
	// rides the SDK's own credential through the request pipeline inside the
	// suppressed context, so it is never itself intercepted.
	observe := !allHosts || routes
	if cfg.observeUncovered != nil {
		observe = *cfg.observeUncovered
	}
	if observe && !observeUncoveredDisabledByEnv() {
		rt.observer = newEgressObserver(func(ctx context.Context, obs []EgressObservation) (*EgressObservationsReport, error) {
			return r.c.Wrap.ReportEgressObservations(ctx, obs)
		}, cfg.onObservationFlush)
	}
	return rt
}

// start arms the manifest store (no-op without one, or when misconfigured).
func (t *WrapRoundTripper) start(ctx context.Context) {
	if t.store != nil && t.initErr == nil {
		t.store.Start(ctx)
	}
}

// RoundTripper returns a *WrapRoundTripper (an http.RoundTripper) that routes a
// wrapped SDK's requests through KnoxCall. Hand it to any SDK that accepts an
// *http.Client:
//
//	hc := &http.Client{Transport: client.Wrap.RoundTripper(knoxcall.WithRoutes())}
//
// Without WithRoutes (the default) this is the ephemeral proxy in transparent
// mode for every request, exactly as before route discovery existed. Transit
// mode (the default): the wrapped SDK's own Authorization header is lifted
// out-of-band and delivered to the upstream by the server — it never transits
// as a raw header and is never logged; the key's Test/Live prefix is asserted
// to match the client's Sandbox flag. Escrow mode (WithEscrow(secret)): the raw
// key stays in KnoxCall custody and only the escrowed name travels. Requests
// matching a route-around rule (raw-card endpoints by default), the client's
// own hosts and — with KNOXCALL_INTERCEPT=off — everything are sent to the
// provider directly, untouched.
//
// With WithRoutes: the intercept manifest is polled and a request whose host +
// path an intercept-enabled Route covers goes through that Route (the path
// rebased under the Route's base path, query kept; the Route injects the stored
// secret). Wait on Ready() before the first request if the first decision must
// already see the manifest.
//
// The returned RoundTripper is safe for concurrent use. A misconfiguration
// (empty escrow secret, non-bare route-around or listed host) fails closed:
// every RoundTrip returns a *WrapConfigError rather than silently degrading.
func (r *WrapResource) RoundTripper(opts ...WrapOption) *WrapRoundTripper {
	rt := r.newRoundTripper(opts, true, false)
	rt.start(context.Background())
	return rt
}

// Ready is closed once the first manifest attempt settled (immediately when
// route discovery is off). It never signals an error.
func (t *WrapRoundTripper) Ready() <-chan struct{} { return t.ready }

// Wait blocks until Ready or ctx is done.
func (t *WrapRoundTripper) Wait(ctx context.Context) error {
	select {
	case <-t.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refresh fetches the manifest now (a no-op without route discovery).
func (t *WrapRoundTripper) Refresh(ctx context.Context) error {
	if t.store == nil {
		return nil
	}
	_, err := t.store.Refresh(ctx, "manual", true)
	return err
}

// Manifest is the manifest this transport is deciding on, or nil.
func (t *WrapRoundTripper) Manifest() *InterceptManifest {
	if t.store == nil {
		return nil
	}
	return t.store.Get()
}

// Stop ends polling and drops the manifest; the transport keeps working, on
// the ephemeral path for listed hosts and direct otherwise. Pending
// uncovered-egress observations are flushed once more (bounded by a short
// timeout; never an error).
func (t *WrapRoundTripper) Stop() {
	if t.store != nil {
		t.store.Stop()
	}
	if t.observer != nil {
		t.observer.stop()
	}
}

// fetchManifest is the store's fetch: the client's environment, and the held
// version as If-None-Match (a 304 comes back as nil, nil — PARITY §21.1).
func (t *WrapRoundTripper) fetchManifest(ctx context.Context, ifNoneMatch string) (*InterceptManifest, error) {
	return t.c.Wrap.InterceptManifest(ctx, InterceptManifestOptions{Environment: t.c.opts.Environment, IfNoneMatch: ifNoneMatch})
}

// onRefresh warns once per entry that will be refused or is ambiguous, then
// forwards to the caller's hook.
func (t *WrapRoundTripper) onRefresh(info ManifestRefreshInfo) {
	for _, e := range info.Added {
		if e.RequiresClients {
			warnOnce("KNOXCALL_INTERCEPT_REQUIRES_CLIENTS:"+e.Slug, fmt.Sprintf(
				"KnoxCall route %q (%s%s) requires a registered client; a bearer-only SDK call will be refused (403). "+
					"Register this process as a client of the route, or leave the route out of interception.", e.Slug, e.Host, e.BasePath))
		}
		if e.Ambiguous {
			warnOnce("KNOXCALL_INTERCEPT_AMBIGUOUS:"+e.Host+e.BasePath, fmt.Sprintf(
				"KnoxCall: more than one intercept-enabled route covers %s%s; the lexically lowest slug is used. Disable the others.", e.Host, e.BasePath))
		}
	}
	if t.cfg.onRefresh != nil {
		t.cfg.onRefresh(info)
	}
}

// ownHosts: the client's management and data-plane hosts, never intercepted.
func (t *WrapRoundTripper) ownHosts() map[string]struct{} {
	out := map[string]struct{}{}
	add := func(raw string) {
		if raw == "" {
			return
		}
		if u, err := url.Parse(raw); err == nil {
			if h := normalizeHost(u.Hostname()); h != "" {
				out[h] = struct{}{}
			}
		}
	}
	add(t.c.baseURL)
	t.c.mu.Lock()
	proxy := t.c.proxyBaseURL
	t.c.mu.Unlock()
	add(proxy)
	return out
}

func (t *WrapRoundTripper) decide(req *http.Request) InterceptDecision {
	var m *InterceptManifest
	if t.store != nil {
		m = t.store.Get()
	}
	return resolveIntercept(interceptInput{
		url:            req.URL.String(),
		method:         req.Method,
		hosts:          t.hosts,
		allHosts:       t.allHosts,
		manifest:       m,
		ownHosts:       t.ownHosts(),
		routeAround:    t.rules,
		killSwitch:     interceptKillSwitch(),
		requireContext: t.cfg.requireContext,
		inContext:      inRoutedContext(req.Context()),
	})
}

// RoundTrip applies the decision table to req and sends it: untouched via the
// base transport (direct), through the covering Route (route), or through the
// ephemeral proxy in transparent mode (ephemeral). It honours req.Context()
// for cancellation/timeout and forwards the method, body bytes and headers
// (minus Authorization, Host, Content-Length) verbatim.
func (t *WrapRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.initErr != nil {
		return nil, t.initErr
	}
	// The SDK's OWN traffic (the uncovered-egress report) goes straight to the
	// base transport: never intercepted, never observed.
	if inSuppressedContext(req.Context()) {
		return t.cfg.base.RoundTrip(req)
	}

	decision := t.decide(req)
	if decision.Mode == InterceptDirect {
		// Decided BEFORE the body is read — the ORIGINAL request is forwarded
		// untouched (body/stream intact), never "try KnoxCall then fall back"
		// (which would already have transited the credential).
		if decision.Reason == ReasonRouteAround && t.cfg.onRouteAround != nil {
			t.cfg.onRouteAround(RouteAroundInfo{URL: req.URL.String(), Host: req.URL.Hostname(), Reason: decision.RouteAroundReason})
		}
		// Uncovered egress (PARITY §21.3): observed AFTER the decision, BEFORE
		// the direct send, only for `unlisted`, and never into this request.
		if decision.Reason == ReasonUnlisted && t.observer != nil {
			t.observer.observe(req)
		}
		return t.cfg.base.RoundTrip(req)
	}

	// Transparent forwarding: read the exact request bytes so the wrapped SDK's
	// own encoding (form-urlencoded, protobuf, …) survives. A RoundTripper owns
	// consuming and closing req.Body. Holding the bytes also makes a resend
	// after a routing refusal replayable by construction.
	body, err := readBody(req)
	if err != nil {
		return nil, err
	}

	if decision.Mode == InterceptRoute {
		return t.sendRouteWithRefresh(req, body, decision)
	}

	// Ephemeral.
	if decision.Reason == ReasonNoBasePathMatch {
		key := decision.Host + " " + firstSegment(req.URL.Path)
		if _, warned := t.unmatched.LoadOrStore(key, struct{}{}); !warned && t.cfg.onUnmatchedPath != nil {
			t.cfg.onUnmatchedPath(UnmatchedPathInfo{Host: decision.Host, URL: req.URL.String()})
		}
	}
	t.reroute(RerouteInfo{Host: decision.Host, URL: req.URL.String(), Mode: InterceptEphemeral, Reason: decision.Reason})
	return t.sendEphemeral(req, body, decision.Host)
}

func (t *WrapRoundTripper) reroute(info RerouteInfo) {
	if t.cfg.onReroute != nil {
		t.cfg.onReroute(info)
	}
}

// sendRoute sends through the existing Call pipeline (x-knoxcall-route, the
// client's environment, retry + one re-mint inherited) — never a second proxy
// implementation. path carries the rebased path plus the query verbatim.
func (t *WrapRoundTripper) sendRoute(ctx context.Context, slug, path string, req *http.Request, body []byte) (*http.Response, error) {
	// Every route-mode reroute is marked (PARITY §21.2): this is a third-party
	// SDK's call the pipeline redirected, which is what the API Log's
	// "SDK intercept" origin means.
	opts := &CallOptions{Method: req.Method, Path: path, Headers: forwardableHeaders(req.Header), interceptOrigin: true}
	if len(body) > 0 {
		opts.Body = body
	}
	return t.c.Call(ctx, slug, opts)
}

// sendRouteWithRefresh: a KnoxCall-origin 401 in route mode, after Call's own
// re-mint, means either the credential is refused or the manifest is stale
// (PARITY §21 — route-resolution refusals are 401 on purpose). ONE forced
// refresh tells them apart; re-decide ONCE; resend only when the decision
// changed (a routing refusal is answered before any upstream contact, so the
// body is safe to replay). Never loop.
func (t *WrapRoundTripper) sendRouteWithRefresh(req *http.Request, body []byte, decision InterceptDecision) (*http.Response, error) {
	t.reroute(RerouteInfo{Host: decision.Host, URL: req.URL.String(), Mode: InterceptRoute, Slug: decision.Slug, Reason: decision.Reason})
	res, err := t.sendRoute(req.Context(), decision.Slug, decision.Path, req, body)
	if err != nil || t.store == nil || !isRouteRefusal(res) {
		return res, err
	}
	_, _ = t.store.Refresh(req.Context(), "route_refused", true)
	again := t.decide(req)
	changed := again.Mode != InterceptRoute || again.Slug != decision.Slug || again.Path != decision.Path
	if t.cfg.onRefused != nil {
		info := RefusedInfo{Host: decision.Host, URL: req.URL.String(), Slug: decision.Slug, Status: res.StatusCode}
		if changed {
			info.Redecided = again.Mode
		}
		t.cfg.onRefused(info)
	}
	if !changed {
		return res, nil
	}
	drainAndClose(res)
	switch again.Mode {
	case InterceptRoute:
		t.reroute(RerouteInfo{Host: again.Host, URL: req.URL.String(), Mode: InterceptRoute, Slug: again.Slug, Reason: again.Reason})
		return t.sendRoute(req.Context(), again.Slug, again.Path, req, body)
	case InterceptEphemeral:
		t.reroute(RerouteInfo{Host: again.Host, URL: req.URL.String(), Mode: InterceptEphemeral, Reason: again.Reason})
		return t.sendEphemeral(req, body, again.Host)
	default:
		return t.cfg.base.RoundTrip(withBody(req, body))
	}
}

// sendEphemeral is today's transparent path: transit lifts the SDK's own
// Authorization out-of-band; escrow (transport-wide or per host) sends the
// credential NAME; both-must-agree on the Stripe key's Test/Live prefix.
func (t *WrapRoundTripper) sendEphemeral(req *http.Request, body []byte, host string) (*http.Response, error) {
	hc := t.hostCfg[host]
	credential := t.cfg.credential
	if hc != nil && hc.credential != nil {
		credential = hc.credential
	}

	opts := &EphemeralOptions{
		Method:  req.Method,
		Headers: forwardableHeaders(req.Header),
		Mode:    "transparent",
	}
	if len(body) > 0 {
		// Content-Type is forwarded verbatim when the SDK set one. NOTE: a body
		// with NO Content-Type inherits the shared client's application/json
		// default (Client.encodeBody) — consistent with every other body-bearing
		// call in this SDK, and moot for real SDKs (they always set one on a
		// body). This is the one spot the Go transport differs from node
		// wrap-transport review item #5.
		opts.Body = body
	}

	if credential != nil {
		// Escrow mode — send the secret reference, never the raw key. No
		// Test/Live assertion: the SDK's own key is an ignored placeholder.
		opts.UpstreamAuthSecret = credential.secret
		if credential.scheme != "" {
			opts.UpstreamAuthScheme = credential.scheme
		}
	} else {
		// Transit mode — lift the SDK's own Authorization header out-of-band.
		auth := req.Header.Get("Authorization")
		if err := assertKeyMatchesSandbox(auth, t.c.opts.Sandbox); err != nil {
			return nil, err
		}
		if auth != "" {
			opts.UpstreamAuthorization = auth
		}
	}

	// Ephemeral builds its own request to <base>/v1/proxy with the SDK's own
	// KnoxCall credential and returns the upstream response verbatim; the
	// request context carries cancellation/timeout through unchanged.
	res, err := t.c.Ephemeral(req.Context(), req.URL.String(), opts)
	if err != nil {
		// D4: fail closed by default. Going direct is honoured only for TRANSIT
		// traffic — the key is in the process there. Escrow has nothing to go
		// direct with.
		direct := t.cfg.unavailableDirect || (hc != nil && hc.unavailableDirect)
		var ce *ConnectionError
		if direct && credential == nil && errors.As(err, &ce) {
			if t.cfg.onFallback != nil {
				t.cfg.onFallback(FallbackInfo{Host: host, URL: req.URL.String(), Err: err})
			}
			return t.cfg.base.RoundTrip(withBody(req, body))
		}
		return nil, err
	}

	// Promoted-route hint: a Route now covers this host. The hint is a signal
	// to refresh the manifest — the manifest is the truth.
	if slug := res.Header.Get("X-Knox-Promoted-Route"); slug != "" && host != "" {
		if t.cfg.onPromoted != nil {
			t.cfg.onPromoted(PromotedInfo{Host: host, Slug: slug})
		}
		if t.store != nil {
			t.store.Hint()
		}
	}
	return res, nil
}

// isRouteRefusal is the route-mode REFUSAL predicate (PARITY §21.1,
// "Refusal-driven refresh"; the cross-language contract is
// sdk/fixtures/route-refusal.json).
//
// A KnoxCall-origin refusal on the route data plane is the one response the
// interceptor answers by refreshing its manifest ONCE and re-deciding ONCE:
//
//   - a 401 with no upstream stamp — the credential was refused, or the caller
//     is not authenticated for the route it named. Call has already spent its
//     one re-mint by the time we see this.
//   - a 404 whose envelope error.type is route_not_found — since the founder's
//     2026-09-26 decision an AUTHENTICATED key gets a real 404 for a route that
//     does not resolve, and a stale manifest naming a Route deleted since the
//     poll is exactly this. The environment_* types are refused as-is: a
//     refresh cannot fix an environment.
//
// Any response carrying X-Knox-Upstream-Status (the route data plane's response
// block) or X-Knox-Destination-Status (the ephemeral proxy's older spelling) is
// the UPSTREAM's answer, whatever its status or body, and never a refusal.
//
// The 404 branch reads the body and puts it back, so the caller's response is
// returned intact whichever way the decision goes.
func isRouteRefusal(res *http.Response) bool {
	if res.Header.Get("X-Knox-Upstream-Status") != "" || res.Header.Get("X-Knox-Destination-Status") != "" {
		return false
	}
	if res.StatusCode == http.StatusUnauthorized {
		return true
	}
	if res.StatusCode != http.StatusNotFound {
		return false
	}
	return routeRefusalType(res) == "route_not_found"
}

// routeRefusalType is the envelope's error.type on a 404 — "" for anything that
// is not the Shape-A envelope {"error":{"type","message","request_id"}}. The
// body is restored on res so the caller can still read it.
func routeRefusalType(res *http.Response) string {
	if res.Body == nil {
		return ""
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	res.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	var envelope struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	// A flat `"error": "…"` string, a non-object body or non-JSON all fail to
	// unmarshal into the envelope shape, which is the answer: not a refusal.
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	return envelope.Error.Type
}

// readBody consumes and closes req.Body (a RoundTripper's obligation) and
// returns the bytes; nil when there was no body.
func readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	b, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, err
	}
	return b, nil
}

// withBody clones req with its (already consumed) body restored from bytes, so
// it can be sent through the base transport after KnoxCall has been tried.
func withBody(req *http.Request, body []byte) *http.Request {
	r := req.Clone(req.Context())
	if body == nil {
		r.Body = nil
		r.ContentLength = 0
		r.GetBody = nil
		return r
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return r
}

func drainAndClose(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
}

// firstSegment is "/x" for "/x/y/z" — the granularity of the unmatched-path hook.
func firstSegment(path string) string {
	p := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return "/" + p
}

// assertInterceptHost rejects a listed host that is not a bare DNS hostname (a
// scheme/port/path slipped in) — it could never match a parsed request host and
// would silently disable the listing, so fail loud instead.
func assertInterceptHost(host string) error {
	h := strings.TrimSpace(host)
	parsed := ""
	if u, err := url.Parse("https://" + h); err == nil {
		parsed = u.Hostname()
	}
	if h == "" || normalizeHost(parsed) != normalizeHost(h) {
		return &WrapConfigError{Message: fmt.Sprintf(
			"knoxcall: invalid intercept host %q: expected a bare DNS hostname (no scheme, port, or path)", host)}
	}
	return nil
}

// ── the process-wide form ────────────────────────────────────────────────────

// ErrInterceptInstalled is returned by Intercept when a handle is already
// installed in this process; Stop it first.
var ErrInterceptInstalled = errors.New("knoxcall: Intercept is already installed in this process; Stop() the existing handle first")

var (
	interceptMu        sync.Mutex
	interceptInstalled *InterceptHandle
)

// InterceptHandle is what Intercept returns: the route-aware controls plus Stop.
type InterceptHandle struct {
	rt   *WrapRoundTripper
	prev http.RoundTripper
	once sync.Once
}

// Intercept swaps http.DefaultTransport for a route-aware RoundTripper that
// wraps the previous one, so an untouched third-party SDK on http.DefaultClient
// (or any *http.Client with a nil Transport) has its calls sent through the
// Route that covers them, through the ephemeral proxy for hosts listed with
// WithHosts/WithHost, and to the previous transport untouched otherwise.
// Route discovery is ON unless WithoutRoutes is given. ctx bounds the manifest
// polling (the manifest is kept when it ends); Stop restores the previous
// transport.
//
//	stop, err := client.Wrap.Intercept(ctx, knoxcall.WithHosts("api.resend.com"))
//	if err != nil { … }
//	defer stop.Stop()
//	<-stop.Ready()            // first manifest loaded
//	hubspot.Crm.Contacts.GetPage(…)   // an untouched SDK, via the Route that covers api.hubapi.com
//
// One handle per process: a second Intercept returns ErrInterceptInstalled. A
// misconfiguration (non-bare host, empty escrow secret) is returned here, at
// install, rather than surfacing on every request. WithBaseTransport sets
// where direct traffic goes (default: the transport being replaced).
func (r *WrapResource) Intercept(ctx context.Context, opts ...WrapOption) (*InterceptHandle, error) {
	interceptMu.Lock()
	defer interceptMu.Unlock()
	if interceptInstalled != nil {
		return nil, ErrInterceptInstalled
	}
	prev := http.DefaultTransport
	rt := r.newRoundTripper(opts, false, true)
	if rt.initErr != nil {
		return nil, rt.initErr
	}
	h := &InterceptHandle{rt: rt, prev: prev}
	http.DefaultTransport = rt
	interceptInstalled = h
	rt.start(ctx)
	return h, nil
}

// Routed marks ctx as a routed scope. With WithRequireContext, only requests
// whose context descends from a Routed context are intercepted — you mark the
// CALL SITE, not the SDK. Without WithRequireContext it changes nothing.
func (r *WrapResource) Routed(ctx context.Context) context.Context {
	return context.WithValue(ctx, routedKey{}, true)
}

type routedKey struct{}

func inRoutedContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(routedKey{}).(bool)
	return v
}

// Stop restores the previous http.DefaultTransport and drops the manifest.
// Idempotent. If something else replaced http.DefaultTransport after
// Intercept, it is left in place (never clobber a later installer) and a
// one-time warning is written.
func (h *InterceptHandle) Stop() {
	h.once.Do(func() {
		interceptMu.Lock()
		defer interceptMu.Unlock()
		if http.DefaultTransport == http.RoundTripper(h.rt) {
			http.DefaultTransport = h.prev
		} else {
			warnOnce("KNOXCALL_INTERCEPT_NOT_RESTORED",
				"another RoundTripper replaced http.DefaultTransport after Wrap.Intercept(); Stop() left it in place")
		}
		if interceptInstalled == h {
			interceptInstalled = nil
		}
		h.rt.Stop()
	})
}

// Transport is the installed RoundTripper (for hooks such as Wait / Refresh).
func (h *InterceptHandle) Transport() *WrapRoundTripper { return h.rt }

// Ready is closed once the first manifest attempt settled.
func (h *InterceptHandle) Ready() <-chan struct{} { return h.rt.Ready() }

// Wait blocks until Ready or ctx is done.
func (h *InterceptHandle) Wait(ctx context.Context) error { return h.rt.Wait(ctx) }

// Refresh fetches the manifest now.
func (h *InterceptHandle) Refresh(ctx context.Context) error { return h.rt.Refresh(ctx) }

// Manifest is the manifest the interceptor is deciding on, or nil.
func (h *InterceptHandle) Manifest() *InterceptManifest { return h.rt.Manifest() }
