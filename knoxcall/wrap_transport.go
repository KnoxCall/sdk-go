package knoxcall

// Wrap transport — the Go analog of the Node SDK's wrap.fetch()
// (sdk-wrapping plan PR4; see sdk/knoxcall-node/src/wrap-transport.ts and
// resources/wrap.ts fetch()).
//
// A wrapped third-party SDK (Stripe first) keeps its own serialization,
// retries, idempotency keys and error types; only its HTTP transport is
// swapped for one that re-targets each request through KnoxCall's ephemeral
// proxy in transparent mode. In Go the universal seam is http.RoundTripper —
// virtually every official SDK accepts &http.Client{Transport: rt} (Stripe's
// stripe.NewBackends, OpenAI's option.WithHTTPClient, Google's
// option.WithHTTPClient, …). So RoundTripper() returns an http.RoundTripper
// the caller hands to the wrapped SDK:
//
//	client, _ := knoxcall.New(knoxcall.Options{ /* … */ })
//	hc := &http.Client{Transport: client.Wrap.RoundTripper()}
//	sc := &stripe.Client{Backends: stripe.NewBackends(hc)}   // Stripe SDK, wrapped
//
// The provider credential the SDK sets on its Authorization header is LIFTED
// out-of-band (transit mode — delivered to the upstream by the server, never
// forwarded as a raw header, never logged), or — in escrow mode — replaced by
// a named escrowed credential the server resolves and host-pins. A request
// matching a route-around rule (raw-card endpoints by default) is sent to the
// provider DIRECTLY, untouched.
//
// This adapter is deliberately THIN: it turns *http.Request into a call to the
// existing Client.Ephemeral (transparent mode) — or, with WithRoutes, into a
// call to Client.Call through the Route the intercept manifest names — and
// returns the *http.Response straight back. All the proxy heavy-lifting lives
// server-side and in Ephemeral / Call; nothing is reimplemented here. The
// RoundTripper itself, the route-aware options and the process-wide
// Intercept() live in intercept.go; this file keeps the shared pieces
// (route-around rules, escrow config, header forwarding, the Test/Live check).

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// RouteAroundRule sends a matching request DIRECTLY to the provider (via the
// base transport), never through KnoxCall — the client-side half of the PCI
// posture (plan §3) and the escape hatch for un-proxyable calls (streaming,
// multipart, host-signed).
type RouteAroundRule struct {
	// Host is the exact upstream host this rule matches (a bare, lower-case
	// DNS hostname — no scheme, port, or path).
	Host string
	// PathPrefix, when set, narrows the rule to requests whose path starts
	// with it; empty routes the whole host around.
	PathPrefix string
	// Reason is a human explanation, surfaced to WithOnRouteAround and docs.
	Reason string
}

// RouteAroundInfo is passed to the WithOnRouteAround observability hook when a
// request is sent directly to the provider instead of through KnoxCall.
type RouteAroundInfo struct {
	URL    string
	Host   string
	Reason string
}

// DefaultRouteAround mirrors the SERVER's raw-PAN refusal
// (src/client-api/ephemeral-proxy.ts PAN_ENDPOINT_DENYLIST) so a wrapped SDK's
// raw-card call is sent straight to Stripe instead of hard-failing on the 403.
// Deliberately conservative and identical in spirit to the server list; the
// durable answer is tokenize-at-the-edge (plan §3). Disable with
// WithoutDefaultRouteAround; extend with WithRouteAround.
var DefaultRouteAround = []RouteAroundRule{
	{Host: "api.stripe.com", PathPrefix: "/v1/tokens", Reason: "raw-card endpoint (PCI): sent direct to the provider"},
	{Host: "api.stripe.com", PathPrefix: "/v1/sources", Reason: "raw-card endpoint (PCI): sent direct to the provider"},
}

// WrapSandboxMismatchError is returned by a wrap RoundTripper (in transit mode)
// when the wrapped SDK's provider key does not agree with the KnoxCall client's
// Sandbox flag — a Stripe TEST key wrapped by a LIVE client, or vice versa — or
// when a Stripe publishable key (pk_) is presented (it is not a server
// credential and cannot be wrapped). This is the Test/Live collision the
// sandbox invariant exists to prevent, enforced one level down at the wrap seam.
type WrapSandboxMismatchError struct{ Message string }

func (e *WrapSandboxMismatchError) Error() string { return e.Message }

// WrapConfigError is returned (on every RoundTrip, fail-closed) when the wrap
// RoundTripper was misconfigured: an escrow credential with an empty secret
// name (which must NOT silently fall through to transit mode and leak the SDK's
// raw key), or a route-around Host that is not a bare DNS hostname (which could
// never match and would silently disable the rule). Because RoundTripper()
// returns only an http.RoundTripper, the configuration error is surfaced on the
// first (every) RoundTrip rather than at construction — the request fails loud
// instead of quietly doing the wrong, less-safe thing.
type WrapConfigError struct{ Message string }

func (e *WrapConfigError) Error() string { return e.Message }

// escrowCredential is the internal representation of an escrowed wrap
// credential (see WithEscrow). Nil on the config means transit mode.
type escrowCredential struct {
	secret string
	scheme string
}

// wrapConfig accumulates WrapOption settings for one RoundTripper.
type wrapConfig struct {
	credential       *escrowCredential // nil => transit mode (lift the SDK's own Authorization)
	routeAround      []RouteAroundRule
	disableDefaultRA bool
	base             http.RoundTripper // transport for direct calls; nil => http.DefaultTransport
	onRouteAround    func(RouteAroundInfo)

	// Route-aware interception (intercept.go). routes is tri-state: nil takes
	// the form's default (off for RoundTripper, on for Intercept).
	routes            *bool
	hosts             map[string]*hostConfig
	unavailableDirect bool
	requireContext    bool
	onReroute         func(RerouteInfo)
	onRefresh         func(ManifestRefreshInfo)
	onManifestError   func(error)
	onUnmatchedPath   func(UnmatchedPathInfo)
	onRefused         func(RefusedInfo)
	onFallback        func(FallbackInfo)
	onPromoted        func(PromotedInfo)

	// Uncovered-egress observations (PARITY §21.3). observeUncovered is
	// tri-state: nil takes the form's default (on for Intercept and for a
	// RoundTripper WithRoutes).
	observeUncovered   *bool
	onObservationFlush func(ObservationFlushInfo)
}

// host returns the per-host config for host, creating it on first mention.
func (c *wrapConfig) host(host string) *hostConfig {
	if c.hosts == nil {
		c.hosts = map[string]*hostConfig{}
	}
	hc, ok := c.hosts[host]
	if !ok {
		hc = &hostConfig{}
		c.hosts[host] = hc
	}
	return hc
}

// WrapOption configures a wrap RoundTripper. Options compose in the order given.
type WrapOption func(*wrapConfig)

// WithEscrow selects ESCROW mode: instead of lifting the wrapped SDK's own
// Authorization header, send the NAME of a previously escrowed wrap credential
// (from WrapResource.Escrow). KnoxCall resolves and injects the real key
// server-side, host-pinned, so the raw provider key never travels and the
// SDK's own key becomes an ignored placeholder. An optional scheme overrides
// the server default ("Bearer"); pass "none" to send the resolved value raw.
//
// secret must be non-empty; an empty secret is a WrapConfigError (fail-closed)
// rather than a silent fall-through to transit mode.
func WithEscrow(secret string, scheme ...string) WrapOption {
	return func(c *wrapConfig) {
		cred := &escrowCredential{secret: secret}
		if len(scheme) > 0 {
			cred.scheme = scheme[0]
		}
		c.credential = cred
	}
}

// WithRouteAround adds route-around rules, merged after the built-in defaults
// (unless WithoutDefaultRouteAround is also given). A matching request is sent
// to the provider directly, untouched — never through KnoxCall.
func WithRouteAround(rules ...RouteAroundRule) WrapOption {
	return func(c *wrapConfig) { c.routeAround = append(c.routeAround, rules...) }
}

// WithoutDefaultRouteAround drops the built-in DefaultRouteAround rules, leaving
// only the rules supplied via WithRouteAround.
func WithoutDefaultRouteAround() WrapOption {
	return func(c *wrapConfig) { c.disableDefaultRA = true }
}

// WithBaseTransport sets the transport used for DIRECT calls: route-around
// matches, the client's own hosts, unlisted hosts under Intercept, the kill
// switch, and an unavailable-direct fallback. Defaults to http.DefaultTransport
// (under Intercept: the transport being replaced). This is the transport the
// wrapped SDK would have used had it not been wrapped — inject one here to
// keep its proxy / TLS / timeout settings for direct calls.
func WithBaseTransport(rt http.RoundTripper) WrapOption {
	return func(c *wrapConfig) { c.base = rt }
}

// WithOnRouteAround registers an observability hook fired (before dispatch)
// whenever a request is routed directly to the provider.
func WithOnRouteAround(fn func(RouteAroundInfo)) WrapOption {
	return func(c *wrapConfig) { c.onRouteAround = fn }
}

// dropForwarded are the request headers the shim must NOT forward to the
// upstream: Authorization is lifted out-of-band (transit) or replaced by the
// escrow reference; Host and Content-Length are recomputed by the ephemeral
// call. Matched case-insensitively.
var dropForwarded = map[string]bool{
	"authorization":  true,
	"host":           true,
	"content-length": true,
}

// forwardableHeaders copies every header the SDK set except the dropped ones,
// collapsing multi-value headers to a single comma-joined value (the shape
// EphemeralOptions.Headers accepts). Content-Type is preserved verbatim.
func forwardableHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		if dropForwarded[strings.ToLower(k)] || len(vals) == 0 {
			continue
		}
		out[k] = strings.Join(vals, ", ")
	}
	return out
}

// normalizeHost is PARITY §21's host contract: lower-case, surrounding
// whitespace and IPv6 brackets stripped, a single trailing dot stripped — so a
// trailing-dot host ("api.stripe.com.") can't dodge an exact-match rule. The
// server's PAN denylist and the intercept manifest normalize the same way,
// keeping the client decision and the server guarantee consistent.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.TrimSuffix(h, ".")
}

// matchRouteAround returns the first rule matching u, and whether one matched.
func matchRouteAround(u *url.URL, rules []RouteAroundRule) (RouteAroundRule, bool) {
	if u == nil {
		return RouteAroundRule{}, false
	}
	host := normalizeHost(u.Hostname())
	for _, r := range rules {
		if host != normalizeHost(r.Host) {
			continue
		}
		if r.PathPrefix != "" && !strings.HasPrefix(u.Path, r.PathPrefix) {
			continue
		}
		return r, true
	}
	return RouteAroundRule{}, false
}

// assertRouteAroundRules rejects a caller-supplied Host that is not a bare DNS
// hostname (a scheme/port/path slipped in) — it can never match a parsed
// request host and would silently disable the rule, so fail loud instead.
func assertRouteAroundRules(rules []RouteAroundRule) error {
	for _, r := range rules {
		h := strings.TrimSpace(r.Host)
		parsed := ""
		if u, err := url.Parse("https://" + h); err == nil {
			parsed = u.Hostname()
		}
		if h == "" || normalizeHost(parsed) != normalizeHost(h) {
			return &WrapConfigError{Message: fmt.Sprintf(
				"knoxcall: invalid routeAround host %q: expected a bare DNS hostname (no scheme, port, or path)", r.Host)}
		}
	}
	return nil
}

var (
	reWrapBearer      = regexp.MustCompile(`(?i)^Bearer\s+`)
	reWrapPublishable = regexp.MustCompile(`^pk_(test|live)_`)
	reWrapSecretKey   = regexp.MustCompile(`^(?:sk|rk)_(test|live)_`)
)

// assertKeyMatchesSandbox enforces both-must-agree: a Stripe key's Test/Live
// prefix must match the KnoxCall client's Sandbox flag, so a test key can never
// be wrapped by a live client (or vice versa). Publishable keys (pk_) are
// rejected outright — they are not server credentials. Non-Stripe schemes we
// cannot classify are left alone (returns nil). auth is the full header value,
// e.g. "Bearer sk_live_…".
func assertKeyMatchesSandbox(auth string, sandbox bool) error {
	if auth == "" {
		return nil
	}
	// Trim BEFORE stripping the scheme: leading whitespace would otherwise stop
	// the anchored ^Bearer from matching, leaving "Bearer sk_live_…" in token,
	// which the classifier can't parse — silently skipping the check.
	token := strings.TrimSpace(auth)
	token = reWrapBearer.ReplaceAllString(token, "")
	token = strings.TrimSpace(token)

	if reWrapPublishable.MatchString(token) {
		return &WrapSandboxMismatchError{Message: "knoxcall: a Stripe publishable key (pk_…) is not a server credential " +
			"and cannot be wrapped. Use a secret (sk_…) or restricted (rk_…) key."}
	}
	m := reWrapSecretKey.FindStringSubmatch(token)
	if m == nil {
		return nil // unknown / non-Stripe scheme — nothing to assert
	}
	keyIsTest := m[1] == "test"
	if keyIsTest != sandbox {
		kind := "LIVE"
		if keyIsTest {
			kind = "TEST"
		}
		return &WrapSandboxMismatchError{Message: fmt.Sprintf(
			"knoxcall: provider key is a %s key but the KnoxCall client was constructed with Sandbox=%t. "+
				"Test keys require Sandbox=true, live keys require Sandbox=false — construct a matching client.",
			kind, sandbox)}
	}
	return nil
}
