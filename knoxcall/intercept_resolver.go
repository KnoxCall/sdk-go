package knoxcall

// The route-aware interception decision table — pure, no I/O
// (docs/internal/sdk-wrapping/route-aware-interception-plan.md §2.2, PARITY §21.1).
//
// One request in, one decision out: send it DIRECT (untouched, via the base
// transport), through a ROUTE (the manifest says an intercept-enabled Route
// covers this host + path; the Route injects the stored secret), or through the
// EPHEMERAL proxy (the caller listed the host, no Route covers it; the SDK's own
// credential is lifted out-of-band). The order of the rules is the feature: a
// listed host silently upgrades from ephemeral to route the moment a Route
// covers it, and downgrades back when the Route is disabled.
//
// Every SDK's resolver passes the SAME fixtures — sdk/fixtures/intercept-resolver.json
// (intercept_resolver_test.go runs them here) — so this file is the Go copy of a
// contract whose reference is sdk/knoxcall-node/src/intercept-resolver.ts, not a
// private heuristic. Keep it boring: no goroutines, no globals, no client access.

import (
	"net/url"
	"os"
	"sort"
	"strings"
)

// InterceptMode is where a route-aware transport sends one request.
type InterceptMode string

const (
	// InterceptDirect: untouched, via the base transport.
	InterceptDirect InterceptMode = "direct"
	// InterceptRoute: through the Route the manifest names (x-knoxcall-route).
	InterceptRoute InterceptMode = "route"
	// InterceptEphemeral: through the ephemeral proxy in transparent mode.
	InterceptEphemeral InterceptMode = "ephemeral"
)

// InterceptReason is the stable code every SDK reports for a decision
// (observability hooks carry it; the fixtures pin it).
type InterceptReason string

const (
	ReasonKillSwitch      InterceptReason = "kill_switch"
	ReasonUnparseable     InterceptReason = "unparseable"
	ReasonOwnHost         InterceptReason = "own_host"
	ReasonRouteAround     InterceptReason = "route_around"
	ReasonOutsideContext  InterceptReason = "outside_context"
	ReasonManifest        InterceptReason = "manifest"
	ReasonNoBasePathMatch InterceptReason = "no_base_path_match"
	ReasonNoRoute         InterceptReason = "no_route"
	ReasonUnlisted        InterceptReason = "unlisted"
)

// InterceptDecision is the resolver's answer for one request.
type InterceptDecision struct {
	Mode   InterceptMode
	Reason InterceptReason
	// Host is the normalised request host ("" when unparseable).
	Host string
	// Slug (route mode): what to send as x-knoxcall-route.
	Slug string
	// Path (route mode): the rebased path plus the query, verbatim.
	Path string
	// Entry (route mode): the manifest entry that matched (RequiresClients / Ambiguous).
	Entry *InterceptManifestRoute
	// RouteAroundReason: the matching rule's human reason.
	RouteAroundReason string
}

// interceptInput is everything the decision table reads.
type interceptInput struct {
	url    string
	method string
	// hosts is the caller's explicit host list (normalised); allHosts is the
	// explicit-transport form (Wrap.RoundTripper), where every request the
	// wrapped SDK makes is by definition one the caller chose to send through
	// KnoxCall.
	hosts    map[string]struct{}
	allHosts bool
	manifest *InterceptManifest
	// ownHosts: the client's own hosts (management + data plane), never intercepted.
	ownHosts       map[string]struct{}
	routeAround    []RouteAroundRule
	killSwitch     bool
	requireContext bool
	inContext      bool
}

// interceptKillSwitch reports whether KNOXCALL_INTERCEPT=off (or 0 / false)
// is set: every interceptor and route-aware transport becomes pass-through, per
// request, with no deploy.
func interceptKillSwitch() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("KNOXCALL_INTERCEPT"))) {
	case "off", "0", "false":
		return true
	}
	return false
}

// isPlatformHost: KnoxCall's own domains are never intercepted, whatever a
// manifest or a host list says (anti-recursion).
func isPlatformHost(host string) bool {
	return host == "knoxcall.com" || strings.HasSuffix(host, ".knoxcall.com")
}

// rebasePath returns the request path with the route's base prefix removed
// (leading slash kept), and false when the request is not under the base.
// "/crm/v3" covers "/crm/v3" and "/crm/v3/x", never "/crm/v30" — the boundary is
// a path segment. Mirrors the server's rebasePath (src/lib/route-target-host.ts).
func rebasePath(requestPath, basePath string) (string, bool) {
	reqPath := requestPath
	if reqPath == "" {
		reqPath = "/"
	}
	if basePath == "/" || basePath == "" {
		if strings.HasPrefix(reqPath, "/") {
			return reqPath, true
		}
		return "/" + reqPath, true
	}
	if reqPath == basePath {
		return "/", true
	}
	if !strings.HasPrefix(reqPath, basePath+"/") {
		return "", false
	}
	rest := reqPath[len(basePath):]
	if rest == "" {
		rest = "/"
	}
	return rest, true
}

// entriesForHost returns the manifest entries for a host in the order the
// server sorts them — longest base_path first, then base_path, then slug — so
// the first entry whose base covers the path is the longest-prefix,
// lowest-slug match.
func entriesForHost(m *InterceptManifest, host string) []InterceptManifestRoute {
	if m == nil {
		return nil
	}
	var out []InterceptManifestRoute
	for _, e := range m.Routes {
		if normalizeHost(e.Host) == host {
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if len(a.BasePath) != len(b.BasePath) {
			return len(a.BasePath) > len(b.BasePath)
		}
		if a.BasePath != b.BasePath {
			return a.BasePath < b.BasePath
		}
		return a.Slug < b.Slug
	})
	return out
}

// resolveIntercept applies the decision table. First match wins.
func resolveIntercept(in interceptInput) InterceptDecision {
	if in.killSwitch {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonKillSwitch}
	}
	u, err := url.Parse(in.url)
	if err != nil {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonUnparseable}
	}
	if s := strings.ToLower(u.Scheme); s != "https" && s != "http" {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonUnparseable}
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonUnparseable}
	}

	if _, own := in.ownHosts[host]; own || isPlatformHost(host) {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonOwnHost, Host: host}
	}

	if rule, ok := matchRouteAround(u, in.routeAround); ok {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonRouteAround, Host: host, RouteAroundReason: rule.Reason}
	}

	if in.requireContext && !in.inContext {
		return InterceptDecision{Mode: InterceptDirect, Reason: ReasonOutsideContext, Host: host}
	}

	entries := entriesForHost(in.manifest, host)
	for i := range entries {
		rebased, ok := rebasePath(u.Path, entries[i].BasePath)
		if !ok {
			continue
		}
		path := rebased
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		entry := entries[i]
		return InterceptDecision{Mode: InterceptRoute, Reason: ReasonManifest, Host: host, Slug: entry.Slug, Path: path, Entry: &entry}
	}

	_, listed := in.hosts[host]
	if in.allHosts || listed {
		reason := ReasonNoRoute
		if len(entries) > 0 {
			reason = ReasonNoBasePathMatch
		}
		return InterceptDecision{Mode: InterceptEphemeral, Reason: reason, Host: host}
	}
	return InterceptDecision{Mode: InterceptDirect, Reason: ReasonUnlisted, Host: host}
}
