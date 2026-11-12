package knoxcall

// The route-aware decision table, driven by the CROSS-LANGUAGE fixtures in
// sdk/fixtures/intercept-resolver.json (route-aware-interception-plan.md §2.2,
// PARITY §21.1). Node is the reference; this is the Go mirror running the same
// cases unchanged. The file is read from the monorepo path on purpose — the
// contract is the shared file, not a copy that could drift — and a missing
// file FAILS rather than skips: a skipped contract test reads as a pass.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type resolverFixture struct {
	OwnHosts []string           `json:"own_hosts"`
	Manifest *InterceptManifest `json:"manifest"`
	Cases    []resolverCase     `json:"cases"`
}

type resolverCase struct {
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Hosts          json.RawMessage   `json:"hosts"`
	KillSwitch     bool              `json:"kill_switch"`
	RequireContext bool              `json:"require_context"`
	InContext      bool              `json:"in_context"`
	Manifest       json.RawMessage   `json:"manifest"`
	Expect         map[string]string `json:"expect"`
}

func loadResolverFixture(t *testing.T) resolverFixture {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", "intercept-resolver.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the shared resolver fixture must exist at %s — every SDK's resolver runs it: %v", path, err)
	}
	var f resolverFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return f
}

func hostSet(hosts ...string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, h := range hosts {
		out[normalizeHost(h)] = struct{}{}
	}
	return out
}

func TestInterceptResolverSharedFixture(t *testing.T) {
	f := loadResolverFixture(t)
	if len(f.Cases) <= 15 || f.Manifest == nil || len(f.Manifest.Routes) <= 3 {
		t.Fatalf("fixture is trivial: %d cases, manifest %+v", len(f.Cases), f.Manifest)
	}
	own := hostSet(f.OwnHosts...)

	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			in := interceptInput{
				url:            c.URL,
				method:         c.Method,
				manifest:       f.Manifest,
				ownHosts:       own,
				routeAround:    DefaultRouteAround,
				killSwitch:     c.KillSwitch,
				requireContext: c.RequireContext,
				inContext:      c.InContext,
			}
			if len(c.Manifest) > 0 {
				// The case names its own manifest (possibly null = none).
				var m *InterceptManifest
				if err := json.Unmarshal(c.Manifest, &m); err != nil {
					t.Fatalf("case manifest: %v", err)
				}
				in.manifest = m
			}
			if string(c.Hosts) == `"all"` {
				in.allHosts = true
			} else {
				var hs []string
				if err := json.Unmarshal(c.Hosts, &hs); err != nil {
					t.Fatalf("case hosts: %v", err)
				}
				in.hosts = hostSet(hs...)
			}

			d := resolveIntercept(in)
			if string(d.Mode) != c.Expect["mode"] {
				t.Fatalf("%s: mode = %q, want %q (reason %q)", c.URL, d.Mode, c.Expect["mode"], d.Reason)
			}
			if string(d.Reason) != c.Expect["reason"] {
				t.Fatalf("%s: reason = %q, want %q", c.URL, d.Reason, c.Expect["reason"])
			}
			if slug, ok := c.Expect["slug"]; ok && d.Slug != slug {
				t.Fatalf("%s: slug = %q, want %q", c.URL, d.Slug, slug)
			}
			if path, ok := c.Expect["path"]; ok && d.Path != path {
				t.Fatalf("%s: path = %q, want %q", c.URL, d.Path, path)
			}
			if d.Mode != InterceptRoute && (d.Slug != "" || d.Path != "" || d.Entry != nil) {
				t.Fatalf("%s: a non-route decision must carry no slug/path/entry: %+v", c.URL, d)
			}
			if d.Mode == InterceptRoute && (d.Entry == nil || d.Entry.Slug != d.Slug) {
				t.Fatalf("%s: a route decision carries its manifest entry: %+v", c.URL, d)
			}
		})
	}
}

func TestRebasePathIsSegmentAware(t *testing.T) {
	cases := []struct {
		req, base string
		want      string
		ok        bool
	}{
		{"/crm/v3/objects", "/crm/v3", "/objects", true},
		{"/crm/v3", "/crm/v3", "/", true},
		{"/crm/v30/x", "/crm/v3", "", false},
		{"/anything", "/", "/anything", true},
		{"", "/", "/", true},
		{"x", "/", "/x", true},
		{"/crm/v3/", "/crm/v3", "/", true},
		{"/other", "/crm/v3", "", false},
	}
	for _, c := range cases {
		got, ok := rebasePath(c.req, c.base)
		if ok != c.ok || got != c.want {
			t.Errorf("rebasePath(%q, %q) = (%q, %v), want (%q, %v)", c.req, c.base, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizeHostContract(t *testing.T) {
	cases := map[string]string{
		" API.Example. ": "api.example",
		"[::1]":          "::1",
		"api.stripe.com": "api.stripe.com",
		"":               "",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPlatformHost(t *testing.T) {
	for host, want := range map[string]bool{
		"knoxcall.com":              true,
		"acme.knoxcall.com":         true,
		"x.wrap.knoxcall.com":       true,
		"knoxcall.com.evil.test":    false,
		"notknoxcall.com":           false,
		"api.hubapi.com":            false,
		"sandbox-acme.knoxcall.com": true,
	} {
		if got := isPlatformHost(host); got != want {
			t.Errorf("isPlatformHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestEntriesForHostOrdersLongestBaseThenSlug(t *testing.T) {
	m := &InterceptManifest{Routes: []InterceptManifestRoute{
		{Host: "h.example", BasePath: "/", Slug: "z"},
		{Host: "h.example", BasePath: "/a/b", Slug: "deep"},
		{Host: "H.EXAMPLE.", BasePath: "/", Slug: "a"},
		{Host: "other.example", BasePath: "/", Slug: "o"},
	}}
	got := entriesForHost(m, "h.example")
	slugs := make([]string, 0, len(got))
	for _, e := range got {
		slugs = append(slugs, e.Slug)
	}
	if len(slugs) != 3 || slugs[0] != "deep" || slugs[1] != "a" || slugs[2] != "z" {
		t.Fatalf("order = %v, want [deep a z]", slugs)
	}
	if entriesForHost(nil, "h.example") != nil {
		t.Fatalf("a nil manifest has no entries")
	}
}

func TestPortInRequestURLNeverAffectsHostMatch(t *testing.T) {
	m := &InterceptManifest{Routes: []InterceptManifestRoute{{Host: "h.example", BasePath: "/", Slug: "h"}}}
	d := resolveIntercept(interceptInput{url: "https://h.example:8443/x?y=1", method: "GET", manifest: m})
	if d.Mode != InterceptRoute || d.Slug != "h" || d.Path != "/x?y=1" {
		t.Fatalf("decision = %+v, want route h /x?y=1", d)
	}
}

func TestInterceptKillSwitchSpellings(t *testing.T) {
	for value, want := range map[string]bool{"off": true, "OFF": true, " 0 ": true, "false": true, "on": false, "": false, "1": false} {
		t.Setenv("KNOXCALL_INTERCEPT", value)
		if got := interceptKillSwitch(); got != want {
			t.Errorf("KNOXCALL_INTERCEPT=%q → %v, want %v", value, got, want)
		}
	}
}
