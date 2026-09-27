# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/); versions follow
[Semantic Versioning](https://semver.org/).

**Nothing has been released.** `knoxcall-go` is not published to the Go module proxy, there is no
a `v1.0.0` git tag on the public mirror, and `git tag --list` in this repository is empty. Everything below is
unreleased work in the monorepo at `sdk/knoxcall-go/`.

There is deliberately **no back-filled history**. This file starts at
`[Unreleased]` rather than reconstructing changes that predate any release,
because a changelog exists to tell a consumer what changed *between versions
they could have installed* — and there are none. The first release heading is
written when the first version is actually published.

Release headings take the form `## [X.Y.Z] — YYYY-MM-DD`.
`tests/coverage/sdk-changelog-honesty.test.ts` refuses any release heading that
has no matching git tag, so this file cannot claim a release that did not happen.

## [Unreleased]

### Changed
- **SDK version is 1.0.0** (the `KnoxCall-Sdk` user-agent version; was 0.1.0), aligned with the other SDKs for the first release. The release tag on `KnoxCall/sdk-go` is `v1.0.0`.
- **Module path is now `github.com/knoxcall/sdk-go`** (was `github.com/knoxcall/knoxcall-go`), so every KnoxCall package follows one `knoxcall/sdk` convention and the path matches the public mirror repo `KnoxCall/sdk-go` that `go get` resolves. Nothing was ever published under the old path. Imports change from `github.com/knoxcall/knoxcall-go/knoxcall` to `github.com/knoxcall/sdk-go/knoxcall`; the package name `knoxcall` is unchanged.
- **Refusal-driven refresh learns the 404.** The route data plane now answers an AUTHENTICATED credential's call to a Route that does not resolve with `404 {"error":{"type":"route_not_found"|"environment_not_configured"|"environment_disabled","message","request_id"}}` plus the KnoxCall response block, instead of the opaque `401 Unauthorized` (which callers the tenant has not authenticated keep — founder decision 2026-09-26, PARITY §21). `Wrap.Intercept` and `Wrap.RoundTripper(WithRoutes())` now treat a KnoxCall-origin `404` whose envelope `error.type` is `route_not_found` as a refresh trigger alongside the 401 — a stale manifest naming a deleted Route is exactly that — refreshing once and re-deciding once, never looping. The `environment_*` types are surfaced as-is; an UPSTREAM 404 (`X-Knox-Upstream-Status` present) never triggers it, whatever its body says; the decision re-buffers the body, so the caller's response is intact. `RefusedInfo.Status` is 404 for that case. `Call` is unchanged: it returns the 404 raw (PARITY §5) and spends no re-mint on it. Cross-language contract: `sdk/fixtures/route-refusal.json`.

### Added
- **Uncovered-egress observations (PARITY §21.3), on by default.** `Wrap.Intercept` (and `Wrap.RoundTripper(WithRoutes())`) now counts calls sent direct because their host is `unlisted` while they carry a credential-bearing header — host, first path segment, method and the header NAME; never the value, the query string or the body — and reports them to `POST /v1/wrap/egress-observations` about once a minute (a `time.AfterFunc`; at 200 distinct keys at once; once more on `Stop()`). Opt out with `WithObserveUncovered(false)` or `KNOXCALL_OBSERVE_UNCOVERED=off`; nothing is reported while `KNOXCALL_INTERCEPT=off`; a 403 stops reporting with one warning. New `WithOnObservationFlush`, `Wrap.ReportEgressObservations(ctx, observations)`, `EgressObservation`, `EgressObservationsReport`, `CredentialHeaderName`, `IsCredentialHeaderName`. The report runs in a suppressed context the route-aware `RoundTrip` hands straight to its base transport. (Founder decision 2026-09-26: default-on with an opt-out.)
- **A credential in the path is never reported.** Before an uncovered-egress observation is sent, a first path segment that looks like a credential (Telegram's `/bot<id>:<secret>`, a Stripe/GitHub/AWS/Google/Slack/JWT token, any segment over 64 characters, or a 24+ character mixed-class run — raw or percent-decoded) is reported as `/`; the server's identical rule (#1022) counts it under the receipt's new `redacted` field, now on the report type. (PARITY §21.3.)
- `Wrap.InterceptManifest(ctx, InterceptManifestOptions{IfNoneMatch: v})` — the conditional poll. Pass the manifest `Version` you hold and the SDK sends `If-None-Match: W/"<version>"` (`ManifestETag()`); the server's `304` returns `(nil, nil)` — keep what you hold. The route-aware store (`Wrap.Intercept`, `Wrap.RoundTripper(WithRoutes())`) now polls this way on every refresh after the first, scheduled or forced: a `304` keeps the manifest, re-arms at one TTL, clears backoff and fires no `WithOnRefresh` hook, so a steady-state poll costs no body bytes. Auth, the one re-auth on 401 and retries are unchanged; the unconditional call never returns `(nil, nil)`. (PARITY §21.1 "Conditional poll"; fixture `sdk/fixtures/intercept-store-conditional.json`.)
- **Origin marker on rerouted calls.** Every route-mode send from `Wrap.Intercept` / `Wrap.RoundTripper(WithRoutes())` now carries `x-knoxcall-origin: sdk-intercept`, so the API Log shows the call as **SDK intercept** rather than **Direct** (`RequestLog.ClientOrigin`: `"direct"` | `"sdk_intercept"`). A direct `Call` / bound route sends nothing; an ephemeral hop sends nothing. A caller-supplied `x-knoxcall-origin` in `CallOptions.Headers` / `EphemeralOptions.Headers` is stripped like the proxy-auth headers — the server treats the marker as informational either way. The seam is an unexported `CallOptions` field only this package can set. (PARITY §21.2.)
- **Route-aware interception.** `Wrap.Intercept(ctx, opts...)` swaps `http.DefaultTransport` for a route-aware `*WrapRoundTripper` wrapping the previous one (idiomatic, not a monkeypatch) and, by default, sends each request through the Route that covers its host + path (the Route injects the secret; no provider credential travels), through the ephemeral proxy for hosts listed with `WithHosts` / `WithHost` that no Route covers, and to the previous transport untouched otherwise. A Route created, enabled or disabled later takes effect on the next poll, on a refusal, or on `Refresh(ctx)`. The handle has `Ready()` / `Wait(ctx)` / `Refresh(ctx)` / `Manifest()` / `Stop()` (restores; never clobbers a later installer); a second install returns `ErrInterceptInstalled`; `WithRequireContext()` scopes interception to `Wrap.Routed(ctx)`. `Wrap.RoundTripper(WithRoutes())` gives an explicit transport the same decisions (the default stays ephemeral-only); it now returns `*WrapRoundTripper` (still an `http.RoundTripper`) carrying the same controls. New options: `WithRoutes` / `WithoutRoutes`, `WithHosts`, `WithHost` + `HostEscrow` / `HostUnavailableDirect`, `WithUnavailableDirect` (transit only — route mode and escrow always fail closed), `WithRequireContext`, and the hooks `WithOnReroute`, `WithOnRefresh`, `WithOnManifestError`, `WithOnUnmatchedPath`, `WithOnRefused`, `WithOnFallback`, `WithOnPromoted`. `KNOXCALL_INTERCEPT=off` is the kill switch. Exported decision types `InterceptMode`, `InterceptReason`, `InterceptDecision`, `ManifestRefreshInfo`. (route-aware-interception-plan.md PR4; PARITY §21.1.)
- `Wrap.InterceptManifest(ctx, InterceptManifestOptions{Environment})` — `GET /v1/wrap/intercept-manifest`, the per-environment list of upstream hosts an intercept-enabled Route covers (`InterceptManifest`, `InterceptManifestRoute`; `Version` doubles as the ETag). What a route-aware interceptor polls (route-aware-interception-plan.md PR1).
- `InterceptEnabled *bool` on `CreateRouteInput`, `UpdateRouteInput` and `RouteEnvironmentInput` — the per-environment interception opt-in. `Route.InterceptEnabled` (bool) carries the base environment's value on list/get.

### Fixed
- `Wrap.RoundTripper` / `Wrap.Intercept`: `Ready()` (and `Wait`) now fire only after the first manifest attempt's hooks (`WithOnRefresh`, `WithOnManifestError`, the once-per-route warnings) have run, not merely after the manifest was stored — a caller that read hook-produced state straight after `Wait` could race the refresh goroutine (a `-race` report on 2026-09-25).
- `Call` — and bound routes, the CLI and the interceptors' route mode, which delegate to it — now places the upstream path under the tenant host's `/api` data-plane entry point whenever the proxy base is a KnoxCall cloud tenant host with no path of its own (derived, or an explicit override naming one); any other base is used verbatim. Before, `Call(ctx, "r", &CallOptions{Path: "/users"})` sent `https://{tenant}.knoxcall.com/users`, which a tenant host answers with the dashboard, not the proxy — every documented example was affected, and `Path: "/api/…"` was the only form that worked. `Path` is now always the upstream path (PARITY §5).
- `Call()` / `Ephemeral()` no longer spend their one token re-mint on an UPSTREAM 401 relayed by the data plane: a response carrying `X-Knox-Upstream-Status` (the route data plane's response block) or `X-Knox-Destination-Status` (the ephemeral proxy) is the upstream's answer and is returned as-is, so a real revocation later in the same call is still recoverable. Mirrors the Node and Python fix.
- `normalizeHost` now also trims surrounding whitespace and IPv6 brackets (PARITY §21's host contract), so a bracketed IPv6 literal cannot dodge a route-around rule.

The package's behaviour is specified by [`sdk/PARITY.md`](../PARITY.md), which is
authoritative over this file for anything describing current behaviour.

### Added

- `WorkloadCredentialProvider` / `NewWorkloadCredentialProvider` — caches a
  workload-identity capability token and refreshes it on a two-tier schedule
  (advisory at expiry-120s, mandatory at expiry-30s), calling the `Assertion`
  source before every exchange. Because KnoxCall assertions are single-use, a
  source that returns bytes already spent is refused locally with
  `*StaleAssertionError` rather than sent and refused as a replay. Goroutine-safe:
  N concurrent callers cause one exchange. PARITY section 20.

### Owed at first release

- Replace the local-path / `git` install in the public docs with a **pinned**
  registry install (`go get github.com/knoxcall/sdk-go@vX.Y.Z`) — see `sdk/PARITY.md` §"Documented installs must
  pin a version".
- Write the first `## [X.Y.Z] — YYYY-MM-DD` heading, and tag it.
