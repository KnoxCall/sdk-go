package knoxcall

import (
	"context"
	"net/http"
	"net/url"
)

// WrapCredentialInput is the request body for WrapResource.Escrow
// (POST /v1/wrap/credentials). It hands KnoxCall custody of a raw provider
// credential: Value is sent exactly ONCE and never returned — the escrowed key
// is thereafter referenced by Name. Hosts is the load-bearing pin: the set of
// upstream hostnames the escrowed credential is allowed to reach.
type WrapCredentialInput struct {
	// Provider is a free-form label for the credential's origin ("stripe", …).
	Provider string `json:"provider"`
	// Name is the secret name the escrowed key is stored under and later
	// referenced by.
	Name string `json:"name"`
	// Value is the raw provider credential. It is transmitted once and never
	// echoed back in the response.
	Value string `json:"value"`
	// Hosts is the allow-list of upstream hostnames the escrowed credential may
	// be used against — the pin that keeps the credential from being replayed
	// elsewhere.
	Hosts []string `json:"hosts"`
}

// WrappedCredential is the metadata WrapResource.Escrow returns after escrowing
// a credential. It deliberately never carries the raw value back — only the
// stored secret's identity, provider label, the pinned hosts, and the sandbox
// flag.
type WrappedCredential struct {
	SecretID     string   `json:"secret_id"`
	Name         string   `json:"name"`
	Provider     string   `json:"provider"`
	AllowedHosts []string `json:"allowed_hosts"`
	Sandbox      bool     `json:"sandbox"`
}

// GatewayURLInput is the request body for WrapResource.GatewayURL
// (POST /v1/wrap/tokens). It mints a base-URL gateway token bound to an
// escrowed credential.
type GatewayURLInput struct {
	// Secret is the escrowed credential (name or id, from Escrow) to inject.
	Secret string `json:"secret"`
	// Host is the upstream host to pin; optional when the credential allows
	// exactly one host.
	Host string `json:"host,omitempty"`
	// TTLSeconds is an optional token TTL in seconds; omit for a non-expiring
	// token.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Label is an optional human label for the token list.
	Label string `json:"label,omitempty"`
	// Style selects which base_url form to return. "path"
	// (…/wg/<token>/<host>) is always available; "subdomain"
	// (<label>.wrap.<domain>) is only available when the operator has enabled
	// the wildcard-subdomain gateway (WRAP_WILDCARD_DOMAIN) — otherwise the
	// call 400s. Empty lets the server choose (subdomain when enabled, else
	// path). NOTE: the subdomain form carries the token in the TLS SNI
	// (plaintext on the wire) — weaker token confidentiality than the path
	// form; prefer a short TTLSeconds.
	Style string `json:"style,omitempty"`
}

// GatewayToken is the metadata WrapResource.GatewayURL returns after minting a
// base-URL gateway token. Token is a bearer credential embedded in BaseURL —
// treat the whole struct as a secret.
type GatewayToken struct {
	// ID is the wrap-token id — pass to RevokeGatewayToken to revoke it.
	ID string `json:"id"`
	// Token is the wrap-token, a bearer credential embedded in BaseURL. Treat
	// as a secret.
	Token string `json:"token"`
	// BaseURL is what to set as the wrapped SDK's base URL; the SDK's own key
	// becomes a placeholder.
	BaseURL string `json:"base_url"`
	// BaseURLStyle reports which base_url form was returned ("path" or
	// "subdomain"). Empty when the server does not report it (older servers).
	BaseURLStyle string `json:"base_url_style"`
	Host         string `json:"host"`
	SecretID     string `json:"secret_id"`
	Sandbox      bool   `json:"sandbox"`
	// ExpiresAt is the token's expiry; nil for a non-expiring token.
	ExpiresAt *string `json:"expires_at"`
}

// WrapGatewayToken is one gateway token's metadata as returned by
// WrapResource.ListGatewayTokens. The token value itself is never returned by
// the list endpoint — only its identity, pinned host, and lifecycle timestamps.
// InterceptManifestRoute is one entry of the intercept manifest: an upstream
// host an intercept-enabled Route covers, and the slug to send it under.
type InterceptManifestRoute struct {
	// Host is the lower-case DNS hostname, no port, trailing dot stripped.
	Host string `json:"host"`
	// BasePath is the path prefix the route serves under ("/" when its target
	// has none); forward the request path with this prefix removed.
	BasePath string `json:"base_path"`
	// Slug is what to send as x-knoxcall-route.
	Slug    string `json:"slug"`
	RouteID string `json:"route_id"`
	// RequiresClients: the environment requires a registered client — a
	// bearer-only SDK call will be refused.
	RequiresClients bool `json:"requires_clients"`
	// AllowedMethods is the upper-cased verb list when method restrictions are
	// on for this environment; nil otherwise.
	AllowedMethods []string `json:"allowed_methods"`
	// Ambiguous is true when another entry shares this (host, base_path); take
	// the lexically lowest slug and warn.
	Ambiguous bool    `json:"ambiguous,omitempty"`
	UpdatedAt *string `json:"updated_at"`
}

// InterceptManifest is GET /v1/wrap/intercept-manifest: which upstream hosts an
// intercept-enabled Route covers for one environment of this space. Version
// doubles as the ETag; poll again after TTLSeconds.
type InterceptManifest struct {
	Version     string                   `json:"version"`
	TTLSeconds  int                      `json:"ttl_seconds"`
	Environment string                   `json:"environment"`
	Sandbox     bool                     `json:"sandbox"`
	Routes      []InterceptManifestRoute `json:"routes"`
}

// InterceptManifestOptions selects the environment the manifest is resolved
// for; an empty Environment means the tenant's default.
//
// IfNoneMatch is the manifest Version the caller already holds (not an ETag —
// the SDK sends it as the server's weak tag, `If-None-Match: W/"<version>"`).
// When the server's manifest still has that version it answers 304 and
// InterceptManifest returns (nil, nil): keep what you hold. Empty means an
// unconditional fetch.
type InterceptManifestOptions struct {
	Environment string
	IfNoneMatch string
}

// ManifestETag is the weak ETag the manifest endpoint sets for a Version
// (src/client-api/wrap.ts) — the value InterceptManifest sends as If-None-Match.
func ManifestETag(version string) string {
	return `W/"` + version + `"`
}

// EgressObservation is one uncovered-egress observation (PARITY §21.3): a
// credentialed call the interceptor sent DIRECT because no Route covered its
// host and nobody listed it. Names, never values — HeaderName is the
// credential header's NAME, never its value; FirstSegment is "/" or
// "/<first path segment>", never the query string, never deeper.
type EgressObservation struct {
	// Host is the normalised host: lower-case, no port, brackets and trailing dot stripped.
	Host string `json:"host"`
	// FirstSegment is "/" or "/<first path segment>".
	FirstSegment string `json:"first_segment"`
	// Method is the upper-case HTTP method.
	Method string `json:"method"`
	// HeaderName is the lower-case NAME of the credential-bearing header.
	HeaderName string `json:"header_name"`
	// Count is the number of calls aggregated into this observation (positive).
	Count int `json:"count"`
	// FirstSeen and LastSeen are ISO-8601 UTC.
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// EgressObservationsReport is what POST /v1/wrap/egress-observations did with
// a report.
type EgressObservationsReport struct {
	Accepted int `json:"accepted"`
	Dropped  int `json:"dropped"`
	// Reasons counts dropped observations by reason.
	Reasons map[string]int `json:"reasons"`
	// Redacted counts accepted observations whose content the server reduced,
	// by reason (e.g. "first_segment_looks_like_credential").
	Redacted map[string]int `json:"redacted,omitempty"`
}

// ReportEgressObservationsOptions: SDK is "<language>/<version>" of the
// reporting SDK; empty means this one's.
type ReportEgressObservationsOptions struct {
	SDK string
}

type egressObservationsBody struct {
	SDK          string              `json:"sdk"`
	Observations []EgressObservation `json:"observations"`
}

type WrapGatewayToken struct {
	ID       string `json:"id"`
	SecretID string `json:"secret_id"`
	Host     string `json:"host"`
	// Label is the human label set at mint time; nil when unset.
	Label *string `json:"label"`
	// CreatedAt is when the token was minted; nil only if the API omits it.
	CreatedAt *string `json:"created_at"`
	// ExpiresAt is the token's expiry; nil for a non-expiring token.
	ExpiresAt *string `json:"expires_at"`
	// RevokedAt is when the token was revoked; nil while active.
	RevokedAt *string `json:"revoked_at"`
	// LastUsedAt is when the token was last used; nil if never used.
	LastUsedAt *string `json:"last_used_at"`
}

// wrapGatewayTokenList is the inner shape of the GET /v1/wrap/tokens envelope:
// the response is {data: {tokens: [...]}}, so the slice sits one level below
// `data` (unlike the paginated / bare-array list endpoints).
type wrapGatewayTokenList struct {
	Tokens []WrapGatewayToken `json:"tokens"`
}

// RevokeResult is the unwrapped result of WrapResource.RevokeGatewayToken;
// Revoked is true when the token was revoked.
type RevokeResult struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// WrapResource escrows raw provider credentials into KnoxCall custody.
type WrapResource struct{ c *Client }

// Escrow hands KnoxCall custody of a raw provider credential
// (POST /v1/wrap/credentials). The value is transmitted once and never
// returned; the response carries only the stored secret's metadata (its id,
// name, provider label, the pinned allowed hosts, and the sandbox flag). Like
// every mutating management request it goes through the client's request
// pipeline, inheriting auth, retry, envelope-unwrapping, and error mapping, and
// carries a stable idempotency key exactly as Secrets.Create does.
func (r *WrapResource) Escrow(ctx context.Context, input WrapCredentialInput) (*WrappedCredential, error) {
	return doUnwrap[WrappedCredential](ctx, r.c, requestOpts{method: "POST", path: "/v1/wrap/credentials", body: input})
}

// GatewayURL mints a base-URL gateway token bound to an escrowed credential
// (POST /v1/wrap/tokens). Set the returned BaseURL as the wrapped SDK's base
// URL — the SDK's own key becomes a placeholder and KnoxCall injects the
// escrowed secret server-side, so the real key never enters your process. This
// path is ESCROW-ONLY (the mint requires a previously escrowed credential). The
// returned Token is a bearer credential embedded in BaseURL — treat it as a
// secret. Like every mutating management request it goes through the client's
// request pipeline, inheriting auth, retry, envelope-unwrapping, and error
// mapping, and carries a stable idempotency key exactly as Secrets.Create does.
func (r *WrapResource) GatewayURL(ctx context.Context, input GatewayURLInput) (*GatewayToken, error) {
	return doUnwrap[GatewayToken](ctx, r.c, requestOpts{method: "POST", path: "/v1/wrap/tokens", body: input})
}

// ListGatewayTokens returns this space's gateway tokens (metadata only — the
// token value itself is never returned by the list). The endpoint answers
// {data: {tokens: [...]}}, so the envelope's `data` is unwrapped and the nested
// tokens slice returned.
// InterceptManifest fetches the intercept manifest
// (GET /v1/wrap/intercept-manifest): which upstream hosts an intercept-enabled
// Route covers in this space for one environment, and the slug to send them
// under. This is what a route-aware interceptor polls. Scope: routes:read.
// InterceptManifest is GET /v1/wrap/intercept-manifest: which upstream hosts an
// intercept-enabled Route covers in this space, for one environment, and the
// slug to send them under. What a route-aware transport polls; Version is the
// ETag. Scope: routes:read.
//
// Conditional form: with IfNoneMatch set the SDK sends
// `If-None-Match: W/"<version>"`; a 304 returns (nil, nil) — keep what you
// hold. Everything else (auth, the one re-auth on 401, retries, a 200 with a
// newer manifest) is exactly the unconditional call.
func (r *WrapResource) InterceptManifest(ctx context.Context, opts ...InterceptManifestOptions) (*InterceptManifest, error) {
	var query url.Values
	ifNoneMatch := ""
	for _, o := range opts {
		if o.Environment != "" {
			query = url.Values{"environment": []string{o.Environment}}
		}
		if o.IfNoneMatch != "" {
			ifNoneMatch = o.IfNoneMatch
		}
	}
	req := requestOpts{method: "GET", path: "/v1/wrap/intercept-manifest", query: query}
	if ifNoneMatch == "" {
		return doUnwrap[InterceptManifest](ctx, r.c, req)
	}
	var notModified bool
	req.header = http.Header{"If-None-Match": []string{ManifestETag(ifNoneMatch)}}
	req.notModified = &notModified
	var env struct {
		Data InterceptManifest `json:"data"`
	}
	if err := r.c.do(ctx, req, &env); err != nil {
		return nil, err
	}
	if notModified {
		return nil, nil
	}
	return &env.Data, nil
}

// ReportEgressObservations reports uncovered-egress observations
// (POST /v1/wrap/egress-observations; PARITY §21.3) — the thin typed wrapper
// the interceptor's reporter uses, exported so an integrator can report by
// hand. At most 200 observations per call. The body carries names, never
// values: a credential header's NAME, the host, the first path segment, the
// method and counts. Scope: routes:read. Like every mutating management
// request it goes through the client's request pipeline (auth, retry,
// envelope-unwrapping, error mapping, a stable idempotency key).
func (r *WrapResource) ReportEgressObservations(ctx context.Context, observations []EgressObservation, opts ...ReportEgressObservationsOptions) (*EgressObservationsReport, error) {
	sdk := "go/" + sdkVersion
	for _, o := range opts {
		if o.SDK != "" {
			sdk = o.SDK
		}
	}
	if observations == nil {
		observations = []EgressObservation{}
	}
	body := egressObservationsBody{SDK: sdk, Observations: observations}
	return doUnwrap[EgressObservationsReport](ctx, r.c, requestOpts{method: "POST", path: "/v1/wrap/egress-observations", body: body})
}

func (r *WrapResource) ListGatewayTokens(ctx context.Context) ([]WrapGatewayToken, error) {
	res, err := doUnwrap[wrapGatewayTokenList](ctx, r.c, requestOpts{method: "GET", path: "/v1/wrap/tokens"})
	if err != nil {
		return nil, err
	}
	return res.Tokens, nil
}

// RevokeGatewayToken revokes a single gateway token by id
// (DELETE /v1/wrap/tokens/{id}), from GatewayURL or ListGatewayTokens. Like
// every mutating management request it goes through the client's request
// pipeline, inheriting auth, retry, envelope-unwrapping, and error mapping, and
// carries a stable idempotency key exactly as Secrets.Create does.
func (r *WrapResource) RevokeGatewayToken(ctx context.Context, id string) (*RevokeResult, error) {
	return doUnwrap[RevokeResult](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/wrap/tokens/" + encode(id)})
}
