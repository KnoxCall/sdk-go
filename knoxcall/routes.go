package knoxcall

import (
	"context"
	"iter"
	"net/url"
	"strconv"
)

// Route mirrors the server's route projections (src/client-api/routes.ts).
// List rows carry the core fields plus the aggregate rate-limit/signature
// columns; Get adds configured_environments (and, when a base-env
// config row exists, payload_structure/injection_rules/ip_allowlist);
// Create/Update return the full routes row (tenant_id, sandbox, …).
// Fields absent from a given response stay zero.
type Route struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Slug is the write-once machine handle — reference the route in code
	// via the slug (UUIDs also work; bare names are legacy).
	Slug *string `json:"slug"`
	// TargetBaseURL is derived from the base environment's config row; nil
	// only when the route has no environment configs.
	TargetBaseURL   *string `json:"target_base_url"`
	BaseEnvironment *string `json:"base_environment"`
	Enabled         bool    `json:"enabled"`
	RequiresClients bool    `json:"requires_clients"`
	// InterceptEnabled is the base environment's transparent-interception opt-in
	// (list + get projections; per-environment rows carry their own).
	InterceptEnabled bool    `json:"intercept_enabled"`
	CollectionID     *string `json:"collection_id"`
	CreatedAt        string  `json:"created_at"`

	// List/Get projections.
	EnvironmentOverrideCount int      `json:"environment_override_count"`
	RequireSignature         *bool    `json:"require_signature"`
	RateLimitEnabled         *bool    `json:"rate_limit_enabled"`
	RateLimitRequests        *int     `json:"rate_limit_requests"`
	RateLimitWindowSec       *int     `json:"rate_limit_window_sec"`
	AllowedMethods           []string `json:"allowed_methods"`

	// Get only.
	MTLSCertificateID      *string        `json:"mtls_certificate_id"`
	ConfiguredEnvironments []string       `json:"configured_environments"`
	PayloadStructure       map[string]any `json:"payload_structure"`
	InjectionRules         []any          `json:"injection_rules"`
	IPAllowlist            []string       `json:"ip_allowlist"`
	DataPlaneNodeID        *string        `json:"data_plane_node_id"`

	// Create/Update (full routes row) only.
	TenantID         string  `json:"tenant_id"`
	Sandbox          bool    `json:"sandbox"`
	EgressServerID   *string `json:"egress_server_id"`
	FaviconURL       *string `json:"favicon_url"`
	FaviconUpdatedAt *string `json:"favicon_updated_at"`
	FaviconData      *string `json:"favicon_data"`
}

// RequestLog is one api_requests row, returned by GET /v1/routes/{id}/logs and
// by GET /v1/logs.
//
// ONE type for one table, deliberately: a second struct for the second endpoint
// would drift silently the first time a column changed. The two endpoints
// project different subsets, so a field the endpoint you called does not return
// stays at its zero value — the fields below are grouped by which populates
// them.
//
// ID is a decimal STRING because api_requests.id is a bigint and a JSON number
// is a double, which cannot hold one exactly past 2^53.
//
// Method, Path and RateLimited are NOT pointers, so a null from the server
// decodes to "" / false rather than being distinguishable from an absent value.
// That predates GET /v1/logs and is left alone rather than widened here: making
// them pointers would break every existing caller of GET /v1/routes/{id}/logs
// for a distinction neither endpoint's consumers have asked for.
type RequestLog struct {
	ID              string  `json:"id"`
	RequestID       string  `json:"request_id"`
	Ts              string  `json:"ts"`
	SrcIP           *string `json:"src_ip,omitempty"`
	Method          string  `json:"method"`
	Path            string  `json:"path"`
	StatusCode      *int    `json:"status_code"`
	LatencyMs       *int    `json:"latency_ms"`
	UpstreamHost    *string `json:"upstream_host"`
	Error           *string `json:"error"`
	Environment     *string `json:"environment"`
	RateLimited     bool    `json:"rate_limited"`
	SignatureValid  *bool   `json:"signature_valid"`
	SourceIPCountry *string `json:"source_ip_country"`
	SourceIPCity    *string `json:"source_ip_city"`

	// ── GET /v1/logs only ───────────────────────────────────────────────────
	//
	// Together with ID, RequestID, SrcIP, Method, StatusCode, Environment and
	// Ts, the first block below is exactly what the Merkle anchor commits to.
	// See LogsResource.Proof.
	TenantID string  `json:"tenant_id,omitempty"`
	RouteID  *string `json:"route_id,omitempty"`
	// Identity tier: ABSENT (not null) unless the caller holds
	// log:read_identity. SrcIP is in the same tier.
	MatchedClientID *string `json:"matched_client_id,omitempty"`
	// Identity tier. How the caller was attributed: "ip", "mtls_thumbprint", …
	IdentificationMethod *string `json:"identification_method,omitempty"`
	// Live/Test partition. nil on rows written before the partition existed,
	// which are treated as Live. nil, false and true are three distinct facts
	// and the anchor keeps them apart.
	Sandbox   *bool   `json:"sandbox,omitempty"`
	ProxyMode *string `json:"proxy_mode,omitempty"`
	// How the call arrived at the Route: "sdk_intercept" when a KnoxCall SDK's
	// route-aware interceptor rerouted a third-party SDK's request (PARITY
	// §21.2), "direct" for a plain Call and for every row written before the
	// marker existed. Informational only.
	ClientOrigin string `json:"client_origin,omitempty"`
	// Opaque resume token. Pass the last row's value as CursorParams.Cursor.
	Cursor string `json:"cursor,omitempty"`
}

// RouteEnvironmentConfig is a route_environment_configs row. ListEnvironments
// returns the per-environment projection; UpsertEnvironment returns the full
// row (extra fields stay zero on the list projection).
type RouteEnvironmentConfig struct {
	EnvironmentName       string         `json:"environment_name"`
	TargetBaseURL         string         `json:"target_base_url"`
	InjectHeadersJSON     map[string]any `json:"inject_headers_json"`
	InjectBodyJSON        map[string]any `json:"inject_body_json"`
	RequireSignature      bool           `json:"require_signature"`
	SignatureToleranceSec int            `json:"signature_tolerance_sec"`
	RateLimitEnabled      bool           `json:"rate_limit_enabled"`
	RateLimitRequests     *int           `json:"rate_limit_requests"`
	RateLimitWindowSec    *int           `json:"rate_limit_window_sec"`
	RateLimitBurst        *int           `json:"rate_limit_burst"`
	AllowedMethods        []string       `json:"allowed_methods"`
	// Enabled is the per-environment serving switch — false pauses this
	// environment only (routes-level enabled is the route-wide kill switch).
	Enabled bool `json:"enabled"`
	// RequiresClients gates client authorization for this environment
	// (per-environment since migration 20260723).
	RequiresClients bool `json:"requires_clients"`
	// MTLSCertificateID is the certificate-type secret used for upstream
	// mTLS in this environment (nil = plain TLS).
	MTLSCertificateID *string `json:"mtls_certificate_id"`

	// Full-row fields (UpsertEnvironment only).
	ID                            string         `json:"id"`
	RouteID                       string         `json:"route_id"`
	CreatedAt                     string         `json:"created_at"`
	UpdatedAt                     string         `json:"updated_at"`
	MethodConfigs                 []any          `json:"method_configs"`
	UseMethodSpecificConfigs      *bool          `json:"use_method_specific_configs"`
	HTTPMethodRestrictionsEnabled *bool          `json:"http_method_restrictions_enabled"`
	EgressServerID                *string        `json:"egress_server_id"`
	PayloadStructure              map[string]any `json:"payload_structure"`
	InjectionRules                []any          `json:"injection_rules"`
	IPAllowlist                   []string       `json:"ip_allowlist"`
	DataPlaneNodeID               *string        `json:"data_plane_node_id"`
	InterceptEnabled              bool           `json:"intercept_enabled"`
}

// RouteAction is a declarative field-level encrypt/decrypt/tokenize/
// detokenize action the proxy applies to a route (Relay field-actions).
type RouteAction struct {
	ID          string   `json:"id"`
	RouteID     string   `json:"route_id"`
	TenantID    string   `json:"tenant_id"`
	Direction   string   `json:"direction"` // "request" | "response"
	Action      string   `json:"action"`    // "encrypt" | "decrypt" | "tokenize" | "detokenize"
	Selectors   []string `json:"selectors"`
	KeyName     *string  `json:"key_name"`
	DataRole    *string  `json:"data_role"`
	ContentType string   `json:"content_type"`
	SortOrder   int      `json:"sort_order"`
	Enabled     bool     `json:"enabled"`
}

// ListRoutesParams selects a page of routes plus the endpoint's filters.
type ListRoutesParams struct {
	Page    int
	PerPage int
	// Enabled filters by enabled state when non-nil.
	Enabled *bool
}

func (p *ListRoutesParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setPageQuery(q, p.Page, p.PerPage)
	if p.Enabled != nil {
		q.Set("enabled", strconv.FormatBool(*p.Enabled))
	}
	return q
}

type CreateRouteInput struct {
	Name string `json:"name"`
	// Slug is the write-once machine handle (1-63 chars, [a-z0-9-]). Omit to
	// derive "{collection}-{name}" automatically. Immutable once set.
	Slug              string         `json:"slug,omitempty"`
	TargetBaseURL     string         `json:"target_base_url"`
	BaseEnvironment   string         `json:"base_environment,omitempty"`
	InjectHeadersJSON map[string]any `json:"inject_headers_json,omitempty"`
	InjectBodyJSON    map[string]any `json:"inject_body_json,omitempty"`
	// InterceptEnabled opts the base environment into transparent interception
	// (the agent's intercept mode and the SDKs' wrap.Intercept).
	InterceptEnabled *bool `json:"intercept_enabled,omitempty"`
	// Deprecated: never applied to any request. The API rejects a non-empty
	// value with 400 (wave-2 row 2-273). Use {{secret_id:<uuid>}} /
	// {{secret:<name>}} placeholders in the request body your client sends;
	// an empty array is still accepted as a no-op. Retained so the API's own
	// explanatory refusal reaches the caller instead of a bare compile error.
	InjectionRules []any    `json:"injection_rules,omitempty"`
	IPAllowlist    []string `json:"ip_allowlist,omitempty"`
	MethodConfigs  []any    `json:"method_configs,omitempty"`
	CollectionID   string   `json:"collection_id,omitempty"`
}

type UpdateRouteInput struct {
	Name *string `json:"name,omitempty"`
	// Slug is settable only while the route has none, immutable after.
	Slug            *string `json:"slug,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
	RequiresClients *bool   `json:"requires_clients,omitempty"`
	// InterceptEnabled opts the base environment into transparent interception
	// (the agent's intercept mode and the SDKs' wrap.Intercept).
	InterceptEnabled  *bool          `json:"intercept_enabled,omitempty"`
	TargetBaseURL     *string        `json:"target_base_url,omitempty"`
	InjectHeadersJSON map[string]any `json:"inject_headers_json,omitempty"`
	InjectBodyJSON    map[string]any `json:"inject_body_json,omitempty"`
	// Deprecated: never applied to any request. The API rejects a non-empty
	// value with 400 (wave-2 row 2-273). Use {{secret_id:<uuid>}} /
	// {{secret:<name>}} placeholders in the request body your client sends;
	// an empty array is still accepted as a no-op. Retained so the API's own
	// explanatory refusal reaches the caller instead of a bare compile error.
	InjectionRules                []any    `json:"injection_rules,omitempty"`
	MethodConfigs                 []any    `json:"method_configs,omitempty"`
	IPAllowlist                   []string `json:"ip_allowlist,omitempty"`
	RequireSignature              *bool    `json:"require_signature,omitempty"`
	SignatureToleranceSec         *int     `json:"signature_tolerance_sec,omitempty"`
	RateLimitEnabled              *bool    `json:"rate_limit_enabled,omitempty"`
	RateLimitRequests             *int     `json:"rate_limit_requests,omitempty"`
	RateLimitWindowSec            *int     `json:"rate_limit_window_sec,omitempty"`
	RateLimitBurst                *int     `json:"rate_limit_burst,omitempty"`
	AllowedMethods                []string `json:"allowed_methods,omitempty"`
	HTTPMethodRestrictionsEnabled *bool    `json:"http_method_restrictions_enabled,omitempty"`
	EgressServerID                *string  `json:"egress_server_id,omitempty"`
	DataPlaneNodeID               *string  `json:"data_plane_node_id,omitempty"`
}

type RouteEnvironmentInput struct {
	TargetBaseURL     *string        `json:"target_base_url,omitempty"`
	InjectHeadersJSON map[string]any `json:"inject_headers_json,omitempty"`
	InjectBodyJSON    map[string]any `json:"inject_body_json,omitempty"`
	// Deprecated: never applied to any request. The API rejects a non-empty
	// value with 400 (wave-2 row 2-273). Use {{secret_id:<uuid>}} /
	// {{secret:<name>}} placeholders in the request body your client sends;
	// an empty array is still accepted as a no-op. Retained so the API's own
	// explanatory refusal reaches the caller instead of a bare compile error.
	InjectionRules        []any    `json:"injection_rules,omitempty"`
	IPAllowlist           []string `json:"ip_allowlist,omitempty"`
	RequireSignature      *bool    `json:"require_signature,omitempty"`
	SignatureToleranceSec *int     `json:"signature_tolerance_sec,omitempty"`
	RateLimitEnabled      *bool    `json:"rate_limit_enabled,omitempty"`
	RateLimitRequests     *int     `json:"rate_limit_requests,omitempty"`
	RateLimitWindowSec    *int     `json:"rate_limit_window_sec,omitempty"`
	RateLimitBurst        *int     `json:"rate_limit_burst,omitempty"`
	AllowedMethods        []string `json:"allowed_methods,omitempty"`
	// InterceptEnabled opts this environment into transparent interception
	// (the agent's intercept mode and the SDKs' wrap.Intercept).
	InterceptEnabled *bool `json:"intercept_enabled,omitempty"`
}

// CreateRouteActionInput creates a Relay field-action on a route.
type CreateRouteActionInput struct {
	Direction   string   `json:"direction"` // "request" | "response"
	Action      string   `json:"action"`    // "encrypt" | "decrypt" | "tokenize" | "detokenize"
	Selectors   []string `json:"selectors"`
	KeyName     string   `json:"key_name,omitempty"`
	DataRole    string   `json:"data_role,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	SortOrder   *int     `json:"sort_order,omitempty"`
}

type RoutesResource struct{ c *Client }

// List returns one page of routes (server default 20/page, cap 100).
func (r *RoutesResource) List(ctx context.Context, params *ListRoutesParams) (*Page[Route], error) {
	return doPage[Route](ctx, r.c, requestOpts{method: "GET", path: "/v1/routes", query: params.query()})
}

// ListAll walks every page starting at params.Page (default 1) and returns
// all routes.
func (r *RoutesResource) ListAll(ctx context.Context, params *ListRoutesParams) ([]Route, error) {
	p := ListRoutesParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Route], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every route one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *RoutesResource) Iterate(ctx context.Context, params *ListRoutesParams) iter.Seq2[Route, error] {
	p := ListRoutesParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Route], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *RoutesResource) Get(ctx context.Context, routeID string) (*Route, error) {
	return doUnwrap[Route](ctx, r.c, requestOpts{method: "GET", path: "/v1/routes/" + encode(routeID)})
}

func (r *RoutesResource) Create(ctx context.Context, input CreateRouteInput) (*Route, error) {
	return doUnwrap[Route](ctx, r.c, requestOpts{method: "POST", path: "/v1/routes", body: input})
}

func (r *RoutesResource) Update(ctx context.Context, routeID string, input UpdateRouteInput) (*Route, error) {
	return doUnwrap[Route](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/routes/" + encode(routeID), body: input})
}

func (r *RoutesResource) Delete(ctx context.Context, routeID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/routes/" + encode(routeID)})
}

// GetLogs returns one page of the route's request logs.
func (r *RoutesResource) GetLogs(ctx context.Context, routeID string, params *ListParams) (*Page[RequestLog], error) {
	return doPage[RequestLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/routes/" + encode(routeID) + "/logs", query: params.query()})
}

// ListEnvironments returns the route's environment configs (bare array —
// not paginated).
func (r *RoutesResource) ListEnvironments(ctx context.Context, routeID string) ([]RouteEnvironmentConfig, error) {
	return doSlice[RouteEnvironmentConfig](ctx, r.c, requestOpts{method: "GET", path: "/v1/routes/" + encode(routeID) + "/environments"})
}

func (r *RoutesResource) UpsertEnvironment(ctx context.Context, routeID, envName string, input RouteEnvironmentInput) (*RouteEnvironmentConfig, error) {
	return doUnwrap[RouteEnvironmentConfig](ctx, r.c, requestOpts{method: "PUT", path: "/v1/routes/" + encode(routeID) + "/environments/" + encode(envName), body: input})
}

func (r *RoutesResource) DeleteEnvironment(ctx context.Context, routeID, envName string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/routes/" + encode(routeID) + "/environments/" + encode(envName)})
}

// -- Relay field-actions (declarative field-level encrypt/decrypt/tokenize) ----

// ListActions returns the route's Relay field-actions (bare array).
func (r *RoutesResource) ListActions(ctx context.Context, routeID string) ([]RouteAction, error) {
	return doSlice[RouteAction](ctx, r.c, requestOpts{method: "GET", path: "/v1/routes/" + encode(routeID) + "/actions"})
}

// CreateAction adds a Relay field-action to the route.
func (r *RoutesResource) CreateAction(ctx context.Context, routeID string, input CreateRouteActionInput) (*RouteAction, error) {
	return doUnwrap[RouteAction](ctx, r.c, requestOpts{method: "POST", path: "/v1/routes/" + encode(routeID) + "/actions", body: input})
}

// DeleteAction removes a Relay field-action; the response echoes the action
// id as {deleted: "<actionId>"}.
func (r *RoutesResource) DeleteAction(ctx context.Context, routeID, actionID string) (*DeletedNameResponse, error) {
	return doUnwrap[DeletedNameResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/routes/" + encode(routeID) + "/actions/" + encode(actionID)})
}
