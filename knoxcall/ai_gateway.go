package knoxcall

import (
	"context"
	"iter"
	"net/url"
)

// AI Gateway control plane (src/client-api/ai-gateway.ts) — gateways, their
// agents, per-agent phantom tokens, and cost/usage rollups. Follows the SDK's
// flat-method convention for sub-collections (like Routes.ListActions): the
// gateway/agent/token nesting is expressed with method-name prefixes
// (ListGateways/CreateAgent/MintToken/…) on a single AIGatewayResource, not
// nested sub-namespaces. All responses use the {data, meta} envelope; lists are
// page/per_page paginated (PARITY §4).
//
// Sandbox is unchanged: a sandbox (test) client mints test-env tokens
// server-side from the token string + route env — there is no env parameter on
// any method here.

// AIGateway is one ai_gateways row (rowToGateway in the service). Budget fields
// are pg numerics serialized as strings (nil when unset).
type AIGateway struct {
	ID               string  `json:"id"`
	TenantID         string  `json:"tenant_id"`
	Name             string  `json:"name"`
	Slug             string  `json:"slug"`
	Description      *string `json:"description"`
	BudgetDailyUSD   *string `json:"budget_daily_usd"`
	BudgetMonthlyUSD *string `json:"budget_monthly_usd"`
	// BudgetOverageAction is what happens when a cap above is spent (AIGW-150):
	// "block" refuses on BOTH data planes, "warn" serves and emits the
	// X-Knox-AI-Budget-* headers. No "fallback" — that action swaps an agent's
	// route and model, which a gateway does not have.
	BudgetOverageAction string  `json:"budget_overage_action,omitempty"`
	Status              string  `json:"status"` // "active" | "paused" | "archived"
	PausedReason        *string `json:"paused_reason"`
	// ModelAliases are shared by every agent under this gateway (AIGW-42):
	// {alias: real_model_id}. Resolved BEFORE the per-agent model policy, so an
	// alias target is still subject to that agent's allow/deny list — an alias
	// is a naming convenience, never a way around a control.
	ModelAliases map[string]string `json:"model_aliases,omitempty"`
	CreatedAt    string            `json:"created_at"`
	UpdatedAt    string            `json:"updated_at"`
	CreatedBy    *string           `json:"created_by"`
}

// AIGatewayAgent is one ai_gateway_agents row (rowToAgent in the service). It
// mirrors every column the service projects; numeric budget/similarity fields
// arrive from pg as strings.
type AIGatewayAgent struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenant_id"`
	GatewayID   string  `json:"gateway_id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Description *string `json:"description"`

	PrimaryRouteID   *string  `json:"primary_route_id"`
	FallbackRouteIDs []string `json:"fallback_route_ids"`

	ModelAllowlist []string          `json:"model_allowlist"`
	ModelDenylist  []string          `json:"model_denylist"`
	DefaultModel   *string           `json:"default_model"`
	ModelRewrite   map[string]string `json:"model_rewrite"`

	BudgetDailyUSD         *string `json:"budget_daily_usd"`
	BudgetMonthlyUSD       *string `json:"budget_monthly_usd"`
	BudgetPerCallMaxTokens *int    `json:"budget_per_call_max_tokens"`
	BudgetOverageAction    string  `json:"budget_overage_action"` // "block" | "warn" | "fallback"
	FallbackAgentID        *string `json:"fallback_agent_id"`

	PIIRedactPolicyID *string `json:"pii_redact_policy_id"`
	// PIIDetokenizeResponse is AIGW-100's read-only mirror of
	// PIIResponseMode == "detokenize"; the column is GENERATED server-side.
	PIIDetokenizeResponse bool `json:"pii_detokenize_response"`
	// PIIRequestMode is "off" | "tokenize": what happens to the PROMPT before
	// it leaves KnoxCall. "off" is the only mode on which the provider receives
	// the real value.
	PIIRequestMode string `json:"pii_request_mode"`
	// PIIResponseMode is "redact" | "detokenize": what happens to the answer.
	PIIResponseMode           string `json:"pii_response_mode"`
	PIIStreamingHoldbackChars int    `json:"pii_streaming_holdback_chars"`
	// PIIStreamingMode is "holdback" | "buffer" | "monitor". "monitor" reports
	// detections without rewriting the stream, so the raw value reaches the
	// client — read it before concluding a streamed answer was redacted.
	PIIStreamingMode string `json:"pii_streaming_mode"`

	// Tags are the agent's FinOps attribution labels (cost_center/team/…).
	//
	// A field absent from this struct is DROPPED by encoding/json on unmarshal
	// with no error, so a read model that lags the API is a silently invisible
	// setting: tags, PIIStreamingMode and Provider were all settable server-side
	// and unreadable here until AIGW-161.
	Tags map[string]string `json:"tags"`
	// Provider is the upstream shape this agent fronts (any id in the
	// server-side catalog; AIProviderIDs is the convenience copy, not a
	// validation set). Set once, at create time — it is
	// deliberately NOT patchable, because changing it without re-pointing
	// PrimaryRouteID at a matching route would make the stored value a lie.
	// nil on a pre-AIGW-20 agent whose route shape the backfill did not
	// recognise; render that as "custom", never as a guess.
	Provider *string `json:"provider"`

	CacheMode                string  `json:"cache_mode"` // "off" | "exact" | "semantic"
	CacheTTLSeconds          int     `json:"cache_ttl_seconds"`
	CacheSimilarityThreshold string  `json:"cache_similarity_threshold"`
	CacheEmbeddingModel      *string `json:"cache_embedding_model"`

	StreamingEnabled       bool           `json:"streaming_enabled"`
	FirewallPolicyID       *string        `json:"firewall_policy_id"`
	ToolAllowlist          []string       `json:"tool_allowlist"`
	OutputSchema           map[string]any `json:"output_schema"`
	OutputValidationAction string         `json:"output_validation_action"` // "block" | "retry" | "warn"

	// AIGW-45: the external guardrail webhook. Mode is the STRING "off" when the
	// agent has no hook — never a boolean, whatever an unquoted YAML enum in an
	// older copy of the spec may have implied.
	GuardrailWebhookURL           *string `json:"guardrail_webhook_url"`
	GuardrailWebhookSecretID      *string `json:"guardrail_webhook_secret_id"`
	GuardrailWebhookMode          string  `json:"guardrail_webhook_mode"`           // "off" | "request" | "response" | "both"
	GuardrailWebhookTimeoutMs     int     `json:"guardrail_webhook_timeout_ms"`     // clamped [100, 10000], defaults to 2000
	GuardrailWebhookFailureAction string  `json:"guardrail_webhook_failure_action"` // "fail_open" | "fail_closed"

	// AIGW-42: retry and fail-over policy. Empty on an agent that never set one.
	RoutingPolicy *AIGatewayRoutingPolicy `json:"routing_policy,omitempty"`

	DataResidencyRegion *string `json:"data_residency_region"`
	CMEKKeyID           *string `json:"cmek_key_id"`
	Status              string  `json:"status"` // "active" | "paused" | "archived"
	PausedReason        *string `json:"paused_reason"`

	// AgentURL is the data-plane base URL for this agent --
	// https://{tenant}.knoxcall.com/v1/ai/{slug}. Point an AI SDK base_url
	// here and give it a capability token as the API key. Server-computed, not
	// stored: it MOVES when Slug changes. Empty when the tenant slug cannot be
	// resolved, so treat "" as "not available" rather than as a URL.
	AgentURL string `json:"agent_url"`

	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
	CreatedBy *string `json:"created_by"`
}

// AIGatewayToken is one phantom-token list row. The plaintext token is NEVER
// present here — it is shown once by MintToken and never again.
type AIGatewayToken struct {
	ID           string         `json:"id"`
	Name         *string        `json:"name"`
	Kind         string         `json:"kind"` // "agent" | "read" | "tool" | "oneshot"
	Prefix       string         `json:"prefix"`
	DPoPRequired bool           `json:"dpop_required"`
	Scope        map[string]any `json:"scope_jsonb"`
	ExpiresAt    *string        `json:"expires_at"`
	RevokedAt    *string        `json:"revoked_at"`
	LastUsedAt   *string        `json:"last_used_at"`
	CreatedAt    string         `json:"created_at"`
}

// AIGatewayMintedToken is the POST …/tokens result. Token is the plaintext
// value shown EXACTLY ONCE — store it immediately.
type AIGatewayMintedToken struct {
	ID           string  `json:"id"`
	Name         *string `json:"name"`
	Kind         string  `json:"kind"`
	Prefix       string  `json:"prefix"`
	Token        string  `json:"token"` // plaintext — shown once
	DPoPRequired bool    `json:"dpop_required"`
	ExpiresAt    *string `json:"expires_at"`
}

// AIGatewayArchived is the DELETE result for a gateway/agent (soft archive):
// {id, status}.
type AIGatewayArchived struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// AIGatewayTokenRevoked is the token-revoke result: {id, revoked:true}.
type AIGatewayTokenRevoked struct {
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}

// AIGatewayUsage is the GET …/usage rollup: totals plus a per-model breakdown
// over the requested window.
type AIGatewayUsage struct {
	PeriodDays int                     `json:"period_days"`
	ByModel    []AIGatewayUsageByModel `json:"by_model"`
	Totals     AIGatewayUsageTotals    `json:"totals"`
}

// AIGatewayUsageByModel is one (provider, model) row of the usage breakdown.
type AIGatewayUsageByModel struct {
	Provider         string  `json:"provider"`
	Model            string  `json:"model"`
	Requests         int     `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	UnpricedRequests int     `json:"unpriced_requests"`
}

// AIGatewayUsageTotals sums the breakdown across every model.
type AIGatewayUsageTotals struct {
	Requests         int     `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	UnpricedRequests int     `json:"unpriced_requests"`
}

// AIGatewayUsageExport is the GET …/usage/export result (the SDK always
// requests format=json): the grouping key, the window in days, and one
// aggregated FinOps row per group.
type AIGatewayUsageExport struct {
	GroupBy    string                    `json:"group_by"`
	PeriodDays int                       `json:"period_days"`
	Rows       []AIGatewayUsageExportRow `json:"rows"`
}

// AIGatewayUsageExportRow is one aggregated row of a usage export. Group is nil
// for the null/unattributed bucket (e.g. requests with no team or tag value).
type AIGatewayUsageExportRow struct {
	Group            *string `json:"group"`
	Requests         int     `json:"requests"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	UnpricedRequests int     `json:"unpriced_requests"`
}

// -- Inputs --------------------------------------------------------------------

// CreateAIGatewayInput is the POST /v1/ai-gateway/gateways body.
type CreateAIGatewayInput struct {
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Description      string   `json:"description,omitempty"`
	BudgetDailyUSD   *float64 `json:"budget_daily_usd,omitempty"`
	BudgetMonthlyUSD *float64 `json:"budget_monthly_usd,omitempty"`
	// BudgetOverageAction: "block" (default) or "warn". AIGW-150.
	BudgetOverageAction string `json:"budget_overage_action,omitempty"`
	// ModelAliases: {alias: real_model_id}, max 100 entries. AIGW-42.
	ModelAliases map[string]string `json:"model_aliases,omitempty"`
}

// UpdateAIGatewayInput is the PATCH /v1/ai-gateway/gateways/{id} body. Only the
// non-nil fields are sent.
type UpdateAIGatewayInput struct {
	Name             *string  `json:"name,omitempty"`
	Description      *string  `json:"description,omitempty"`
	BudgetDailyUSD   *float64 `json:"budget_daily_usd,omitempty"`
	BudgetMonthlyUSD *float64 `json:"budget_monthly_usd,omitempty"`
	// BudgetOverageAction: "block" or "warn". AIGW-150.
	BudgetOverageAction string `json:"budget_overage_action,omitempty"`
	// ModelAliases replaces the whole map; an empty non-nil map clears it.
	ModelAliases map[string]string `json:"model_aliases,omitempty"`
}

// AIProviderIDs is a CONVENIENCE list of provider ids, for prompts and
// completions -- not a validation set. The catalog is server-side and has
// grown from six ids to fourteen; CreateAIGatewayAgentInput.Provider is a
// plain string so a provider added server-side works without an SDK release
// (sdk/PARITY.md -- "SDKs do not enumerate the list in code"). Do not gate a
// call on membership here: send the string and surface the server's 400,
// which names the valid set.
//
// Upstream is required for the four providers whose endpoint is yours rather
// than the vendor's: azure-openai, ollama, bedrock and openai-compatible.
// Creating an agent on one of those four without Upstream is a 400, not a
// default; openai-compatible also needs DefaultModel.
var AIProviderIDs = []string{
	"anthropic", "openai", "gemini", "cohere", "azure-openai", "ollama",
	"groq", "together", "mistral", "deepseek", "fireworks", "xai",
	"bedrock", "openai-compatible",
}

// AIGatewayRoutingPolicy is how one agent retries and spreads load (AIGW-42).
// An empty policy — the default for every agent — means one attempt per route
// and fail-over to FallbackRouteIDs on 5xx only, which is the behaviour the
// gateway has always had.
//
// Every field is clamped server-side: a request parked waiting to retry holds
// one of the gateway's API workers, so MaxAttempts caps at 5, any single delay
// at 30s, a honoured Retry-After at 60s, and the total sleep for one request at
// 60s however the fields combine.
type AIGatewayRoutingPolicy struct {
	// MaxAttempts is attempts per candidate route, including the first. The
	// server forces it to 1 when RetryOn is empty, so a stored policy never
	// claims a retry that cannot happen.
	MaxAttempts *int `json:"max_attempts,omitempty"`
	// RetryOn are the conditions that trigger a retry. Empty disables retrying.
	RetryOn []string `json:"retry_on,omitempty"`
	// BackoffMs is the delay before the second attempt.
	BackoffMs         *int     `json:"backoff_ms,omitempty"`
	BackoffMultiplier *float64 `json:"backoff_multiplier,omitempty"`
	MaxBackoffMs      *int     `json:"max_backoff_ms,omitempty"`
	// Jitter defaults to true: spreads each delay across 50-100% of its computed
	// value so a fleet does not retry in lockstep.
	Jitter *bool `json:"jitter,omitempty"`
	// RespectRetryAfter defaults to true. An upstream Retry-After is honoured
	// when it asks for LONGER than the computed backoff — it can extend a wait,
	// never shorten one.
	RespectRetryAfter *bool `json:"respect_retry_after,omitempty"`
	MaxRetryAfterMs   *int  `json:"max_retry_after_ms,omitempty"`
}

// CreateAIGatewayAgentInput is the POST …/gateways/{gatewayId}/agents body.
type CreateAIGatewayAgentInput struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`

	// PrimaryRouteID is the route carrying the upstream provider credential.
	// Supply this OR Provider, never both (400) - and supplying NEITHER
	// creates an agent with no upstream, whose first data-plane call 502s.
	PrimaryRouteID string `json:"primary_route_id,omitempty"`

	// Provider composes the upstream route instead of PrimaryRouteID:
	// KnoxCall creates an `ai-gateway-<slug>` route for it, injecting
	// UpstreamSecretID through the envelope store, and sets the default model
	// from its pricebook default. One of AIProviderIDs.
	//
	// The route is created in the CALLING KEY's data space: a token minted in
	// one environment is refused against a route in the other.
	Provider string `json:"provider,omitempty"`
	// UpstreamSecretID is REQUIRED with Provider: the KnoxCall secret holding
	// the provider key. Referenced, never copied.
	UpstreamSecretID string `json:"upstream_secret_id,omitempty"`
	// Upstream is the base URL, required for the four providers whose endpoint
	// is yours rather than the vendor's: azure-openai, ollama, bedrock and
	// openai-compatible. Ignored for the rest, whose origin is fixed.
	//
	// It is not defaulted: a bedrock or openai-compatible agent created
	// without Upstream is refused with a 400 at create time.
	Upstream string `json:"upstream,omitempty"`

	DefaultModel      string   `json:"default_model,omitempty"`
	ModelAllowlist    []string `json:"model_allowlist,omitempty"`
	ModelDenylist     []string `json:"model_denylist,omitempty"`
	BudgetDailyUSD    *float64 `json:"budget_daily_usd,omitempty"`
	BudgetMonthlyUSD  *float64 `json:"budget_monthly_usd,omitempty"`
	StreamingEnabled  *bool    `json:"streaming_enabled,omitempty"`
	FirewallPolicyID  string   `json:"firewall_policy_id,omitempty"`
	PIIRedactPolicyID string   `json:"pii_redact_policy_id,omitempty"`
	// PIIRequestMode is AIGW-100's "off" | "tokenize": what happens to the
	// PROMPT before it leaves KnoxCall. Empty means the server default,
	// "tokenize". "off" is the only mode on which the provider receives the
	// real value, so a declarative caller has to write it down.
	PIIRequestMode string `json:"pii_request_mode,omitempty"`
	// PIIResponseMode is "redact" | "detokenize" (server default
	// "detokenize"): what happens to the provider's answer.
	PIIResponseMode string `json:"pii_response_mode,omitempty"`

	// AIGW-45. The destination is resolved and refused at write time AND on
	// every call, so a private, loopback, link-local or cloud-metadata address
	// is a 400 here — DNS is not a promise.
	GuardrailWebhookURL           string `json:"guardrail_webhook_url,omitempty"`
	GuardrailWebhookSecretID      string `json:"guardrail_webhook_secret_id,omitempty"`
	GuardrailWebhookMode          string `json:"guardrail_webhook_mode,omitempty"`
	GuardrailWebhookTimeoutMs     *int   `json:"guardrail_webhook_timeout_ms,omitempty"`
	GuardrailWebhookFailureAction string `json:"guardrail_webhook_failure_action,omitempty"`

	// AIGW-42.
	RoutingPolicy *AIGatewayRoutingPolicy `json:"routing_policy,omitempty"`

	// Everything below is accepted at CREATE and was reachable only by a
	// follow-up PATCH until 2026-09-15. That gap is why the Terraform provider
	// parks 17 of these columns: a create-then-patch apply whose second call
	// fails leaves an agent that is not what the plan showed.
	FallbackRouteIDs []string `json:"fallback_route_ids,omitempty"`
	// ModelRewrite maps a requested model onto the one actually called.
	ModelRewrite           map[string]string `json:"model_rewrite,omitempty"`
	BudgetPerCallMaxTokens *int              `json:"budget_per_call_max_tokens,omitempty"`
	// BudgetOverageAction is "block" | "warn" | "fallback"; "fallback" needs
	// FallbackAgentID, or the overage behaves as "block".
	BudgetOverageAction string `json:"budget_overage_action,omitempty"`
	FallbackAgentID     string `json:"fallback_agent_id,omitempty"`
	// PIIDetokenizeResponse is AIGW-100's legacy alias for PIIResponseMode.
	// Sending both with contradictory values is a 400.
	//
	// Deprecated: set PIIResponseMode instead.
	PIIDetokenizeResponse     *bool `json:"pii_detokenize_response,omitempty"`
	PIIStreamingHoldbackChars *int  `json:"pii_streaming_holdback_chars,omitempty"`
	// PIIStreamingMode is "holdback" | "buffer" | "monitor": how a STREAMED
	// answer is rewritten. "monitor" REPORTS detections without rewriting, so
	// the raw value reaches the client — observability, not redaction.
	PIIStreamingMode string `json:"pii_streaming_mode,omitempty"`
	// Tags are FinOps attribution labels echoed onto this agent's usage rows.
	Tags map[string]string `json:"tags,omitempty"`

	// CacheMode is "off" | "exact" | "semantic"; "semantic" also needs
	// CacheEmbeddingModel or the cache reports itself degraded and serves
	// nothing.
	CacheMode       string `json:"cache_mode,omitempty"`
	CacheTTLSeconds *int   `json:"cache_ttl_seconds,omitempty"`
	// CacheSimilarityThreshold is the cosine floor for a semantic hit, 0..1.
	// Lower means more hits and more wrong ones.
	CacheSimilarityThreshold *float64 `json:"cache_similarity_threshold,omitempty"`
	CacheEmbeddingModel      string   `json:"cache_embedding_model,omitempty"`

	ToolAllowlist []string `json:"tool_allowlist,omitempty"`
	// OutputSchema is the JSON Schema the answer is validated against.
	OutputSchema map[string]any `json:"output_schema,omitempty"`
	// OutputValidationAction is "block" | "retry" | "warn".
	OutputValidationAction string `json:"output_validation_action,omitempty"`

	// DataResidencyRegion is one of us|eu|uk|ca|au|jp|in — anything else is a
	// 400. Not a cloud region id.
	DataResidencyRegion string `json:"data_residency_region,omitempty"`
	CMEKKeyID           string `json:"cmek_key_id,omitempty"`
}

// UpdateAIGatewayAgentInput is the PATCH …/agents/{agentId} body. Only the
// non-nil/non-empty fields are sent (the server applies a field allowlist).
//
// Every field here must correspond to a column the server's UPDATABLE_COLUMNS
// accepts, and every one of those columns must appear here: a typed patch input
// is the only thing between a caller and a server capability, so a field
// missing here is a feature this SDK does not have. Pinned from the server side
// by tests/coverage/ai-gateway-sdk-typed-patch-parity.test.ts.
//
// KNOWN LIMITATION (FOLLOW-UPS §6, 2026-09-12): `omitempty` on a slice or map omits the EMPTY
// value as well as nil, so a collection field cannot be CLEARED through this
// struct — `Tags: map[string]string{}` is indistinguishable on the wire from
// not setting Tags at all. Clearing one needs the free-form Do() escape hatch
// until the module's Go floor allows `omitzero` (go1.24), which omits only nil.
type UpdateAIGatewayAgentInput struct {
	Name *string `json:"name,omitempty"`
	// Slug RENAMES the agent, which MOVES its data-plane URL: the server
	// computes AgentURL from the slug, so every caller pointed at the old one
	// gets a 404 from the moment this lands. Re-read AgentURL after a rename.
	Slug             *string  `json:"slug,omitempty"`
	Description      *string  `json:"description,omitempty"`
	PrimaryRouteID   *string  `json:"primary_route_id,omitempty"`
	FallbackRouteIDs []string `json:"fallback_route_ids,omitempty"`
	DefaultModel     *string  `json:"default_model,omitempty"`
	ModelAllowlist   []string `json:"model_allowlist,omitempty"`
	ModelDenylist    []string `json:"model_denylist,omitempty"`
	// ModelRewrite maps a requested model onto the one actually called.
	ModelRewrite           map[string]string `json:"model_rewrite,omitempty"`
	BudgetDailyUSD         *float64          `json:"budget_daily_usd,omitempty"`
	BudgetMonthlyUSD       *float64          `json:"budget_monthly_usd,omitempty"`
	BudgetPerCallMaxTokens *int              `json:"budget_per_call_max_tokens,omitempty"`
	// BudgetOverageAction is "block" | "warn" | "fallback"; "fallback" needs
	// FallbackAgentID set, or the overage behaves as "block".
	BudgetOverageAction *string `json:"budget_overage_action,omitempty"`
	FallbackAgentID     *string `json:"fallback_agent_id,omitempty"`
	StreamingEnabled    *bool   `json:"streaming_enabled,omitempty"`
	FirewallPolicyID    *string `json:"firewall_policy_id,omitempty"`
	PIIRedactPolicyID   *string `json:"pii_redact_policy_id,omitempty"`
	// Deprecated: AIGW-100 legacy alias for PIIResponseMode. Sending both with
	// contradictory values is a 400.
	PIIDetokenizeResponse *bool `json:"pii_detokenize_response,omitempty"`
	// PIIRequestMode is "off" | "tokenize" (server default "tokenize").
	PIIRequestMode *string `json:"pii_request_mode,omitempty"`
	// PIIResponseMode is "redact" | "detokenize" (server default "detokenize").
	PIIResponseMode           *string `json:"pii_response_mode,omitempty"`
	PIIStreamingHoldbackChars *int    `json:"pii_streaming_holdback_chars,omitempty"`
	// PIIStreamingMode is "holdback" | "buffer" | "monitor": how a STREAMED
	// answer is rewritten. "monitor" detects and reports without rewriting, so
	// the raw value reaches the client — it is an observability mode, not a
	// redaction one.
	PIIStreamingMode *string `json:"pii_streaming_mode,omitempty"`
	// Tags are FinOps attribution labels (cost_center/team/project/…) echoed
	// onto this agent's usage rows.
	Tags map[string]string `json:"tags,omitempty"`

	// CacheMode is "off" | "exact" | "semantic"; "semantic" additionally needs
	// CacheEmbeddingModel.
	CacheMode       *string `json:"cache_mode,omitempty"`
	CacheTTLSeconds *int    `json:"cache_ttl_seconds,omitempty"`
	// CacheSimilarityThreshold is the cosine floor for a semantic cache hit,
	// 0..1. Lower means more hits and more wrong ones.
	CacheSimilarityThreshold *float64 `json:"cache_similarity_threshold,omitempty"`
	CacheEmbeddingModel      *string  `json:"cache_embedding_model,omitempty"`

	ToolAllowlist []string `json:"tool_allowlist,omitempty"`
	// OutputSchema is the JSON Schema the answer is validated against.
	OutputSchema map[string]any `json:"output_schema,omitempty"`
	// OutputValidationAction is "block" | "retry" | "warn".
	OutputValidationAction *string `json:"output_validation_action,omitempty"`

	DataResidencyRegion *string `json:"data_residency_region,omitempty"`
	CMEKKeyID           *string `json:"cmek_key_id,omitempty"`

	// AIGW-45. A pointer to the empty string clears the hook; omitting the field
	// leaves whatever is stored, which is what the server's allowlist expects.
	GuardrailWebhookURL           *string `json:"guardrail_webhook_url,omitempty"`
	GuardrailWebhookSecretID      *string `json:"guardrail_webhook_secret_id,omitempty"`
	GuardrailWebhookMode          *string `json:"guardrail_webhook_mode,omitempty"`
	GuardrailWebhookTimeoutMs     *int    `json:"guardrail_webhook_timeout_ms,omitempty"`
	GuardrailWebhookFailureAction *string `json:"guardrail_webhook_failure_action,omitempty"`

	// AIGW-42.
	RoutingPolicy *AIGatewayRoutingPolicy `json:"routing_policy,omitempty"`
}

// MintAIGatewayTokenInput is the POST …/agents/{agentId}/tokens body. When
// DPoPRequired is set the server requires DPoPJKT (the base64url SHA-256
// thumbprint of the caller's DPoP public key).
type MintAIGatewayTokenInput struct {
	Name         string `json:"name,omitempty"`
	Kind         string `json:"kind,omitempty"` // "agent" | "read" | "tool" | "oneshot"
	DPoPRequired bool   `json:"dpop_required,omitempty"`
	DPoPJKT      string `json:"dpop_jkt,omitempty"`
	// Defaults to 30 days when omitted; clamped to [60s, 90d]. A non-expiring token cannot be minted.
	ExpiresInSeconds *int `json:"expires_in_seconds,omitempty"`
}

// AIGatewayUsageParams selects the usage window and optional agent filter.
type AIGatewayUsageParams struct {
	// Period is one of "7d", "30d", "90d" (server default 30d).
	Period string
	// AgentID scopes the rollup to a single agent when set.
	AgentID string
}

func (p *AIGatewayUsageParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	if p.Period != "" {
		q.Set("period", p.Period)
	}
	if p.AgentID != "" {
		q.Set("agent_id", p.AgentID)
	}
	return q
}

// AIGatewayUsageExportParams selects the FinOps export grouping, window, and
// optional agent filter. GroupBy is required.
type AIGatewayUsageExportParams struct {
	// GroupBy is required: one of "user", "team", "agent", "model",
	// "provider", or "tag:<key>".
	GroupBy string
	// Period is one of "7d", "30d", "90d" (server default 30d).
	Period string
	// AgentID scopes the export to a single agent when set.
	AgentID string
}

func (p AIGatewayUsageExportParams) query() url.Values {
	q := url.Values{}
	// The SDK always requests the JSON representation of the export.
	q.Set("format", "json")
	if p.GroupBy != "" {
		q.Set("group_by", p.GroupBy)
	}
	if p.Period != "" {
		q.Set("period", p.Period)
	}
	if p.AgentID != "" {
		q.Set("agent_id", p.AgentID)
	}
	return q
}

// AIGatewayFirewallRule is one heuristic rule inside a firewall policy. Regex
// patterns are compiled server-side with a linear-time engine, so lookahead,
// lookbehind and backreferences are rejected at write time (400) rather than
// stored and silently skipped when the policy runs.
type AIGatewayFirewallRule struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "regex" | "keyword"
	Pattern string `json:"pattern"`
	Flags   string `json:"flags,omitempty"` // only i,m,s,g,y — defaults to "i"
}

// AIGatewayFirewallPolicy is one ai_gateway_firewall_policies row. Policies are
// tenant-scoped and shared across gateways; attach one to an agent with
// FirewallPolicyID. An agent with NO policy still runs the built-in
// prompt-injection patterns but its outcome can never exceed "warn" — attach a
// policy with Action "block" to have matching requests refused with HTTP 400
// firewall_block on the data plane.
type AIGatewayFirewallPolicy struct {
	ID                      string                  `json:"id"`
	TenantID                string                  `json:"tenant_id"`
	Name                    string                  `json:"name"`
	Version                 int                     `json:"version"`
	Heuristics              []AIGatewayFirewallRule `json:"heuristics"`
	CanaryEnabled           bool                    `json:"canary_enabled"`
	VectorClassifierEnabled bool                    `json:"vector_classifier_enabled"`
	LakeraEnabled           bool                    `json:"lakera_enabled"`
	ModelClassifierID       *string                 `json:"model_classifier_id"`
	Action                  string                  `json:"action"` // "block" | "warn" | "tag"
	CreatedAt               string                  `json:"created_at"`
}

// CreateAIGatewayFirewallPolicyInput is the POST body. Re-using an existing Name
// creates version N+1 rather than conflicting; agents stay bound to the version
// id they reference.
type CreateAIGatewayFirewallPolicyInput struct {
	Name          string                  `json:"name"`
	Heuristics    []AIGatewayFirewallRule `json:"heuristics,omitempty"`
	CanaryEnabled *bool                   `json:"canary_enabled,omitempty"`
	Action        string                  `json:"action,omitempty"` // "block" | "warn" | "tag"
}

// UpdateAIGatewayFirewallPolicyInput is the PATCH body. Updates the policy in
// place — the version is NOT bumped. Rules are re-validated.
type UpdateAIGatewayFirewallPolicyInput struct {
	Heuristics    []AIGatewayFirewallRule `json:"heuristics,omitempty"`
	CanaryEnabled *bool                   `json:"canary_enabled,omitempty"`
	Action        string                  `json:"action,omitempty"`
}

// AIGatewayFirewallTestInput dry-runs rules against sample text.
type AIGatewayFirewallTestInput struct {
	Text       string                  `json:"text"`
	Heuristics []AIGatewayFirewallRule `json:"heuristics,omitempty"`
}

// AIGatewayFirewallTestMatch is one hit from the rule tester.
type AIGatewayFirewallTestMatch struct {
	Rule    string `json:"rule"`
	Span    []int  `json:"span"`
	Matched string `json:"matched"`
}

// AIGatewayFirewallSkippedRule names a rule that could not be compiled and so
// did not run. Always empty from the tester, which validates first.
type AIGatewayFirewallSkippedRule struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// AIGatewayFirewallTestResult is the rule-tester response.
type AIGatewayFirewallTestResult struct {
	Matched bool                           `json:"matched"`
	Matches []AIGatewayFirewallTestMatch   `json:"matches"`
	Skipped []AIGatewayFirewallSkippedRule `json:"skipped"`
}

// AIGatewayFirewallPolicyDeleted is the delete result: {id, deleted:true}.
type AIGatewayFirewallPolicyDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// ── PII policies and recognizers (AIGW-160) ───────────────────────────────────
//
// Tenant-scoped like firewall policies: one policy attaches to any number of
// agents through an agent's PiiRedactPolicyID. Until AIGW-160 these lived only
// on the admin plane, so CreateAgent accepted a policy id that no /v1 call could
// produce.
//
// Both action fields take the same four values, and each does something
// different to a matching value: "redact" replaces it with a placeholder,
// "tokenize" swaps it for a reversible token the gateway restores in the
// response, "warn" records the hit and forwards the value UNCHANGED, and
// "whitelist" exempts the shape from every other detector.

// AIGatewayPiiPolicy is one PII redaction policy: a bundle of recognizers plus a
// default action, attachable to any number of agents.
//
// An EMPTY RecognizerIDs does NOT mean "no recognizers" — it means "every
// enabled recognizer this tenant owns". That is also why the server refuses to
// delete a recognizer a policy still lists: dropping the last id would WIDEN the
// policy rather than shrink it.
type AIGatewayPiiPolicy struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	// RecognizerIDs are recognizers this tenant owns. Empty means "every enabled
	// recognizer", never "none".
	RecognizerIDs []string `json:"recognizer_ids"`
	DefaultAction string   `json:"default_action"` // "redact" | "tokenize" | "whitelist" | "warn"
	Description   *string  `json:"description"`
	CreatedAt     string   `json:"created_at"`
}

// CreateAIGatewayPiiPolicyInput is the POST body. Name is 2-64 characters
// (letters, digits, space, underscore, hyphen) and unique per tenant.
type CreateAIGatewayPiiPolicyInput struct {
	Name string `json:"name"`
	// RecognizerIDs must each name a recognizer THIS tenant owns: a foreign or
	// unknown id is a 400 recognizer_not_found at write time, rather than a
	// stored value that resolves to nothing at scan time and leaves the policy
	// quietly running fewer detectors than it lists.
	//
	// Omit it for "every enabled recognizer" — that is what an empty list means
	// on the server, so an empty slice here is not "no detectors".
	RecognizerIDs []string `json:"recognizer_ids,omitempty"`
	DefaultAction string   `json:"default_action,omitempty"` // server default "redact"
	Description   string   `json:"description,omitempty"`
}

// UpdateAIGatewayPiiPolicyInput is the PATCH body. Updates the policy in place —
// the version is NOT bumped. Every recognizer id is re-checked against this
// tenant, so a foreign id is a 400 recognizer_not_found here too.
//
// Zero-valued fields are omitted and leave the stored value alone. The server
// treats an ABSENT recognizer_ids and an explicit empty one as different intents
// — absent is "leave it", empty is "reset to every enabled recognizer" — but
// omitempty collapses them here, so this input can narrow a policy and cannot
// widen it back. Same limitation as UpdateAIGatewayFirewallPolicyInput.Heuristics;
// use CreatePiiPolicy for a policy that should scan everything.
type UpdateAIGatewayPiiPolicyInput struct {
	RecognizerIDs []string `json:"recognizer_ids,omitempty"`
	DefaultAction string   `json:"default_action,omitempty"`
	Description   string   `json:"description,omitempty"`
}

// AIGatewayPiiPolicyDeleted is the delete result: {id, deleted:true}.
type AIGatewayPiiPolicyDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// AIGatewayPiiRecognizer is one of the tenant's custom PII detectors.
type AIGatewayPiiRecognizer struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	// Kind is how the recognizer executes: "regex" and "aho_corasick" run
	// in-process, while "presidio_pattern", "presidio_ner" and "presidio_custom"
	// are handed to a Presidio sidecar.
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	// ContextWords must appear near a hit for the match to count.
	ContextWords []string `json:"context_words"`
	Confidence   float64  `json:"confidence"`
	Action       string   `json:"action"` // "redact" | "tokenize" | "whitelist" | "warn"
	// Format is the token format used when Action is "tokenize" — one of
	// "email", "pan", "ssn", "phone", "generic" or "fpe", not a free-form
	// template — and nil otherwise.
	Format *string `json:"format"`
	// Enabled false mutes the recognizer without losing its definition.
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

// CreateAIGatewayPiiRecognizerInput is the POST body.
type CreateAIGatewayPiiRecognizerInput struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // "regex" | "aho_corasick" | "presidio_pattern" | "presidio_ner" | "presidio_custom"
	// Pattern is compiled server-side with the same linear-time engine the data
	// plane runs, so lookahead, lookbehind and backreferences are a 400 here
	// rather than a stored recognizer that is skipped at scan time (fail-open).
	Pattern      string   `json:"pattern"`
	ContextWords []string `json:"context_words,omitempty"`
	// Confidence is 0-1, server default 0.85. A pointer so an explicit 0 is sent
	// rather than read as "unset".
	Confidence *float64 `json:"confidence,omitempty"`
	Action     string   `json:"action,omitempty"` // "redact" | "tokenize" | "whitelist" | "warn"
	// Format is the token format for Action "tokenize" and is an enum, not a
	// free-form template: "email" | "pan" | "ssn" | "phone" | "generic" | "fpe".
	Format string `json:"format,omitempty"`
	// Enabled is a pointer so an explicit false is sent rather than dropped; the
	// server default is true.
	Enabled *bool `json:"enabled,omitempty"`
}

// UpdateAIGatewayPiiRecognizerInput is the PATCH body — every field optional.
//
// The server validates the MERGED state, not the patch, so an Action of
// "whitelist" on its own is still checked against the STORED pattern: a
// whitelist that matches arbitrary text is a kill switch for the built-in tier
// and is refused.
type UpdateAIGatewayPiiRecognizerInput struct {
	Name         string   `json:"name,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
	ContextWords []string `json:"context_words,omitempty"`
	Confidence   *float64 `json:"confidence,omitempty"`
	Action       string   `json:"action,omitempty"`
	Format       string   `json:"format,omitempty"` // "email" | "pan" | "ssn" | "phone" | "generic" | "fpe"
	Enabled      *bool    `json:"enabled,omitempty"`
}

// AIGatewayPiiRecognizerTestInput dry-runs a candidate recognizer against sample
// text. Pattern and Text are required; the rest default the way Create does.
type AIGatewayPiiRecognizerTestInput struct {
	Pattern      string   `json:"pattern"`
	Text         string   `json:"text"`
	Kind         string   `json:"kind,omitempty"`
	Action       string   `json:"action,omitempty"`
	ContextWords []string `json:"context_words,omitempty"`
	Name         string   `json:"name,omitempty"`
}

// AIGatewayPiiRecognizerMatch is one hit from the recognizer tester. Span is the
// [start, end) offset pair into the submitted text, and Replacement is what the
// gateway would substitute for the matched value.
type AIGatewayPiiRecognizerMatch struct {
	Span        []int  `json:"span"`
	Matched     string `json:"matched"`
	Replacement string `json:"replacement"`
	EntityType  string `json:"entity_type"`
}

// AIGatewayPiiRecognizerTestResult is the recognizer-tester response.
type AIGatewayPiiRecognizerTestResult struct {
	Matched bool                          `json:"matched"`
	Matches []AIGatewayPiiRecognizerMatch `json:"matches"`
}

// AIGatewayPiiRecognizerDeleted is the delete result: {id, deleted:true}.
type AIGatewayPiiRecognizerDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// AIGatewayMcpServer is one ai_gateway_mcp_servers row plus the two connect
// strings the API computes.
//
// ConnectURL and Resource are deliberately DIFFERENT values: ConnectURL is
// where an MCP client points (the tenant data-plane host, the only host that
// serves /v1/mcp/), Resource is the RFC 8707 value a token for this server must
// be bound to. A token bound to a different resource is refused at the server.
type AIGatewayMcpServer struct {
	ID          string  `json:"id"`
	GatewayID   *string `json:"gateway_id"`
	Name        string  `json:"name"`
	Slug        *string `json:"slug"`
	Description *string `json:"description"`

	// ServerType is "upstream" or "collection"; only "upstream" can be created
	// today — the data plane does not serve "collection" yet.
	ServerType string `json:"server_type"`
	// Transport is "streamable_http" or "sse".
	Transport   *string `json:"transport"`
	UpstreamURL *string `json:"upstream_url"`

	// AllowedTools EMPTY means the server advertises NOTHING.
	AllowedTools  []string `json:"allowed_tools"`
	PIIInspection bool     `json:"pii_inspection"`
	// Auth holds only {{secret_id:…}} references — never a credential.
	Auth map[string]any `json:"auth"`

	// Sandbox is which Live/Test space this server lives in (AIGW-152).
	// READ-ONLY: it comes from the mode of the request that created the server.
	// Reads and writes are confined to the calling key's own space, a capability
	// token reaches only servers in its own space, and the same slug may exist
	// in both.
	// PiiRedactPolicyID is the tenant PII policy whose recognizers apply to
	// this server's tool arguments and results (AIGW-151). Empty means every
	// enabled recognizer this tenant owns, on top of the built-ins.
	PiiRedactPolicyID *string `json:"pii_redact_policy_id"`
	FirewallPolicyID  *string `json:"firewall_policy_id"`
	// The tenant's own external scanner (AIGW-150). Mode is
	// "off"|"request"|"response"|"both"; `request` sees the tool ARGUMENTS
	// after redaction and before they leave, `response` sees the RESULT.
	GuardrailWebhookURL           *string `json:"guardrail_webhook_url"`
	GuardrailWebhookSecretID      *string `json:"guardrail_webhook_secret_id"`
	GuardrailWebhookMode          string  `json:"guardrail_webhook_mode,omitempty"`
	GuardrailWebhookTimeoutMs     int     `json:"guardrail_webhook_timeout_ms,omitempty"`
	GuardrailWebhookFailureAction string  `json:"guardrail_webhook_failure_action,omitempty"`
	Sandbox                       bool    `json:"sandbox"`
	Status                        string  `json:"status"`
	CreatedAt                     string  `json:"created_at"`
	UpdatedAt                     string  `json:"updated_at"`

	ConnectURL string `json:"connect_url"`
	Resource   string `json:"resource"`
}

// AIGatewayMcpAuth is an MCP server's upstream auth. Every header value must
// reference a KnoxCall secret (e.g. "Bearer {{secret_id:<uuid>}}"); a literal
// credential is refused with 422, because this column is not encrypted.
type AIGatewayMcpAuth struct {
	Headers         map[string]string `json:"headers,omitempty"`
	EnvironmentName string            `json:"environment_name,omitempty"`
}

// CreateAIGatewayMcpServerInput registers an upstream MCP server.
//
// UpstreamURL must be a public https:// address — private, loopback,
// link-local and cloud-metadata destinations are refused, because the request
// carries the decrypted upstream credential.
type CreateAIGatewayMcpServerInput struct {
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	UpstreamURL string  `json:"upstream_url"`
	Description *string `json:"description,omitempty"`
	Transport   *string `json:"transport,omitempty"`
	// AllowedTools empty (the default) means the server advertises nothing.
	AllowedTools  []string          `json:"allowed_tools,omitempty"`
	PIIInspection *bool             `json:"pii_inspection,omitempty"`
	Auth          *AIGatewayMcpAuth `json:"auth,omitempty"`
}

// UpdateAIGatewayMcpServerInput patches an MCP server. Status accepts "active"
// or "paused"; use DeleteMcpServer to archive.
type UpdateAIGatewayMcpServerInput struct {
	Name          *string           `json:"name,omitempty"`
	Description   *string           `json:"description,omitempty"`
	UpstreamURL   *string           `json:"upstream_url,omitempty"`
	Transport     *string           `json:"transport,omitempty"`
	AllowedTools  []string          `json:"allowed_tools,omitempty"`
	PIIInspection *bool             `json:"pii_inspection,omitempty"`
	Auth          *AIGatewayMcpAuth `json:"auth,omitempty"`
	Status        *string           `json:"status,omitempty"`
}

// AIGatewayMcpTool is a tool metadata row. It does not widen what the server
// advertises: a client sees the intersection of AllowedTools, the upstream's
// real tools, and the presented token's own tool scope.
type AIGatewayMcpTool struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	McpServerID string         `json:"mcp_server_id"`
	ToolName    string         `json:"tool_name"`
	RouteID     *string        `json:"route_id"`
	Description *string        `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
	Enabled     bool           `json:"enabled"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
}

// UpsertAIGatewayMcpToolInput inserts or updates a tool row by ToolName.
type UpsertAIGatewayMcpToolInput struct {
	ToolName    string         `json:"tool_name"`
	Description *string        `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
}

// UpdateAIGatewayMcpToolInput enables, disables or re-describes a tool row.
type UpdateAIGatewayMcpToolInput struct {
	Description *string        `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
}

// AIGatewayMcpToolDeleted is the DELETE …/tools/:toolId response.
type AIGatewayMcpToolDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// AIGatewayMcpGrant is one person's delegated-OAuth connection to an MCP server
// (AIGW-190). It NEVER carries the stored tokens — `HasRefreshToken` is the only
// thing said about them.
type AIGatewayMcpGrant struct {
	ID               string   `json:"id"`
	AttributedUserID string   `json:"attributed_user_id"`
	ExternalID       string   `json:"external_id"`
	DisplayName      *string  `json:"display_name"`
	Scopes           []string `json:"scopes"`
	Status           string   `json:"status"`
	CreatedAt        string   `json:"created_at"`
	LastRefreshedAt  *string  `json:"last_refreshed_at"`
	LastUsedAt       *string  `json:"last_used_at"`
	HasRefreshToken  bool     `json:"has_refresh_token"`
}

// AIGatewayMcpGrantRevoked is the DELETE …/grants/:grantId response.
type AIGatewayMcpGrantRevoked struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// AIGatewayMcpGrantsRevoked is the DELETE …/grants response.
type AIGatewayMcpGrantsRevoked struct {
	ID      string `json:"id"`
	Revoked int    `json:"revoked"`
}

type AIGatewayResource struct{ c *Client }

// ── Gateways ──────────────────────────────────────────────────────────────────

// ListGateways returns one page of AI gateways (server default 20/page, cap 100).
func (r *AIGatewayResource) ListGateways(ctx context.Context, params *ListParams) (*Page[AIGateway], error) {
	return doPage[AIGateway](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/gateways", query: params.query()})
}

// ListAllGateways walks every page and returns all gateways.
func (r *AIGatewayResource) ListAllGateways(ctx context.Context, params *ListParams) ([]AIGateway, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGateway], error) {
		p.Page = page
		return r.ListGateways(ctx, &p)
	})
}

// IterateGateways lazily streams every gateway one at a time, fetching pages on
// demand (the streaming analog of ListAllGateways — see helpers.iterate). Range
// over it with two variables and break on the first non-nil error.
func (r *AIGatewayResource) IterateGateways(ctx context.Context, params *ListParams) iter.Seq2[AIGateway, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGateway], error) {
		p.Page = page
		return r.ListGateways(ctx, &p)
	})
}

func (r *AIGatewayResource) GetGateway(ctx context.Context, gatewayID string) (*AIGateway, error) {
	return doUnwrap[AIGateway](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/gateways/" + encode(gatewayID)})
}

func (r *AIGatewayResource) CreateGateway(ctx context.Context, input CreateAIGatewayInput) (*AIGateway, error) {
	return doUnwrap[AIGateway](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/gateways", body: input})
}

func (r *AIGatewayResource) UpdateGateway(ctx context.Context, gatewayID string, input UpdateAIGatewayInput) (*AIGateway, error) {
	return doUnwrap[AIGateway](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/gateways/" + encode(gatewayID), body: input})
}

// DeleteGateway archives the gateway; the response echoes {id, status}.
func (r *AIGatewayResource) DeleteGateway(ctx context.Context, gatewayID string) (*AIGatewayArchived, error) {
	return doUnwrap[AIGatewayArchived](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/gateways/" + encode(gatewayID)})
}

// ── Agents ────────────────────────────────────────────────────────────────────

// ListAgents returns one page of the gateway's agents.
func (r *AIGatewayResource) ListAgents(ctx context.Context, gatewayID string, params *ListParams) (*Page[AIGatewayAgent], error) {
	return doPage[AIGatewayAgent](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/agents", query: params.query()})
}

// ListAllAgents walks every page and returns all of the gateway's agents.
func (r *AIGatewayResource) ListAllAgents(ctx context.Context, gatewayID string, params *ListParams) ([]AIGatewayAgent, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayAgent], error) {
		p.Page = page
		return r.ListAgents(ctx, gatewayID, &p)
	})
}

// IterateAgents lazily streams all of the gateway's agents one at a time,
// fetching pages on demand (the streaming analog of ListAllAgents — see
// helpers.iterate). Range over it with two variables and break on the first
// non-nil error.
func (r *AIGatewayResource) IterateAgents(ctx context.Context, gatewayID string, params *ListParams) iter.Seq2[AIGatewayAgent, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayAgent], error) {
		p.Page = page
		return r.ListAgents(ctx, gatewayID, &p)
	})
}

func (r *AIGatewayResource) CreateAgent(ctx context.Context, gatewayID string, input CreateAIGatewayAgentInput) (*AIGatewayAgent, error) {
	return doUnwrap[AIGatewayAgent](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/agents", body: input})
}

// GetAgent fetches an agent by id (agents are addressed directly, not nested
// under the gateway on read/update/delete).
func (r *AIGatewayResource) GetAgent(ctx context.Context, agentID string) (*AIGatewayAgent, error) {
	return doUnwrap[AIGatewayAgent](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/agents/" + encode(agentID)})
}

func (r *AIGatewayResource) UpdateAgent(ctx context.Context, agentID string, input UpdateAIGatewayAgentInput) (*AIGatewayAgent, error) {
	return doUnwrap[AIGatewayAgent](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/agents/" + encode(agentID), body: input})
}

// DeleteAgent archives the agent; the response echoes {id, status}.
func (r *AIGatewayResource) DeleteAgent(ctx context.Context, agentID string) (*AIGatewayArchived, error) {
	return doUnwrap[AIGatewayArchived](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/agents/" + encode(agentID)})
}

// ── MCP servers ───────────────────────────────────────────────────────────────

// ListMcpServers returns one page of the gateway's MCP servers.
func (r *AIGatewayResource) ListMcpServers(ctx context.Context, gatewayID string, params *ListParams) (*Page[AIGatewayMcpServer], error) {
	return doPage[AIGatewayMcpServer](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/mcp-servers", query: params.query()})
}

// ListAllMcpServers walks every page and returns all of the gateway's MCP servers.
func (r *AIGatewayResource) ListAllMcpServers(ctx context.Context, gatewayID string, params *ListParams) ([]AIGatewayMcpServer, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpServer], error) {
		p.Page = page
		return r.ListMcpServers(ctx, gatewayID, &p)
	})
}

// IterateMcpServers lazily streams the gateway's MCP servers one at a time.
func (r *AIGatewayResource) IterateMcpServers(ctx context.Context, gatewayID string, params *ListParams) iter.Seq2[AIGatewayMcpServer, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpServer], error) {
		p.Page = page
		return r.ListMcpServers(ctx, gatewayID, &p)
	})
}

// CreateMcpServer registers an upstream MCP server under a gateway.
// server_type "collection" is not accepted — the data plane does not serve it.
func (r *AIGatewayResource) CreateMcpServer(ctx context.Context, gatewayID string, input CreateAIGatewayMcpServerInput) (*AIGatewayMcpServer, error) {
	return doUnwrap[AIGatewayMcpServer](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/mcp-servers", body: input})
}

// GetMcpServer fetches an MCP server by id (addressed directly, not nested
// under the gateway on read/update/delete).
func (r *AIGatewayResource) GetMcpServer(ctx context.Context, serverID string) (*AIGatewayMcpServer, error) {
	return doUnwrap[AIGatewayMcpServer](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID)})
}

func (r *AIGatewayResource) UpdateMcpServer(ctx context.Context, serverID string, input UpdateAIGatewayMcpServerInput) (*AIGatewayMcpServer, error) {
	return doUnwrap[AIGatewayMcpServer](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID), body: input})
}

// DeleteMcpServer archives the server; the response echoes {id, status}.
func (r *AIGatewayResource) DeleteMcpServer(ctx context.Context, serverID string) (*AIGatewayArchived, error) {
	return doUnwrap[AIGatewayArchived](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID)})
}

// ── MCP tools ─────────────────────────────────────────────────────────────────

// ListMcpTools returns one page of the server's tool metadata rows.
func (r *AIGatewayResource) ListMcpTools(ctx context.Context, serverID string, params *ListParams) (*Page[AIGatewayMcpTool], error) {
	return doPage[AIGatewayMcpTool](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/tools", query: params.query()})
}

// ListAllMcpTools walks every page and returns all of the server's tool rows.
func (r *AIGatewayResource) ListAllMcpTools(ctx context.Context, serverID string, params *ListParams) ([]AIGatewayMcpTool, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpTool], error) {
		p.Page = page
		return r.ListMcpTools(ctx, serverID, &p)
	})
}

// IterateMcpTools lazily streams the server's tool rows one at a time.
func (r *AIGatewayResource) IterateMcpTools(ctx context.Context, serverID string, params *ListParams) iter.Seq2[AIGatewayMcpTool, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpTool], error) {
		p.Page = page
		return r.ListMcpTools(ctx, serverID, &p)
	})
}

// UpsertMcpTool inserts or updates a tool row by tool_name.
func (r *AIGatewayResource) UpsertMcpTool(ctx context.Context, serverID string, input UpsertAIGatewayMcpToolInput) (*AIGatewayMcpTool, error) {
	return doUnwrap[AIGatewayMcpTool](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/tools", body: input})
}

// UpdateMcpTool enables, disables or re-describes a tool row.
func (r *AIGatewayResource) UpdateMcpTool(ctx context.Context, serverID, toolID string, input UpdateAIGatewayMcpToolInput) (*AIGatewayMcpTool, error) {
	return doUnwrap[AIGatewayMcpTool](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/tools/" + encode(toolID), body: input})
}

// DeleteMcpTool removes a tool row; the response echoes {id, deleted}.
func (r *AIGatewayResource) DeleteMcpTool(ctx context.Context, serverID, toolID string) (*AIGatewayMcpToolDeleted, error) {
	return doUnwrap[AIGatewayMcpToolDeleted](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/tools/" + encode(toolID)})
}

// ── Delegated-OAuth connections (AIGW-190) ────────────────────────────────────
//
// A connection holds ONE person's upstream refresh token, envelope-encrypted
// under the tenant key. Nothing here returns it, redacted or otherwise.
//
// There is deliberately no ConnectMcpServer: consent has to be given by the
// person whose credential it is, so the flow starts from a signed-in KnoxCall
// session in the admin console. An API key is not a person.

// ListMcpGrants returns one page of the people who have connected their upstream
// account to this MCP server.
func (r *AIGatewayResource) ListMcpGrants(ctx context.Context, serverID string, params *ListParams) (*Page[AIGatewayMcpGrant], error) {
	return doPage[AIGatewayMcpGrant](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/grants", query: params.query()})
}

// ListAllMcpGrants walks every page and returns all of this server's connections.
func (r *AIGatewayResource) ListAllMcpGrants(ctx context.Context, serverID string, params *ListParams) ([]AIGatewayMcpGrant, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpGrant], error) {
		p.Page = page
		return r.ListMcpGrants(ctx, serverID, &p)
	})
}

// IterateMcpGrants lazily streams this server's connections one at a time.
func (r *AIGatewayResource) IterateMcpGrants(ctx context.Context, serverID string, params *ListParams) iter.Seq2[AIGatewayMcpGrant, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayMcpGrant], error) {
		p.Page = page
		return r.ListMcpGrants(ctx, serverID, &p)
	})
}

// RevokeMcpGrant revokes ONE person's connection; the stored tokens are destroyed.
func (r *AIGatewayResource) RevokeMcpGrant(ctx context.Context, serverID, grantID string) (*AIGatewayMcpGrantRevoked, error) {
	return doUnwrap[AIGatewayMcpGrantRevoked](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/grants/" + encode(grantID)})
}

// RevokeAllMcpGrants revokes EVERY connection on this server.
func (r *AIGatewayResource) RevokeAllMcpGrants(ctx context.Context, serverID string) (*AIGatewayMcpGrantsRevoked, error) {
	return doUnwrap[AIGatewayMcpGrantsRevoked](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/mcp-servers/" + encode(serverID) + "/grants"})
}

// ── Tokens ────────────────────────────────────────────────────────────────────

// ListTokens returns one page of the agent's phantom tokens (plaintext is never
// included — use MintToken to obtain a token value).
func (r *AIGatewayResource) ListTokens(ctx context.Context, agentID string, params *ListParams) (*Page[AIGatewayToken], error) {
	return doPage[AIGatewayToken](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/agents/" + encode(agentID) + "/tokens", query: params.query()})
}

// ListAllTokens walks every page and returns all of the agent's tokens.
func (r *AIGatewayResource) ListAllTokens(ctx context.Context, agentID string, params *ListParams) ([]AIGatewayToken, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayToken], error) {
		p.Page = page
		return r.ListTokens(ctx, agentID, &p)
	})
}

// IterateTokens lazily streams all of the agent's phantom tokens one at a time,
// fetching pages on demand rather than buffering them (the streaming analog of
// ListAllTokens — see helpers.iterate). Preferred over ListAllTokens for agents
// with large token histories. Range over it with two variables and break on the
// first non-nil error. Plaintext is never included — use MintToken.
func (r *AIGatewayResource) IterateTokens(ctx context.Context, agentID string, params *ListParams) iter.Seq2[AIGatewayToken, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayToken], error) {
		p.Page = page
		return r.ListTokens(ctx, agentID, &p)
	})
}

// MintToken issues a phantom token for the agent. The returned Token plaintext
// is shown EXACTLY ONCE — persist it immediately.
func (r *AIGatewayResource) MintToken(ctx context.Context, agentID string, input MintAIGatewayTokenInput) (*AIGatewayMintedToken, error) {
	return doUnwrap[AIGatewayMintedToken](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/agents/" + encode(agentID) + "/tokens", body: input})
}

// RevokeToken revokes a phantom token; the response is {id, revoked:true}.
func (r *AIGatewayResource) RevokeToken(ctx context.Context, agentID, tokenID string) (*AIGatewayTokenRevoked, error) {
	return doUnwrap[AIGatewayTokenRevoked](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/agents/" + encode(agentID) + "/tokens/" + encode(tokenID)})
}

// ── Firewall policies ─────────────────────────────────────────────────────────

// ListFirewallPolicies returns one page of the tenant's prompt-firewall
// policies. Policies are tenant-scoped, not per gateway.
func (r *AIGatewayResource) ListFirewallPolicies(ctx context.Context, params *ListParams) (*Page[AIGatewayFirewallPolicy], error) {
	return doPage[AIGatewayFirewallPolicy](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/firewall-policies", query: params.query()})
}

// ListAllFirewallPolicies buffers every page into one slice.
func (r *AIGatewayResource) ListAllFirewallPolicies(ctx context.Context, params *ListParams) ([]AIGatewayFirewallPolicy, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayFirewallPolicy], error) {
		p.Page = page
		return r.ListFirewallPolicies(ctx, &p)
	})
}

// ListGatewayTokens returns one page of every token under a gateway, INCLUDING
// gateway-level tokens with no agent — the shape POST /v1/oauth/token mints for
// MCP. ListTokens filters on the agent and cannot see them. Plaintext is never
// returned by a list endpoint.
func (r *AIGatewayResource) ListGatewayTokens(ctx context.Context, gatewayID string, params *ListParams) (*Page[AIGatewayToken], error) {
	return doPage[AIGatewayToken](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/tokens", query: params.query()})
}

// ListAllGatewayTokens walks every page and returns all of the gateway's tokens.
func (r *AIGatewayResource) ListAllGatewayTokens(ctx context.Context, gatewayID string, params *ListParams) ([]AIGatewayToken, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayToken], error) {
		p.Page = page
		return r.ListGatewayTokens(ctx, gatewayID, &p)
	})
}

// IterateFirewallPolicies lazily streams every policy, fetching pages on demand.
func (r *AIGatewayResource) IterateFirewallPolicies(ctx context.Context, params *ListParams) iter.Seq2[AIGatewayFirewallPolicy, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayFirewallPolicy], error) {
		p.Page = page
		return r.ListFirewallPolicies(ctx, &p)
	})
}

// IterateGatewayTokens lazily streams every token under a gateway.
func (r *AIGatewayResource) IterateGatewayTokens(ctx context.Context, gatewayID string, params *ListParams) iter.Seq2[AIGatewayToken, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayToken], error) {
		p.Page = page
		return r.ListGatewayTokens(ctx, gatewayID, &p)
	})
}

// GetFirewallPolicy fetches one policy by id.
func (r *AIGatewayResource) GetFirewallPolicy(ctx context.Context, policyID string) (*AIGatewayFirewallPolicy, error) {
	return doUnwrap[AIGatewayFirewallPolicy](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/firewall-policies/" + encode(policyID)})
}

// CreateFirewallPolicy creates a policy. Every regex rule is compiled
// server-side before it is stored, so an unsupported pattern is a 400 here
// rather than a rule that silently matches nothing at scan time.
func (r *AIGatewayResource) CreateFirewallPolicy(ctx context.Context, input CreateAIGatewayFirewallPolicyInput) (*AIGatewayFirewallPolicy, error) {
	return doUnwrap[AIGatewayFirewallPolicy](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/firewall-policies", body: input})
}

// UpdateFirewallPolicy updates a policy in place (the version is not bumped).
func (r *AIGatewayResource) UpdateFirewallPolicy(ctx context.Context, policyID string, input UpdateAIGatewayFirewallPolicyInput) (*AIGatewayFirewallPolicy, error) {
	return doUnwrap[AIGatewayFirewallPolicy](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/firewall-policies/" + encode(policyID), body: input})
}

// DeleteFirewallPolicy deletes a policy. Refused with 409 policy_in_use while
// any agent or MCP server is still attached.
func (r *AIGatewayResource) DeleteFirewallPolicy(ctx context.Context, policyID string) (*AIGatewayFirewallPolicyDeleted, error) {
	return doUnwrap[AIGatewayFirewallPolicyDeleted](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/firewall-policies/" + encode(policyID)})
}

// TestFirewallRules dry-runs the built-in patterns plus the supplied rules
// against sample text. Saves nothing; rules are compiled first, so this refuses
// exactly what create/update refuse.
func (r *AIGatewayResource) TestFirewallRules(ctx context.Context, input AIGatewayFirewallTestInput) (*AIGatewayFirewallTestResult, error) {
	return doUnwrap[AIGatewayFirewallTestResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/firewall-policies/test", body: input})
}

// RevokeGatewayToken revokes any token under a gateway, including a
// gateway-level one. Use this rather than RevokeToken for a token minted by
// POST /v1/oauth/token: that token has no agent, so the per-agent revoke can
// never match it.
func (r *AIGatewayResource) RevokeGatewayToken(ctx context.Context, gatewayID, tokenID string) (*AIGatewayTokenRevoked, error) {
	return doUnwrap[AIGatewayTokenRevoked](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/gateways/" + encode(gatewayID) + "/tokens/" + encode(tokenID)})
}

// ── PII policies ──────────────────────────────────────────────────────────────
//
// Tenant-scoped like firewall policies: one policy attaches to any number of
// agents through PiiRedactPolicyID on the agent. Until AIGW-160 these lived only
// on the admin plane, so CreateAgent accepted a PiiRedactPolicyID that no /v1
// call could produce.

// ListPiiPolicies returns one page of the tenant's PII redaction policies.
// Tenant-scoped, not per gateway.
func (r *AIGatewayResource) ListPiiPolicies(ctx context.Context, params *ListParams) (*Page[AIGatewayPiiPolicy], error) {
	return doPage[AIGatewayPiiPolicy](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/pii-policies", query: params.query()})
}

// ListAllPiiPolicies buffers every page into one slice.
func (r *AIGatewayResource) ListAllPiiPolicies(ctx context.Context, params *ListParams) ([]AIGatewayPiiPolicy, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayPiiPolicy], error) {
		p.Page = page
		return r.ListPiiPolicies(ctx, &p)
	})
}

// IteratePiiPolicies lazily streams every PII policy, fetching pages on demand.
func (r *AIGatewayResource) IteratePiiPolicies(ctx context.Context, params *ListParams) iter.Seq2[AIGatewayPiiPolicy, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayPiiPolicy], error) {
		p.Page = page
		return r.ListPiiPolicies(ctx, &p)
	})
}

// CreatePiiPolicy creates a PII policy.
//
// Every id in RecognizerIDs must be a recognizer this tenant owns — a foreign or
// unknown id is a 400 recognizer_not_found rather than a stored value that
// resolves to nothing at scan time. An EMPTY RecognizerIDs is not "no
// detectors": it means "every enabled recognizer this tenant owns".
//
// Custom PII policies are a Pro entitlement, so a tenant that owns none gets a
// 402 plan_feature here; a tenant that already owns one is grandfathered and
// keeps authoring, so a downgrade never strands the agents bound to it.
func (r *AIGatewayResource) CreatePiiPolicy(ctx context.Context, input CreateAIGatewayPiiPolicyInput) (*AIGatewayPiiPolicy, error) {
	return doUnwrap[AIGatewayPiiPolicy](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/pii-policies", body: input})
}

// GetPiiPolicy fetches one PII policy by id.
func (r *AIGatewayResource) GetPiiPolicy(ctx context.Context, policyID string) (*AIGatewayPiiPolicy, error) {
	return doUnwrap[AIGatewayPiiPolicy](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/pii-policies/" + encode(policyID)})
}

// UpdatePiiPolicy updates a PII policy in place (the version is not bumped).
// Recognizer ids are re-checked against this tenant, so a foreign id is a 400
// recognizer_not_found here too.
func (r *AIGatewayResource) UpdatePiiPolicy(ctx context.Context, policyID string, input UpdateAIGatewayPiiPolicyInput) (*AIGatewayPiiPolicy, error) {
	return doUnwrap[AIGatewayPiiPolicy](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/pii-policies/" + encode(policyID), body: input})
}

// DeletePiiPolicy deletes a PII policy. Refused with 409 policy_in_use while any
// agent still references it: the foreign key is ON DELETE SET NULL, so an
// unchecked delete would detach every bound agent and turn redaction OFF for
// each of them with no error anywhere. Point those agents at another policy
// first. ARCHIVED agents count as references — the row keeps the pointer, so an
// agent that returns from archive would come back with no redaction.
func (r *AIGatewayResource) DeletePiiPolicy(ctx context.Context, policyID string) (*AIGatewayPiiPolicyDeleted, error) {
	return doUnwrap[AIGatewayPiiPolicyDeleted](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/pii-policies/" + encode(policyID)})
}

// ── PII recognizers ───────────────────────────────────────────────────────────

// ListPiiRecognizers returns one page of the tenant's custom PII recognizers.
func (r *AIGatewayResource) ListPiiRecognizers(ctx context.Context, params *ListParams) (*Page[AIGatewayPiiRecognizer], error) {
	return doPage[AIGatewayPiiRecognizer](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/pii-recognizers", query: params.query()})
}

// ListAllPiiRecognizers buffers every page into one slice.
func (r *AIGatewayResource) ListAllPiiRecognizers(ctx context.Context, params *ListParams) ([]AIGatewayPiiRecognizer, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayPiiRecognizer], error) {
		p.Page = page
		return r.ListPiiRecognizers(ctx, &p)
	})
}

// IteratePiiRecognizers lazily streams every recognizer, fetching pages on demand.
func (r *AIGatewayResource) IteratePiiRecognizers(ctx context.Context, params *ListParams) iter.Seq2[AIGatewayPiiRecognizer, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AIGatewayPiiRecognizer], error) {
		p.Page = page
		return r.ListPiiRecognizers(ctx, &p)
	})
}

// CreatePiiRecognizer creates a custom recognizer. A "regex" pattern is compiled
// server-side before it is stored, so an unsupported construct is a 400 here
// rather than a detector that silently never runs.
func (r *AIGatewayResource) CreatePiiRecognizer(ctx context.Context, input CreateAIGatewayPiiRecognizerInput) (*AIGatewayPiiRecognizer, error) {
	return doUnwrap[AIGatewayPiiRecognizer](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/pii-recognizers", body: input})
}

// TestPiiRecognizer dry-runs a candidate pattern against sample text. Saves
// nothing.
//
// It compiles with the SAME linear-time engine the data plane runs, so
// lookahead, lookbehind and backreferences are refused here exactly as
// create/update refuse them — a pattern that passes here is one that will
// actually execute. Do NOT preview with Go's own regexp or a browser RegExp
// instead: those accept constructs the server rejects, so a local preview shows
// matches for a recognizer that can never run and then 400s on save.
func (r *AIGatewayResource) TestPiiRecognizer(ctx context.Context, input AIGatewayPiiRecognizerTestInput) (*AIGatewayPiiRecognizerTestResult, error) {
	return doUnwrap[AIGatewayPiiRecognizerTestResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/ai-gateway/pii-recognizers/test", body: input})
}

// GetPiiRecognizer fetches one recognizer by id.
func (r *AIGatewayResource) GetPiiRecognizer(ctx context.Context, recognizerID string) (*AIGatewayPiiRecognizer, error) {
	return doUnwrap[AIGatewayPiiRecognizer](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/pii-recognizers/" + encode(recognizerID)})
}

// UpdatePiiRecognizer updates a recognizer. The server validates the MERGED
// state, not the patch, so an Action of "whitelist" on its own is still checked
// against the stored pattern.
func (r *AIGatewayResource) UpdatePiiRecognizer(ctx context.Context, recognizerID string, input UpdateAIGatewayPiiRecognizerInput) (*AIGatewayPiiRecognizer, error) {
	return doUnwrap[AIGatewayPiiRecognizer](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/ai-gateway/pii-recognizers/" + encode(recognizerID), body: input})
}

// DeletePiiRecognizer deletes a recognizer. Refused with 409 recognizer_in_use
// while any PII policy still lists it: recognizer_ids is a bare uuid array with
// no foreign key, and an EMPTY list means "every enabled recognizer", so
// silently dropping the id would WIDEN the policy rather than shrink it. Remove
// it from each policy first.
func (r *AIGatewayResource) DeletePiiRecognizer(ctx context.Context, recognizerID string) (*AIGatewayPiiRecognizerDeleted, error) {
	return doUnwrap[AIGatewayPiiRecognizerDeleted](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/ai-gateway/pii-recognizers/" + encode(recognizerID)})
}

// ── Usage ─────────────────────────────────────────────────────────────────────

// Usage returns the cost + token rollup by model for the requested window
// (default 30d), optionally scoped to a single agent.
func (r *AIGatewayResource) Usage(ctx context.Context, params *AIGatewayUsageParams) (*AIGatewayUsage, error) {
	return doUnwrap[AIGatewayUsage](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/usage", query: params.query()})
}

// ExportUsage returns a FinOps spend export: aggregated cost + token rows
// grouped by GroupBy ("user" | "team" | "agent" | "model" | "provider" |
// "tag:<key>") over the requested window (default 30d), optionally scoped to a
// single agent. The SDK always requests format=json and returns the JSON rows.
func (r *AIGatewayResource) ExportUsage(ctx context.Context, params AIGatewayUsageExportParams) (*AIGatewayUsageExport, error) {
	return doUnwrap[AIGatewayUsageExport](ctx, r.c, requestOpts{method: "GET", path: "/v1/ai-gateway/usage/export", query: params.query()})
}
