package knoxcall

import (
	"context"
	"iter"
)

// Webhook mirrors the server's webhook projections. List rows carry the core
// fields plus delivery counters; Get adds the config fields; Create adds the
// once-only SecretKey and the hmac_* fields. Fields absent from a given
// response stay zero.
type Webhook struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     *string  `json:"description"`
	URL             string   `json:"url"`
	Method          string   `json:"method"` // GET | POST | PUT | PATCH
	EventTypes      []string `json:"event_types"`
	AuthType        string   `json:"auth_type"` // none | bearer | hmac | basic | header
	Enabled         bool     `json:"enabled"`
	LastTriggeredAt *string  `json:"last_triggered_at"`
	TriggerCount    int      `json:"trigger_count"`
	SuccessCount    int      `json:"success_count"`
	FailureCount    int      `json:"failure_count"`
	CreatedAt       string   `json:"created_at"`

	// Get only.
	//
	// `request_headers` is deliberately ABSENT (server fix row 2-492): it is
	// accepted on create/update but never returned, because the dispatcher
	// spreads it into the outbound header map alongside the
	// `auth_config`-derived `Authorization`, so a value stored there is
	// indistinguishable from a destination API key. Same reason `secret_key`
	// and `auth_config` have never been on this struct.
	RouteFilter         []string `json:"route_filter"`
	IncludeRequestBody  bool     `json:"include_request_body"`
	IncludeResponseBody bool     `json:"include_response_body"`
	IncludeHeaders      bool     `json:"include_headers"`
	TimeoutSeconds      int      `json:"timeout_seconds"`
	RetryOnFailure      bool     `json:"retry_on_failure"`
	MaxRetries          int      `json:"max_retries"`
	LastSuccessAt       *string  `json:"last_success_at"`
	LastFailureAt       *string  `json:"last_failure_at"`

	// Create only.
	HmacKeyID      *string `json:"hmac_key_id"`
	HmacFormat     *string `json:"hmac_format"` // legacy | stripe | github | slack | aws-sns | custom
	HmacHeaderName *string `json:"hmac_header_name"`
	// SecretKey is the endpoint's signing secret — returned ONCE, on create.
	SecretKey string `json:"secret_key"`
}

// WebhookEventType is one subscribable event type from
// GET /v1/webhooks/event-types.
type WebhookEventType struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// WebhookHmacFormatInfo is one signing format from
// GET /v1/webhooks/hmac-formats. It mirrors the server's
// WebhookHmacFormatInfo (src/webhooks/hmac-formats.ts) field for field, and it
// is the live catalogue a client validates `hmac_format` against instead of
// carrying a hardcoded copy that drifts.
type WebhookHmacFormatInfo struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Headers the format emits. Empty for "custom" — the caller names it.
	Headers []string `json:"headers"`
	// RequiresHeaderName is true when hmac_header_name must accompany the
	// format ("custom" today).
	RequiresHeaderName bool `json:"requires_header_name"`
}

// WebhookLog is one delivery-log row from GET /v1/webhooks/{id}/logs.
type WebhookLog struct {
	ID             string  `json:"id"`
	HTTPMethod     *string `json:"http_method"`
	TargetURL      *string `json:"target_url"`
	SourceIP       *string `json:"source_ip"`
	ResponseStatus *int    `json:"response_status"`
	ResponseTimeMs *int    `json:"response_time_ms"`
	ExecutedAt     string  `json:"executed_at"`
	Success        bool    `json:"success"`
	ErrorMessage   *string `json:"error_message"`
}

// WebhookTestResult is the POST /v1/webhooks/{id}/test delivery result.
type WebhookTestResult struct {
	Success        bool   `json:"success"`
	Status         int    `json:"status"`
	ResponseTimeMs int    `json:"response_time_ms"`
	Error          string `json:"error"`
}

type CreateWebhookInput struct {
	Name                string            `json:"name"`
	URL                 string            `json:"url"`
	EventTypes          []string          `json:"event_types"`
	Description         string            `json:"description,omitempty"`
	Method              string            `json:"method,omitempty"`
	AuthType            string            `json:"auth_type,omitempty"`
	AuthConfig          map[string]any    `json:"auth_config,omitempty"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	RouteFilter         []string          `json:"route_filter,omitempty"`
	IncludeRequestBody  *bool             `json:"include_request_body,omitempty"`
	IncludeResponseBody *bool             `json:"include_response_body,omitempty"`
	IncludeHeaders      *bool             `json:"include_headers,omitempty"`
	TimeoutSeconds      *int              `json:"timeout_seconds,omitempty"`
	RetryOnFailure      *bool             `json:"retry_on_failure,omitempty"`
	MaxRetries          *int              `json:"max_retries,omitempty"`
	Enabled             *bool             `json:"enabled,omitempty"`

	// HmacKeyID signs deliveries with an EaaS crypto key instead of the
	// webhook's generated `secret_key`. The signing material then never
	// appears in any API response — the state-safe path for infrastructure-as-
	// code callers, and the reason these three fields exist on the input at
	// all. The server has accepted them on POST and PATCH since Stage 2.5
	// (src/client-api/webhooks.ts); no SDK could set them until now.
	HmacKeyID string `json:"hmac_key_id,omitempty"`
	// HmacFormat is one of the values GET /v1/webhooks/hmac-formats offers.
	HmacFormat string `json:"hmac_format,omitempty"`
	// HmacHeaderName is required when HmacFormat is "custom".
	HmacHeaderName string `json:"hmac_header_name,omitempty"`
}

type UpdateWebhookInput struct {
	URL                 *string           `json:"url,omitempty"`
	EventTypes          []string          `json:"event_types,omitempty"`
	Description         *string           `json:"description,omitempty"`
	Method              *string           `json:"method,omitempty"`
	AuthType            *string           `json:"auth_type,omitempty"`
	AuthConfig          map[string]any    `json:"auth_config,omitempty"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	RouteFilter         []string          `json:"route_filter,omitempty"`
	IncludeRequestBody  *bool             `json:"include_request_body,omitempty"`
	IncludeResponseBody *bool             `json:"include_response_body,omitempty"`
	IncludeHeaders      *bool             `json:"include_headers,omitempty"`
	TimeoutSeconds      *int              `json:"timeout_seconds,omitempty"`
	RetryOnFailure      *bool             `json:"retry_on_failure,omitempty"`
	MaxRetries          *int              `json:"max_retries,omitempty"`
	Enabled             *bool             `json:"enabled,omitempty"`

	// The EaaS signing trio — see CreateWebhookInput.HmacKeyID. Pointers here
	// so a PATCH can distinguish "leave alone" (nil) from a new value; the
	// server's allowedFields map accepts all three
	// (src/client-api/webhooks.ts) and re-validates the format/header-name
	// pair against the EFFECTIVE post-write row.
	HmacKeyID      *string `json:"hmac_key_id,omitempty"`
	HmacFormat     *string `json:"hmac_format,omitempty"`
	HmacHeaderName *string `json:"hmac_header_name,omitempty"`
}

type WebhooksResource struct{ c *Client }

// List returns one page of webhooks.
func (r *WebhooksResource) List(ctx context.Context, params *ListParams) (*Page[Webhook], error) {
	return doPage[Webhook](ctx, r.c, requestOpts{method: "GET", path: "/v1/webhooks", query: params.query()})
}

// ListAll walks every page and returns all webhooks.
func (r *WebhooksResource) ListAll(ctx context.Context, params *ListParams) ([]Webhook, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Webhook], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every webhook one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *WebhooksResource) Iterate(ctx context.Context, params *ListParams) iter.Seq2[Webhook, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Webhook], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *WebhooksResource) Get(ctx context.Context, webhookID string) (*Webhook, error) {
	return doUnwrap[Webhook](ctx, r.c, requestOpts{method: "GET", path: "/v1/webhooks/" + encode(webhookID)})
}

// Create registers a webhook. The response's SecretKey (the HMAC signing
// secret for ConstructWebhookEvent) is returned exactly once — store it now.
func (r *WebhooksResource) Create(ctx context.Context, input CreateWebhookInput) (*Webhook, error) {
	return doUnwrap[Webhook](ctx, r.c, requestOpts{method: "POST", path: "/v1/webhooks", body: input})
}

func (r *WebhooksResource) Update(ctx context.Context, webhookID string, input UpdateWebhookInput) (*Webhook, error) {
	return doUnwrap[Webhook](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/webhooks/" + encode(webhookID), body: input})
}

func (r *WebhooksResource) Delete(ctx context.Context, webhookID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/webhooks/" + encode(webhookID)})
}

// GetLogs returns one page of the webhook's delivery logs.
func (r *WebhooksResource) GetLogs(ctx context.Context, webhookID string, params *ListParams) (*Page[WebhookLog], error) {
	return doPage[WebhookLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/webhooks/" + encode(webhookID) + "/logs", query: params.query()})
}

// ListEventTypes returns the webhook event types that can be subscribed to.
func (r *WebhooksResource) ListEventTypes(ctx context.Context) ([]WebhookEventType, error) {
	out, err := doUnwrap[struct {
		EventTypes []WebhookEventType `json:"event_types"`
	}](ctx, r.c, requestOpts{method: "GET", path: "/v1/webhooks/event-types"})
	if err != nil {
		return nil, err
	}
	return out.EventTypes, nil
}

// ListHmacFormats returns the signing formats this server offers for
// `hmac_format`. It is the live counterpart to a hardcoded enum: the set is
// derived server-side from ALL_WEBHOOK_HMAC_FORMATS
// (src/webhooks/hmac-formats.ts), which is also the set the write path
// enforces, so a client that validates against this answer cannot drift out of
// step with what the server accepts.
func (r *WebhooksResource) ListHmacFormats(ctx context.Context) ([]WebhookHmacFormatInfo, error) {
	out, err := doUnwrap[struct {
		HmacFormats []WebhookHmacFormatInfo `json:"hmac_formats"`
	}](ctx, r.c, requestOpts{method: "GET", path: "/v1/webhooks/hmac-formats"})
	if err != nil {
		return nil, err
	}
	return out.HmacFormats, nil
}

// Test fires a synthetic webhook.test event and returns the delivery result.
func (r *WebhooksResource) Test(ctx context.Context, webhookID string) (*WebhookTestResult, error) {
	return doUnwrap[WebhookTestResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/webhooks/" + encode(webhookID) + "/test"})
}
