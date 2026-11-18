package knoxcall

// Opportunities resource — mirrors src/client-api/opportunities.ts (PR5) and
// the Node SDK's OpportunitiesResource.
//
// Promotion opportunities: "we detected outbound API usage → create a route",
// from two sources (agent_monitor + gateway_traffic). List refreshes gateway
// detection on read; Accept promotes a suggestion to a durable route + secret.

import (
	"context"
	"iter"
	"net/url"
)

// OpportunitySource is the detector that surfaced the opportunity.
// One of "agent_monitor" or "gateway_traffic".
type OpportunitySource = string

// OpportunityStatus is the lifecycle state of an opportunity.
// One of "pending", "snoozed", "onboarded", or "dismissed".
type OpportunityStatus = string

// Opportunity is one GET /v1/opportunities row: a detected outbound API usage
// that can be promoted into a durable route + secret binding.
type Opportunity struct {
	ID     string            `json:"id"`
	Source OpportunitySource `json:"source"`
	// Service is the detected upstream service label.
	Service string `json:"service"`
	// DestinationHost is the detected upstream hostname; nil when unknown.
	DestinationHost *string           `json:"destination_host"`
	Status          OpportunityStatus `json:"status"`
	// Confidence is the detector's 0..1 score; nil when not scored.
	Confidence *float64 `json:"confidence"`
	// SuggestedRouteJSON is the detector's proposed route config; nil when absent.
	SuggestedRouteJSON map[string]any `json:"suggested_route_json"`
	// EvidenceJSON is the supporting detection evidence; nil when absent.
	EvidenceJSON map[string]any `json:"evidence_json"`
	// AcceptedRouteID is the route created on accept; nil until onboarded.
	AcceptedRouteID *string `json:"accepted_route_id"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	// ActedAt is when the opportunity was accepted or dismissed; nil while pending.
	ActedAt *string `json:"acted_at"`
}

// AcceptOpportunityInput is the POST /v1/opportunities/{id}/accept body. Every
// field is optional; omitted fields fall back to the suggestion's values or the
// tenant defaults server-side.
type AcceptOpportunityInput struct {
	// CollectionName files the route under a collection (else the suggestion's,
	// else "Wrapped APIs").
	CollectionName string `json:"collection_name,omitempty"`
	// Environment the route config is written into (else the tenant default).
	Environment string `json:"environment,omitempty"`
	// Secret is the secret name/id to bind (else an escrowed wrap credential for
	// the host is auto-bound).
	Secret string `json:"secret,omitempty"`
	// HeaderName is the injected header name (default Authorization) and
	// ValuePrefix its value prefix (default "Bearer ").
	HeaderName  string `json:"header_name,omitempty"`
	ValuePrefix string `json:"value_prefix,omitempty"`
}

// AcceptedOpportunityRoute is the route created when an opportunity is accepted.
type AcceptedOpportunityRoute struct {
	ID   string  `json:"id"`
	Slug *string `json:"slug"`
	Name string  `json:"name"`
}

// AcceptOpportunityResponse is the unwrapped result of accepting an opportunity.
type AcceptOpportunityResponse struct {
	OpportunityID string                   `json:"opportunity_id"`
	Route         AcceptedOpportunityRoute `json:"route"`
	CollectionID  string                   `json:"collection_id"`
	Environment   string                   `json:"environment"`
}

// DismissOpportunityResponse is the unwrapped result of dismissing an
// opportunity; Status is always "dismissed".
type DismissOpportunityResponse struct {
	OpportunityID string `json:"opportunity_id"`
	Status        string `json:"status"`
}

// OpportunityParams selects a page of opportunities plus the endpoint's status
// filter. Zero values are omitted, so the server defaults apply.
type OpportunityParams struct {
	Page    int
	PerPage int
	// Status filters to one lifecycle state ("pending", "snoozed", "onboarded",
	// "dismissed"); empty returns all.
	Status OpportunityStatus
}

func (p *OpportunityParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setPageQuery(q, p.Page, p.PerPage)
	if p.Status != "" {
		q.Set("status", p.Status)
	}
	return q
}

// OpportunitiesResource lists and acts on promotion opportunities.
type OpportunitiesResource struct{ c *Client }

// List returns one page of promotion opportunities (refreshes gateway
// detection on read).
func (r *OpportunitiesResource) List(ctx context.Context, params *OpportunityParams) (*Page[Opportunity], error) {
	return doPage[Opportunity](ctx, r.c, requestOpts{method: "GET", path: "/v1/opportunities", query: params.query()})
}

// ListAll walks every page and returns all matching opportunities.
func (r *OpportunitiesResource) ListAll(ctx context.Context, params *OpportunityParams) ([]Opportunity, error) {
	p := OpportunityParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Opportunity], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every matching opportunity one at a time, fetching
// pages on demand rather than buffering them all (the streaming analog of
// ListAll — see helpers.iterate). Range over it with two variables and break on
// the first non-nil error.
func (r *OpportunitiesResource) Iterate(ctx context.Context, params *OpportunityParams) iter.Seq2[Opportunity, error] {
	p := OpportunityParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Opportunity], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Accept promotes a gateway suggestion to a durable route + secret binding.
// Input may be the zero value to accept with the suggestion's defaults. Like
// every mutating management request it goes through the client's request
// pipeline, inheriting auth, retry, envelope-unwrapping, and error mapping, and
// carries a stable idempotency key exactly as Secrets.Create does.
func (r *OpportunitiesResource) Accept(ctx context.Context, opportunityID string, input AcceptOpportunityInput) (*AcceptOpportunityResponse, error) {
	return doUnwrap[AcceptOpportunityResponse](ctx, r.c, requestOpts{method: "POST", path: "/v1/opportunities/" + encode(opportunityID) + "/accept", body: input})
}

// Dismiss dismisses a pending suggestion.
func (r *OpportunitiesResource) Dismiss(ctx context.Context, opportunityID string) (*DismissOpportunityResponse, error) {
	return doUnwrap[DismissOpportunityResponse](ctx, r.c, requestOpts{method: "POST", path: "/v1/opportunities/" + encode(opportunityID) + "/dismiss"})
}
