package knoxcall

// Coverage for the promotion-opportunities resource. List GETs
// /v1/opportunities (paginated, status filter passed through), Accept POSTs
// /v1/opportunities/<id>/accept with the body and unwraps the route summary,
// and Dismiss POSTs .../dismiss. Captured at the HTTP boundary via
// envelopeServer, exactly like the secrets/wrap coverage — the method is never
// mocked.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestOpportunitiesList(t *testing.T) {
	row := `{"id":"opp_1","source":"gateway_traffic","service":"Stripe","destination_host":"api.stripe.com","status":"pending","confidence":0.92,"suggested_route_json":{"name":"stripe"},"evidence_json":{"count":7},"accepted_route_id":null,"created_at":"2026-08-10T00:00:00Z","updated_at":"2026-08-10T00:00:00Z","acted_at":null}`
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, pageEnvelope([]string{row}, 1, 1, 20))
	})

	page, err := c.Opportunities.List(context.Background(), &OpportunityParams{Status: "pending"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Data) != 1 {
		t.Fatalf("List returned %d rows, want 1", len(page.Data))
	}
	opp := page.Data[0]
	if opp.ID != "opp_1" || opp.Source != "gateway_traffic" || opp.Service != "Stripe" || opp.Status != "pending" {
		t.Fatalf("opportunity = %+v, want the row unwrapped", opp)
	}
	if opp.DestinationHost == nil || *opp.DestinationHost != "api.stripe.com" {
		t.Fatalf("DestinationHost = %v, want api.stripe.com", opp.DestinationHost)
	}
	if opp.Confidence == nil || *opp.Confidence != 0.92 {
		t.Fatalf("Confidence = %v, want 0.92", opp.Confidence)
	}
	if opp.AcceptedRouteID != nil || opp.ActedAt != nil {
		t.Fatalf("pending opportunity should have nil accepted_route_id/acted_at, got %+v", opp)
	}

	req := requests()[0]
	if req.Method != http.MethodGet || req.Path != "/v1/opportunities" {
		t.Fatalf("request = %s %s, want GET /v1/opportunities", req.Method, req.Path)
	}
	if req.Query["status"] != "pending" {
		t.Fatalf("status query = %q, want pending", req.Query["status"])
	}
}

func TestOpportunitiesAccept(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"opportunity_id":"opp_1","route":{"id":"r_1","slug":"stripe","name":"Stripe"},"collection_id":"col_1","environment":"production"},"meta":{"request_id":"req_1"}}`)
	})

	res, err := c.Opportunities.Accept(context.Background(), "opp_1", AcceptOpportunityInput{
		CollectionName: "Payments",
		Environment:    "production",
		Secret:         "stripe-live",
		HeaderName:     "Authorization",
		ValuePrefix:    "Bearer ",
	})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if res.OpportunityID != "opp_1" || res.Route.ID != "r_1" || res.CollectionID != "col_1" || res.Environment != "production" {
		t.Fatalf("Accept = %+v, want the promotion result unwrapped", res)
	}
	if res.Route.Slug == nil || *res.Route.Slug != "stripe" || res.Route.Name != "Stripe" {
		t.Fatalf("Route = %+v, want the created route summary", res.Route)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/opportunities/opp_1/accept" {
		t.Fatalf("request = %s %s, want POST /v1/opportunities/opp_1/accept", req.Method, req.Path)
	}
	// Every mutating management request carries a stable idempotency key.
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Errorf("missing X-Idempotency-Key on the accept POST")
	}
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal accept body: %v", err)
	}
	if body["collection_name"] != "Payments" || body["environment"] != "production" || body["secret"] != "stripe-live" {
		t.Fatalf("accept body = %v, want the snake_case accept fields", body)
	}
	if body["header_name"] != "Authorization" || body["value_prefix"] != "Bearer " {
		t.Fatalf("accept body header fields = %v, want header_name/value_prefix", body)
	}
}

func TestOpportunitiesAcceptEmptyBody(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"opportunity_id":"opp_2","route":{"id":"r_2","slug":null,"name":"Detected API"},"collection_id":"col_2","environment":"default"},"meta":{"request_id":"req_2"}}`)
	})

	res, err := c.Opportunities.Accept(context.Background(), "opp_2", AcceptOpportunityInput{})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if res.Route.Slug != nil {
		t.Fatalf("Route.Slug = %v, want nil for a slugless route", res.Route.Slug)
	}

	req := requests()[0]
	if req.Path != "/v1/opportunities/opp_2/accept" {
		t.Fatalf("path = %q, want /v1/opportunities/opp_2/accept", req.Path)
	}
	// The zero-value input omits every optional field.
	if strings.TrimSpace(string(req.Body)) != "{}" {
		t.Fatalf("empty accept body = %q, want {}", string(req.Body))
	}
}

func TestOpportunitiesDismiss(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"opportunity_id":"opp_1","status":"dismissed"},"meta":{"request_id":"req_1"}}`)
	})

	res, err := c.Opportunities.Dismiss(context.Background(), "opp_1")
	if err != nil {
		t.Fatalf("Dismiss: %v", err)
	}
	if res.OpportunityID != "opp_1" || res.Status != "dismissed" {
		t.Fatalf("Dismiss = %+v, want the dismissed status unwrapped", res)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/opportunities/opp_1/dismiss" {
		t.Fatalf("request = %s %s, want POST /v1/opportunities/opp_1/dismiss", req.Method, req.Path)
	}
}
