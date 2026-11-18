package knoxcall

// Tests for the response-envelope unwrapping + page/per_page pagination
// (../../PARITY.md §4) and the 2026-07 resource additions (§11). Every mock
// returns the REAL server envelope — {data, meta} exactly as
// src/client-api/helpers.ts builds it — never the bare object.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// recordedRequest captures one management request seen by the mock server.
type recordedRequest struct {
	Method string
	Path   string
	Query  map[string]string
	Body   []byte
	Header http.Header
}

// envelopeServer serves /oauth/token plus a handler, recording every
// non-token request.
func envelopeServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*Client, func() []recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var seen []recordedRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			writeToken(w, "kc_live_aaaa", 3600)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		mu.Lock()
		seen = append(seen, recordedRequest{Method: r.Method, Path: r.URL.Path, Query: q, Body: body, Header: r.Header.Clone()})
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	requests := func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]recordedRequest(nil), seen...)
	}
	return newTestClient(t, ts.URL, nil), requests
}

func writeJSON(w http.ResponseWriter, status int, payload string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(payload))
}

// pageEnvelope renders rows as one real paginated envelope.
func pageEnvelope(rows []string, total, page, perPage int) string {
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	return fmt.Sprintf(`{"data":[%s],"meta":{"total":%d,"page":%d,"per_page":%d,"total_pages":%d,"request_id":"req_mock"}}`,
		strings.Join(rows, ","), total, page, perPage, totalPages)
}

// ── Single-object unwrapping ──────────────────────────────────────────────────

func TestGetUnwrapsSingleObjectEnvelope(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"r_1","name":"orders","slug":"api-orders","target_base_url":"https://upstream.example.test","enabled":true,"configured_environments":["production"],"environment_override_count":1},"meta":{"request_id":"req_1"}}`)
	})
	route, err := c.Routes.Get(context.Background(), "r_1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if route.ID != "r_1" || route.Name != "orders" || route.Slug == nil || *route.Slug != "api-orders" {
		t.Fatalf("route = %+v, want the envelope's data unwrapped", route)
	}
	if route.TargetBaseURL == nil || *route.TargetBaseURL != "https://upstream.example.test" || route.ConfiguredEnvironments[0] != "production" {
		t.Fatalf("route = %+v, want typed nested fields decoded", route)
	}
}

func TestDeleteShapesAreNotUnified(t *testing.T) {
	// routes, vaults AND vault TOKENS → {deleted: true}; route ACTIONS (like
	// dyn-db creds) → {deleted: "<id>"}. The server deliberately varies these;
	// both the boolean and the name/id-string forms must decode.
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/actions/") {
			writeJSON(w, 200, `{"data":{"deleted":"ra_2"},"meta":{"request_id":"req_2"}}`)
			return
		}
		writeJSON(w, 200, `{"data":{"deleted":true},"meta":{"request_id":"req_1"}}`)
	})
	rd, err := c.Routes.Delete(context.Background(), "r_1")
	if err != nil || !rd.Deleted {
		t.Fatalf("Routes.Delete = %+v, %v; want {Deleted:true}", rd, err)
	}
	vd, err := c.Vaults.Delete(context.Background(), "cards-vault")
	if err != nil || !vd.Deleted {
		t.Fatalf("Vaults.Delete = %+v, %v; want {Deleted:true}", vd, err)
	}
	td, err := c.Vaults.DeleteToken(context.Background(), "cards-vault", "tok_9")
	if err != nil || !td.Deleted {
		t.Fatalf("Vaults.DeleteToken = %+v, %v; want {Deleted:true}", td, err)
	}
	ad, err := c.Routes.DeleteAction(context.Background(), "r_1", "ra_2")
	if err != nil || ad.Deleted != "ra_2" {
		t.Fatalf("Routes.DeleteAction = %+v, %v; want the action id echoed", ad, err)
	}
}

// ── Paginated lists ───────────────────────────────────────────────────────────

func TestListReturnsTypedPageEnvelope(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, pageEnvelope([]string{
			`{"id":"r_1","name":"a","target_base_url":"https://a.example.test","enabled":true}`,
			`{"id":"r_2","name":"b","target_base_url":"https://b.example.test","enabled":false}`,
		}, 7, 2, 2))
	})
	page, err := c.Routes.List(context.Background(), &ListRoutesParams{Page: 2, PerPage: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Data) != 2 || page.Data[0].ID != "r_1" || page.Data[1].Name != "b" {
		t.Fatalf("page.Data = %+v, want the typed rows", page.Data)
	}
	if page.Meta.Total != 7 || page.Meta.Page != 2 || page.Meta.PerPage != 2 || page.Meta.TotalPages != 4 || page.Meta.RequestID != "req_mock" {
		t.Fatalf("page.Meta = %+v, want the envelope meta verbatim", page.Meta)
	}

	req := requests()[0]
	if req.Query["page"] != "2" || req.Query["per_page"] != "2" {
		t.Fatalf("query = %v, want page/per_page params", req.Query)
	}
	for _, dead := range []string{"cursor", "limit", "next_cursor"} {
		if _, ok := req.Query[dead]; ok {
			t.Fatalf("query = %v, must never send the dead %q param", req.Query, dead)
		}
	}
}

func TestListFiltersAreSent(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, pageEnvelope(nil, 0, 1, 20))
	})
	enabled := true
	if _, err := c.Routes.List(context.Background(), &ListRoutesParams{Enabled: &enabled}); err != nil {
		t.Fatalf("Routes.List: %v", err)
	}
	if _, err := c.AuditLogs.List(context.Background(), &AuditLogParams{Action: "secret.create", ResourceType: "secret"}); err != nil {
		t.Fatalf("AuditLogs.List: %v", err)
	}
	if _, err := c.Clients.List(context.Background(), &ListClientsParams{Type: "server"}); err != nil {
		t.Fatalf("Clients.List: %v", err)
	}
	reqs := requests()
	if reqs[0].Query["enabled"] != "true" {
		t.Errorf("routes query = %v, want enabled=true", reqs[0].Query)
	}
	if reqs[1].Query["action"] != "secret.create" || reqs[1].Query["resource_type"] != "secret" {
		t.Errorf("audit query = %v, want action + resource_type filters", reqs[1].Query)
	}
	if reqs[2].Query["type"] != "server" {
		t.Errorf("clients query = %v, want type=server", reqs[2].Query)
	}
}

func TestListAllWalksEveryPage(t *testing.T) {
	// 5 secrets at 2/page → pages 1..3.
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		total, perPage := 5, 2
		start := (page - 1) * perPage
		var rows []string
		for i := start; i < start+perPage && i < total; i++ {
			rows = append(rows, fmt.Sprintf(`{"id":"sec_%d","name":"s%d","secret_type":"string"}`, i, i))
		}
		writeJSON(w, 200, pageEnvelope(rows, total, page, perPage))
	})

	all, err := c.Secrets.ListAll(context.Background(), &ListParams{PerPage: 2})
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 5 || all[0].ID != "sec_0" || all[4].ID != "sec_4" {
		t.Fatalf("ListAll returned %d items (%+v), want all 5 across 3 pages", len(all), all)
	}
	reqs := requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d, want exactly 3 (one per page)", len(reqs))
	}
	for i, want := range []string{"1", "2", "3"} {
		if reqs[i].Query["page"] != want {
			t.Errorf("request %d page = %q, want %s", i, reqs[i].Query["page"], want)
		}
	}
}

func TestListAllStopsDefensivelyOnEmptyPage(t *testing.T) {
	// A lying meta (total_pages 99) with an empty page must not loop.
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":[],"meta":{"total":198,"page":1,"per_page":2,"total_pages":99,"request_id":"req_mock"}}`)
	})
	all, err := c.Secrets.ListAll(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 0 || len(requests()) != 1 {
		t.Fatalf("items = %d, requests = %d; want an empty page to stop the walk", len(all), len(requests()))
	}
}

// ── Bare-array endpoints ──────────────────────────────────────────────────────

func TestBareArrayEndpointsUnwrapToPlainSlices(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/environments":
			writeJSON(w, 200, `{"data":[{"id":"env_1","name":"production","display_name":"Production","color":"#00ff00","is_default":true,"created_at":"2026-01-01T00:00:00Z"}],"meta":{"request_id":"req_1"}}`)
		case r.URL.Path == "/v1/crypto/keys":
			writeJSON(w, 200, `{"data":[{"id":"key_1","name":"default","key_type":"aes256-gcm96","mode":"cloud-only","current_version":3,"deletion_allowed":false,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"}],"meta":{"request_id":"req_2"}}`)
		case r.URL.Path == "/v1/agents":
			writeJSON(w, 200, `{"data":[{"id":"ag_1","name":"ci","agent_id":"agent_abc","status":"active","require_verified_build":false,"created_at":"2026-01-01T00:00:00Z","has_tamper_events":false}],"meta":{"request_id":"req_3"}}`)
		default:
			writeJSON(w, 404, `{"error":{"type":"not_found","message":"nope","request_id":"req_x"}}`)
		}
	})

	envs, err := c.Environments.List(context.Background())
	if err != nil || len(envs) != 1 || envs[0].Name != "production" || !envs[0].IsDefault {
		t.Fatalf("Environments.List = %+v, %v; want the unwrapped array", envs, err)
	}
	keys, err := c.Crypto.ListKeys(context.Background())
	if err != nil || len(keys) != 1 || keys[0].CurrentVersion != 3 {
		t.Fatalf("Crypto.ListKeys = %+v, %v; want the unwrapped array", keys, err)
	}
	agents, err := c.Agents.List(context.Background())
	if err != nil || len(agents) != 1 || agents[0].AgentID != "agent_abc" {
		t.Fatalf("Agents.List = %+v, %v; want the unwrapped array", agents, err)
	}
	for _, req := range requests() {
		if len(req.Query) != 0 {
			t.Errorf("%s sent query %v — bare-array endpoints take NO page params", req.Path, req.Query)
		}
	}
}

// ── Special envelopes ─────────────────────────────────────────────────────────

func TestOAuthClientCreateAttachesTopLevelWarning(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/oauth-clients" {
			writeJSON(w, 201, `{"data":{"id":"oc_1","client_id":"tk_new","client_secret":"cs_once","type":"confidential","grant_types":["client_credentials"],"allowed_scopes":["*:*"],"redirect_uris":[]},"warning":"broad scopes granted"}`)
			return
		}
		writeJSON(w, 200, `{"data":{"client_id":"tk_new","client_secret":"cs_rotated"},"warning":"store the new secret now"}`)
	})
	created, err := c.OAuthClients.Create(context.Background(), CreateOAuthClientInput{Name: "svc"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ClientID != "tk_new" || created.ClientSecret == nil || *created.ClientSecret != "cs_once" {
		t.Fatalf("created = %+v, want the unwrapped data", created)
	}
	if created.Warning != "broad scopes granted" {
		t.Fatalf("Warning = %q, want the top-level warning attached", created.Warning)
	}
	rotated, err := c.OAuthClients.RotateSecret(context.Background(), "oc_1")
	if err != nil || rotated.ClientSecret != "cs_rotated" || rotated.Warning != "store the new secret now" {
		t.Fatalf("RotateSecret = %+v, %v; want secret + warning", rotated, err)
	}
}

func TestOAuthClientCreatePublicHasNilSecret(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, `{"data":{"id":"oc_2","client_id":"tk_pub","client_secret":null,"type":"public","grant_types":["authorization_code"],"allowed_scopes":[],"redirect_uris":["https://app.example.test/cb"]}}`)
	})
	created, err := c.OAuthClients.Create(context.Background(), CreateOAuthClientInput{Name: "spa", Type: "public"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ClientSecret != nil {
		t.Fatalf("ClientSecret = %v, want nil for public clients", *created.ClientSecret)
	}
	if created.Warning != "" {
		t.Fatalf("Warning = %q, want empty when the response has none", created.Warning)
	}
}

func TestAgentsCreateUnwrapsOnceOnlySecret(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Hand-rolled 201: meta has secret_shown_once and NO request_id.
		writeJSON(w, 201, `{"data":{"id":"ag_1","name":"ci","agent_id":"agent_abc","status":"active","require_verified_build":false,"created_at":"2026-01-01T00:00:00Z","agent_secret":"as_once"},"meta":{"secret_shown_once":true}}`)
	})
	created, err := c.Agents.Create(context.Background(), "ci")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.AgentSecret != "as_once" || created.AgentID != "agent_abc" {
		t.Fatalf("created = %+v, want agent_secret unwrapped from data", created)
	}
}

func TestDynDbListLeasesUnwrapsLimitOffsetInsideData(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"leases":[{"id":7,"status":"active","expires_at":"2026-07-02T01:00:00Z","issued_at":"2026-07-02T00:00:00Z","username":"v_abc","connection_name":"main-pg","role_name":"readonly","engine":"postgres"}],"total":1,"limit":50,"offset":0},"meta":{"request_id":"req_1"}}`)
	})
	leases, err := c.DynamicDB.ListLeases(context.Background(), &ListLeasesParams{Limit: 50, Connection: "main-pg"})
	if err != nil {
		t.Fatalf("ListLeases: %v", err)
	}
	if leases.Total != 1 || leases.Limit != 50 || len(leases.Leases) != 1 || leases.Leases[0].ID != 7 {
		t.Fatalf("leases = %+v, want {leases,total,limit,offset} unwrapped", leases)
	}
	req := requests()[0]
	if req.Query["limit"] != "50" || req.Query["connection"] != "main-pg" {
		t.Fatalf("query = %v, want limit/connection (this endpoint keeps limit/offset)", req.Query)
	}
}

func TestPKIRawPEMAndCRLBypassJSONDecoding(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cert") {
			w.Header().Set("Content-Type", "text/x-pem-file")
			_, _ = w.Write([]byte(pem))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("crl-body"))
	})
	got, err := c.PKI.GetRootCert(context.Background(), "internal")
	if err != nil || got != pem {
		t.Fatalf("GetRootCert = %q, %v; want the raw PEM text", got, err)
	}
	crl, err := c.PKI.GetCRL(context.Background(), "internal")
	if err != nil || crl != "crl-body" {
		t.Fatalf("GetCRL = %q, %v; want the raw text", crl, err)
	}
}

func TestErrorEnvelopeIsParsedIntoTypedError(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, `{"error":{"type":"not_found","message":"Route not found.","request_id":"req_err"}}`)
	})
	_, err := c.Routes.Get(context.Background(), "r_missing")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("err = %v (%T), want *NotFoundError", err, err)
	}
	if nf.Message != "not_found" || nf.Detail != "Route not found." || nf.RequestID != "req_err" {
		t.Fatalf("error = %+v, want the nested error envelope parsed", nf.APIError)
	}
}

// ── Webhooks: event types + test delivery ─────────────────────────────────────

func TestWebhookListEventTypesAndTest(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/webhooks/event-types" {
			writeJSON(w, 200, `{"data":{"event_types":[{"value":"request.success","label":"Request success","description":"2xx responses"},{"value":"audit.event","label":"Audit event","description":"audit rows"}]},"meta":{"request_id":"req_1"}}`)
			return
		}
		writeJSON(w, 200, `{"data":{"success":true,"status":204,"response_time_ms":38},"meta":{"request_id":"req_2"}}`)
	})
	types, err := c.Webhooks.ListEventTypes(context.Background())
	if err != nil || len(types) != 2 || types[0].Value != "request.success" {
		t.Fatalf("ListEventTypes = %+v, %v; want the unwrapped event_types", types, err)
	}
	res, err := c.Webhooks.Test(context.Background(), "wh_1")
	if err != nil || !res.Success || res.Status != 204 || res.ResponseTimeMs != 38 {
		t.Fatalf("Test = %+v, %v; want the typed delivery result", res, err)
	}
}
