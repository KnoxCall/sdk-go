package knoxcall

// Happy-path coverage for the Workflows resource (PARITY §11). Every mock
// returns the REAL {data, meta} server envelope, never the bare object.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

func TestWorkflowsCRUDAndExecute(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workflows":
			writeJSON(w, 200, pageEnvelope([]string{
				`{"id":"wf_1","name":"nightly","description":null,"definition":{"nodes":[]},"environment":"production","enabled":true,"version":3,"sandbox":false,"timeout_seconds":null,"published_at":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z","run_count":12}`,
			}, 1, 1, 20))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workflows/wf_1":
			writeJSON(w, 200, `{"data":{"id":"wf_1","name":"nightly","description":"nightly sync","definition":{"nodes":[]},"environment":"production","enabled":true,"version":3,"sandbox":false,"timeout_seconds":30,"published_at":"2026-01-02T00:00:00Z","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z"},"meta":{"request_id":"req_g"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/workflows":
			writeJSON(w, 201, `{"data":{"id":"wf_2","name":"new","description":null,"definition":{"nodes":[]},"environment":null,"enabled":false,"version":1,"sandbox":false,"timeout_seconds":null,"published_at":null,"created_at":"2026-01-03T00:00:00Z","updated_at":"2026-01-03T00:00:00Z"},"meta":{"request_id":"req_c"}}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/workflows/wf_1":
			writeJSON(w, 200, `{"data":{"id":"wf_1","name":"renamed","description":null,"definition":{"nodes":[]},"environment":"production","enabled":true,"version":4,"sandbox":false,"timeout_seconds":null,"published_at":null,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-04T00:00:00Z"},"meta":{"request_id":"req_u"}}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workflows/wf_1":
			writeJSON(w, 200, `{"data":{"id":"wf_1","deleted":true},"meta":{"request_id":"req_d"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/workflows/wf_1/execute":
			writeJSON(w, 202, `{"data":{"id":"wex_1","workflow_id":"wf_1","status":"queued"},"meta":{"request_id":"req_x"}}`)
		default:
			writeJSON(w, 404, `{"error":{"type":"not_found","message":"nope","request_id":"req_z"}}`)
		}
	})

	ctx := context.Background()

	page, err := c.Workflows.List(ctx, &ListParams{PerPage: 20})
	if err != nil || len(page.Data) != 1 || page.Data[0].ID != "wf_1" || page.Data[0].Description != nil {
		t.Fatalf("List = %+v, %v; want one typed workflow with a null description", page, err)
	}
	if page.Data[0].RunCount == nil || *page.Data[0].RunCount != 12 {
		t.Fatalf("run_count = %v, want 12 on the list projection", page.Data[0].RunCount)
	}
	if page.Meta.RequestID != "req_mock" {
		t.Fatalf("meta = %+v, want the envelope meta", page.Meta)
	}

	wf, err := c.Workflows.Get(ctx, "wf_1")
	if err != nil || wf.Name != "nightly" || wf.Description == nil || *wf.Description != "nightly sync" {
		t.Fatalf("Get = %+v, %v; want the unwrapped workflow", wf, err)
	}
	if wf.TimeoutSeconds == nil || *wf.TimeoutSeconds != 30 {
		t.Fatalf("Get timeout_seconds = %v, want 30", wf.TimeoutSeconds)
	}

	created, err := c.Workflows.Create(ctx, CreateWorkflowInput{Name: "new", Definition: map[string]any{"nodes": []any{}}})
	if err != nil || created.ID != "wf_2" || created.Enabled {
		t.Fatalf("Create = %+v, %v; want the created workflow", created, err)
	}

	newName := "renamed"
	updated, err := c.Workflows.Update(ctx, "wf_1", UpdateWorkflowInput{Name: &newName})
	if err != nil || updated.Name != "renamed" || updated.Version != 4 {
		t.Fatalf("Update = %+v, %v; want the updated workflow", updated, err)
	}

	del, err := c.Workflows.Delete(ctx, "wf_1")
	if err != nil || del.ID != "wf_1" || !del.Deleted {
		t.Fatalf("Delete = %+v, %v; want {id, deleted:true}", del, err)
	}

	run, err := c.Workflows.Execute(ctx, "wf_1", map[string]any{"foo": "bar"})
	if err != nil || run.ID != "wex_1" || run.WorkflowID != "wf_1" || run.Status != "queued" {
		t.Fatalf("Execute = %+v, %v; want the queued run ack", run, err)
	}

	reqs := requests()

	// Create body: definition present; empty description/enabled omitted.
	var createBody map[string]any
	for i := range reqs {
		if reqs[i].Method == http.MethodPost && reqs[i].Path == "/v1/workflows" {
			_ = json.Unmarshal(reqs[i].Body, &createBody)
			if reqs[i].Header.Get("X-Idempotency-Key") == "" {
				t.Errorf("create missing idempotency key — mutations must carry one")
			}
		}
	}
	if createBody["name"] != "new" {
		t.Errorf("create body = %v, want name=new", createBody)
	}
	if _, ok := createBody["description"]; ok {
		t.Errorf("create body = %v, empty description must be omitted", createBody)
	}

	// Execute body must be {"input": {...}} and carry an idempotency key.
	var execReq *recordedRequest
	for i := range reqs {
		if reqs[i].Path == "/v1/workflows/wf_1/execute" {
			execReq = &reqs[i]
		}
	}
	if execReq == nil {
		t.Fatal("no execute request recorded")
	}
	var execBody map[string]any
	if err := json.Unmarshal(execReq.Body, &execBody); err != nil {
		t.Fatalf("unmarshal execute body: %v", err)
	}
	input, ok := execBody["input"].(map[string]any)
	if !ok || input["foo"] != "bar" {
		t.Fatalf("execute body = %v, want {\"input\":{\"foo\":\"bar\"}}", execBody)
	}
	if execReq.Header.Get("X-Idempotency-Key") == "" {
		t.Fatalf("execute missing idempotency key — mutations must carry one")
	}

	// GET requests never carry an idempotency key.
	for i := range reqs {
		if reqs[i].Method == http.MethodGet && reqs[i].Header.Get("X-Idempotency-Key") != "" {
			t.Errorf("GET %s carried an idempotency key, want none", reqs[i].Path)
		}
	}
}

func TestWorkflowExecutionsListGetCancelAndPagination(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workflows/wf_1/executions":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page == 0 {
				page = 1
			}
			total, perPage := 3, 2
			start := (page - 1) * perPage
			var rows []string
			for i := start; i < start+perPage && i < total; i++ {
				rows = append(rows, fmt.Sprintf(`{"id":"wex_%d","workflow_id":"wf_1","status":"succeeded","trigger_type":"manual","started_at":null,"completed_at":null,"execution_time_ms":null,"error_message":null,"workflow_version":3,"created_at":"2026-01-01T00:00:00Z"}`, i))
			}
			writeJSON(w, 200, pageEnvelope(rows, total, page, perPage))
		case r.URL.Path == "/v1/workflows/executions/wex_0":
			writeJSON(w, 200, `{"data":{"id":"wex_0","workflow_id":"wf_1","status":"succeeded","trigger_type":"manual","started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:05Z","execution_time_ms":5000,"error_message":null,"workflow_version":3,"created_at":"2026-01-01T00:00:00Z","node_executions":[{"node":"start"}]},"meta":{"request_id":"req_ge"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/workflows/executions/wex_0/cancel":
			writeJSON(w, 200, `{"data":{"id":"wex_0","status":"cancelled"},"meta":{"request_id":"req_ce"}}`)
		default:
			writeJSON(w, 404, `{"error":{"type":"not_found","message":"nope","request_id":"req_z"}}`)
		}
	})

	ctx := context.Background()

	page, err := c.Workflows.ListExecutions(ctx, "wf_1", &ListParams{PerPage: 2})
	if err != nil || len(page.Data) != 2 || page.Data[0].ID != "wex_0" || page.Data[0].Status != "succeeded" {
		t.Fatalf("ListExecutions = %+v, %v; want a typed page of executions", page, err)
	}

	all, err := c.Workflows.ListAllExecutions(ctx, "wf_1", &ListParams{PerPage: 2})
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAllExecutions = %d items, %v; want 3 across 2 pages", len(all), err)
	}

	ex, err := c.Workflows.GetExecution(ctx, "wex_0")
	if err != nil || ex.Status != "succeeded" || ex.ExecutionTimeMs == nil || *ex.ExecutionTimeMs != 5000 {
		t.Fatalf("GetExecution = %+v, %v; want the composed execution", ex, err)
	}
	if len(ex.NodeExecutions) != 1 {
		t.Fatalf("GetExecution node_executions = %v, want the step details", ex.NodeExecutions)
	}

	cancel, err := c.Workflows.CancelExecution(ctx, "wex_0")
	if err != nil || cancel.ID != "wex_0" || cancel.Status != "cancelled" {
		t.Fatalf("CancelExecution = %+v, %v; want {id, status}", cancel, err)
	}

	paths := map[string]bool{}
	for _, req := range requests() {
		paths[req.Path] = true
	}
	for _, want := range []string{
		"/v1/workflows/wf_1/executions",
		"/v1/workflows/executions/wex_0",
		"/v1/workflows/executions/wex_0/cancel",
	} {
		if !paths[want] {
			t.Errorf("missing request to %s", want)
		}
	}
}

// PARITY §11 Workflows — "an unpublishable definition may never be the running
// one". CREATE keeps the caller's data and withholds the switch; UPDATE
// refuses. Both are reachable on an ordinary request, so both are pinned.
func TestWorkflowLiveRuleWithheldOnCreateRefusedOnUpdate(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/workflows":
			// The definition's steps are incomplete, so the row is created NOT
			// enabled even though the request asked for `true`. A normal 200,
			// not an error — the SDK must report what the server stored.
			writeJSON(w, 200, `{"data":{"id":"wf_5","name":"new","description":null,"definition":{"nodes":[]},"environment":null,"enabled":false,"version":1,"sandbox":false,"timeout_seconds":null,"published_at":null,"created_at":"2026-01-03T00:00:00Z","updated_at":"2026-01-03T00:00:00Z"},"meta":{"request_id":"req_c"}}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/workflows/wf_5":
			writeJSON(w, 422, `{"error":{"type":"invalid_definition","message":"This workflow cannot be enabled: node \"n1\": HTTP method is required","request_id":"req_e"}}`)
		default:
			writeJSON(w, 404, `{"error":{"type":"not_found","message":"nope","request_id":"req_z"}}`)
		}
	})

	ctx := context.Background()
	wantEnabled := true

	created, err := c.Workflows.Create(ctx, CreateWorkflowInput{
		Name:       "new",
		Definition: map[string]any{"nodes": []any{}},
		Enabled:    &wantEnabled,
	})
	if err != nil {
		t.Fatalf("Create = %v; withholding the switch is a success, not an error", err)
	}
	if created.Enabled {
		t.Fatalf("Create enabled = true; the SDK must surface the server's value, not echo the request")
	}

	_, err = c.Workflows.Update(ctx, "wf_5", UpdateWorkflowInput{Enabled: &wantEnabled})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("Update err = %v (%T); want *ValidationError for the 422", err, err)
	}
	if ve.Message != "invalid_definition" {
		t.Fatalf("error type = %q; want invalid_definition", ve.Message)
	}

	// A 422 is a client error: retrying it unchanged burns the tenant's rate
	// limit and can never succeed.
	patches := 0
	for _, req := range requests() {
		if req.Method == http.MethodPatch {
			patches++
		}
	}
	if patches != 1 {
		t.Fatalf("PATCH attempts = %d; a 422 must not be retried", patches)
	}
}
