package knoxcall

// Workflows resource — mirrors knoxcall-node's src/resources/workflows.ts
// (PARITY §11). Wraps /v1/workflows: list (paginated) + list-all, get, create,
// update, delete, execute, plus the executions sub-collection (list/list-all,
// get, cancel). Mutating methods carry the ULID idempotency key like every
// other resource (applied by the request pipeline for non-GET/HEAD methods).

import (
	"context"
	"iter"
)

// Workflow is one row returned by GET /v1/workflows. Fields absent from a
// given response stay zero/nil.
type Workflow struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// Definition is the workflow graph (nodes/edges); shape is server-defined,
	// so it is carried opaquely.
	Definition     any     `json:"definition"`
	Environment    *string `json:"environment"`
	Enabled        bool    `json:"enabled"`
	Version        int     `json:"version"`
	Sandbox        bool    `json:"sandbox"`
	TimeoutSeconds *int    `json:"timeout_seconds"`
	PublishedAt    *string `json:"published_at"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	// RunCount is present only on list projections.
	RunCount *int `json:"run_count,omitempty"`
}

// WorkflowExecution is one workflow run (GET /v1/workflows/{id}/executions and
// GET /v1/workflows/executions/{id}).
type WorkflowExecution struct {
	ID              string  `json:"id"`
	WorkflowID      string  `json:"workflow_id"`
	Status          string  `json:"status"`
	TriggerType     string  `json:"trigger_type"`
	StartedAt       *string `json:"started_at"`
	CompletedAt     *string `json:"completed_at"`
	ExecutionTimeMs *int    `json:"execution_time_ms"`
	ErrorMessage    *string `json:"error_message"`
	WorkflowVersion *int    `json:"workflow_version"`
	CreatedAt       string  `json:"created_at"`
	// NodeExecutions is present only on the single-execution projection.
	NodeExecutions []any `json:"node_executions,omitempty"`
}

// WorkflowRun is the queued-execution acknowledgement returned by Execute.
type WorkflowRun struct {
	ID         string `json:"id"`
	WorkflowID string `json:"workflow_id"`
	Status     string `json:"status"`
}

// WorkflowDeleted is the delete acknowledgement: {id, deleted: true}.
type WorkflowDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// WorkflowExecutionCancel is the cancel acknowledgement: {id, status}.
type WorkflowExecutionCancel struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// CreateWorkflowInput is the POST /v1/workflows body.
type CreateWorkflowInput struct {
	Name          string `json:"name"`
	Definition    any    `json:"definition"`
	Description   string `json:"description,omitempty"`
	TriggerConfig any    `json:"trigger_config,omitempty"`
	Environment   string `json:"environment,omitempty"`
	Enabled       *bool  `json:"enabled,omitempty"`
}

// UpdateWorkflowInput is the PATCH /v1/workflows/{id} body — the partial
// analog of CreateWorkflowInput. Nil / empty fields are omitted.
type UpdateWorkflowInput struct {
	Name          *string `json:"name,omitempty"`
	Definition    any     `json:"definition,omitempty"`
	Description   *string `json:"description,omitempty"`
	TriggerConfig any     `json:"trigger_config,omitempty"`
	Environment   *string `json:"environment,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

type WorkflowsResource struct{ c *Client }

// List returns one page of workflows (server default 20/page, cap 100).
func (r *WorkflowsResource) List(ctx context.Context, params *ListParams) (*Page[Workflow], error) {
	return doPage[Workflow](ctx, r.c, requestOpts{method: "GET", path: "/v1/workflows", query: params.query()})
}

// ListAll walks every page starting at params.Page (default 1) and returns all
// workflows — the Go analog of node's iterate().
func (r *WorkflowsResource) ListAll(ctx context.Context, params *ListParams) ([]Workflow, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Workflow], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every workflow one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *WorkflowsResource) Iterate(ctx context.Context, params *ListParams) iter.Seq2[Workflow, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Workflow], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Get fetches one workflow by id.
func (r *WorkflowsResource) Get(ctx context.Context, id string) (*Workflow, error) {
	return doUnwrap[Workflow](ctx, r.c, requestOpts{method: "GET", path: "/v1/workflows/" + encode(id)})
}

// Create creates a workflow.
func (r *WorkflowsResource) Create(ctx context.Context, input CreateWorkflowInput) (*Workflow, error) {
	return doUnwrap[Workflow](ctx, r.c, requestOpts{method: "POST", path: "/v1/workflows", body: input})
}

// Update updates a workflow.
func (r *WorkflowsResource) Update(ctx context.Context, id string, input UpdateWorkflowInput) (*Workflow, error) {
	return doUnwrap[Workflow](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/workflows/" + encode(id), body: input})
}

// Delete deletes a workflow; the response echoes {id, deleted: true}.
func (r *WorkflowsResource) Delete(ctx context.Context, id string) (*WorkflowDeleted, error) {
	return doUnwrap[WorkflowDeleted](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/workflows/" + encode(id)})
}

// Execute queues a run and returns the execution ack. Idempotent: the
// pipeline's per-request ULID key (stable across retries) makes a replay
// return the same execution. input is sent as the JSON body {"input": ...}.
func (r *WorkflowsResource) Execute(ctx context.Context, id string, input any) (*WorkflowRun, error) {
	return doUnwrap[WorkflowRun](ctx, r.c, requestOpts{
		method: "POST",
		path:   "/v1/workflows/" + encode(id) + "/execute",
		body:   map[string]any{"input": input},
	})
}

// ListExecutions returns one page of a workflow's executions (paginated).
func (r *WorkflowsResource) ListExecutions(ctx context.Context, id string, params *ListParams) (*Page[WorkflowExecution], error) {
	return doPage[WorkflowExecution](ctx, r.c, requestOpts{method: "GET", path: "/v1/workflows/" + encode(id) + "/executions", query: params.query()})
}

// ListAllExecutions walks every page of a workflow's executions.
func (r *WorkflowsResource) ListAllExecutions(ctx context.Context, id string, params *ListParams) ([]WorkflowExecution, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[WorkflowExecution], error) {
		p.Page = page
		return r.ListExecutions(ctx, id, &p)
	})
}

// IterateExecutions lazily streams every execution of a workflow one at a time,
// fetching pages on demand rather than buffering them (the streaming analog of
// ListAllExecutions — see helpers.iterate). Preferred over ListAllExecutions for
// long-running workflows with large execution histories. Range over it with two
// variables and break on the first non-nil error.
func (r *WorkflowsResource) IterateExecutions(ctx context.Context, id string, params *ListParams) iter.Seq2[WorkflowExecution, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[WorkflowExecution], error) {
		p.Page = page
		return r.ListExecutions(ctx, id, &p)
	})
}

// GetExecution fetches one execution (with composed step details).
func (r *WorkflowsResource) GetExecution(ctx context.Context, executionID string) (*WorkflowExecution, error) {
	return doUnwrap[WorkflowExecution](ctx, r.c, requestOpts{method: "GET", path: "/v1/workflows/executions/" + encode(executionID)})
}

// CancelExecution cancels a running execution; the response echoes {id, status}.
func (r *WorkflowsResource) CancelExecution(ctx context.Context, executionID string) (*WorkflowExecutionCancel, error) {
	return doUnwrap[WorkflowExecutionCancel](ctx, r.c, requestOpts{method: "POST", path: "/v1/workflows/executions/" + encode(executionID) + "/cancel"})
}
