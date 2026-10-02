package knoxcall

import (
	"context"
	"iter"
	"net/url"
)

// AuditLog is one GET /v1/audit-logs row.
type AuditLog struct {
	ID           string         `json:"id"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *string        `json:"resource_id"`
	Details      map[string]any `json:"details"` // genuinely free-form JSON
	IPAddress    *string        `json:"ip_address"`
	CreatedAt    string         `json:"created_at"`
}

// AuditLogParams selects a page of audit logs plus the endpoint's filters.
type AuditLogParams struct {
	Page         int
	PerPage      int
	Action       string
	ResourceType string
}

func (p *AuditLogParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setPageQuery(q, p.Page, p.PerPage)
	if p.Action != "" {
		q.Set("action", p.Action)
	}
	if p.ResourceType != "" {
		q.Set("resource_type", p.ResourceType)
	}
	return q
}

type AuditLogsResource struct{ c *Client }

// List returns one page of audit logs.
func (r *AuditLogsResource) List(ctx context.Context, params *AuditLogParams) (*Page[AuditLog], error) {
	return doPage[AuditLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/audit-logs", query: params.query()})
}

// ListAll walks every page and returns all matching audit logs.
func (r *AuditLogsResource) ListAll(ctx context.Context, params *AuditLogParams) ([]AuditLog, error) {
	p := AuditLogParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[AuditLog], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every matching audit log one at a time, fetching pages
// on demand rather than buffering them all (the streaming analog of ListAll —
// see helpers.iterate). Preferred over ListAll for large audit trails. Range
// over it with two variables and break on the first non-nil error.
func (r *AuditLogsResource) Iterate(ctx context.Context, params *AuditLogParams) iter.Seq2[AuditLog, error] {
	p := AuditLogParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[AuditLog], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// AuditEventParams selects a page of the keyset audit event feed.
//
// Action is exact-match; ActionPrefix subscribes to a whole SURFACE —
// "ai_gateway." covers every AI-gateway action INCLUDING names added after your
// integration was built, which exact-match cannot.
type AuditEventParams struct {
	CursorParams
	Action       string
	ActionPrefix string
	ResourceType string
}

func (p *AuditEventParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setCursorQuery(q, p.Cursor, p.Limit)
	if p.Action != "" {
		q.Set("action", p.Action)
	}
	if p.ActionPrefix != "" {
		q.Set("action_prefix", p.ActionPrefix)
	}
	if p.ResourceType != "" {
		q.Set("resource_type", p.ResourceType)
	}
	return q
}

// Events returns one page of the keyset audit event feed — the endpoint a SIEM
// shipper should use.
//
// List is offset-paginated over created_at DESC, which is right for a console
// and wrong for a feed: rows written while you page shift the offsets underneath
// you, so events are skipped or repeated with no way to tell which. This is
// ordered by a monotonic sequence and resumes from an opaque cursor.
//
// Delivery is AT LEAST ONCE — dedupe on ID. Meta.NextCursor is OPAQUE; pass it
// back verbatim rather than parsing it.
func (r *AuditLogsResource) Events(ctx context.Context, params *AuditEventParams) (*CursorPage[AuditLog], error) {
	return doCursorPage[AuditLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/audit-logs/events", query: params.query()})
}

// IterateEvents lazily streams the event feed until it is drained to the
// watermark. Range over it with two variables and break on the first non-nil
// error.
func (r *AuditLogsResource) IterateEvents(ctx context.Context, params *AuditEventParams) iter.Seq2[AuditLog, error] {
	p := AuditEventParams{}
	if params != nil {
		p = *params
	}
	return iterateCursor(ctx, p.Cursor, func(ctx context.Context, cursor string) (*CursorPage[AuditLog], error) {
		p.Cursor = cursor
		return r.Events(ctx, &p)
	})
}
