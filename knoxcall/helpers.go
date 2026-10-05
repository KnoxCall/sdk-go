package knoxcall

// Response-envelope plumbing (see ../../PARITY.md §4).
//
// The server wraps every JSON success response in {"data": ..., "meta": ...}
// (src/client-api/helpers.ts) and paginates with ?page= / ?per_page= query
// params, reporting {total, page, per_page, total_pages, request_id} in meta.
// Resource methods unwrap the envelope: single-object methods return `data`,
// bare-array endpoints return a plain slice, and paginated lists return the
// typed Page envelope.
//
// TWO endpoints are keyset/cursor paginated instead — GET /v1/audit-logs/events
// and GET /v1/logs — and use CursorPage below. (Earlier revisions of this
// comment said there was no cursor pagination anywhere; that stopped being true
// when the audit event feed shipped.)

import (
	"context"
	"iter"
	"net/url"
	"strconv"
)

func encode(s string) string {
	return url.PathEscape(s)
}

// PageMeta mirrors the server's pagination meta block.
type PageMeta struct {
	Total      int    `json:"total"`
	Page       int    `json:"page"`
	PerPage    int    `json:"per_page"`
	TotalPages int    `json:"total_pages"`
	RequestID  string `json:"request_id"`
}

// Page is one page of a paginated list response, exactly mirroring the
// server's {data, meta} envelope.
type Page[T any] struct {
	Data []T      `json:"data"`
	Meta PageMeta `json:"meta"`
}

// ListParams selects a page of results for paginated list endpoints.
// Zero values are omitted from the query, so the server defaults apply
// (page 1, per_page 20; per_page is capped at 100 server-side).
type ListParams struct {
	Page    int
	PerPage int
}

// setPageQuery writes non-zero page/per_page params into q.
func setPageQuery(q url.Values, page, perPage int) {
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if perPage > 0 {
		q.Set("per_page", strconv.Itoa(perPage))
	}
}

func (p *ListParams) query() url.Values {
	q := url.Values{}
	if p != nil {
		setPageQuery(q, p.Page, p.PerPage)
	}
	return q
}

// doUnwrap requests r and returns the envelope's `data` member decoded as T.
// The client core's request pipeline stays envelope-agnostic; unwrapping
// lives here in the resource layer.
func doUnwrap[T any](ctx context.Context, c *Client, r requestOpts) (*T, error) {
	var env struct {
		Data T `json:"data"`
	}
	if err := c.do(ctx, r, &env); err != nil {
		return nil, err
	}
	return &env.Data, nil
}

// doSlice requests a bare-array endpoint (the envelope's `data` is a plain
// array with no pagination meta) and returns the decoded slice.
func doSlice[T any](ctx context.Context, c *Client, r requestOpts) ([]T, error) {
	var env struct {
		Data []T `json:"data"`
	}
	if err := c.do(ctx, r, &env); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// doPage requests a paginated endpoint and returns the typed page envelope.
func doPage[T any](ctx context.Context, c *Client, r requestOpts) (*Page[T], error) {
	var page Page[T]
	if err := c.do(ctx, r, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// listAll walks a paginated endpoint page by page and returns every item.
// It starts at startPage (min 1), fetches, appends, and stops when
// page >= meta.total_pages or a page comes back empty (defensive) —
// otherwise page += 1. This is the Go analog of the other SDKs' iterate().
func listAll[T any](ctx context.Context, startPage int, fetch func(ctx context.Context, page int) (*Page[T], error)) ([]T, error) {
	page := startPage
	if page < 1 {
		page = 1
	}
	var out []T
	for {
		p, err := fetch(ctx, page)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Data...)
		if len(p.Data) == 0 || page >= p.Meta.TotalPages {
			return out, nil
		}
		page++
	}
}

// iterate lazily streams a paginated endpoint one item at a time via
// range-over-func (Go 1.23+ iter.Seq2), fetching each page only as the previous
// one is consumed. It uses listAll's paging exactly — start at startPage (min 1),
// fetch, yield every row, then stop when page >= meta.total_pages or a page comes
// back empty (defensive) — but never buffers more than a single page in memory,
// so it is the form to reach for on large audit-log / token lists. A per-page
// fetch error is surfaced once as the second range value (with the zero item)
// and ends the sequence; ranging stops early the moment the caller's loop breaks.
//
//	for item, err := range iterate(ctx, startPage, fetch) {
//	    if err != nil { /* handle and break */ }
//	    // use item
//	}
func iterate[T any](ctx context.Context, startPage int, fetch func(ctx context.Context, page int) (*Page[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		page := startPage
		if page < 1 {
			page = 1
		}
		for {
			p, err := fetch(ctx, page)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range p.Data {
				if !yield(item, nil) {
					return
				}
			}
			if len(p.Data) == 0 || page >= p.Meta.TotalPages {
				return
			}
			page++
		}
	}
}

// -- Small result payloads shared across resources ------------------------------
//
// The server deliberately varies these shapes (see the shapes catalog):
// `deleted` is boolean true for routes/secrets/webhooks/clients/environments/
// vaults/vault-tokens but the NAME/ID STRING for dynamic-DB and route actions;
// `revoked` is boolean for api-keys/agents/oauth-clients but the lease id INT
// for DB leases. Do not unify them.

// DeletedResponse is {deleted: true} — routes, secrets, webhooks, clients,
// environments, route environment configs, client credentials, vaults, vault
// tokens.
type DeletedResponse struct {
	Deleted bool `json:"deleted"`
}

// DeletedNameResponse is {deleted: "<name-or-id>"} — dynamic-DB
// connections/roles, route actions.
type DeletedNameResponse struct {
	Deleted string `json:"deleted"`
}

// RevokedResponse is {revoked: true} — api-keys, agents.
type RevokedResponse struct {
	Revoked bool `json:"revoked"`
}

// UpdatedResponse is {updated: true} — vault tokens.
type UpdatedResponse struct {
	Updated bool `json:"updated"`
}

// UpdatedNameResponse is {updated: "<name>"} — dynamic-DB connections/roles.
type UpdatedNameResponse struct {
	Updated string `json:"updated"`
}

// ── Cursor (keyset) feeds ───────────────────────────────────────────────────
//
// Two endpoints are keyset paginated rather than offset paginated, and
// deliberately so: GET /v1/audit-logs/events and GET /v1/logs. Offset
// pagination over a table that is being written to skips and repeats rows with
// no way to tell which — fine for a console, wrong for a feed.

// CursorMeta is the meta block on a keyset feed.
//
// NextCursor is OPAQUE: pass it back verbatim and never parse or rebuild it.
// A nil/empty NextCursor means the feed is drained to the watermark, NOT that
// it has ended — poll again later with your last non-empty cursor.
type CursorMeta struct {
	NextCursor *string `json:"next_cursor"`
	Limit      int     `json:"limit"`
	// Always "at_least_once". Consumers MUST dedupe on DedupeOn.
	Delivery string `json:"delivery"`
	// The field to dedupe on: "id" for audit events, "request_id" for logs.
	DedupeOn string `json:"dedupe_on"`
	// How far the feed trails real time.
	WatermarkSeconds int `json:"watermark_seconds"`
	// Tiers withheld from every row, e.g. ["identity"].
	Redacted  []string `json:"_redacted,omitempty"`
	RequestID string   `json:"request_id,omitempty"`
}

// CursorPage is one page of a keyset feed.
type CursorPage[T any] struct {
	Data []T        `json:"data"`
	Meta CursorMeta `json:"meta"`
}

// CursorParams are the query params common to every keyset feed. Zero values
// are omitted, so the server defaults apply.
type CursorParams struct {
	// The opaque Meta.NextCursor from your previous response. Empty starts at
	// the beginning.
	Cursor string
	Limit  int
}

func setCursorQuery(q url.Values, cursor string, limit int) {
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
}

// doCursorPage requests a keyset endpoint and returns the typed page.
func doCursorPage[T any](ctx context.Context, c *Client, r requestOpts) (*CursorPage[T], error) {
	var page CursorPage[T]
	if err := c.do(ctx, r, &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// iterateCursor lazily streams every row of a keyset feed, fetching pages on
// demand. It STOPS when the server reports a null next_cursor, i.e. the feed is
// drained to the watermark — it does not poll, because a Seq2 that blocked
// forever would be unusable from a batch job. To keep following the feed, range
// again later starting from the last cursor you saw.
//
// Delivery is at-least-once: dedupe on Meta.DedupeOn.
func iterateCursor[T any](ctx context.Context, startCursor string, fetch func(ctx context.Context, cursor string) (*CursorPage[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		cursor := startCursor
		for {
			p, err := fetch(ctx, cursor)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range p.Data {
				if !yield(item, nil) {
					return
				}
			}
			if p.Meta.NextCursor == nil || *p.Meta.NextCursor == "" {
				return
			}
			cursor = *p.Meta.NextCursor
		}
	}
}
