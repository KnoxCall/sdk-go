package knoxcall

// Request Logs — the per-call proxy log, and Merkle inclusion proofs.
//
// Distinct from AuditLogs, which is the CHANGE log (who edited what). This is
// the record of requests that went THROUGH the proxy, and Proof is the evidence
// that a given entry existed, unaltered, when it was anchored.

import (
	"context"
	"iter"
	"net/url"
	"strconv"
)

// RequestLog itself lives in routes.go — one type for one table; see the note
// there on which endpoint populates which fields.

// RequestLogParams selects a page of the request log feed.
type RequestLogParams struct {
	CursorParams
	// Only requests handled by this route.
	RouteID string
	// Only requests that returned this status.
	StatusCode int
}

func (p *RequestLogParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setCursorQuery(q, p.Cursor, p.Limit)
	if p.RouteID != "" {
		q.Set("route_id", p.RouteID)
	}
	if p.StatusCode > 0 {
		q.Set("status_code", strconv.Itoa(p.StatusCode))
	}
	return q
}

// ProofStep is one sibling on the path from leaf to root. Right reports which
// side the sibling sits on: true means hash(accumulator, sibling).
type ProofStep struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right"`
}

// ProofAnchor is the anchor row a proof stands on.
type ProofAnchor struct {
	ID string `json:"id"`
	// Position in the hash-chained critical audit log, as a decimal string.
	SequenceNumber string `json:"sequence_number"`
	AnchoredAt     string `json:"anchored_at"`
	Algo           string `json:"algo"`
	// Hex root committed by the anchor.
	MerkleRoot string `json:"merkle_root"`
	LeafCount  int    `json:"leaf_count"`
	FromID     string `json:"from_id"`
	ToID       string `json:"to_id"`
	// Hex row hash of the anchor's own audit-chain entry. Ties the root to the
	// chain that is verified daily and exported offsite.
	ChainRowHash *string `json:"chain_row_hash"`
}

// ProofVerification is everything needed to redo the computation without
// trusting KnoxCall.
type ProofVerification struct {
	Algo string `json:"algo"`
	// Field order the leaf was serialised in. Fixed forever.
	LeafFields []string `json:"leaf_fields"`
	// The canonicalisation and domain-separation scheme, in prose.
	Note string `json:"note"`
}

// Proof failure reasons. RangeIncomplete is the EXPECTED outcome once retention
// has trimmed an anchored range and is not a sign of tampering; RootMismatch is.
const (
	ProofReasonNotYetAnchored      = "not_yet_anchored"
	ProofReasonRangeIncomplete     = "range_incomplete"
	ProofReasonRangeGrew           = "range_grew"
	ProofReasonRootMismatch        = "root_mismatch"
	ProofReasonRowNotInRange       = "row_not_in_range"
	ProofReasonAnchorRangeTooLarge = "anchor_range_too_large"
)

// RequestLogProof is GET /v1/logs/{request_id}/proof. It embeds the row itself.
//
// Every outcome is a 200 — read Anchored and Verified rather than branching on
// an error. Proof is nil whenever Verified is not true: a proof is never
// returned alongside a failed verification.
type RequestLogProof struct {
	RequestLog
	Anchored bool  `json:"anchored"`
	Verified *bool `json:"verified,omitempty"`
	// One of the ProofReason* constants. Empty when Verified is true.
	Reason string `json:"reason,omitempty"`
	// A sentence explaining Reason in context.
	Detail            string             `json:"detail,omitempty"`
	ObservedLeafCount *int               `json:"observed_leaf_count,omitempty"`
	RecomputedRoot    *string            `json:"recomputed_root,omitempty"`
	Anchor            *ProofAnchor       `json:"anchor,omitempty"`
	LeafIndex         *int               `json:"leaf_index,omitempty"`
	LeafHash          string             `json:"leaf_hash,omitempty"`
	Proof             []ProofStep        `json:"proof,omitempty"`
	Verification      *ProofVerification `json:"verification,omitempty"`
	Redacted          []string           `json:"_redacted,omitempty"`
}

type LogsResource struct{ c *Client }

// List returns one page of the request log feed.
//
// Keyset, not offset: ordering is ascending Cursor and stable across calls.
// Delivery is AT LEAST ONCE — dedupe on RequestID. Meta.NextCursor is OPAQUE;
// pass it back verbatim. A nil NextCursor means the feed is drained to the
// watermark, NOT that it has ended.
func (r *LogsResource) List(ctx context.Context, params *RequestLogParams) (*CursorPage[RequestLog], error) {
	return doCursorPage[RequestLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/logs", query: params.query()})
}

// Iterate lazily streams every row of the feed, fetching pages on demand, and
// stops when the feed is drained to the watermark. Range over it with two
// variables and break on the first non-nil error.
func (r *LogsResource) Iterate(ctx context.Context, params *RequestLogParams) iter.Seq2[RequestLog, error] {
	p := RequestLogParams{}
	if params != nil {
		p = *params
	}
	return iterateCursor(ctx, p.Cursor, func(ctx context.Context, cursor string) (*CursorPage[RequestLog], error) {
		p.Cursor = cursor
		return r.List(ctx, &p)
	})
}

// Get fetches one request by its request_id (the X-Request-Id header value).
func (r *LogsResource) Get(ctx context.Context, requestID string) (*RequestLog, error) {
	return doUnwrap[RequestLog](ctx, r.c, requestOpts{method: "GET", path: "/v1/logs/" + encode(requestID)})
}

// Proof returns the Merkle inclusion proof for one request.
//
// It returns a non-nil result for every outcome the server can express — read
// Anchored and Verified rather than treating a missing proof as an error. A
// Verified-false result with Reason == ProofReasonRangeIncomplete is the
// expected state for an old entry whose anchored range has since been trimmed
// by retention, and is NOT a sign of tampering; ProofReasonRootMismatch is.
func (r *LogsResource) Proof(ctx context.Context, requestID string) (*RequestLogProof, error) {
	return doUnwrap[RequestLogProof](ctx, r.c, requestOpts{method: "GET", path: "/v1/logs/" + encode(requestID) + "/proof"})
}
