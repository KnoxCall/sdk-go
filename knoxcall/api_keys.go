package knoxcall

import (
	"context"
	"iter"
	"net/url"
)

// APIKey is one GET /v1/api-keys row (never includes the key material).
type APIKey struct {
	ID                 string  `json:"id"`
	KeyID              string  `json:"key_id"`
	KeyPrefix          string  `json:"key_prefix"`
	KeyType            string  `json:"key_type"` // test | standard | access_key
	Name               string  `json:"name"`
	Active             bool    `json:"active"`
	CreatedAt          string  `json:"created_at"`
	LastUsedAt         *string `json:"last_used_at"`
	RateLimitRequests  *int    `json:"rate_limit_requests"`
	RateLimitWindowSec *int    `json:"rate_limit_window_sec"`
}

// CreatedAPIKey is the POST /v1/api-keys result. APIKey is the plaintext
// key, returned ONCE — store it immediately.
type CreatedAPIKey struct {
	// ID is the row UUID — what Revoke and role assignments reference.
	ID        string `json:"id"`
	KeyID     string `json:"key_id"`
	APIKey    string `json:"api_key"`
	KeyPrefix string `json:"key_prefix"`
	KeyType   string `json:"key_type"` // "test" in sandbox, else "standard"
	Name      string `json:"name"`
	// RoleIDs are the roles attached in the same transaction as the key.
	RoleIDs []string `json:"role_ids"`
	Message string   `json:"message"`
}

type CreateAPIKeyInput struct {
	Name               string `json:"name"`
	RateLimitRequests  *int   `json:"rate_limit_requests,omitempty"`
	RateLimitWindowSec *int   `json:"rate_limit_window_sec,omitempty"`
	// RoleIDs attaches permission roles in the SAME transaction as the key.
	// Discover them with Client.Roles.List with SubjectKind "api_key". A key
	// created with no role is default-denied on every policy-gated endpoint.
	//
	// A key can never mint a key more privileged than itself: if a requested
	// role grants something this credential does not hold, the server answers
	// 403 privilege_escalation (an *APIError whose Type is
	// "privilege_escalation") naming the offending grant verbatim.
	RoleIDs []string `json:"role_ids,omitempty"`
}

// Role is one GET /v1/roles row. The rules a role grants are deliberately not
// exposed on /v1 — enumerating them would map the tenant's authorization
// surface to every machine credential in it.
type Role struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
	// AppliesTo is a subset of {"user", "api_key"}. Only roles including
	// "api_key" may be passed in CreateAPIKeyInput.RoleIDs.
	AppliesTo []string `json:"applies_to"`
	IsDefault bool     `json:"is_default"`
	// Seeded marks roles the platform creates and maintains.
	Seeded bool `json:"seeded"`
}

// ListRolesParams adds the audience filter to the standard page params.
type ListRolesParams struct {
	ListParams
	// SubjectKind filters to roles whose applies_to includes it
	// ("api_key" or "user"). Empty means no filter.
	SubjectKind string
}

func (p *ListRolesParams) rolesQuery() url.Values {
	if p == nil {
		return url.Values{}
	}
	q := p.ListParams.query()
	if p.SubjectKind != "" {
		q.Set("subject_kind", p.SubjectKind)
	}
	return q
}

// RolesResource is the read-only role catalog. Roles are created and edited on
// the MFA-gated admin surface; /v1 exposes them so CreateAPIKeyInput.RoleIDs
// can be written in code instead of by copying a UUID out of a browser URL bar.
type RolesResource struct{ c *Client }

// List returns one page of roles.
func (r *RolesResource) List(ctx context.Context, params *ListRolesParams) (*Page[Role], error) {
	return doPage[Role](ctx, r.c, requestOpts{method: "GET", path: "/v1/roles", query: params.rolesQuery()})
}

// ListAll walks every page and returns all roles.
func (r *RolesResource) ListAll(ctx context.Context, params *ListRolesParams) ([]Role, error) {
	p := ListRolesParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Role], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every role, fetching pages on demand.
func (r *RolesResource) Iterate(ctx context.Context, params *ListRolesParams) iter.Seq2[Role, error] {
	p := ListRolesParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Role], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

type APIKeysResource struct{ c *Client }

// List returns one page of API keys.
func (r *APIKeysResource) List(ctx context.Context, params *ListParams) (*Page[APIKey], error) {
	return doPage[APIKey](ctx, r.c, requestOpts{method: "GET", path: "/v1/api-keys", query: params.query()})
}

// ListAll walks every page and returns all API keys.
func (r *APIKeysResource) ListAll(ctx context.Context, params *ListParams) ([]APIKey, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[APIKey], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every API key one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *APIKeysResource) Iterate(ctx context.Context, params *ListParams) iter.Seq2[APIKey, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[APIKey], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *APIKeysResource) Create(ctx context.Context, input CreateAPIKeyInput) (*CreatedAPIKey, error) {
	return doUnwrap[CreatedAPIKey](ctx, r.c, requestOpts{method: "POST", path: "/v1/api-keys", body: input})
}

func (r *APIKeysResource) Revoke(ctx context.Context, keyID string) (*RevokedResponse, error) {
	return doUnwrap[RevokedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/api-keys/" + encode(keyID)})
}
