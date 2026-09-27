package knoxcall

import (
	"context"
	"iter"
	"net/url"
)

// KnoxClient is a tenant client (calling machine/user). List rows carry the
// core fields; Get adds RouteAssignments; Create/Update return the full
// clients row (TenantID, agent telemetry fields, …).
type KnoxClient struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Type         string         `json:"type"` // "user" | "server"
	IPAddress    string         `json:"ip_address"`
	IPNotes      map[string]any `json:"ip_notes"`
	Description  *string        `json:"description"`
	Enabled      bool           `json:"enabled"`
	CollectionID *string        `json:"collection_id"`
	CreatedAt    string         `json:"created_at"`
	UpdatedAt    string         `json:"updated_at"`

	// Get only.
	RouteAssignments []ClientRouteAssignment `json:"route_assignments"`

	// Create/Update (full clients row) only.
	TenantID      string  `json:"tenant_id"`
	CreatedBy     *string `json:"created_by"`
	AgentVersion  *string `json:"agent_version"`
	AgentOS       *string `json:"agent_os"`
	AgentArch     *string `json:"agent_arch"`
	AgentHostname *string `json:"agent_hostname"`
	AgentLastSeen *string `json:"agent_last_seen"`
	AgentMode     *string `json:"agent_mode"`
}

// ClientRouteAssignment links a client to a route+environment.
type ClientRouteAssignment struct {
	RouteID         string `json:"route_id"`
	RouteName       string `json:"route_name"`
	EnvironmentName string `json:"environment_name"`
}

// ClientCredential is a redacted client credential (secret material is
// stripped server-side). CreateCredential's mtls "issue" mode additionally
// carries a one-shot Reveal.
type ClientCredential struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	TenantID string `json:"tenant_id"`
	// Kind: ip | mtls_thumbprint | signature_hmac | signature_ed25519 |
	// machine_id | workload_identity.
	Kind          string         `json:"kind"`
	Label         *string        `json:"label"`
	Data          map[string]any `json:"data"` // redacted public fields
	Enabled       bool           `json:"enabled"`
	ExpiresAt     *string        `json:"expires_at"`
	CreatedAt     string         `json:"created_at"`
	UpdatedAt     string         `json:"updated_at"`
	LastMatchedAt *string        `json:"last_matched_at"`

	// Reveal is present ONLY on mtls "issue" creates — shown once.
	Reveal *CredentialReveal `json:"reveal"`
}

// CredentialReveal is the one-shot key material from an mtls issue.
type CredentialReveal struct {
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CAChainPEM     string `json:"ca_chain_pem"`
}

// ListClientsParams selects a page of clients plus the endpoint's filters.
type ListClientsParams struct {
	Page    int
	PerPage int
	// Type filters by client type ("user" | "server") when non-empty.
	Type string
}

func (p *ListClientsParams) query() url.Values {
	q := url.Values{}
	if p == nil {
		return q
	}
	setPageQuery(q, p.Page, p.PerPage)
	if p.Type != "" {
		q.Set("type", p.Type)
	}
	return q
}

type CreateClientInput struct {
	Name        string         `json:"name"`
	Type        string         `json:"type,omitempty"` // "user" | "server"
	IPAddress   string         `json:"ip_address,omitempty"`
	IPNotes     map[string]any `json:"ip_notes,omitempty"`
	Description string         `json:"description,omitempty"`
}

type UpdateClientInput struct {
	Name        *string        `json:"name,omitempty"`
	IPAddress   *string        `json:"ip_address,omitempty"`
	IPNotes     map[string]any `json:"ip_notes,omitempty"`
	Description *string        `json:"description,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
}

type ClientsResource struct{ c *Client }

// List returns one page of clients.
func (r *ClientsResource) List(ctx context.Context, params *ListClientsParams) (*Page[KnoxClient], error) {
	return doPage[KnoxClient](ctx, r.c, requestOpts{method: "GET", path: "/v1/clients", query: params.query()})
}

// ListAll walks every page and returns all clients.
func (r *ClientsResource) ListAll(ctx context.Context, params *ListClientsParams) ([]KnoxClient, error) {
	p := ListClientsParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[KnoxClient], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every client one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *ClientsResource) Iterate(ctx context.Context, params *ListClientsParams) iter.Seq2[KnoxClient, error] {
	p := ListClientsParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[KnoxClient], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *ClientsResource) Get(ctx context.Context, clientID string) (*KnoxClient, error) {
	return doUnwrap[KnoxClient](ctx, r.c, requestOpts{method: "GET", path: "/v1/clients/" + encode(clientID)})
}

func (r *ClientsResource) Create(ctx context.Context, input CreateClientInput) (*KnoxClient, error) {
	return doUnwrap[KnoxClient](ctx, r.c, requestOpts{method: "POST", path: "/v1/clients", body: input})
}

func (r *ClientsResource) Update(ctx context.Context, clientID string, input UpdateClientInput) (*KnoxClient, error) {
	return doUnwrap[KnoxClient](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/clients/" + encode(clientID), body: input})
}

func (r *ClientsResource) Delete(ctx context.Context, clientID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/clients/" + encode(clientID)})
}

// ListCredentials returns the client's credentials (bare array — not
// paginated).
func (r *ClientsResource) ListCredentials(ctx context.Context, clientID string) ([]ClientCredential, error) {
	return doSlice[ClientCredential](ctx, r.c, requestOpts{method: "GET", path: "/v1/clients/" + encode(clientID) + "/credentials"})
}

// CreateCredential adds a credential (only kinds "ip" and "mtls_thumbprint"
// are accepted for create in V1). For mtls "issue" mode the response carries
// a one-shot Reveal with the key material.
func (r *ClientsResource) CreateCredential(ctx context.Context, clientID, kind, label string, data any) (*ClientCredential, error) {
	body := map[string]any{"kind": kind, "label": label, "data": data}
	return doUnwrap[ClientCredential](ctx, r.c, requestOpts{method: "POST", path: "/v1/clients/" + encode(clientID) + "/credentials", body: body})
}

func (r *ClientsResource) UpdateCredential(ctx context.Context, clientID, credentialID string, enabled *bool, label *string) (*ClientCredential, error) {
	body := map[string]any{}
	if enabled != nil {
		body["enabled"] = *enabled
	}
	if label != nil {
		body["label"] = *label
	}
	return doUnwrap[ClientCredential](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/clients/" + encode(clientID) + "/credentials/" + encode(credentialID), body: body})
}

func (r *ClientsResource) DeleteCredential(ctx context.Context, clientID, credentialID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/clients/" + encode(clientID) + "/credentials/" + encode(credentialID)})
}
