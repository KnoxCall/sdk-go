package knoxcall

import "context"

// The oauth-clients endpoints bypass the standard success() wrapper: the
// envelope is {data} with NO meta and NO pagination, and create/rotate carry
// a TOP-LEVEL warning string, which the SDK attaches to the returned object.

// OAuthClient is a tenant OAuth 2.1 client. StepUpScopes is present on Get
// only; SourceKeyType on List only.
type OAuthClient struct {
	ID            string   `json:"id"`
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"` // "confidential" | "public"
	GrantTypes    []string `json:"grant_types"`
	AllowedScopes []string `json:"allowed_scopes"`
	RedirectURIs  []string `json:"redirect_uris"`
	RequireDPoP   bool     `json:"require_dpop"`
	RequirePKCE   bool     `json:"require_pkce"` // always true; PKCE is mandatory on the authorization-code flow
	TokenFormat   string   `json:"token_format"` // always "opaque" (the RFC 9068 "jwt" format was withdrawn)
	Active        bool     `json:"active"`
	RevokedAt     *string  `json:"revoked_at"`
	CreatedAt     string   `json:"created_at"`
	LastUsedAt    *string  `json:"last_used_at"`
	SourceAPIKey  *string  `json:"source_api_key_id"`
	SourceKeyType *string  `json:"source_key_type"` // List only
	StepUpScopes  []string `json:"step_up_scopes"`  // Get only
}

// CreatedOAuthClient is the POST /v1/oauth-clients result. ClientSecret is
// nil for public clients and shown exactly once for confidential ones.
type CreatedOAuthClient struct {
	ID            string   `json:"id"`
	ClientID      string   `json:"client_id"`
	ClientSecret  *string  `json:"client_secret"`
	Type          string   `json:"type"`
	GrantTypes    []string `json:"grant_types"`
	AllowedScopes []string `json:"allowed_scopes"`
	RedirectURIs  []string `json:"redirect_uris"`
	// Warning is the response's top-level warning (empty when absent).
	Warning string `json:"-"`
}

// RotatedOAuthClientSecret is the rotate-secret result (secret shown once).
type RotatedOAuthClientSecret struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// Warning is the response's top-level warning (empty when absent).
	Warning string `json:"-"`
}

// UpdatedOAuthClient acknowledges a PATCH.
type UpdatedOAuthClient struct {
	ID string `json:"id"`
}

// RevokedOAuthClient acknowledges a revocation with {revoked: true}. The
// server no longer echoes the client id in this payload.
type RevokedOAuthClient struct {
	Revoked bool `json:"revoked"`
}

type CreateOAuthClientInput struct {
	Name string `json:"name"`
	// Type defaults to "confidential"; pass "public" for PKCE-only clients.
	Type string `json:"type,omitempty"`
	// GrantTypes defaults to ["client_credentials"]. Allowed values:
	// client_credentials, authorization_code, refresh_token,
	// urn:ietf:params:oauth:grant-type:token-exchange.
	GrantTypes    []string `json:"grant_types,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	RedirectURIs  []string `json:"redirect_uris,omitempty"`
}

type UpdateOAuthClientInput struct {
	Name *string `json:"name,omitempty"`
	// The three list fields deliberately carry NO `omitempty`.
	//
	// `omitempty` drops an EMPTY slice as well as a nil one, so with it there
	// is no way to say "make this list empty" — and for allowed_scopes that is
	// a security-relevant instruction, not a cosmetic one. Without it a nil
	// slice marshals as JSON `null`, and the server's guard is
	// `if (Array.isArray(body.allowed_scopes))` (src/client-api/oauth-clients.ts),
	// which treats `null` exactly as it treats an absent field: no update. So
	// this change is behaviour-preserving for every existing caller and adds
	// the missing third state — nil = leave alone, `[]` = clear, values = set.
	AllowedScopes []string `json:"allowed_scopes"`
	RedirectURIs  []string `json:"redirect_uris"`
	RequireDPoP   *bool    `json:"require_dpop,omitempty"`
	RequirePKCE   *bool    `json:"require_pkce,omitempty"` // the only accepted value is true; false is refused with 400
	Active        *bool    `json:"active,omitempty"`
	TokenFormat   *string  `json:"token_format,omitempty"` // the only accepted value is "opaque"; anything else is refused with 400

	// StepUpScopes is a POINTER, unlike the two lists above, and that difference
	// is load-bearing.
	//
	// The server gates writes to this column behind `oauth_client:step_up_manage`
	// — an action a machine subject may never even be GRANTED, because it
	// controls the re-authentication a HUMAN is forced through at the authorize
	// endpoint (src/policies/role-grant-guard.ts, HUMAN_PLANE_ACTIONS). And the
	// gate keys on the PRESENCE OF THE KEY, deliberately and fail-closed:
	//
	//     return STEP_UP_FIELD in body   // src/lib/oauth-client-machine-plane.ts
	//
	// while the handler one layer down only writes when the value is an array.
	// So `{"step_up_scopes": null}` — the "leave alone" spelling the sibling
	// lists rely on — writes nothing yet is REFUSED 403, which made every
	// machine-plane update of an already-applied client fail on a field the
	// caller never touched.
	//
	// A pointer with `omitempty` keeps all three states while sending the key
	// only when it is meant: nil omits it entirely, &[]string{} sends `[]`
	// (clear), and a populated slice sets it. AllowedScopes and RedirectURIs
	// keep the plain-slice spelling because neither is gated, and `null` there
	// really does mean "leave alone" all the way down.
	StepUpScopes *[]string `json:"step_up_scopes,omitempty"`
}

type OAuthClientsResource struct{ c *Client }

// List returns every OAuth client (this endpoint has no pagination).
func (r *OAuthClientsResource) List(ctx context.Context) ([]OAuthClient, error) {
	return doSlice[OAuthClient](ctx, r.c, requestOpts{method: "GET", path: "/v1/oauth-clients"})
}

func (r *OAuthClientsResource) Get(ctx context.Context, id string) (*OAuthClient, error) {
	return doUnwrap[OAuthClient](ctx, r.c, requestOpts{method: "GET", path: "/v1/oauth-clients/" + encode(id)})
}

// Create registers an OAuth client. ClientSecret is shown exactly once.
func (r *OAuthClientsResource) Create(ctx context.Context, input CreateOAuthClientInput) (*CreatedOAuthClient, error) {
	var env struct {
		Data    CreatedOAuthClient `json:"data"`
		Warning string             `json:"warning"`
	}
	if err := r.c.do(ctx, requestOpts{method: "POST", path: "/v1/oauth-clients", body: input}, &env); err != nil {
		return nil, err
	}
	env.Data.Warning = env.Warning
	return &env.Data, nil
}

func (r *OAuthClientsResource) Update(ctx context.Context, id string, input UpdateOAuthClientInput) (*UpdatedOAuthClient, error) {
	return doUnwrap[UpdatedOAuthClient](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/oauth-clients/" + encode(id), body: input})
}

// RotateSecret mints a new client secret (shown exactly once).
//
// Rotation is containment: every access and refresh token the OLD secret minted
// is revoked in the same transaction as the re-key, so they stop working
// immediately rather than at their TTL. A rotation whose revocation cannot
// complete is refused and the old secret keeps working — you never hold a new
// secret for a client whose old tokens are still live.
func (r *OAuthClientsResource) RotateSecret(ctx context.Context, id string) (*RotatedOAuthClientSecret, error) {
	var env struct {
		Data    RotatedOAuthClientSecret `json:"data"`
		Warning string                   `json:"warning"`
	}
	if err := r.c.do(ctx, requestOpts{method: "POST", path: "/v1/oauth-clients/" + encode(id) + "/rotate-secret", body: map[string]any{}}, &env); err != nil {
		return nil, err
	}
	env.Data.Warning = env.Warning
	return &env.Data, nil
}

func (r *OAuthClientsResource) Revoke(ctx context.Context, id string) (*RevokedOAuthClient, error) {
	return doUnwrap[RevokedOAuthClient](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/oauth-clients/" + encode(id)})
}
