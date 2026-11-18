package knoxcall

import (
	"context"
	"iter"
	"net/url"
)

// Secret mirrors the server's secret projections (metadata only — values are
// never returned). List/Get rows carry the core fields; the create responses
// add type-specific extras (oauth2: Provider/RedirectURI/ConnectionStatus;
// certificate: CertificateType/CertificateMetadata) that stay zero elsewhere.
type Secret struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	ShortcodeName   string  `json:"shortcode_name"`
	BaseEnvironment *string `json:"base_environment"`
	// SecretType is "string", "oauth2", or "certificate".
	SecretType              string  `json:"secret_type"`
	CollectionID            *string `json:"collection_id"`
	CreatedAt               string  `json:"created_at"`
	ExpiresAt               *string `json:"expires_at"`
	StrictExpiryEnforcement bool    `json:"strict_expiry_enforcement"`
	EnvironmentCount        int     `json:"environment_count"`

	// Environments carries one entry per environment holding a value, ordered
	// by environment name. Populated by Get; nil on List and on the create
	// responses.
	Environments []SecretEnvironmentVersion `json:"environments,omitempty"`

	// oauth2 create response only.
	Provider          string  `json:"provider"`
	RedirectURI       string  `json:"redirect_uri"`
	ConnectionStatus  string  `json:"connection_status"`
	MTLSCertificateID *string `json:"mtls_certificate_id"`

	// certificate create response only.
	CertificateType     string               `json:"certificate_type"`
	CertificateMetadata *CertificateMetadata `json:"metadata"`
}

// SecretEnvironmentVersion is per-environment metadata for a secret, returned
// in Secret.Environments by GET /v1/secrets/{id}. It never carries the value.
//
// ValueVersion counts genuine value writes for the environment, starting at 1
// when its first value is stored. It moves ONLY for writes that change the
// stored value — rotations, admin value/certificate updates, platform-managed
// custodial key rotation — and deliberately not for OAuth2 token refreshes,
// expiry-override edits, certificate metadata re-parsing, or a re-encryption of
// the same plaintext under a new tenant key. Compare it against the version
// your own last write returned to detect a rotation performed outside your
// tooling; UpdatedAt cannot be used for that, because non-value writes move it.
type SecretEnvironmentVersion struct {
	EnvironmentName string `json:"environment_name"`
	ValueVersion    int    `json:"value_version"`
	// UpdatedAt is the last change of ANY kind to this environment's row.
	UpdatedAt string `json:"updated_at"`
	// ExpiresAtOverride is nil when the environment inherits the
	// secret-level expiry.
	ExpiresAtOverride *string `json:"expires_at_override"`
}

// CertificateMetadata is the parsed-certificate summary returned when a
// certificate secret is created.
type CertificateMetadata struct {
	Subject       *string `json:"subject"`
	Issuer        *string `json:"issuer"`
	ExpiresAt     *string `json:"expires_at"`
	HasPrivateKey bool    `json:"has_private_key"`
	// HasPassphrase reports whether a passphrase was stored for the private
	// key. KnoxCall never returns the passphrase; this boolean is the only
	// confirmation that one was received, which is what makes an omitted
	// passphrase a detectable mistake rather than a silent one.
	HasPassphrase bool `json:"has_passphrase"`
}

// SecretValueResponse is the PUT /v1/secrets/{id}/value result.
type SecretValueResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Environment string `json:"environment"`
	// ValueVersion is the environment's version AFTER this write: 1 when this
	// call stored the environment's first value, otherwise the previous version
	// plus one. It is the version this call produced, so storing it has no
	// read-after-write race with a concurrent rotation.
	ValueVersion int `json:"value_version"`
}

// OAuth2TokenResponse is the GET /v1/secrets/{id}/oauth2/token result.
type OAuth2TokenResponse struct {
	AccessToken      string  `json:"access_token"`
	ExpiresAt        *string `json:"expires_at"`
	TokenType        string  `json:"token_type"`
	ConnectionStatus string  `json:"connection_status"`
}

type CreateSecretInput struct {
	Name string `json:"name"`
	// SecretType is "string" (default), "oauth2", or "certificate".
	SecretType              string `json:"secret_type,omitempty"`
	Value                   any    `json:"value,omitempty"`
	CollectionID            string `json:"collection_id,omitempty"`
	ExpiresAt               string `json:"expires_at,omitempty"`
	StrictExpiryEnforcement *bool  `json:"strict_expiry_enforcement,omitempty"`
}

// CreateOAuth2SecretInput creates an OAuth2-provider secret via
// POST /v1/secrets/oauth2. The proxy uses these to inject the provider's access
// token into upstream requests. Name, Provider and ClientID are required; most
// grant types also need either ClientSecret or MTLSCertificateID. CreateSecretInput
// is closed to name/secret_type/value and cannot carry these fields, so use this
// typed helper via CreateOAuth2.
type CreateOAuth2SecretInput struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	ClientID string `json:"client_id"`
	// ClientSecret is required unless MTLSCertificateID is set, or GrantType is
	// "implicit"/"password".
	ClientSecret string `json:"client_secret,omitempty"`
	// MTLSCertificateID uses a stored mTLS client certificate instead of a
	// client secret.
	MTLSCertificateID string   `json:"mtls_certificate_id,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	AuthURL           string   `json:"auth_url,omitempty"`
	TokenURL          string   `json:"token_url,omitempty"`
	GrantType         string   `json:"grant_type,omitempty"`
	// Username and Password carry the "password" (ROPC) grant credentials.
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	CollectionID string `json:"collection_id,omitempty"`
}

// CreateCertificateSecretInput creates a certificate / mTLS secret via
// POST /v1/secrets/certificate. Name and CertificateContent are required.
type CreateCertificateSecretInput struct {
	Name string `json:"name"`
	// CertificateContent is the certificate material — PEM text, or base64 for
	// binary formats.
	CertificateContent string `json:"certificate_content"`
	PrivateKey         string `json:"private_key,omitempty"`
	Passphrase         string `json:"passphrase,omitempty"`
	// CertificateType is one of pem|pfx|p12|crt|cer|key|pkcs7|p7b|p7c. Defaults
	// to "pem" server-side.
	CertificateType string `json:"certificate_type,omitempty"`
	CollectionID    string `json:"collection_id,omitempty"`
}

type UpdateSecretInput struct {
	ExpiresAt               *string `json:"expires_at,omitempty"`
	StrictExpiryEnforcement *bool   `json:"strict_expiry_enforcement,omitempty"`
}

type SecretsResource struct{ c *Client }

// List returns one page of secrets (metadata only).
func (r *SecretsResource) List(ctx context.Context, params *ListParams) (*Page[Secret], error) {
	return doPage[Secret](ctx, r.c, requestOpts{method: "GET", path: "/v1/secrets", query: params.query()})
}

// ListAll walks every page and returns all secrets.
func (r *SecretsResource) ListAll(ctx context.Context, params *ListParams) ([]Secret, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Secret], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every secret one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *SecretsResource) Iterate(ctx context.Context, params *ListParams) iter.Seq2[Secret, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Secret], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *SecretsResource) Get(ctx context.Context, secretID string) (*Secret, error) {
	return doUnwrap[Secret](ctx, r.c, requestOpts{method: "GET", path: "/v1/secrets/" + encode(secretID)})
}

func (r *SecretsResource) Create(ctx context.Context, input CreateSecretInput) (*Secret, error) {
	return doUnwrap[Secret](ctx, r.c, requestOpts{method: "POST", path: "/v1/secrets", body: input})
}

// CreateOAuth2 creates an OAuth2-provider secret (the proxy injects the
// provider's access token into upstream requests). The base Create cannot carry
// the provider/client fields, so use this typed helper. Like every mutating
// request it carries a stable idempotency key, exactly as Create does.
func (r *SecretsResource) CreateOAuth2(ctx context.Context, input CreateOAuth2SecretInput) (*Secret, error) {
	return doUnwrap[Secret](ctx, r.c, requestOpts{method: "POST", path: "/v1/secrets/oauth2", body: input})
}

// CreateCertificate creates a certificate / mTLS secret from PEM (or base64 for
// binary formats). The base Create cannot carry the certificate fields, so use
// this typed helper. Carries an idempotency key exactly as Create does.
func (r *SecretsResource) CreateCertificate(ctx context.Context, input CreateCertificateSecretInput) (*Secret, error) {
	return doUnwrap[Secret](ctx, r.c, requestOpts{method: "POST", path: "/v1/secrets/certificate", body: input})
}

func (r *SecretsResource) Update(ctx context.Context, secretID string, input UpdateSecretInput) (*Secret, error) {
	return doUnwrap[Secret](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/secrets/" + encode(secretID), body: input})
}

func (r *SecretsResource) Delete(ctx context.Context, secretID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/secrets/" + encode(secretID)})
}

// SetValue replaces the secret's value for one environment (the secret's
// base environment when environment is empty).
func (r *SecretsResource) SetValue(ctx context.Context, secretID string, value any, environment string) (*SecretValueResponse, error) {
	body := map[string]any{"value": value}
	if environment != "" {
		body["environment"] = environment
	}
	return doUnwrap[SecretValueResponse](ctx, r.c, requestOpts{method: "PUT", path: "/v1/secrets/" + encode(secretID) + "/value", body: body})
}

// GetOAuthToken returns a live access token for an oauth2 secret.
func (r *SecretsResource) GetOAuthToken(ctx context.Context, secretID, environment string) (*OAuth2TokenResponse, error) {
	q := url.Values{}
	if environment != "" {
		q.Set("environment", environment)
	}
	return doUnwrap[OAuth2TokenResponse](ctx, r.c, requestOpts{method: "GET", path: "/v1/secrets/" + encode(secretID) + "/oauth2/token", query: q})
}
