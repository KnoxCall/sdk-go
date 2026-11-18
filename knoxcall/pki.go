package knoxcall

import "context"

// CARoot is a tenant CA root.
type CARoot struct {
	ID            string         `json:"id"`
	TenantID      string         `json:"tenant_id"`
	Name          string         `json:"name"`
	CertPEM       string         `json:"cert_pem"`
	Subject       string         `json:"subject"`
	SubjectFields map[string]any `json:"subject_fields"`
	NotBefore     string         `json:"not_before"`
	NotAfter      string         `json:"not_after"`
	Status        string         `json:"status"` // "active" | "retired" | "revoked"
	CreatedAt     string         `json:"created_at"`
	Sandbox       bool           `json:"sandbox"`
}

// CARole is an issuance role under a CA root.
type CARole struct {
	ID                string   `json:"id"`
	CARootID          string   `json:"ca_root_id"`
	Name              string   `json:"name"`
	AllowedDomains    []string `json:"allowed_domains"`
	AllowSubdomains   bool     `json:"allow_subdomains"`
	AllowWildcards    bool     `json:"allow_wildcards"`
	MaxTTLSeconds     int      `json:"max_ttl_seconds"`
	DefaultTTLSeconds int      `json:"default_ttl_seconds"`
	KeyAlgorithm      string   `json:"key_algorithm"` // "ecdsa-p256"
}

// CreatedCARoot is the POST /v1/pki/roots result.
type CreatedCARoot struct {
	Root                 CARoot `json:"root"`
	IntermediateNotAfter string `json:"intermediate_not_after"`
}

// RotatedIntermediate is the rotate-intermediate result.
type RotatedIntermediate struct {
	IntermediateID string `json:"intermediate_id"`
	NotAfter       string `json:"not_after"`
}

// IssuedCertificate is the issue result. PrivateKeyPEM is returned once.
type IssuedCertificate struct {
	SerialHex     string `json:"serial_hex"`
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	CAChainPEM    string `json:"ca_chain_pem"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
}

// CertRevocation is the revoke result.
type CertRevocation struct {
	Revoked bool `json:"revoked"`
}

type CreatePKIRoleInput struct {
	Name            string   `json:"name"`
	AllowedDomains  []string `json:"allowed_domains,omitempty"`
	AllowSubdomains *bool    `json:"allow_subdomains,omitempty"`
	AllowWildcards  *bool    `json:"allow_wildcards,omitempty"`
	MaxTTLSeconds   *int     `json:"max_ttl_seconds,omitempty"`
	DefaultTTLSec   *int     `json:"default_ttl_seconds,omitempty"`
}

type IssueCertInput struct {
	Subject    map[string]any `json:"subject,omitempty"`
	SANDns     []string       `json:"san_dns,omitempty"`
	SANIp      []string       `json:"san_ip,omitempty"`
	TTLSeconds *int           `json:"ttl_seconds,omitempty"`
}

type PKIResource struct{ c *Client }

// -- CA roots --

// ListRoots returns every CA root (bare array — no pagination).
func (r *PKIResource) ListRoots(ctx context.Context) ([]CARoot, error) {
	return doSlice[CARoot](ctx, r.c, requestOpts{method: "GET", path: "/v1/pki/roots"})
}

func (r *PKIResource) CreateRoot(ctx context.Context, name string, subject map[string]any) (*CreatedCARoot, error) {
	body := map[string]any{"name": name, "subject": subject}
	return doUnwrap[CreatedCARoot](ctx, r.c, requestOpts{method: "POST", path: "/v1/pki/roots", body: body})
}

// GetRootCert returns the root certificate as raw PEM text (this endpoint
// has no JSON wrapper).
func (r *PKIResource) GetRootCert(ctx context.Context, name string) (string, error) {
	var pem string
	err := r.c.do(ctx, requestOpts{method: "GET", path: "/v1/pki/roots/" + encode(name) + "/cert", raw: true}, &pem)
	return pem, err
}

func (r *PKIResource) RotateIntermediate(ctx context.Context, name string) (*RotatedIntermediate, error) {
	return doUnwrap[RotatedIntermediate](ctx, r.c, requestOpts{method: "POST", path: "/v1/pki/roots/" + encode(name) + "/rotate-intermediate", body: map[string]any{}})
}

// GetCRL returns the root's certificate revocation list as raw text (this
// endpoint has no JSON wrapper).
func (r *PKIResource) GetCRL(ctx context.Context, name string) (string, error) {
	var crl string
	err := r.c.do(ctx, requestOpts{method: "GET", path: "/v1/pki/roots/" + encode(name) + "/crl", raw: true}, &crl)
	return crl, err
}

// -- Roles --

// ListRoles returns the root's issuance roles (bare array).
func (r *PKIResource) ListRoles(ctx context.Context, rootName string) ([]CARole, error) {
	return doSlice[CARole](ctx, r.c, requestOpts{method: "GET", path: "/v1/pki/roots/" + encode(rootName) + "/roles"})
}

func (r *PKIResource) CreateRole(ctx context.Context, rootName string, input CreatePKIRoleInput) (*CARole, error) {
	return doUnwrap[CARole](ctx, r.c, requestOpts{method: "POST", path: "/v1/pki/roots/" + encode(rootName) + "/roles", body: input})
}

// -- Certificates --

// IssueCert issues a leaf certificate under the named role
// (POST /v1/pki/roots/{root}/issue/{role}).
func (r *PKIResource) IssueCert(ctx context.Context, rootName, roleName string, input IssueCertInput) (*IssuedCertificate, error) {
	return doUnwrap[IssuedCertificate](ctx, r.c, requestOpts{method: "POST", path: "/v1/pki/roots/" + encode(rootName) + "/issue/" + encode(roleName), body: input})
}

func (r *PKIResource) RevokeCert(ctx context.Context, rootName, serialHex, reason string) (*CertRevocation, error) {
	body := map[string]string{"serial_hex": serialHex, "reason": reason}
	return doUnwrap[CertRevocation](ctx, r.c, requestOpts{method: "POST", path: "/v1/pki/roots/" + encode(rootName) + "/revoke", body: body})
}
