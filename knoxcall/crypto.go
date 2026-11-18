package knoxcall

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// CryptoKey is a transit key. ListKeys returns the projection (no
// TenantID/CreatedBy/Sandbox); GetKey/CreateKey return the full row.
type CryptoKey struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	KeyType         string  `json:"key_type"`
	Mode            string  `json:"mode"` // "cloud-only" | "bundled"
	CurrentVersion  int     `json:"current_version"`
	DeletionAllowed bool    `json:"deletion_allowed"`
	Description     *string `json:"description"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`

	// Full-row fields (GetKey/CreateKey only).
	TenantID  string  `json:"tenant_id"`
	CreatedBy *string `json:"created_by"`
	Sandbox   bool    `json:"sandbox"`
}

type CreateCryptoKeyInput struct {
	Name        string `json:"name"`
	Mode        string `json:"mode"`
	Description string `json:"description,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
}

// KeyRotationResult is the rotate result.
type KeyRotationResult struct {
	NewVersion int `json:"new_version"`
}

// KeyUpdateResult is the result of setting the destroy safety latch.
type KeyUpdateResult struct {
	Name            string `json:"name"`
	DeletionAllowed bool   `json:"deletion_allowed"`
}

// UpdateCryptoKeyInput sets the per-key destroy safety latch.
type UpdateCryptoKeyInput struct {
	DeletionAllowed bool `json:"deletion_allowed"`
}

// KeyVersionDestroyed is the destroy-key-version result.
type KeyVersionDestroyed struct {
	Destroyed int `json:"destroyed"`
}

// EncryptResult is the keyed transit encrypt/rewrap result.
type EncryptResult struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
}

// DecryptResult is the keyed transit decrypt result: PlaintextB64 by
// default, Plaintext when format "utf8" was requested.
type DecryptResult struct {
	PlaintextB64 string `json:"plaintext_b64"`
	Plaintext    string `json:"plaintext"`
	KeyVersion   int    `json:"key_version"`
}

// SignResult is the sign result.
type SignResult struct {
	Signature  string `json:"signature"`
	KeyVersion int    `json:"key_version"`
}

// VerifyResult is the verify result.
type VerifyResult struct {
	Valid      bool `json:"valid"`
	KeyVersion int  `json:"key_version"`
}

// PublicKeyResult is the public-key result.
type PublicKeyResult struct {
	PEM        string         `json:"pem"`
	JWK        map[string]any `json:"jwk"`
	KeyVersion int            `json:"key_version"`
}

// SignJWTResult is the JWT-sign result.
type SignJWTResult struct {
	Token      string `json:"token"`
	KeyVersion int    `json:"key_version"`
	Alg        string `json:"alg"`
}

// VerifyJWTResult is the JWT-verify result — all fields but Valid are
// optional.
type VerifyJWTResult struct {
	Valid      bool           `json:"valid"`
	Claims     map[string]any `json:"claims"`
	KeyVersion int            `json:"key_version"`
	Alg        string         `json:"alg"`
	Error      string         `json:"error"`
	Kid        string         `json:"kid"`
}

// SignWebhookResult is the webhook-sign result.
type SignWebhookResult struct {
	SignatureHeader  string `json:"signature_header"` // "t=<unix>,v1=<hex>"
	TimestampSeconds int    `json:"timestamp_seconds"`
	KeyVersion       int    `json:"key_version"`
	Format           string `json:"format"` // "stripe"
}

// EncryptInput selects what to encrypt (one of Plaintext / PlaintextB64).
type EncryptInput struct {
	Plaintext    string `json:"plaintext,omitempty"`
	PlaintextB64 string `json:"plaintext_b64,omitempty"`
}

// SignInput selects what to sign.
type SignInput struct {
	Data       string `json:"data,omitempty"`
	DataB64    string `json:"data_b64,omitempty"`
	RSAPadding string `json:"rsa_padding,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

// VerifyInput carries the signed data + signature to verify.
type VerifyInput struct {
	Data       string `json:"data,omitempty"`
	DataB64    string `json:"data_b64,omitempty"`
	Signature  string `json:"signature"`
	RSAPadding string `json:"rsa_padding,omitempty"`
	Hash       string `json:"hash,omitempty"`
}

// SignWebhookInput configures webhook-payload signing.
type SignWebhookInput struct {
	Payload          string `json:"payload,omitempty"`
	PayloadB64       string `json:"payload_b64,omitempty"`
	TimestampSeconds *int   `json:"timestamp_seconds,omitempty"`
	Format           string `json:"format,omitempty"`
}

// -- Portable kc: encryption types ----------------------------------------------

// EncryptDataResult is the structure-preserving POST /v1/encrypt result:
// Ciphertext has the same JSON shape as the input with scalar leaves replaced
// by portable `kc:` ciphertext strings.
type EncryptDataResult struct {
	Ciphertext json.RawMessage `json:"ciphertext"`
	Key        string          `json:"key"`
	KeyVersion int             `json:"key_version"`
}

// DecryptDataResult is the POST /v1/decrypt result (the inverse shape —
// non-kc: values pass through).
type DecryptDataResult struct {
	Plaintext json.RawMessage `json:"plaintext"`
}

// EncryptDataOptions selects the key/role for EncryptData. An empty Key uses
// the tenant's zero-config default ecdh key (auto-provisioned on first use).
type EncryptDataOptions struct {
	Key  string
	Role string
}

// DecryptDataOptions selects the data-role for DecryptData.
type DecryptDataOptions struct {
	Role string
}

// InspectResult is metadata about a single ciphertext (no decryption).
// When Encrypted is false the other fields are zero.
type InspectResult struct {
	Encrypted   bool           `json:"encrypted"`
	Scheme      string         `json:"scheme"` // "kc"
	Version     int            `json:"version"`
	Datatype    string         `json:"datatype"`
	KeyRef      *InspectKeyRef `json:"key_ref"`
	Fingerprint string         `json:"fingerprint"` // ciphertext fingerprint, not plaintext
}

// InspectKeyRef names the key a kc: ciphertext was sealed with. NOTE: this
// endpoint serializes camelCase (unlike the sealing bundle's snake_case).
type InspectKeyRef struct {
	TenantID   string `json:"tenantId"`
	AppKeyID   string `json:"appKeyId"`
	KeyVersion int    `json:"keyVersion"`
}

// MintClientTokenInput mints a single-use, payload-pinned capability token.
type MintClientTokenInput struct {
	// Action: "decrypt" or "detokenize".
	Action string `json:"action"`
	// Data is the exact kc: ciphertext (decrypt) or vault token (detokenize)
	// the capability is bound to.
	Data       string `json:"data"`
	Role       string `json:"role,omitempty"`
	TTLSeconds *int   `json:"ttl_seconds,omitempty"`
}

// ClientTokenResult is the minted capability token — hand it to a browser or
// agent so it can reveal exactly the bound value once, via
// POST /v1/client/{decrypt,detokenize}, without an API key.
type ClientTokenResult struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Action    string `json:"action"`
}

// SealingBundle is the public material a browser needs to seal values
// client-side (no private material).
type SealingBundle struct {
	// PublicKeyRaw is the base64url 65-byte uncompressed P-256 point.
	PublicKeyRaw string        `json:"public_key_raw"`
	KeyRef       SealingKeyRef `json:"key_ref"`
}

// SealingKeyRef names the sealing key (snake_case, unlike InspectKeyRef).
type SealingKeyRef struct {
	TenantID   string `json:"tenant_id"`
	AppKeyID   string `json:"app_key_id"`
	KeyVersion int    `json:"key_version"`
}

type CryptoResource struct{ c *Client }

// -- Key management --

// ListKeys returns every transit key (bare array — no pagination).
func (r *CryptoResource) ListKeys(ctx context.Context) ([]CryptoKey, error) {
	return doSlice[CryptoKey](ctx, r.c, requestOpts{method: "GET", path: "/v1/crypto/keys"})
}

func (r *CryptoResource) GetKey(ctx context.Context, name string) (*CryptoKey, error) {
	return doUnwrap[CryptoKey](ctx, r.c, requestOpts{method: "GET", path: "/v1/crypto/keys/" + encode(name)})
}

func (r *CryptoResource) CreateKey(ctx context.Context, input CreateCryptoKeyInput) (*CryptoKey, error) {
	return doUnwrap[CryptoKey](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys", body: input})
}

func (r *CryptoResource) RotateKey(ctx context.Context, name string) (*KeyRotationResult, error) {
	return doUnwrap[KeyRotationResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/rotate", body: map[string]any{}})
}

// UpdateKey raises or lowers the key's destroy safety latch
// (deletion_allowed). A version can only be destroyed while it is true, and
// every new key ships with it false. DestroyKeyVersion on a key with the latch
// down is refused with a 409 (deletion_not_allowed) -- a client error, never
// retry it unchanged. Raise the latch, destroy, lower it again.
func (r *CryptoResource) UpdateKey(ctx context.Context, name string, input UpdateCryptoKeyInput) (*KeyUpdateResult, error) {
	return doUnwrap[KeyUpdateResult](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/crypto/keys/" + encode(name), body: input})
}

func (r *CryptoResource) DestroyKeyVersion(ctx context.Context, name string, version int) (*KeyVersionDestroyed, error) {
	return doUnwrap[KeyVersionDestroyed](ctx, r.c, requestOpts{method: "DELETE", path: fmt.Sprintf("/v1/crypto/keys/%s/versions/%d", encode(name), version)})
}

// GetPublicKey returns the key's public material; version 0 means the
// current version.
func (r *CryptoResource) GetPublicKey(ctx context.Context, name string, version int) (*PublicKeyResult, error) {
	q := url.Values{}
	if version > 0 {
		q.Set("version", strconv.Itoa(version))
	}
	return doUnwrap[PublicKeyResult](ctx, r.c, requestOpts{method: "GET", path: "/v1/crypto/keys/" + encode(name) + "/public-key", query: q})
}

// -- Keyed transit encryption --

func (r *CryptoResource) Encrypt(ctx context.Context, name string, input EncryptInput) (*EncryptResult, error) {
	return doUnwrap[EncryptResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/encrypt", body: input})
}

// Decrypt opens a transit ciphertext. format "" returns PlaintextB64;
// format "utf8" returns Plaintext.
func (r *CryptoResource) Decrypt(ctx context.Context, name, ciphertext, format string) (*DecryptResult, error) {
	q := url.Values{}
	if format != "" {
		q.Set("format", format)
	}
	return doUnwrap[DecryptResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/decrypt", body: map[string]string{"ciphertext": ciphertext}, query: q})
}

func (r *CryptoResource) Rewrap(ctx context.Context, name, ciphertext string) (*EncryptResult, error) {
	return doUnwrap[EncryptResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/rewrap", body: map[string]string{"ciphertext": ciphertext}})
}

// -- Portable kc: encryption (structure-preserving, top-level /v1) --------------
// Distinct from the keyed transit Encrypt above: these take arbitrary JSON
// and return the same shape with scalar leaves swapped for portable,
// self-describing `kc:` ciphertext strings. Backed by ecdh-p256 keys.

// EncryptData encrypts arbitrary JSON structure-preservingly. Pass nil opts
// for the tenant's zero-config default key.
func (r *CryptoResource) EncryptData(ctx context.Context, data any, opts *EncryptDataOptions) (*EncryptDataResult, error) {
	body := map[string]any{"data": data}
	if opts != nil {
		if opts.Key != "" {
			body["key"] = opts.Key
		}
		if opts.Role != "" {
			body["role"] = opts.Role
		}
	}
	return doUnwrap[EncryptDataResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/encrypt", body: body})
}

// DecryptData is the inverse of EncryptData — every kc: leaf is opened,
// non-kc: values pass through.
func (r *CryptoResource) DecryptData(ctx context.Context, data any, opts *DecryptDataOptions) (*DecryptDataResult, error) {
	body := map[string]any{"data": data}
	if opts != nil && opts.Role != "" {
		body["role"] = opts.Role
	}
	return doUnwrap[DecryptDataResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/decrypt", body: body})
}

// Inspect returns metadata about a single ciphertext without decrypting it.
func (r *CryptoResource) Inspect(ctx context.Context, value string) (*InspectResult, error) {
	return doUnwrap[InspectResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/inspect", body: map[string]string{"value": value}})
}

// MintClientToken mints a single-use, payload-pinned client-side capability
// token via POST /v1/client-tokens. The consume endpoints
// (/v1/client/decrypt, /v1/client/detokenize) are browser-side operations
// owned by @knoxcall/browser and are deliberately not wrapped here.
func (r *CryptoResource) MintClientToken(ctx context.Context, input MintClientTokenInput) (*ClientTokenResult, error) {
	return doUnwrap[ClientTokenResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/client-tokens", body: input})
}

// GetSealingBundle fetches the public bits a browser needs to seal values
// client-side. An empty key uses the tenant's default ecdh key.
func (r *CryptoResource) GetSealingBundle(ctx context.Context, key string) (*SealingBundle, error) {
	q := url.Values{}
	if key != "" {
		q.Set("key", key)
	}
	return doUnwrap[SealingBundle](ctx, r.c, requestOpts{method: "GET", path: "/v1/encrypt/sealing-bundle", query: q})
}

// -- Signing --

func (r *CryptoResource) Sign(ctx context.Context, name string, input SignInput) (*SignResult, error) {
	return doUnwrap[SignResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/sign", body: input})
}

func (r *CryptoResource) Verify(ctx context.Context, name string, input VerifyInput) (*VerifyResult, error) {
	return doUnwrap[VerifyResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/verify", body: input})
}

// -- JWT --

func (r *CryptoResource) SignJWT(ctx context.Context, name string, claims map[string]any, headerOverrides map[string]any) (*SignJWTResult, error) {
	body := map[string]any{"claims": claims}
	if len(headerOverrides) > 0 {
		body["header_overrides"] = headerOverrides
	}
	return doUnwrap[SignJWTResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/jwt", body: body})
}

func (r *CryptoResource) VerifyJWT(ctx context.Context, name, token string, expected map[string]any) (*VerifyJWTResult, error) {
	body := map[string]any{"token": token}
	if len(expected) > 0 {
		body["expected"] = expected
	}
	return doUnwrap[VerifyJWTResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/jwt/verify", body: body})
}

// -- Webhook signing --

func (r *CryptoResource) SignWebhook(ctx context.Context, name string, input SignWebhookInput) (*SignWebhookResult, error) {
	return doUnwrap[SignWebhookResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/crypto/keys/" + encode(name) + "/webhook-sign", body: input})
}
