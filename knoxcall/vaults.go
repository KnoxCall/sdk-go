package knoxcall

import (
	"context"
	"encoding/json"
	"iter"
)

// Vault is a tokenization vault. Stats is present on Get only.
type Vault struct {
	ID                string         `json:"id"`
	TenantID          string         `json:"tenant_id"`
	Name              string         `json:"name"`
	TokenFormat       string         `json:"token_format"`
	CryptoKeyID       string         `json:"crypto_key_id"`
	CustodyMode       string         `json:"custody_mode"` // "managed" | "dual"
	DefaultTTLSeconds *int           `json:"default_ttl_seconds"`
	Metadata          map[string]any `json:"metadata_jsonb"`
	Description       *string        `json:"description"`
	Enabled           bool           `json:"enabled"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
	CreatedBy         *string        `json:"created_by"`
	Sandbox           bool           `json:"sandbox"`

	// Get only.
	Stats *VaultStats `json:"stats"`
}

// VaultStats summarizes a vault's tokens (Get only).
type VaultStats struct {
	TokenCount    int `json:"token_count"`
	ActiveCount   int `json:"active_count"`
	ExpiringIn24h int `json:"expiring_in_24h"`
}

// VaultToken is a tokenization result / token-list row. The list rows add
// CreatedByAPIKeyID/CreatedByUserID.
type VaultToken struct {
	ID        string  `json:"id"`
	Token     string  `json:"token"`
	ExpiresAt *string `json:"expires_at"`
	CreatedAt string  `json:"created_at"`

	// CardExpiresOn is the LAST DAY of the CARD's expiry month
	// ("2029-07-31"), or nil. It is NOT ExpiresAt, which is how long the
	// TOKEN lives. Non-nil only for a pan vault whose tokenize call supplied
	// CardExpMonth/CardExpYear; a token created before 2026-09-17 is nil and
	// cannot be backfilled, because the expiry was never captured.
	CardExpiresOn *string `json:"card_expires_on"`

	// CardFundingType is how the issuer funds the card -- "credit", "debit"
	// or "prepaid" -- and CardIssuingCountry is the issuer's country as ISO
	// 3166-1 alpha-2. Both are derived from the card's first six digits.
	//
	// BOTH ARE nil ON EVERY TOKEN TODAY and will be until KnoxCall licenses a
	// BIN table, so treat them as optional indefinitely. They are also nil for
	// every non-pan vault and for any BIN a future table does not carry.
	CardFundingType    *string `json:"card_funding_type"`
	CardIssuingCountry *string `json:"card_issuing_country"`

	// List rows only.
	CreatedByAPIKeyID *string `json:"created_by_api_key_id"`
	CreatedByUserID   *string `json:"created_by_user_id"`
}

// BulkTokenizeResult is the tokens/bulk result.
type BulkTokenizeResult struct {
	Tokens []VaultToken `json:"tokens"`
	Count  int          `json:"count"`
}

// DetokenizedToken is the GET .../tokens/{idOrToken} result — the token row
// plus the revealed value.
type DetokenizedToken struct {
	ID               string          `json:"id"`
	Token            string          `json:"token"`
	ExpiresAt        *string         `json:"expires_at"`
	CreatedAt        string          `json:"created_at"`
	Value            string          `json:"value"`
	ValueB64         string          `json:"value_b64"`
	Metadata         json.RawMessage `json:"metadata"`
	CryptoKeyVersion int             `json:"crypto_key_version"`
}

// VaultRotation is the rotate result.
type VaultRotation struct {
	NewVersion int `json:"new_version"`
}

type CreateVaultInput struct {
	Name              string         `json:"name"`
	TokenFormat       string         `json:"token_format,omitempty"`
	DefaultTTLSeconds *int           `json:"default_ttl_seconds,omitempty"`
	Description       string         `json:"description,omitempty"`
	Metadata          map[string]any `json:"metadata_jsonb,omitempty"`
}

type UpdateVaultInput struct {
	DefaultTTLSeconds *int           `json:"default_ttl_seconds,omitempty"`
	Description       *string        `json:"description,omitempty"`
	Enabled           *bool          `json:"enabled,omitempty"`
	Metadata          map[string]any `json:"metadata_jsonb,omitempty"`
}

type TokenizeInput struct {
	Value      string         `json:"value"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	TTLSeconds *int           `json:"ttl_seconds,omitempty"`

	// CardExpMonth and CardExpYear are the CARD's own expiry, for a pan vault
	// only -- not TTLSeconds, which is the TOKEN's lifetime. Both or neither;
	// the year is four digits (2029, never 29). Supplying them subscribes the
	// token to the vault.token.expiring webhook, emitted 60 and 30 days before
	// the card expires. Offering them to a non-pan vault is a validation_error.
	CardExpMonth *int `json:"card_exp_month,omitempty"`
	CardExpYear  *int `json:"card_exp_year,omitempty"`
}

type VaultsResource struct{ c *Client }

// List returns one page of vaults.
func (r *VaultsResource) List(ctx context.Context, params *ListParams) (*Page[Vault], error) {
	return doPage[Vault](ctx, r.c, requestOpts{method: "GET", path: "/v1/vaults", query: params.query()})
}

// ListAll walks every page and returns all vaults.
func (r *VaultsResource) ListAll(ctx context.Context, params *ListParams) ([]Vault, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[Vault], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

// Iterate lazily streams every vault one at a time, fetching pages on demand
// (the streaming analog of ListAll — see helpers.iterate). Range over it with
// two variables and break on the first non-nil error.
func (r *VaultsResource) Iterate(ctx context.Context, params *ListParams) iter.Seq2[Vault, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[Vault], error) {
		p.Page = page
		return r.List(ctx, &p)
	})
}

func (r *VaultsResource) Get(ctx context.Context, nameOrID string) (*Vault, error) {
	return doUnwrap[Vault](ctx, r.c, requestOpts{method: "GET", path: "/v1/vaults/" + encode(nameOrID)})
}

func (r *VaultsResource) Create(ctx context.Context, input CreateVaultInput) (*Vault, error) {
	return doUnwrap[Vault](ctx, r.c, requestOpts{method: "POST", path: "/v1/vaults", body: input})
}

func (r *VaultsResource) Update(ctx context.Context, nameOrID string, input UpdateVaultInput) (*Vault, error) {
	return doUnwrap[Vault](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/vaults/" + encode(nameOrID), body: input})
}

// Delete removes the vault; the response acknowledges with {deleted: true}.
func (r *VaultsResource) Delete(ctx context.Context, nameOrID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/vaults/" + encode(nameOrID)})
}

func (r *VaultsResource) Rotate(ctx context.Context, nameOrID string) (*VaultRotation, error) {
	return doUnwrap[VaultRotation](ctx, r.c, requestOpts{method: "POST", path: "/v1/vaults/" + encode(nameOrID) + "/rotate", body: map[string]any{}})
}

// -- Token operations --

func (r *VaultsResource) Tokenize(ctx context.Context, nameOrID string, input TokenizeInput) (*VaultToken, error) {
	return doUnwrap[VaultToken](ctx, r.c, requestOpts{method: "POST", path: "/v1/vaults/" + encode(nameOrID) + "/tokens", body: input})
}

func (r *VaultsResource) BulkTokenize(ctx context.Context, nameOrID string, values []TokenizeInput) (*BulkTokenizeResult, error) {
	return doUnwrap[BulkTokenizeResult](ctx, r.c, requestOpts{method: "POST", path: "/v1/vaults/" + encode(nameOrID) + "/tokens/bulk", body: map[string]any{"values": values}})
}

// ListTokens returns one page of the vault's tokens (values are never
// included — use Detokenize).
func (r *VaultsResource) ListTokens(ctx context.Context, nameOrID string, params *ListParams) (*Page[VaultToken], error) {
	return doPage[VaultToken](ctx, r.c, requestOpts{method: "GET", path: "/v1/vaults/" + encode(nameOrID) + "/tokens", query: params.query()})
}

// ListAllTokens walks every page and returns all of the vault's tokens.
func (r *VaultsResource) ListAllTokens(ctx context.Context, nameOrID string, params *ListParams) ([]VaultToken, error) {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return listAll(ctx, p.Page, func(ctx context.Context, page int) (*Page[VaultToken], error) {
		p.Page = page
		return r.ListTokens(ctx, nameOrID, &p)
	})
}

// IterateTokens lazily streams all of the vault's tokens one at a time, fetching
// pages on demand rather than buffering them (the streaming analog of
// ListAllTokens — see helpers.iterate). Preferred over ListAllTokens for large
// token sets. Range over it with two variables and break on the first non-nil
// error. Values are never included — use Detokenize.
func (r *VaultsResource) IterateTokens(ctx context.Context, nameOrID string, params *ListParams) iter.Seq2[VaultToken, error] {
	p := ListParams{}
	if params != nil {
		p = *params
	}
	return iterate(ctx, p.Page, func(ctx context.Context, page int) (*Page[VaultToken], error) {
		p.Page = page
		return r.ListTokens(ctx, nameOrID, &p)
	})
}

// Detokenize reveals the value bound to a token.
func (r *VaultsResource) Detokenize(ctx context.Context, nameOrID, idOrToken string) (*DetokenizedToken, error) {
	return doUnwrap[DetokenizedToken](ctx, r.c, requestOpts{method: "GET", path: "/v1/vaults/" + encode(nameOrID) + "/tokens/" + encode(idOrToken)})
}

func (r *VaultsResource) UpdateToken(ctx context.Context, nameOrID, idOrToken string, metadata map[string]any) (*UpdatedResponse, error) {
	return doUnwrap[UpdatedResponse](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/vaults/" + encode(nameOrID) + "/tokens/" + encode(idOrToken), body: map[string]any{"metadata": metadata}})
}

// DeleteToken removes a token; the response acknowledges with {deleted: true}.
func (r *VaultsResource) DeleteToken(ctx context.Context, nameOrID, idOrToken string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/vaults/" + encode(nameOrID) + "/tokens/" + encode(idOrToken)})
}
