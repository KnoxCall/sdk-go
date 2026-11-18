package knoxcall

import (
	"context"
	"net/url"
	"strconv"
)

// DbConnection is a dynamic-DB connection. List/Get return the full row;
// Create returns only ID/Name/Engine/ExecutionMode (other fields stay zero).
type DbConnection struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Engine            string         `json:"engine"` // postgres | mysql | mongo
	Host              string         `json:"host"`
	Port              *int           `json:"port"`
	DatabaseName      *string        `json:"database_name"`
	AdminUsername     string         `json:"admin_username"`
	ExecutionMode     string         `json:"execution_mode"` // direct | agent_tunnel | ssh_tunnel | iam
	AgentID           *string        `json:"agent_id"`
	DefaultTTLSeconds int            `json:"default_ttl_seconds"`
	MaxTTLSeconds     int            `json:"max_ttl_seconds"`
	ConnectOptions    map[string]any `json:"connect_options"`
	Enabled           bool           `json:"enabled"`
	CreatedAt         string         `json:"created_at"`
	UpdatedAt         string         `json:"updated_at"`
	SSHHost           *string        `json:"ssh_host"`
	SSHPort           *int           `json:"ssh_port"`
	SSHUsername       *string        `json:"ssh_username"`
	IAMRegion         *string        `json:"iam_region"`
	IAMDbUser         *string        `json:"iam_db_user"`
}

// DbRole is one GET /v1/dyn-db-credentials/{name}/roles row.
type DbRole struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	CreationSQLTemplate   string `json:"creation_sql_template"`
	RevocationSQLTemplate string `json:"revocation_sql_template"`
	DefaultTTLSeconds     *int   `json:"default_ttl_seconds"`
	MaxTTLSeconds         *int   `json:"max_ttl_seconds"`
	CreatedAt             string `json:"created_at"`
	UpdatedAt             string `json:"updated_at"`
}

// CreatedDbRole is the POST .../roles result.
type CreatedDbRole struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Connection string `json:"connection"`
}

// MintedDbCredentials is a freshly minted, leased DB credential. Password is
// returned ONCE.
type MintedDbCredentials struct {
	Username       string `json:"username"`
	Password       string `json:"password"`
	ExpiresAt      string `json:"expires_at"`
	LeaseID        int    `json:"lease_id"`
	ConnectionName string `json:"connection_name"`
	RoleName       string `json:"role_name"`
}

// DbLease is one lease row.
type DbLease struct {
	ID             int     `json:"id"`
	Status         string  `json:"status"`
	ExpiresAt      string  `json:"expires_at"`
	IssuedAt       string  `json:"issued_at"`
	Username       *string `json:"username"`
	ConnectionName *string `json:"connection_name"`
	RoleName       *string `json:"role_name"`
	Engine         *string `json:"engine"`
}

// DbLeaseList is the GET /v1/dyn-db-credentials/leases result. Unlike every
// other paginated endpoint, this one really is limit/offset INSIDE data.
type DbLeaseList struct {
	Leases []DbLease `json:"leases"`
	Total  int       `json:"total"`
	Limit  int       `json:"limit"`
	Offset int       `json:"offset"`
}

// ListLeasesParams filters/pages the lease list (limit/offset, not
// page/per_page — this endpoint predates the page convention).
type ListLeasesParams struct {
	Limit      int
	Offset     int
	Connection string
}

// RevokedLease is the lease-revoke result (echoes the lease id).
type RevokedLease struct {
	Revoked int `json:"revoked"`
}

// SSHKeyRotation is the rotate-ssh-key result.
type SSHKeyRotation struct {
	Rotated            string `json:"rotated"`
	FingerprintUpdated bool   `json:"fingerprint_updated"`
}

type CreateDbConnectionInput struct {
	Name               string         `json:"name"`
	Engine             string         `json:"engine"`
	Host               string         `json:"host,omitempty"`
	Port               *int           `json:"port,omitempty"`
	DatabaseName       string         `json:"database_name,omitempty"`
	AdminUsername      string         `json:"admin_username,omitempty"`
	AdminPassword      string         `json:"admin_password,omitempty"`
	ExecutionMode      string         `json:"execution_mode,omitempty"`
	AgentID            string         `json:"agent_id,omitempty"`
	SSHHost            string         `json:"ssh_host,omitempty"`
	SSHPort            *int           `json:"ssh_port,omitempty"`
	SSHUsername        string         `json:"ssh_username,omitempty"`
	SSHPrivateKey      string         `json:"ssh_private_key,omitempty"`
	SSHPassphrase      string         `json:"ssh_passphrase,omitempty"`
	SSHHostFingerprint string         `json:"ssh_host_fingerprint,omitempty"`
	IAMRegion          string         `json:"iam_region,omitempty"`
	IAMDbUser          string         `json:"iam_db_user,omitempty"`
	DefaultTTLSec      *int           `json:"default_ttl_seconds,omitempty"`
	MaxTTLSec          *int           `json:"max_ttl_seconds,omitempty"`
	ConnectOptions     map[string]any `json:"connect_options,omitempty"`
}

type UpdateDbConnectionInput struct {
	Host           *string        `json:"host,omitempty"`
	Port           *int           `json:"port,omitempty"`
	DatabaseName   *string        `json:"database_name,omitempty"`
	AdminUsername  *string        `json:"admin_username,omitempty"`
	AdminPassword  *string        `json:"admin_password,omitempty"`
	DefaultTTLSec  *int           `json:"default_ttl_seconds,omitempty"`
	MaxTTLSec      *int           `json:"max_ttl_seconds,omitempty"`
	ConnectOptions map[string]any `json:"connect_options,omitempty"`
	AgentID        *string        `json:"agent_id,omitempty"`
	Enabled        *bool          `json:"enabled,omitempty"`
}

type CreateDbRoleInput struct {
	Name          string `json:"name"`
	Template      string `json:"template,omitempty"`
	CreationSQL   string `json:"creation_sql,omitempty"`
	RevocationSQL string `json:"revocation_sql,omitempty"`
	DefaultTTLSec *int   `json:"default_ttl_seconds,omitempty"`
	MaxTTLSec     *int   `json:"max_ttl_seconds,omitempty"`
}

type UpdateDbRoleInput struct {
	CreationSQL   *string `json:"creation_sql,omitempty"`
	RevocationSQL *string `json:"revocation_sql,omitempty"`
	DefaultTTLSec *int    `json:"default_ttl_seconds,omitempty"`
	MaxTTLSec     *int    `json:"max_ttl_seconds,omitempty"`
}

type DynamicDBResource struct{ c *Client }

// -- Connections --

// List returns every connection (bare array — no pagination).
func (r *DynamicDBResource) List(ctx context.Context) ([]DbConnection, error) {
	return doSlice[DbConnection](ctx, r.c, requestOpts{method: "GET", path: "/v1/dyn-db-credentials"})
}

func (r *DynamicDBResource) Get(ctx context.Context, name string) (*DbConnection, error) {
	return doUnwrap[DbConnection](ctx, r.c, requestOpts{method: "GET", path: "/v1/dyn-db-credentials/" + encode(name)})
}

func (r *DynamicDBResource) Create(ctx context.Context, input CreateDbConnectionInput) (*DbConnection, error) {
	return doUnwrap[DbConnection](ctx, r.c, requestOpts{method: "POST", path: "/v1/dyn-db-credentials", body: input})
}

// Update patches the connection; the response echoes the name as
// {updated: "<name>"}.
func (r *DynamicDBResource) Update(ctx context.Context, name string, input UpdateDbConnectionInput) (*UpdatedNameResponse, error) {
	return doUnwrap[UpdatedNameResponse](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/dyn-db-credentials/" + encode(name), body: input})
}

// Delete removes the connection; the response echoes the name as
// {deleted: "<name>"}.
func (r *DynamicDBResource) Delete(ctx context.Context, name string) (*DeletedNameResponse, error) {
	return doUnwrap[DeletedNameResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/dyn-db-credentials/" + encode(name)})
}

func (r *DynamicDBResource) RotateSSHKey(ctx context.Context, name, sshPrivateKey, sshPassphrase, sshHostFingerprint string) (*SSHKeyRotation, error) {
	body := map[string]string{"ssh_private_key": sshPrivateKey}
	if sshPassphrase != "" {
		body["ssh_passphrase"] = sshPassphrase
	}
	if sshHostFingerprint != "" {
		body["ssh_host_fingerprint"] = sshHostFingerprint
	}
	return doUnwrap[SSHKeyRotation](ctx, r.c, requestOpts{method: "POST", path: "/v1/dyn-db-credentials/" + encode(name) + "/rotate-ssh-key", body: body})
}

// -- Roles --

// ListRoles returns the connection's roles (bare array).
func (r *DynamicDBResource) ListRoles(ctx context.Context, connectionName string) ([]DbRole, error) {
	return doSlice[DbRole](ctx, r.c, requestOpts{method: "GET", path: "/v1/dyn-db-credentials/" + encode(connectionName) + "/roles"})
}

func (r *DynamicDBResource) CreateRole(ctx context.Context, connectionName string, input CreateDbRoleInput) (*CreatedDbRole, error) {
	return doUnwrap[CreatedDbRole](ctx, r.c, requestOpts{method: "POST", path: "/v1/dyn-db-credentials/" + encode(connectionName) + "/roles", body: input})
}

func (r *DynamicDBResource) UpdateRole(ctx context.Context, connectionName, role string, input UpdateDbRoleInput) (*UpdatedNameResponse, error) {
	return doUnwrap[UpdatedNameResponse](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/dyn-db-credentials/" + encode(connectionName) + "/roles/" + encode(role), body: input})
}

func (r *DynamicDBResource) DeleteRole(ctx context.Context, connectionName, role string) (*DeletedNameResponse, error) {
	return doUnwrap[DeletedNameResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/dyn-db-credentials/" + encode(connectionName) + "/roles/" + encode(role)})
}

// -- Credential minting + leases --

// Mint creates a fresh leased credential. Password is shown exactly once.
func (r *DynamicDBResource) Mint(ctx context.Context, connectionName, role string, ttlSeconds *int) (*MintedDbCredentials, error) {
	body := map[string]any{}
	if ttlSeconds != nil {
		body["ttl_seconds"] = *ttlSeconds
	}
	return doUnwrap[MintedDbCredentials](ctx, r.c, requestOpts{method: "POST", path: "/v1/dyn-db-credentials/" + encode(connectionName) + "/creds/" + encode(role), body: body})
}

// ListLeases returns LIVE leases — those whose Status is "active", "renewing"
// or "errored", i.e. every lease whose database user may still exist on your
// server. Expired and revoked leases have had their user dropped and are
// neither listed nor counted in Total. Connection is an exact match on the
// connection's name, scoped to the caller's Live/Test space.
//
// "errored" is included deliberately: renewal was abandoned after five
// consecutive failures, so nothing is refreshing or expiring that lease. It is
// also the set counted by the 409 "has N active credential lease(s)" a
// connection or role delete returns, so anything blocking a delete is listed
// here and can be revoked.
//
// Pagination is limit/offset carried INSIDE the data object (the one endpoint
// that does not use page/per_page).
func (r *DynamicDBResource) ListLeases(ctx context.Context, params *ListLeasesParams) (*DbLeaseList, error) {
	q := url.Values{}
	if params != nil {
		if params.Limit > 0 {
			q.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Offset > 0 {
			q.Set("offset", strconv.Itoa(params.Offset))
		}
		if params.Connection != "" {
			q.Set("connection", params.Connection)
		}
	}
	return doUnwrap[DbLeaseList](ctx, r.c, requestOpts{method: "GET", path: "/v1/dyn-db-credentials/leases", query: q})
}

// RevokeLease revokes a lease; the response echoes the lease id as
// {revoked: <id>}.
func (r *DynamicDBResource) RevokeLease(ctx context.Context, leaseID int) (*RevokedLease, error) {
	return doUnwrap[RevokedLease](ctx, r.c, requestOpts{method: "POST", path: "/v1/dyn-db-credentials/leases/" + strconv.Itoa(leaseID) + "/revoke", body: map[string]any{}})
}
