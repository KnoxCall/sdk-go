package knoxcall

import "context"

// Environment is a tenant environment. TenantID/Sandbox are present on the
// Create/Update full-row responses only.
type Environment struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	DisplayName string  `json:"display_name"`
	Description *string `json:"description"`
	Color       string  `json:"color"`
	IsDefault   bool    `json:"is_default"`
	CreatedAt   string  `json:"created_at"`

	// Create/Update only.
	TenantID string `json:"tenant_id"`
	Sandbox  bool   `json:"sandbox"`
}

type CreateEnvironmentInput struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Color       string `json:"color,omitempty"`
	IsDefault   *bool  `json:"is_default,omitempty"`
}

type UpdateEnvironmentInput struct {
	Name        *string `json:"name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Description *string `json:"description,omitempty"`
	Color       *string `json:"color,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

type EnvironmentsResource struct{ c *Client }

// List returns every environment (bare array — this endpoint has no
// pagination).
func (r *EnvironmentsResource) List(ctx context.Context) ([]Environment, error) {
	return doSlice[Environment](ctx, r.c, requestOpts{method: "GET", path: "/v1/environments"})
}

func (r *EnvironmentsResource) Create(ctx context.Context, input CreateEnvironmentInput) (*Environment, error) {
	return doUnwrap[Environment](ctx, r.c, requestOpts{method: "POST", path: "/v1/environments", body: input})
}

func (r *EnvironmentsResource) Update(ctx context.Context, envID string, input UpdateEnvironmentInput) (*Environment, error) {
	return doUnwrap[Environment](ctx, r.c, requestOpts{method: "PATCH", path: "/v1/environments/" + encode(envID), body: input})
}

func (r *EnvironmentsResource) Delete(ctx context.Context, envID string) (*DeletedResponse, error) {
	return doUnwrap[DeletedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/environments/" + encode(envID)})
}
