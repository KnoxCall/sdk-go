package knoxcall

import (
	"context"
	"net/http"
)

// BoundRouteOptions configures the call defaults bound by Client.Route.
type BoundRouteOptions struct {
	// Environment is the default x-knoxcall-environment for every call made
	// through the handle. A non-empty per-call CallOptions.Environment
	// overrides it.
	Environment string
	// Headers are merged into every call's headers per-key, with the
	// per-call value winning. SDK-set headers (route, environment,
	// Authorization) still beat everything.
	Headers map[string]string
}

// Route binds a route (and optional call defaults) once, so plain HTTP-verb
// calls can be made against it:
//
//	printnode := client.Route("3f1e2c9a-...", &knoxcall.BoundRouteOptions{Environment: "production"})
//	res, err := printnode.Get(ctx, "/computers", nil)
//	res, err = printnode.Post(ctx, "/printjobs", &knoxcall.CallOptions{Body: payload})
//
// Pass the route UUID (preferred) or name as route. No HTTP happens here —
// a BoundRoute is a cheap value that only records the defaults.
func (c *Client) Route(route string, opts *BoundRouteOptions) *BoundRoute {
	b := &BoundRoute{client: c, route: route}
	if opts != nil {
		b.environment = opts.Environment
		if len(opts.Headers) > 0 {
			b.headers = make(map[string]string, len(opts.Headers))
			for k, v := range opts.Headers {
				b.headers[k] = v
			}
		}
	}
	return b
}

// BoundRoute is a route with bound call defaults — see Client.Route.
//
// It holds only the client reference, the route, and the defaults (never a
// token or any pipeline state), and every method delegates to Client.Call,
// so retries, typed transport errors, and the 401 purge + re-mint behave
// exactly as on Call. An empty per-call value inherits the bound default;
// there is no "explicitly clear" mechanism — construct another handle
// instead. For a per-call timeout, pass a context with a deadline
// (context.WithTimeout).
type BoundRoute struct {
	client      *Client
	route       string
	environment string
	headers     map[string]string
}

// Request makes a proxied request through the bound route with an explicit
// HTTP method. The method and path arguments always win over the
// corresponding CallOptions fields; a non-empty per-call Environment beats
// the bound default; headers merge per-key with the per-call value winning.
// The caller's CallOptions is never mutated.
func (b *BoundRoute) Request(ctx context.Context, method, path string, opts *CallOptions) (*http.Response, error) {
	merged := CallOptions{}
	if opts != nil {
		merged = *opts
	}
	merged.Method = method
	merged.Path = path
	if merged.Environment == "" {
		merged.Environment = b.environment
	}
	if len(b.headers) > 0 {
		h := make(map[string]string, len(b.headers)+len(merged.Headers))
		for k, v := range b.headers {
			h[k] = v
		}
		for k, v := range merged.Headers {
			h[k] = v // per-call wins
		}
		merged.Headers = h
	}
	return b.client.Call(ctx, b.route, &merged)
}

// Get makes a GET request through the bound route.
func (b *BoundRoute) Get(ctx context.Context, path string, opts *CallOptions) (*http.Response, error) {
	return b.Request(ctx, http.MethodGet, path, opts)
}

// Post makes a POST request through the bound route.
func (b *BoundRoute) Post(ctx context.Context, path string, opts *CallOptions) (*http.Response, error) {
	return b.Request(ctx, http.MethodPost, path, opts)
}

// Put makes a PUT request through the bound route.
func (b *BoundRoute) Put(ctx context.Context, path string, opts *CallOptions) (*http.Response, error) {
	return b.Request(ctx, http.MethodPut, path, opts)
}

// Patch makes a PATCH request through the bound route.
func (b *BoundRoute) Patch(ctx context.Context, path string, opts *CallOptions) (*http.Response, error) {
	return b.Request(ctx, http.MethodPatch, path, opts)
}

// Delete makes a DELETE request through the bound route.
func (b *BoundRoute) Delete(ctx context.Context, path string, opts *CallOptions) (*http.Response, error) {
	return b.Request(ctx, http.MethodDelete, path, opts)
}
