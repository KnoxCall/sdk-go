package knoxcall

import "context"

// Agent is one GET /v1/agents row.
type Agent struct {
	ID                   string  `json:"id"`
	Name                 string  `json:"name"`
	AgentID              string  `json:"agent_id"`
	Status               string  `json:"status"` // "active" | "revoked"
	RequireVerifiedBuild bool    `json:"require_verified_build"`
	LastSeenAt           *string `json:"last_seen_at"`
	LastSessionIssuedAt  *string `json:"last_session_issued_at"`
	CreatedAt            string  `json:"created_at"`
	HasTamperEvents      bool    `json:"has_tamper_events"`
}

// CreatedAgent is the POST /v1/agents result. AgentSecret is returned
// ONCE — store it immediately.
type CreatedAgent struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	AgentID              string `json:"agent_id"`
	Status               string `json:"status"`
	RequireVerifiedBuild bool   `json:"require_verified_build"`
	CreatedAt            string `json:"created_at"`
	AgentSecret          string `json:"agent_secret"`
}

// TamperEvent is one GET /v1/agents/{id}/tamper-events row.
type TamperEvent struct {
	ID               string  `json:"id"`
	VersionReported  *string `json:"version_reported"`
	BuildSigReported *string `json:"build_sig_reported"`
	SrcIP            *string `json:"src_ip"`
	ActionTaken      *string `json:"action_taken"`
	DetectedAt       string  `json:"detected_at"`
}

type AgentsResource struct{ c *Client }

// List returns every agent (bare array — this endpoint has no pagination).
func (r *AgentsResource) List(ctx context.Context) ([]Agent, error) {
	return doSlice[Agent](ctx, r.c, requestOpts{method: "GET", path: "/v1/agents"})
}

// Create registers an agent. AgentSecret is shown exactly once.
//
// Requires an explicit `agent:create` policy grant: a wildcard (`*:*`) rule
// does not satisfy it, including the `legacy_admin` policy every key created
// before 2026-06-30 still carries. The seeded Key - Infrastructure and Key -
// Editor roles name the action literally and are unaffected. Without it the
// call returns 403. Every successful mint also emails the account's owners.
func (r *AgentsResource) Create(ctx context.Context, name string) (*CreatedAgent, error) {
	return doUnwrap[CreatedAgent](ctx, r.c, requestOpts{method: "POST", path: "/v1/agents", body: map[string]string{"name": name}})
}

func (r *AgentsResource) Revoke(ctx context.Context, agentID string) (*RevokedResponse, error) {
	return doUnwrap[RevokedResponse](ctx, r.c, requestOpts{method: "DELETE", path: "/v1/agents/" + encode(agentID)})
}

// GetTamperEvents returns the agent's latest tamper events (bare array,
// server-limited to 50).
func (r *AgentsResource) GetTamperEvents(ctx context.Context, agentID string) ([]TamperEvent, error) {
	return doSlice[TamperEvent](ctx, r.c, requestOpts{method: "GET", path: "/v1/agents/" + encode(agentID) + "/tamper-events"})
}
