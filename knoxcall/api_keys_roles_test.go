package knoxcall

// role_ids on POST /v1/api-keys + the read-only role catalog
// (IaC plan §6 item 1.3). Mocks return the REAL {data, meta} envelope.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestCreateAPIKeySendsRoleIDsAndDecodesIDAndRoleIDs(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c","key_id":"tk_a1","api_key":"tk_a1_secret","key_prefix":"tk_a1","key_type":"standard","name":"tf","role_ids":["b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"],"message":"save it"},"meta":{"request_id":"req_1"}}`)
	})

	created, err := c.APIKeys.Create(context.Background(), CreateAPIKeyInput{
		Name:    "tf",
		RoleIDs: []string{"b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != "f0a1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c" {
		t.Fatalf("ID = %q, want the row UUID from the response", created.ID)
	}
	if len(created.RoleIDs) != 1 || created.RoleIDs[0] != "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Fatalf("RoleIDs = %v, want the attached role", created.RoleIDs)
	}

	var sent map[string]any
	if err := json.Unmarshal(requests()[0].Body, &sent); err != nil {
		t.Fatalf("request body: %v", err)
	}
	ids, ok := sent["role_ids"].([]any)
	if !ok || len(ids) != 1 || ids[0] != "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Fatalf("body role_ids = %v, want the requested id verbatim", sent["role_ids"])
	}
}

func TestCreateAPIKeyOmitsRoleIDsWhenUnset(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"id":"x","key_id":"tk_a1","api_key":"s","role_ids":[]},"meta":{"request_id":"req_1"}}`)
	})
	if _, err := c.APIKeys.Create(context.Background(), CreateAPIKeyInput{Name: "plain"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(requests()[0].Body, &sent); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if _, present := sent["role_ids"]; present {
		t.Fatalf("body = %v, want role_ids omitted entirely when unset", sent)
	}
}

func TestPrivilegeEscalationSurfacesTypeAndOffendingGrant(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, `{"error":{"type":"privilege_escalation","message":"This API key cannot grant a permission it does not itself hold. Refused grant from role \"Key — Infrastructure\": {\"resource_type\":\"vault\",\"actions\":[\"create\"],\"effect\":\"allow\"} — no rule in your own policy set grants it.","request_id":"req_1"}}`)
	})
	_, err := c.APIKeys.Create(context.Background(), CreateAPIKeyInput{
		Name:    "x",
		RoleIDs: []string{"b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"},
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("StatusCode = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "privilege_escalation" {
		t.Fatalf("code = %q, want privilege_escalation", apiErr.Message)
	}
	// The offending grant must survive verbatim — the provider's §4.5 taxonomy
	// row quotes it back to the practitioner.
	if !contains(apiErr.Error(), `"resource_type":"vault"`) {
		t.Fatalf("error text = %q, want the refused grant verbatim", apiErr.Error())
	}
}

func TestRolesListSendsSubjectKindAndDecodesRows(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, pageEnvelope([]string{
			`{"id":"b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d","name":"Key — Infrastructure","description":null,"applies_to":["api_key"],"is_default":false,"seeded":true}`,
		}, 1, 1, 20))
	})

	page, err := c.Roles.List(context.Background(), &ListRolesParams{SubjectKind: "api_key"})
	if err != nil {
		t.Fatalf("Roles.List: %v", err)
	}
	if len(page.Data) != 1 || !page.Data[0].Seeded || page.Data[0].AppliesTo[0] != "api_key" {
		t.Fatalf("page.Data = %+v, want the seeded api_key role decoded", page.Data)
	}
	if page.Data[0].Description != nil {
		t.Fatalf("Description = %v, want nil for a null description", page.Data[0].Description)
	}
	req := requests()[0]
	if req.Path != "/v1/roles" {
		t.Fatalf("path = %q, want /v1/roles", req.Path)
	}
	if req.Query["subject_kind"] != "api_key" {
		t.Fatalf("query = %v, want subject_kind=api_key", req.Query)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
