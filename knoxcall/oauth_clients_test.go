package knoxcall

import (
	"encoding/json"
	"reflect"
	"testing"
)

// sdk/PARITY.md §22: the registered-key policy fields on PATCH. The three
// nullable bounds have THREE states and each must reach the wire as itself —
// nil omits the key, SetInt sets it, ClearInt sends JSON null (which clears the
// bound server-side). A plain *int could not spell the third.
func TestUpdateOAuthClientInputRegisteredKeyPolicyWire(t *testing.T) {
	on := true
	two := 2
	in := UpdateOAuthClientInput{
		RequireRegisteredKey:  &on,
		MaxRegisteredKeys:     &two,
		AccessTokenTTLSeconds: SetInt(600),
		MaxOutstandingTokens:  ClearInt(),
		// MintRatePerMinute left nil: must be OMITTED, never sent as null.
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// allowed_scopes / redirect_uris carry no omitempty by design (see the
	// struct comment) and marshal as null, which the server treats as absent.
	delete(got, "allowed_scopes")
	delete(got, "redirect_uris")
	want := map[string]any{
		"require_registered_key":   true,
		"max_registered_keys":      float64(2),
		"access_token_ttl_seconds": float64(600),
		"max_outstanding_tokens":   nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire body = %s, want %v", raw, want)
	}
	if _, present := got["mint_rate_per_minute"]; present {
		t.Fatalf("an unset nullable bound was sent (%s) — null CLEARS it server-side", raw)
	}
}
