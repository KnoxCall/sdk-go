package knoxcall

// Happy-path coverage for the 2026-07 resource additions (../../PARITY.md
// §11): route field-actions, portable encryption + capability tokens +
// sealing bundle, and the credential-less Signup function.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── Route field-actions ───────────────────────────────────────────────────────

func TestRouteFieldActionsCRUD(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, 200, `{"data":[{"id":"ra_1","route_id":"r_1","tenant_id":"t_1","direction":"request","action":"tokenize","selectors":["$.card.number"],"key_name":"cards-vault","data_role":null,"content_type":"application/json","sort_order":0,"enabled":true}],"meta":{"request_id":"req_1"}}`)
		case r.Method == http.MethodPost:
			writeJSON(w, 200, `{"data":{"id":"ra_2","route_id":"r_1","tenant_id":"t_1","direction":"response","action":"detokenize","selectors":["$.card.number"],"key_name":"cards-vault","data_role":null,"content_type":"application/json","sort_order":1,"enabled":true},"meta":{"request_id":"req_2"}}`)
		default:
			writeJSON(w, 200, `{"data":{"deleted":"ra_2"},"meta":{"request_id":"req_3"}}`)
		}
	})

	actions, err := c.Routes.ListActions(context.Background(), "r_1")
	if err != nil || len(actions) != 1 || actions[0].Action != "tokenize" || actions[0].Selectors[0] != "$.card.number" {
		t.Fatalf("ListActions = %+v, %v; want the typed bare array", actions, err)
	}

	created, err := c.Routes.CreateAction(context.Background(), "r_1", CreateRouteActionInput{
		Direction: "response", Action: "detokenize", Selectors: []string{"$.card.number"}, KeyName: "cards-vault",
	})
	if err != nil || created.ID != "ra_2" || created.Direction != "response" {
		t.Fatalf("CreateAction = %+v, %v; want the created action unwrapped", created, err)
	}

	deleted, err := c.Routes.DeleteAction(context.Background(), "r_1", "ra_2")
	if err != nil || deleted.Deleted != "ra_2" {
		t.Fatalf("DeleteAction = %+v, %v; want the action id echoed", deleted, err)
	}

	reqs := requests()
	wantPaths := []string{"/v1/routes/r_1/actions", "/v1/routes/r_1/actions", "/v1/routes/r_1/actions/ra_2"}
	for i, want := range wantPaths {
		if reqs[i].Path != want {
			t.Errorf("request %d path = %q, want %q", i, reqs[i].Path, want)
		}
	}
	var body map[string]any
	if err := json.Unmarshal(reqs[1].Body, &body); err != nil {
		t.Fatalf("unmarshal create body: %v", err)
	}
	if body["direction"] != "response" || body["action"] != "detokenize" || body["key_name"] != "cards-vault" {
		t.Fatalf("create body = %v, want the snake_case action fields", body)
	}
}

// ── Portable encryption ───────────────────────────────────────────────────────

func TestCryptoEncryptDataDecryptDataRoundTripShapes(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/encrypt" {
			writeJSON(w, 200, `{"data":{"ciphertext":{"card":"kc:1:enc:abc","name":"kc:1:enc:def"},"key":"default-ecdh","key_version":2},"meta":{"request_id":"req_1"}}`)
			return
		}
		writeJSON(w, 200, `{"data":{"plaintext":{"card":"4242424242424242","name":"Ada"}},"meta":{"request_id":"req_2"}}`)
	})

	enc, err := c.Crypto.EncryptData(context.Background(), map[string]string{"card": "4242424242424242", "name": "Ada"}, &EncryptDataOptions{Role: "pci"})
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if enc.Key != "default-ecdh" || enc.KeyVersion != 2 {
		t.Fatalf("enc = %+v, want key + key_version from the envelope", enc)
	}
	var encData map[string]string
	if err := json.Unmarshal(enc.Ciphertext, &encData); err != nil {
		t.Fatalf("decode enc.Ciphertext: %v", err)
	}
	if encData["card"] != "kc:1:enc:abc" {
		t.Fatalf("enc.Ciphertext = %v, want the structure-preserved kc: leaves", encData)
	}

	// Feed the ciphertext structure straight back — round-trip usability.
	dec, err := c.Crypto.DecryptData(context.Background(), json.RawMessage(enc.Ciphertext), nil)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	var decData map[string]string
	if err := json.Unmarshal(dec.Plaintext, &decData); err != nil {
		t.Fatalf("decode dec.Plaintext: %v", err)
	}
	if decData["card"] != "4242424242424242" {
		t.Fatalf("dec.Plaintext = %v, want the plaintext restored", decData)
	}

	reqs := requests()
	var encBody map[string]any
	_ = json.Unmarshal(reqs[0].Body, &encBody)
	if encBody["role"] != "pci" {
		t.Errorf("encrypt body = %v, want role forwarded", encBody)
	}
	if _, hasKey := encBody["key"]; hasKey {
		t.Errorf("encrypt body = %v, empty key must be omitted (zero-config default)", encBody)
	}
	var decBody map[string]any
	_ = json.Unmarshal(reqs[1].Body, &decBody)
	if _, hasRole := decBody["role"]; hasRole {
		t.Errorf("decrypt body = %v, nil opts must omit role", decBody)
	}
}

func TestCryptoInspect(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		// NOTE: this endpoint's key_ref really is camelCase.
		writeJSON(w, 200, `{"data":{"encrypted":true,"scheme":"kc","version":1,"datatype":"string","key_ref":{"tenantId":"t_1","appKeyId":"key_1","keyVersion":2},"fingerprint":"abcd1234"},"meta":{"request_id":"req_1"}}`)
	})
	res, err := c.Crypto.Inspect(context.Background(), "kc:1:enc:abc")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !res.Encrypted || res.Scheme != "kc" || res.KeyRef == nil || res.KeyRef.AppKeyID != "key_1" || res.KeyRef.KeyVersion != 2 {
		t.Fatalf("Inspect = %+v, want the camelCase key_ref decoded", res)
	}
}

func TestCryptoMintClientToken(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{"token":"cap_once","expires_at":"2026-07-02T01:00:00Z","action":"decrypt"},"meta":{"request_id":"req_1"}}`)
	})
	ttl := 120
	tok, err := c.Crypto.MintClientToken(context.Background(), MintClientTokenInput{Action: "decrypt", Data: "kc:1:enc:abc", TTLSeconds: &ttl})
	if err != nil || tok.Token != "cap_once" || tok.Action != "decrypt" {
		t.Fatalf("MintClientToken = %+v, %v; want the minted token", tok, err)
	}
	req := requests()[0]
	if req.Path != "/v1/client-tokens" || req.Method != http.MethodPost {
		t.Fatalf("request = %s %s, want POST /v1/client-tokens", req.Method, req.Path)
	}
	var body map[string]any
	_ = json.Unmarshal(req.Body, &body)
	if body["data"] != "kc:1:enc:abc" || body["ttl_seconds"] != float64(120) {
		t.Fatalf("body = %v, want the bound payload + ttl", body)
	}
}

func TestCryptoGetSealingBundle(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		// NOTE: unlike inspect, the sealing bundle's key_ref is snake_case.
		writeJSON(w, 200, `{"data":{"public_key_raw":"BPubKeyBase64Url","key_ref":{"tenant_id":"t_1","app_key_id":"key_1","key_version":2}},"meta":{"request_id":"req_1"}}`)
	})
	bundle, err := c.Crypto.GetSealingBundle(context.Background(), "default-ecdh")
	if err != nil {
		t.Fatalf("GetSealingBundle: %v", err)
	}
	if bundle.PublicKeyRaw != "BPubKeyBase64Url" || bundle.KeyRef.AppKeyID != "key_1" || bundle.KeyRef.KeyVersion != 2 {
		t.Fatalf("bundle = %+v, want the snake_case key_ref decoded", bundle)
	}
	req := requests()[0]
	if req.Path != "/v1/encrypt/sealing-bundle" || req.Query["key"] != "default-ecdh" {
		t.Fatalf("request = %s?key=%s, want GET /v1/encrypt/sealing-bundle?key=default-ecdh", req.Path, req.Query["key"])
	}
}

// ── Signup ────────────────────────────────────────────────────────────────────

// Rewritten 2026-08-28 for the F-25 contract (wave-2 row 2-561): signup no
// longer has a 201 and never returns a credential. sdk/PARITY.md §11 requires
// all three success shapes here — the signup 202, the claim's pending 202
// (a SUCCESS, not an error) and the claim's ready 200.

func TestSignupReturnsAClaimHandleAndNoCredential(t *testing.T) {
	var seenAuth, seenPath string
	var seenBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenPath = r.URL.Path
		seenBody, _ = io.ReadAll(r.Body)
		writeJSON(w, 202, `{"data":{
			"status":"pending",
			"claim_handle":"sck_Yy3n0Rz1qF8mKpX2sVb7dH9tLwQ4eJ6uA1cN5gZ8kT0",
			"claim_path":"/v1/signup/claim",
			"poll_after_seconds":5,
			"expires_at":"2026-08-29T09:14:22.117Z",
			"message":"If this email can be registered, a sign-in link has been sent.",
			"documentation":"https://docs.knoxcall.com"
		},"meta":{"request_id":"req_1"}}`)
	}))
	defer ts.Close()

	res, err := Signup(context.Background(), SignupInput{Email: "dev@example.com", TenantName: "Acme Inc"}, &SignupOptions{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if seenAuth != "" {
		t.Fatalf("Authorization = %q, signup must be credential-less", seenAuth)
	}
	if seenPath != "/v1/signup" {
		t.Fatalf("path = %q, want /v1/signup", seenPath)
	}
	var body map[string]any
	_ = json.Unmarshal(seenBody, &body)
	if body["email"] != "dev@example.com" || body["tenant_name"] != "Acme Inc" {
		t.Fatalf("body = %v, want the snake_case signup fields", body)
	}
	if res.Status != "pending" || res.ClaimHandle == "" {
		t.Fatalf("res = %+v, want a pending status and a claim handle", res)
	}
	if res.PollAfterSeconds != 5 || res.ClaimPath != "/v1/signup/claim" {
		t.Fatalf("res = %+v, want the poll instructions decoded", res)
	}
	// The contract row 2-561 exists to enforce: the reply carries a handle,
	// which is NOT key material — no `tk_` value reaches the caller here.
	if len(res.ClaimHandle) < 5 || res.ClaimHandle[:4] != "sck_" {
		t.Fatalf("res.ClaimHandle = %q, want an sck_-prefixed handle", res.ClaimHandle)
	}
}

func TestClaimSignupPendingIsASuccess(t *testing.T) {
	var seenPath string
	var seenBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenBody, _ = io.ReadAll(r.Body)
		writeJSON(w, 202, `{"data":{
			"status":"pending",
			"message":"Not ready yet.",
			"poll_after_seconds":5,
			"expires_at":"2026-08-29T09:14:22.117Z"
		},"meta":{"request_id":"req_1"}}`)
	}))
	defer ts.Close()

	res, err := ClaimSignup(context.Background(), "sck_handle", &SignupOptions{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("ClaimSignup: %v — a pending poll is a SUCCESS, not an error", err)
	}
	if seenPath != "/v1/signup/claim" {
		t.Fatalf("path = %q, want /v1/signup/claim", seenPath)
	}
	var body map[string]any
	_ = json.Unmarshal(seenBody, &body)
	if body["claim_handle"] != "sck_handle" {
		t.Fatalf("body = %v, want the handle sent as claim_handle", body)
	}
	if res.Status != "pending" || res.Starter != nil {
		t.Fatalf("res = %+v, want pending with no starter kit", res)
	}
}

func TestClaimSignupReadyCarriesTheOneTimeKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, `{"data":{
			"status":"ready",
			"tenant":{"id":"t_1","slug":"acme","name":"Acme Inc","region":"us","plan":"free"},
			"starter":{
				"route":{"id":"r_1","name":"getting-started","target_base_url":"https://httpbin.org"},
				"api_key":{"id":"k_1","key_id":"key_abc","api_key":"tk_test_once","key_prefix":"tk_test_","key_type":"test"},
				"sandbox_host":"sandbox-acme.knoxcall.com",
				"curl":"curl https://sandbox-acme.knoxcall.com/"
			},
			"sandbox":{"management_api":"https://sandbox.knoxcall.com/v1","proxy_host":"sandbox-acme.knoxcall.com","note":"test mode"},
			"documentation":"https://docs.knoxcall.com"
		},"meta":{"request_id":"req_1"}}`)
	}))
	defer ts.Close()

	res, err := ClaimSignup(context.Background(), "sck_handle", &SignupOptions{BaseURL: ts.URL})
	if err != nil {
		t.Fatalf("ClaimSignup: %v", err)
	}
	if res.Status != "ready" {
		t.Fatalf("res.Status = %q, want ready", res.Status)
	}
	if res.Tenant == nil || res.Tenant.Slug != "acme" {
		t.Fatalf("res.Tenant = %+v, want the tenant decoded", res.Tenant)
	}
	if res.Starter == nil || res.Starter.APIKey.APIKey != "tk_test_once" || res.Starter.APIKey.KeyType != "test" {
		t.Fatalf("res.Starter = %+v, want the once-only starter key", res.Starter)
	}
	if res.Starter.Route == nil || res.Starter.Route.Name != "getting-started" {
		t.Fatalf("res.Starter.Route = %+v, want the seeded demo route", res.Starter.Route)
	}
}

func TestClaimSignupAlreadyCollectedIsTypedSignupError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 409, `{"error":{"type":"claim_already_collected","message":"already collected","request_id":"req_e"}}`)
	}))
	defer ts.Close()

	_, err := ClaimSignup(context.Background(), "sck_handle", &SignupOptions{BaseURL: ts.URL})
	var se *SignupError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *SignupError", err, err)
	}
	if se.StatusCode != 409 || se.Message != "claim_already_collected" {
		t.Fatalf("SignupError = %+v, want status 409 + type claim_already_collected", se.APIError)
	}
}

func TestSignupFailureIsTypedSignupError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 409, `{"error":{"type":"slug_taken","message":"Tenant slug 'acme' is already taken.","request_id":"req_e"}}`)
	}))
	defer ts.Close()

	_, err := Signup(context.Background(), SignupInput{Email: "dev@example.com", TenantName: "Acme Inc", TenantSlug: "acme"}, &SignupOptions{BaseURL: ts.URL})
	var se *SignupError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *SignupError", err, err)
	}
	if se.StatusCode != 409 || se.Message != "slug_taken" {
		t.Fatalf("SignupError = %+v, want status 409 + type slug_taken", se.APIError)
	}
	// Part of the SDK's error hierarchy: unwraps to *APIError.
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 409 {
		t.Fatalf("SignupError must unwrap to *APIError, got %v", err)
	}
}
