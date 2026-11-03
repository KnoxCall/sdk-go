package knoxcall

// Coverage for the 2026-08 Go SDK additions (../../PARITY.md §11/§5):
//   - typed OAuth2 + certificate secret creation (SecretsResource.CreateOAuth2 /
//     CreateCertificate), which the value-only CreateSecretInput cannot express;
//   - the lazy range-over-func list iterator (helpers.iterate → the Iterate*
//     methods), which streams one item at a time instead of buffering every
//     page the way ListAll does;
//   - the error mapper's X-Request-Id header fallback for the correlation id.
// Every mock returns the REAL server envelope — {data, meta} exactly as
// src/client-api/helpers.ts builds it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// ── Typed OAuth2 + certificate secret creation ────────────────────────────────

func TestSecretsCreateOAuth2(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, `{"data":{
			"id":"sec_o1","name":"stripe-oauth","shortcode_name":"STRIPE_OAUTH",
			"base_environment":"production","secret_type":"oauth2","collection_id":null,
			"created_at":"2026-01-01T00:00:00Z","expires_at":null,
			"strict_expiry_enforcement":false,"environment_count":1,
			"provider":"custom","redirect_uri":"https://app.knoxcall.com/oauth/callback",
			"connection_status":"disconnected","mtls_certificate_id":null
		},"meta":{"request_id":"req_o"}}`)
	})

	secret, err := c.Secrets.CreateOAuth2(context.Background(), CreateOAuth2SecretInput{
		Name:         "stripe-oauth",
		Provider:     "custom",
		ClientID:     "cid_123",
		ClientSecret: "csecret_456",
		Scopes:       []string{"read", "write"},
		TokenURL:     "https://provider.example/token",
	})
	if err != nil {
		t.Fatalf("CreateOAuth2: %v", err)
	}
	if secret.ID != "sec_o1" || secret.SecretType != "oauth2" || secret.Provider != "custom" || secret.ConnectionStatus != "disconnected" {
		t.Fatalf("CreateOAuth2 = %+v, want the oauth2 create response unwrapped", secret)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/secrets/oauth2" {
		t.Fatalf("request = %s %s, want POST /v1/secrets/oauth2", req.Method, req.Path)
	}
	// Mutations carry a stable idempotency key, exactly as Create does.
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Fatalf("CreateOAuth2 missing idempotency key — mutations must carry one")
	}
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["name"] != "stripe-oauth" || body["provider"] != "custom" || body["client_id"] != "cid_123" || body["client_secret"] != "csecret_456" || body["token_url"] != "https://provider.example/token" {
		t.Fatalf("body = %v, want the snake_case oauth2 fields", body)
	}
	scopes, _ := body["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "read" {
		t.Fatalf("body scopes = %v, want [read write]", body["scopes"])
	}
	// Unset optionals must be omitted (omitempty), never sent as empty strings.
	for _, k := range []string{"mtls_certificate_id", "username", "password", "auth_url", "grant_type", "collection_id"} {
		if _, present := body[k]; present {
			t.Errorf("body[%q] present, want the unset optional omitted", k)
		}
	}
}

func TestSecretsCreateCertificate(t *testing.T) {
	c, requests := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 201, `{"data":{
			"id":"sec_c1","name":"mtls-cert","shortcode_name":"MTLS_CERT",
			"base_environment":"production","secret_type":"certificate","collection_id":null,
			"created_at":"2026-01-01T00:00:00Z","expires_at":null,
			"strict_expiry_enforcement":false,"environment_count":1,
			"certificate_type":"pem",
			"metadata":{"subject":"CN=example","issuer":"CN=ca","expires_at":"2027-01-01T00:00:00Z","has_private_key":true}
		},"meta":{"request_id":"req_c"}}`)
	})

	secret, err := c.Secrets.CreateCertificate(context.Background(), CreateCertificateSecretInput{
		Name:               "mtls-cert",
		CertificateContent: "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
		PrivateKey:         "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	if secret.ID != "sec_c1" || secret.SecretType != "certificate" || secret.CertificateType != "pem" {
		t.Fatalf("CreateCertificate = %+v, want the certificate create response unwrapped", secret)
	}
	if secret.CertificateMetadata == nil || !secret.CertificateMetadata.HasPrivateKey {
		t.Fatalf("CreateCertificate metadata = %+v, want the parsed-cert summary", secret.CertificateMetadata)
	}

	req := requests()[0]
	if req.Method != http.MethodPost || req.Path != "/v1/secrets/certificate" {
		t.Fatalf("request = %s %s, want POST /v1/secrets/certificate", req.Method, req.Path)
	}
	if req.Header.Get("X-Idempotency-Key") == "" {
		t.Fatalf("CreateCertificate missing idempotency key — mutations must carry one")
	}
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["name"] != "mtls-cert" || !strings.Contains(body["certificate_content"].(string), "BEGIN CERTIFICATE") || !strings.Contains(body["private_key"].(string), "BEGIN PRIVATE KEY") {
		t.Fatalf("body = %v, want the snake_case certificate fields", body)
	}
	// certificate_type defaults server-side, so an unset one is omitted here.
	for _, k := range []string{"passphrase", "certificate_type", "collection_id"} {
		if _, present := body[k]; present {
			t.Errorf("body[%q] present, want the unset optional omitted", k)
		}
	}
}

// ── Lazy list iterator (range-over-func) ──────────────────────────────────────

// secretPageHandler serves `total` string secrets paginated at `perPage`/page.
func secretPageHandler(total, perPage int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		start := (page - 1) * perPage
		var rows []string
		for i := start; i < start+perPage && i < total; i++ {
			rows = append(rows, fmt.Sprintf(`{"id":"sec_%d","name":"s%d","secret_type":"string"}`, i, i))
		}
		writeJSON(w, 200, pageEnvelope(rows, total, page, perPage))
	}
}

func TestIterateStreamsEveryPage(t *testing.T) {
	// 5 secrets at 2/page → pages 1..3, mirroring TestListAllWalksEveryPage but
	// consumed one item at a time via range-over-func.
	c, requests := envelopeServer(t, secretPageHandler(5, 2))

	var ids []string
	for s, err := range c.Secrets.Iterate(context.Background(), &ListParams{PerPage: 2}) {
		if err != nil {
			t.Fatalf("Iterate yielded error: %v", err)
		}
		ids = append(ids, s.ID)
	}
	if len(ids) != 5 || ids[0] != "sec_0" || ids[4] != "sec_4" {
		t.Fatalf("Iterate yielded %v, want all 5 ids across 3 pages", ids)
	}
	if n := len(requests()); n != 3 {
		t.Fatalf("requests = %d, want exactly 3 (one per page)", n)
	}
}

func TestIterateIsLazyAndStopsOnBreak(t *testing.T) {
	// 6 secrets at 2/page → pages 1..3 are available, but the caller breaks after
	// the first item. Laziness means page 2 and 3 are never fetched.
	c, requests := envelopeServer(t, secretPageHandler(6, 2))

	seen := 0
	for _, err := range c.Secrets.Iterate(context.Background(), &ListParams{PerPage: 2}) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		seen++
		break
	}
	if seen != 1 {
		t.Fatalf("consumed %d items, want exactly 1 before break", seen)
	}
	if n := len(requests()); n != 1 {
		t.Fatalf("requests = %d, want exactly 1 — later pages must not be fetched after an early break", n)
	}
}

func TestIterateSurfacesPerPageError(t *testing.T) {
	// Page 1 is a good page of 2; page 2 fails with a typed 404. The iterator
	// must yield the two good rows, then surface the error as the 2nd range value.
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		if page >= 2 {
			writeJSON(w, 404, `{"error":{"type":"not_found","message":"gone","request_id":"req_e"}}`)
			return
		}
		writeJSON(w, 200, pageEnvelope([]string{
			`{"id":"sec_0","name":"s0","secret_type":"string"}`,
			`{"id":"sec_1","name":"s1","secret_type":"string"}`,
		}, 5, 1, 2))
	})

	good := 0
	var gotErr error
	for s, err := range c.Secrets.Iterate(context.Background(), &ListParams{PerPage: 2}) {
		if err != nil {
			gotErr = err
			break
		}
		_ = s
		good++
	}
	if good != 2 {
		t.Fatalf("streamed %d good items before the error, want 2", good)
	}
	var nf *NotFoundError
	if !errors.As(gotErr, &nf) {
		t.Fatalf("iterator error = %v (%T), want a typed *NotFoundError surfaced as the 2nd range value", gotErr, gotErr)
	}
}

// TestIterateWiredForAuditLogsAndVaultTokens exercises the two endpoints the
// task calls out by name — both stream lazily via the same generic helper.
func TestIterateWiredForAuditLogsAndVaultTokens(t *testing.T) {
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		total, perPage := 3, 2
		start := (page - 1) * perPage
		var rows []string
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/audit-logs"):
			for i := start; i < start+perPage && i < total; i++ {
				rows = append(rows, fmt.Sprintf(`{"id":"al_%d","action":"secret.create","resource_type":"secret","resource_id":null,"details":{},"ip_address":null,"created_at":"2026-01-01T00:00:00Z"}`, i))
			}
		default: // /v1/vaults/<name>/tokens
			for i := start; i < start+perPage && i < total; i++ {
				rows = append(rows, fmt.Sprintf(`{"id":"vt_%d","token":"tok_%d","expires_at":null,"created_at":"2026-01-01T00:00:00Z"}`, i, i))
			}
		}
		writeJSON(w, 200, pageEnvelope(rows, total, page, perPage))
	})

	logs := 0
	for l, err := range c.AuditLogs.Iterate(context.Background(), &AuditLogParams{PerPage: 2}) {
		if err != nil {
			t.Fatalf("audit-log Iterate: %v", err)
		}
		if l.Action != "secret.create" {
			t.Fatalf("audit row = %+v, want the row decoded", l)
		}
		logs++
	}
	if logs != 3 {
		t.Fatalf("audit-log Iterate streamed %d, want 3 across 2 pages", logs)
	}

	toks := 0
	for tk, err := range c.Vaults.IterateTokens(context.Background(), "cards-vault", &ListParams{PerPage: 2}) {
		if err != nil {
			t.Fatalf("vault-token Iterate: %v", err)
		}
		if tk.ID == "" {
			t.Fatalf("token row = %+v, want the row decoded", tk)
		}
		toks++
	}
	if toks != 3 {
		t.Fatalf("vault-token Iterate streamed %d, want 3 across 2 pages", toks)
	}
}

// ── Error correlation-id: X-Request-Id header fallback ─────────────────────────

func TestErrorRequestIDFallsBackToHeader(t *testing.T) {
	// The error body omits request_id; the API now always emits it as a response
	// header, and the error mapper must read it from there.
	c, _ := envelopeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req_hdr")
		writeJSON(w, 404, `{"error":{"type":"not_found","message":"gone"}}`)
	})
	_, err := c.Routes.Get(context.Background(), "r_missing")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("err = %v (%T), want *NotFoundError", err, err)
	}
	if nf.Message != "not_found" || nf.RequestID != "req_hdr" {
		t.Fatalf("error = %+v, want request_id read from the X-Request-Id header when the body omits it", nf.APIError)
	}
}
