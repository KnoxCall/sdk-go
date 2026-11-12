package knoxcall

// ExchangeToken — credential-less RFC 8693 exchange against POST /v1/oauth/token
// (AIGW-26).
//
// Three behaviours a caller gets wrong, all asserted here:
//  1. The response is a BARE OAuth body, not the {data, meta} envelope.
//  2. Resource is only sent when non-nil — sending it EMPTY is a refusal, not
//     "no resource", because dropping it silently would mint an UNCONFINED
//     token while the caller believes it is audience-restricted.
//  3. The path is /v1/oauth/token, NOT the root-host /oauth/token that mints
//     management tokens.
//  4. The HOST is the tenant data plane. Verified against a running server
//     2026-08-25: the same request answers 400 invalid_grant on
//     acme.knoxcall.com and 401 on api.knoxcall.com, so there is no default.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const exchangeOK = `{"access_token":"kc_live_agt_deadbeef","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900,"scope":"{\"providers\":[\"anthropic\"]}"}`

// exchangeRoundTrip lets the host-derivation tests observe the URL the SDK
// builds WITHOUT a real listener — the whole point is that the host is
// https://acme.knoxcall.com, which nothing local can serve.
type exchangeRoundTrip func(*http.Request) (*http.Response, error)

func (f exchangeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func exchangeJSON(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type capturedExchange struct {
	path   string
	body   map[string]any
	header http.Header
}

func exchangeServer(t *testing.T, status int, response string) (*httptest.Server, *capturedExchange) {
	t.Helper()
	seen := &capturedExchange{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.path = r.URL.Path
		seen.header = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seen.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestExchangeTokenPostsTheGrantAndReturnsTheBareBody(t *testing.T) {
	srv, seen := exchangeServer(t, 200, exchangeOK)

	res, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "header.payload.sig"},
		&ExchangeTokenOptions{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}

	if seen.path != "/v1/oauth/token" {
		t.Fatalf("path = %q; want /v1/oauth/token (NOT the root-host /oauth/token)", seen.path)
	}
	if seen.body["grant_type"] != TokenExchangeGrant {
		t.Fatalf("grant_type = %v; want %s", seen.body["grant_type"], TokenExchangeGrant)
	}
	if seen.body["subject_token_type"] != IDTokenType {
		t.Fatalf("subject_token_type = %v; want %s", seen.body["subject_token_type"], IDTokenType)
	}
	if seen.body["audience"] != KnoxCallAudience {
		t.Fatalf("audience = %v; want %s", seen.body["audience"], KnoxCallAudience)
	}
	// The subject token IS the credential — nothing else is sent.
	if got := seen.header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization header = %q; want none", got)
	}
	if res.AccessToken != "kc_live_agt_deadbeef" || res.ExpiresIn != 900 {
		t.Fatalf("response = %+v; want the bare OAuth body unwrapped", res)
	}
}

func TestExchangeTokenOmitsResourceUnlessSet(t *testing.T) {
	srv, seen := exchangeServer(t, 200, exchangeOK)
	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: srv.URL}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if _, present := seen.body["resource"]; present {
		t.Fatalf("resource was sent without being asked for: %v", seen.body["resource"])
	}
}

func TestExchangeTokenForwardsAnEmptyResourceVerbatim(t *testing.T) {
	// It must reach the server and be refused invalid_target. Treating "" as
	// absent would hand back an UNCONFINED agent token to a caller who asked
	// for a confined one — which is why Resource is a *string.
	srv, seen := exchangeServer(t, 200, exchangeOK)
	empty := ""
	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c", Resource: &empty},
		&ExchangeTokenOptions{BaseURL: srv.URL}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	v, present := seen.body["resource"]
	if !present || v != "" {
		t.Fatalf("resource = %v (present=%v); want an empty string sent through", v, present)
	}
}

func TestExchangeTokenSurfacesTheRFC6749Code(t *testing.T) {
	srv, _ := exchangeServer(t, 400,
		`{"error":"invalid_grant","error_description":"No tenant bindings registered for issuer https://x"}`)

	_, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: srv.URL})

	var te *TokenExchangeError
	if !errors.As(err, &te) {
		t.Fatalf("err = %#v; want *TokenExchangeError", err)
	}
	if te.StatusCode != 400 || te.Message != "invalid_grant" {
		t.Fatalf("err = %+v; want 400 invalid_grant", te)
	}
	var api *APIError
	if !errors.As(err, &api) {
		t.Fatalf("*TokenExchangeError must unwrap to *APIError")
	}
}

func TestExchangeTokenRejectsA200WithNoAccessToken(t *testing.T) {
	srv, _ := exchangeServer(t, 200, `{"token_type":"Bearer"}`)
	_, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: srv.URL})
	var te *TokenExchangeError
	if !errors.As(err, &te) || te.Message != "token_exchange_failed" {
		t.Fatalf("err = %#v; want token_exchange_failed", err)
	}
}

func TestExchangeTokenDoesNotMaskANonJSONErrorPage(t *testing.T) {
	srv, _ := exchangeServer(t, 502, `<html>502</html>`)
	_, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: srv.URL})
	var te *TokenExchangeError
	if !errors.As(err, &te) || te.StatusCode != 502 {
		t.Fatalf("err = %#v; want a 502 TokenExchangeError", err)
	}
}

func TestExchangeTokenStripsATrailingSlashFromBaseURL(t *testing.T) {
	srv, seen := exchangeServer(t, 200, exchangeOK)
	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: srv.URL + "/"}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if seen.path != "/v1/oauth/token" {
		t.Fatalf("path = %q; want /v1/oauth/token", seen.path)
	}
}

func TestExchangeTokenDerivesTheTenantDataPlaneHost(t *testing.T) {
	var seen string
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return exchangeJSON(200, exchangeOK), nil
	})}

	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{Tenant: "acme", HTTPClient: hc}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if seen != "https://acme.knoxcall.com/v1/oauth/token" {
		t.Fatalf("url = %q; want the tenant data-plane host", seen)
	}
}

func TestExchangeTokenDerivesTheSandboxDataPlaneHost(t *testing.T) {
	var seen string
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		seen = r.URL.String()
		return exchangeJSON(200, exchangeOK), nil
	})}

	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{Tenant: "acme", Sandbox: true, HTTPClient: hc}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if seen != "https://sandbox-acme.knoxcall.com/v1/oauth/token" {
		t.Fatalf("url = %q; want the sandbox data-plane host", seen)
	}
}

func TestExchangeTokenRefusesToGuessAHost(t *testing.T) {
	// api.knoxcall.com answers 401 for this request — the endpoint is not served
	// there. A default would turn "wrong host" into "your CI token was rejected",
	// the hardest possible thing to debug.
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("no request should be sent, got %s", r.URL)
		return nil, nil
	})}

	_, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{HTTPClient: hc})
	var boot *BootstrapError
	if !errors.As(err, &boot) {
		t.Fatalf("err = %#v; want *BootstrapError", err)
	}
	if !strings.Contains(boot.Message, "Tenant") {
		t.Fatalf("message = %q; want it to name the missing Tenant", boot.Message)
	}
}

func TestExchangeTokenRefusesANonDNSLabelTenant(t *testing.T) {
	// The slug becomes the host the workload OIDC token is sent to.
	hc := &http.Client{Transport: exchangeRoundTrip(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("no request should be sent, got %s", r.URL)
		return nil, nil
	})}

	for _, bad := range []string{"evil.com#", "a b", "-lead", "trail-"} {
		_, err := ExchangeToken(context.Background(),
			ExchangeTokenInput{SubjectToken: "a.b.c"},
			&ExchangeTokenOptions{Tenant: bad, HTTPClient: hc})
		var boot *BootstrapError
		if !errors.As(err, &boot) {
			t.Errorf("slug %q was accepted (err = %#v)", bad, err)
		}
	}
}

func TestExchangeTokenWarnsOnAPlaintextHop(t *testing.T) {
	// The subject token IS a credential, so a plaintext hop leaks it. PARITY §15
	// already warns when a CLIENT is constructed against plaintext http; this
	// function deliberately constructs no client, so the control had to be added
	// on this path too or it would exist on one and be absent on the parallel one.
	resetWarnedForTests()
	var sink strings.Builder
	old := warnWriter
	warnWriter = &sink
	defer func() { warnWriter = old }()

	hc := &http.Client{Transport: exchangeRoundTrip(func(*http.Request) (*http.Response, error) {
		return exchangeJSON(200, exchangeOK), nil
	})}
	if _, err := ExchangeToken(context.Background(),
		ExchangeTokenInput{SubjectToken: "a.b.c"},
		&ExchangeTokenOptions{BaseURL: "http://evil.example", HTTPClient: hc}); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if !strings.Contains(sink.String(), "plaintext HTTP") {
		t.Fatalf("warnings = %q; want the plaintext-transport warning", sink.String())
	}
}

func TestExchangeTokenDoesNotWarnForHTTPSOrLoopback(t *testing.T) {
	// The acceptance harness and local dev both use http://127.0.0.1, so a
	// refusal here would be wrong and a warning there would be noise.
	resetWarnedForTests()
	var sink strings.Builder
	old := warnWriter
	warnWriter = &sink
	defer func() { warnWriter = old }()

	hc := &http.Client{Transport: exchangeRoundTrip(func(*http.Request) (*http.Response, error) {
		return exchangeJSON(200, exchangeOK), nil
	})}
	for _, base := range []string{"https://acme.test", "http://127.0.0.1:3000", "http://localhost:3000"} {
		if _, err := ExchangeToken(context.Background(),
			ExchangeTokenInput{SubjectToken: "a.b.c"},
			&ExchangeTokenOptions{BaseURL: base, HTTPClient: hc}); err != nil {
			t.Fatalf("ExchangeToken(%s): %v", base, err)
		}
	}
	if strings.Contains(sink.String(), "plaintext HTTP") {
		t.Fatalf("warnings = %q; want none for https/loopback", sink.String())
	}
}
