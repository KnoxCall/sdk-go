package main

// CLI tests — the `knoxcall ai` CONTROL plane (AIGW-162): gateways, agents,
// create-agent, mint, usage.
//
// These mirror sdk/knoxcall-node/test/cli-ai.test.ts's
// `knoxcall ai — control-plane sub-commands` block assertion for assertion,
// because PARITY §13's premise is that `knoxcall` has the SAME surface
// whichever SDK put it on your PATH: every sub-command parses its OWN flag
// table, ids are flags and never positionals, no flag can put a provider key in
// argv, and an agent with no upstream credential is refused HERE rather than at
// its first data-plane call.
//
// All HTTP is served by httptest and every credential lives under t.TempDir().

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

// ── fake management API ─────────────────────────────────────────────────────

// recordedRequest is one request the fake management API saw.
type recordedRequest struct {
	method string
	path   string
	query  url.Values
	body   map[string]any
}

// aiTestServer routes on "METHOD /path" and records everything. An UNROUTED
// request fails the test rather than 404ing quietly, so a command that calls
// the wrong endpoint says which one.
type aiTestServer struct {
	t        *testing.T
	mu       sync.Mutex
	seen     []recordedRequest
	handlers map[string]string
	srv      *httptest.Server
}

func newAiTestServer(t *testing.T) *aiTestServer {
	t.Helper()
	s := &aiTestServer{t: t, handlers: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedRequest{method: r.Method, path: r.URL.Path, query: r.URL.Query()}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.body)
		}
		s.mu.Lock()
		s.seen = append(s.seen, rec)
		body, routed := s.handlers[r.Method+" "+r.URL.Path]
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if !routed {
			t.Errorf("unrouted request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"unrouted"}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// on registers the JSON body returned for "METHOD /path".
func (s *aiTestServer) on(route, body string) *aiTestServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[route] = body
	return s
}

func (s *aiTestServer) requests() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRequest(nil), s.seen...)
}

// find returns the first recorded request for "METHOD /path".
func (s *aiTestServer) find(t *testing.T, route string) recordedRequest {
	t.Helper()
	for _, r := range s.requests() {
		if r.method+" "+r.path == route {
			return r
		}
	}
	t.Fatalf("no %s was made; saw %v", route, s.requests())
	return recordedRequest{}
}

func (s *aiTestServer) called(route string) bool {
	for _, r := range s.requests() {
		if r.method+" "+r.path == route {
			return true
		}
	}
	return false
}

// aiLoggedInApp isolates the environment, writes a "default" profile pointing at
// the fake server, and returns an app with captured output. The control-plane
// sub-commands act as the SIGNED-IN TENANT, so without this they refuse.
func aiLoggedInApp(t *testing.T, s *aiTestServer) (*app, *testIO) {
	t.Helper()
	path := isolateEnv(t)
	record := map[string]any{
		"tenant":                  "acme",
		"base_url":                s.srv.URL,
		"client_id":               "kc_cli_real",
		"refresh_token":           "rt_x",
		"access_token":            "kc_stored",
		"access_token_expires_at": credfile.FormatExpiry(time.Now().Add(time.Hour)),
	}
	if err := credfile.WriteProfile(path, "default", record); err != nil {
		t.Fatalf("WriteProfile: %v", err)
	}
	return newTestApp(t)
}

// Canned envelopes. The server answers {data, meta} for lists and {data} for
// single resources, exactly as /v1 does.
const (
	oneGateway = `{"data":[{"id":"gw_1","tenant_id":"t_1","slug":"prod","name":"Production","status":"active",
	  "created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z"}],
	  "meta":{"total":1,"page":1,"per_page":100,"total_pages":1}}`

	noGateways = `{"data":[],"meta":{"total":0,"page":1,"per_page":100,"total_pages":1}}`

	twoGateways = `{"data":[
	  {"id":"gw_1","slug":"prod","name":"Production","status":"active"},
	  {"id":"gw_2","slug":"staging","name":"Staging","status":"active"}],
	  "meta":{"total":2,"page":1,"per_page":100,"total_pages":1}}`

	oneAgent = `{"data":[{"id":"ag_1","tenant_id":"t_1","gateway_id":"gw_1","name":"Copilot","slug":"copilot",
	  "agent_url":"https://acme.knoxcall.com/v1/ai/copilot","status":"active"}],
	  "meta":{"total":1,"page":1,"per_page":100,"total_pages":1}}`

	noSecrets = `{"data":[],"meta":{"total":0,"page":1,"per_page":100,"total_pages":1}}`

	createdAgent = `{"data":{"id":"ag_new","gateway_id":"gw_1","name":"Copilot","slug":"copilot",
	  "agent_url":"https://acme.knoxcall.com/v1/ai/copilot","status":"active"}}`

	mintedToken = `{"data":{"id":"tok_1","kind":"agent","prefix":"kc_live_agt_","token":"kc_live_agt_deadbeef",
	  "dpop_required":false,"expires_at":"2026-10-07T00:00:00Z"}}`

	usageRollup = `{"data":{"period_days":7,
	  "totals":{"requests":12,"input_tokens":3400,"output_tokens":900,"cost_usd":1.2345,"unpriced_requests":1},
	  "by_model":[{"provider":"anthropic","model":"claude-sonnet-5","requests":12,
	    "input_tokens":3400,"output_tokens":900,"cost_usd":1.2345,"unpriced_requests":1}]}}`
)

// ── parsing ─────────────────────────────────────────────────────────────────

func TestAiControlSubcommandsParseTheirOwnFlags(t *testing.T) {
	t.Run("gateways", func(t *testing.T) {
		s := newAiTestServer(t).on("GET /v1/ai-gateway/gateways", oneGateway)
		a, tio := aiLoggedInApp(t, s)
		if code := a.run(context.Background(), []string{"ai", "gateways"}); code != 0 {
			t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
		}
		if got := tio.out.String(); got != "gw_1  prod  Production\n" {
			t.Fatalf("stdout = %q; want `id  slug  name`", got)
		}
	})

	t.Run("agents prints id slug agent_url", func(t *testing.T) {
		// agent_url is on every projection since AIGW-161, so the list alone is
		// enough to point an SDK at an existing agent.
		s := newAiTestServer(t).on("GET /v1/ai-gateway/gateways/gw_1/agents", oneAgent)
		a, tio := aiLoggedInApp(t, s)
		if code := a.run(context.Background(), []string{"ai", "agents", "--gateway", "gw_1"}); code != 0 {
			t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
		}
		want := "ag_1  copilot  https://acme.knoxcall.com/v1/ai/copilot\n"
		if got := tio.out.String(); got != want {
			t.Fatalf("stdout = %q; want %q", got, want)
		}
	})

	t.Run("create-agent", func(t *testing.T) {
		s := newAiTestServer(t).
			on("GET /v1/ai-gateway/gateways", oneGateway).
			on("POST /v1/ai-gateway/gateways/gw_1/agents", createdAgent)
		a, tio := aiLoggedInApp(t, s)
		code := a.run(context.Background(), []string{
			"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
			"--secret", "sec_1", "--gateway", "prod", "--model", "claude-sonnet-5",
			"--upstream", "https://api.anthropic.com", "--name", "Copilot",
		})
		if code != 0 {
			t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
		}
		body := s.find(t, "POST /v1/ai-gateway/gateways/gw_1/agents").body
		for field, want := range map[string]any{
			"slug":               "copilot",
			"name":               "Copilot",
			"provider":           "anthropic",
			"upstream_secret_id": "sec_1",
			"default_model":      "claude-sonnet-5",
			"upstream":           "https://api.anthropic.com",
		} {
			if body[field] != want {
				t.Errorf("body[%q] = %v; want %v", field, body[field], want)
			}
		}
	})

	t.Run("mint", func(t *testing.T) {
		s := newAiTestServer(t).on("POST /v1/ai-gateway/agents/ag_1/tokens", mintedToken)
		a, tio := aiLoggedInApp(t, s)
		code := a.run(context.Background(), []string{
			"ai", "mint", "--agent", "ag_1", "--kind", "read", "--name", "ci",
		})
		if code != 0 {
			t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
		}
		body := s.find(t, "POST /v1/ai-gateway/agents/ag_1/tokens").body
		if body["kind"] != "read" || body["name"] != "ci" {
			t.Fatalf("body = %v; want kind=read name=ci", body)
		}
	})

	t.Run("usage", func(t *testing.T) {
		s := newAiTestServer(t).on("GET /v1/ai-gateway/usage", usageRollup)
		a, tio := aiLoggedInApp(t, s)
		code := a.run(context.Background(), []string{
			"ai", "usage", "--period", "7d", "--agent", "ag_1",
		})
		if code != 0 {
			t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
		}
		q := s.find(t, "GET /v1/ai-gateway/usage").query
		if q.Get("period") != "7d" || q.Get("agent_id") != "ag_1" {
			t.Fatalf("query = %v; want period=7d agent_id=ag_1", q)
		}
		out := tio.out.String()
		for _, want := range []string{
			"Usage — last 7 days (agent ag_1)",
			"requests:      12",
			"cost (USD):    1.2345",
			"anthropic/claude-sonnet-5  12 req  in 3400  out 900  $1.2345",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("stdout missing %q; got:\n%s", want, out)
			}
		}
	})

	t.Run("--profile / --base-url / --sandbox are accepted everywhere", func(t *testing.T) {
		// The three common flags are registered per sub-command, so a missing
		// one would be a usage error (exit 2) on exactly one of the five.
		for _, argv := range [][]string{
			{"ai", "gateways"},
			{"ai", "agents", "--gateway", "gw_1"},
			{"ai", "create-agent", "--slug", "s", "--provider", "p", "--secret", "sec_1"},
			{"ai", "mint", "--agent", "ag_1"},
			{"ai", "usage"},
		} {
			isolateEnv(t)
			a, tio := newTestApp(t)
			// No profile is written, so each must fail with "not logged in"
			// (exit 1) — NOT with an unknown-flag usage error (exit 2).
			full := append(append([]string{}, argv...), "--profile", "nope", "--base-url", "https://x.invalid", "--sandbox")
			if code := a.run(context.Background(), full); code != 1 {
				t.Fatalf("%v: exit = %d; want 1 (stderr: %s)", full, code, tio.err.String())
			}
			if !strings.Contains(tio.err.String(), "not logged in (profile 'nope')") {
				t.Fatalf("%v: stderr = %q", full, tio.err.String())
			}
		}
	})
}

func TestAiControlFlagTablesArePerSubcommand(t *testing.T) {
	// One flat table would accept `ai exchange --period 30d` and silently
	// ignore it, which is the opposite of what every other command does with an
	// unknown flag. Each of these is a flag that exists on a DIFFERENT ai
	// sub-command, so a shared table would let all four through.
	isolateEnv(t)
	for _, argv := range [][]string{
		{"ai", "exchange", "--period", "30d"},
		{"ai", "gateways", "--agent", "ag_1"},
		{"ai", "mint", "--provider", "anthropic"},
		{"ai", "usage", "--secret-from-env", "X"},
	} {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), argv); code != 2 {
			t.Errorf("%v: exit = %d; want 2 (stderr: %s)", argv, code, tio.err.String())
		}
	}
}

func TestAiControlHasNoFlagThatPutsAProviderKeyInArgv(t *testing.T) {
	// Same rule as the subject token: the key is read from the environment
	// named by --secret-from-env. This asserts the ABSENCE of --secret-value —
	// adding one later fails here rather than in someone's shell history, `ps`
	// output, or the CI log line that echoes the command.
	isolateEnv(t)
	a, tio := newTestApp(t)
	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "x", "--secret-value", "sk-ant-live",
	})
	if code != 2 {
		t.Fatalf("exit = %d; want 2 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "secret-value") {
		t.Fatalf("stderr = %q; want it to name the rejected flag", tio.err.String())
	}
}

func TestAiControlTakesIdsAsFlagsNeverPositionals(t *testing.T) {
	// Four of the five SDK CLIs hand-roll their parser and reject positionals
	// outright, so a positional id would be a surface that differs by language.
	// In Go it matters twice over: flag.Parse STOPS at the first non-flag, so a
	// tolerated positional would silently swallow every flag after it.
	isolateEnv(t)
	for _, argv := range [][]string{
		{"ai", "agents", "gw_1"},
		{"ai", "mint", "ag_1"},
		{"ai", "gateways", "extra"},
		{"ai", "create-agent", "copilot"},
		{"ai", "usage", "7d"},
		{"ai", "mint", "ag_1", "--agent", "ag_2"},
	} {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), argv); code != 2 {
			t.Errorf("%v: exit = %d; want 2 (stderr: %s)", argv, code, tio.err.String())
		}
		if !strings.Contains(tio.err.String(), "unrecognized arguments") {
			t.Errorf("%v: stderr = %q; want the positional refusal", argv, tio.err.String())
		}
	}
}

// ── required flags ──────────────────────────────────────────────────────────

func TestAiCreateAgentRefusesWithoutAnUpstreamCredential(t *testing.T) {
	// The API ACCEPTS this and stores an agent whose first data-plane call 502s
	// (AIGW-161). A command whose whole purpose is reaching a working call must
	// not be able to produce one. Note there is no server here at all: the
	// refusal lands before any HTTP, and before the credentials file is read.
	isolateEnv(t)
	a, tio := newTestApp(t)
	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
	})
	if code != 1 {
		t.Fatalf("exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	errOut := tio.err.String()
	if !strings.Contains(errOut, "--secret or --secret-from-env is required") {
		t.Errorf("stderr = %q; want the credential requirement", errOut)
	}
	if !strings.Contains(errOut, "502s on its first call") {
		t.Errorf("stderr = %q; want the 502 reason — it is why the flag is required", errOut)
	}
}

func TestAiCreateAgentRequiresProvider(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--secret", "sec_1",
	})
	if code != 1 {
		t.Fatalf("exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "--provider is required") {
		t.Fatalf("stderr = %q", tio.err.String())
	}
}

func TestAiControlRequiresAgentOnMintAndGatewayOnAgents(t *testing.T) {
	isolateEnv(t)

	a, tio := newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "mint"}); code != 1 {
		t.Fatalf("mint: exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "--agent is required") {
		t.Fatalf("mint: stderr = %q", tio.err.String())
	}

	a, tio = newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "agents"}); code != 1 {
		t.Fatalf("agents: exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "--gateway is required") {
		t.Fatalf("agents: stderr = %q", tio.err.String())
	}
}

func TestAiCreateAgentRequiresSlug(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "create-agent", "--provider", "anthropic"}); code != 1 {
		t.Fatalf("exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "--slug is required") {
		t.Fatalf("stderr = %q", tio.err.String())
	}
}

func TestAiControlRefusesWithoutALogin(t *testing.T) {
	// Unlike `ai exchange`, these act as the signed-in tenant.
	isolateEnv(t)
	a, tio := newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "gateways"}); code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	errOut := tio.err.String()
	if !strings.HasPrefix(errOut, "error: ") {
		t.Errorf("stderr = %q; want the `error: ` contract", errOut)
	}
	if !strings.Contains(errOut, "not logged in") || !strings.Contains(errOut, "knoxcall login") {
		t.Errorf("stderr = %q; want the re-login hint", errOut)
	}
}

// ── create-agent: gateway and secret resolution ─────────────────────────────

func TestAiCreateAgentEscrowsTheKeyFromTheEnvironment(t *testing.T) {
	s := newAiTestServer(t).
		on("GET /v1/ai-gateway/gateways", oneGateway).
		on("GET /v1/secrets", noSecrets).
		on("POST /v1/secrets", `{"data":{"id":"sec_new","name":"ai-gateway-copilot-key","secret_type":"string"}}`).
		on("POST /v1/ai-gateway/gateways/gw_1/agents", createdAgent)
	a, tio := aiLoggedInApp(t, s)
	t.Setenv("TEST_PROVIDER_KEY", "sk-ant-live-supersecret")

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
		"--secret-from-env", "TEST_PROVIDER_KEY",
	})
	if code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}

	escrow := s.find(t, "POST /v1/secrets").body
	if escrow["name"] != "ai-gateway-copilot-key" {
		t.Errorf("secret name = %v; want ai-gateway-copilot-key", escrow["name"])
	}
	if escrow["value"] != "sk-ant-live-supersecret" {
		t.Errorf("the key from the environment did not reach the escrow: %v", escrow["value"])
	}
	if got := s.find(t, "POST /v1/ai-gateway/gateways/gw_1/agents").body["upstream_secret_id"]; got != "sec_new" {
		t.Errorf("upstream_secret_id = %v; want the escrowed secret", got)
	}

	// stdout is captured with $(...), so it must be exactly the agent id.
	if tio.out.String() != "ag_new\n" {
		t.Fatalf("stdout = %q; want exactly the agent id", tio.out.String())
	}
	errOut := tio.err.String()
	for _, want := range []string{
		"escrowed secret 'ai-gateway-copilot-key' (sec_new)",
		"agent:     copilot (ag_new)",
		"gateway:   gw_1",
		"provider:  anthropic",
		"base_url:  https://acme.knoxcall.com/v1/ai/copilot",
		"Next:  knoxcall ai mint --agent ag_new",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q; got:\n%s", want, errOut)
		}
	}
	// The key is in custody now; it must not be echoed anywhere.
	if strings.Contains(errOut, "sk-ant-live-supersecret") || strings.Contains(tio.out.String(), "sk-ant-live-supersecret") {
		t.Error("the provider key leaked to the terminal")
	}
}

func TestAiCreateAgentReusesASecretOfTheSameName(t *testing.T) {
	// Re-running the quickstart must not leave a second copy of the same
	// credential behind.
	s := newAiTestServer(t).
		on("GET /v1/ai-gateway/gateways", oneGateway).
		on("GET /v1/secrets", `{"data":[{"id":"sec_old","name":"ai-gateway-copilot-key","secret_type":"string"}],
		  "meta":{"total":1,"page":1,"per_page":100,"total_pages":1}}`).
		on("POST /v1/ai-gateway/gateways/gw_1/agents", createdAgent)
	a, tio := aiLoggedInApp(t, s)
	t.Setenv("TEST_PROVIDER_KEY", "sk-ant-live")

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
		"--secret-from-env", "TEST_PROVIDER_KEY",
	})
	if code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}
	if s.called("POST /v1/secrets") {
		t.Error("a second copy of the same credential was created")
	}
	if got := s.find(t, "POST /v1/ai-gateway/gateways/gw_1/agents").body["upstream_secret_id"]; got != "sec_old" {
		t.Errorf("upstream_secret_id = %v; want the existing secret", got)
	}
	if !strings.Contains(tio.err.String(), "reusing secret 'ai-gateway-copilot-key' (sec_old)") {
		t.Errorf("stderr = %q", tio.err.String())
	}
}

func TestAiCreateAgentRefusesWhenTheNamedEnvironmentVariableIsEmpty(t *testing.T) {
	s := newAiTestServer(t).on("GET /v1/ai-gateway/gateways", oneGateway)
	a, tio := aiLoggedInApp(t, s)
	t.Setenv("TEST_PROVIDER_KEY", "")

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
		"--secret-from-env", "TEST_PROVIDER_KEY",
	})
	if code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	errOut := tio.err.String()
	if !strings.Contains(errOut, "TEST_PROVIDER_KEY is not set") {
		t.Errorf("stderr = %q; want it to name the variable", errOut)
	}
	if !strings.Contains(errOut, "no\n--secret-value flag") && !strings.Contains(errOut, "no --secret-value flag") {
		t.Errorf("stderr = %q; want it to say why there is no --secret-value", errOut)
	}
}

func TestAiCreateAgentCreatesAGatewayOnAFreshTenant(t *testing.T) {
	// The whole point is that this works on a tenant with nothing in it.
	s := newAiTestServer(t).
		on("GET /v1/ai-gateway/gateways", noGateways).
		on("POST /v1/ai-gateway/gateways", `{"data":{"id":"gw_1","slug":"default","name":"Default","status":"active"}}`).
		on("POST /v1/ai-gateway/gateways/gw_1/agents", createdAgent)
	a, tio := aiLoggedInApp(t, s)

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic", "--secret", "sec_1",
	})
	if code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}
	body := s.find(t, "POST /v1/ai-gateway/gateways").body
	if body["name"] != "Default" || body["slug"] != "default" {
		t.Errorf("created gateway = %v; want Default/default", body)
	}
	if !strings.Contains(tio.err.String(), "created gateway default (gw_1)") {
		t.Errorf("stderr = %q; want the gateway it created to be named", tio.err.String())
	}
}

func TestAiCreateAgentRefusesToPickAmongSeveralGateways(t *testing.T) {
	// "whichever sorts first" is how the quickstart wizard silently landed a
	// second agent in the wrong gateway.
	s := newAiTestServer(t).on("GET /v1/ai-gateway/gateways", twoGateways)
	a, tio := aiLoggedInApp(t, s)

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic", "--secret", "sec_1",
	})
	if code != 1 {
		t.Fatalf("exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	errOut := tio.err.String()
	for _, want := range []string{"--gateway is required", "2 gateways", "prod (gw_1)", "staging (gw_2)"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q; got: %s", want, errOut)
		}
	}
	if s.called("POST /v1/ai-gateway/gateways/gw_1/agents") {
		t.Error("an agent was created in a gateway the caller did not choose")
	}
}

func TestAiCreateAgentResolvesAGatewaySlugAndRefusesAnUnknownOne(t *testing.T) {
	s := newAiTestServer(t).on("GET /v1/ai-gateway/gateways", twoGateways)
	a, tio := aiLoggedInApp(t, s)

	code := a.run(context.Background(), []string{
		"ai", "create-agent", "--slug", "copilot", "--provider", "anthropic",
		"--secret", "sec_1", "--gateway", "nope",
	})
	if code != 1 {
		t.Fatalf("exit = %d; want 1 (stderr: %s)", code, tio.err.String())
	}
	if !strings.Contains(tio.err.String(), "no gateway 'nope'") ||
		!strings.Contains(tio.err.String(), "staging (gw_2)") {
		t.Fatalf("stderr = %q; want the refusal to list what exists", tio.err.String())
	}
}

// ── mint ────────────────────────────────────────────────────────────────────

func TestAiMintPrintsOnlyTheTokenOnStdout(t *testing.T) {
	s := newAiTestServer(t).on("POST /v1/ai-gateway/agents/ag_1/tokens", mintedToken)
	a, tio := aiLoggedInApp(t, s)

	if code := a.run(context.Background(), []string{"ai", "mint", "--agent", "ag_1"}); code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}
	// The plaintext is returned ONCE, and `> token.txt` must capture it alone.
	if tio.out.String() != "kc_live_agt_deadbeef\n" {
		t.Fatalf("stdout = %q; want exactly the token", tio.out.String())
	}
	errOut := tio.err.String()
	if strings.Contains(errOut, "kc_live_agt_deadbeef") {
		t.Error("stderr repeated the token")
	}
	for _, want := range []string{
		"id:       tok_1",
		"kind:     agent",
		"prefix:   kc_live_agt_",
		"dpop:     false",
		"expires:  2026-10-07T00:00:00Z",
		"Save this token now — it will not be shown again.",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr missing %q; got:\n%s", want, errOut)
		}
	}
}

// ── empty-state and help ────────────────────────────────────────────────────

func TestAiControlEmptyListsSaySoOnStderr(t *testing.T) {
	// An empty stdout is the correct machine answer; the human hint goes to
	// stderr so a pipeline sees nothing.
	s := newAiTestServer(t).
		on("GET /v1/ai-gateway/gateways", noGateways).
		on("GET /v1/ai-gateway/gateways/gw_1/agents", noGateways)
	a, tio := aiLoggedInApp(t, s)

	if code := a.run(context.Background(), []string{"ai", "gateways"}); code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if tio.out.String() != "" {
		t.Errorf("stdout = %q; want nothing", tio.out.String())
	}
	if !strings.Contains(tio.err.String(), "No AI gateways.") {
		t.Errorf("stderr = %q", tio.err.String())
	}

	a, tio = aiLoggedInApp(t, s)
	if code := a.run(context.Background(), []string{"ai", "agents", "--gateway", "gw_1"}); code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	if tio.out.String() != "" {
		t.Errorf("stdout = %q; want nothing", tio.out.String())
	}
	if !strings.Contains(tio.err.String(), "No agents in that gateway.") {
		t.Errorf("stderr = %q", tio.err.String())
	}
}

func TestAiHelpListsEveryControlSubcommand(t *testing.T) {
	isolateEnv(t)

	a, tio := newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "--help"}); code != 0 {
		t.Fatalf("exit = %d; want 0", code)
	}
	for _, want := range []string{
		"usage: knoxcall ai [-h] {exchange,gateways,agents,create-agent,mint,usage} ...",
		"create-agent        create an agent with its upstream credential",
		"--secret-from-env ANTHROPIC_API_KEY",
	} {
		if !strings.Contains(tio.out.String(), want) {
			t.Errorf("ai --help missing %q; got:\n%s", want, tio.out.String())
		}
	}

	for sub, want := range map[string]string{
		"gateways":     "usage: knoxcall ai gateways",
		"agents":       "usage: knoxcall ai agents",
		"create-agent": "usage: knoxcall ai create-agent",
		"mint":         "usage: knoxcall ai mint",
		"usage":        "usage: knoxcall ai usage",
	} {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), []string{"ai", sub, "--help"}); code != 0 {
			t.Fatalf("ai %s --help: exit = %d; want 0 (stderr: %s)", sub, code, tio.err.String())
		}
		if !strings.Contains(tio.out.String(), want) {
			t.Errorf("ai %s --help = %q; want %q", sub, tio.out.String(), want)
		}
		// The common options are documented on every one of them.
		if !strings.Contains(tio.out.String(), "--profile PROFILE") {
			t.Errorf("ai %s --help does not document --profile", sub)
		}
	}
}

func TestAiUnknownSubcommandNamesTheWholeSet(t *testing.T) {
	isolateEnv(t)
	a, tio := newTestApp(t)
	if code := a.run(context.Background(), []string{"ai", "nope"}); code != 2 {
		t.Fatalf("exit = %d; want 2", code)
	}
	if !strings.Contains(tio.err.String(), "'create-agent'") {
		t.Fatalf("stderr = %q; want the full choice list", tio.err.String())
	}
}
