package main

// CLI tests — `knoxcall ai exchange` (RFC 8693 workload federation).
//
// The python CLI is PARITY §13's reference implementation, so these mirror
// sdk/knoxcall-python/tests/test_cli_ai.py assertion for assertion: the subject
// token comes from the environment and never from argv, a host is required
// rather than guessed, stdout carries the token and nothing else, and the exit
// codes are 0 / 1 / 2.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const aiExchangeOK = `{"access_token":"kc_live_agt_deadbeef","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`

// aiExchangeServer stands in for the tenant data plane and records what
// reached it.
func aiExchangeServer(t *testing.T, status int, body string) (*httptest.Server, *map[string]any) {
	t.Helper()
	seen := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen["path"] = r.URL.Path
		var parsed map[string]any
		_ = json.NewDecoder(r.Body).Decode(&parsed)
		seen["body"] = parsed
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestAiExchangeRefusesWithoutTheEnvironmentVariable(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "")
	a, tio := newTestApp(t)

	if code := a.run(context.Background(), []string{"ai", "exchange", "--tenant", "acme"}); code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(tio.err.String(), subjectTokenEnv) {
		t.Fatalf("stderr = %q; want it to name %s", tio.err.String(), subjectTokenEnv)
	}
	if !strings.HasPrefix(tio.err.String(), "error: ") {
		t.Fatalf("stderr = %q; want the `error: ` contract", tio.err.String())
	}
}

func TestAiExchangeRefusesToGuessAHost(t *testing.T) {
	// api.knoxcall.com answers 401 for this request — the endpoint is not served
	// there — and that 401 reads as "your CI token was rejected".
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "a.b.c")
	a, tio := newTestApp(t)

	if code := a.run(context.Background(), []string{"ai", "exchange"}); code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.Contains(tio.err.String(), "--tenant") || !strings.Contains(tio.err.String(), "401") {
		t.Fatalf("stderr = %q; want it to name --tenant and the 401 trap", tio.err.String())
	}
}

func TestAiExchangePrintsOnlyTheTokenOnStdout(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "header.payload.sig")
	srv, seen := aiExchangeServer(t, 200, aiExchangeOK)
	a, tio := newTestApp(t)

	if code := a.run(context.Background(), []string{"ai", "exchange", "--base-url", srv.URL}); code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}
	// stdout is captured with $(...), so it must be exactly the token.
	if tio.out.String() != "kc_live_agt_deadbeef\n" {
		t.Fatalf("stdout = %q; want exactly the token", tio.out.String())
	}
	if !strings.Contains(tio.err.String(), "agent token") {
		t.Fatalf("stderr = %q; want the human line", tio.err.String())
	}
	if (*seen)["path"] != "/v1/oauth/token" {
		t.Fatalf("path = %v; want /v1/oauth/token", (*seen)["path"])
	}
}

func TestAiExchangeOmitsResourceUnlessGiven(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "a.b.c")
	srv, seen := aiExchangeServer(t, 200, aiExchangeOK)
	a, _ := newTestApp(t)

	a.run(context.Background(), []string{"ai", "exchange", "--base-url", srv.URL})

	body, _ := (*seen)["body"].(map[string]any)
	if _, present := body["resource"]; present {
		t.Fatalf("resource was sent without --resource: %v", body["resource"])
	}
}

func TestAiExchangeNarrowsWithResource(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "a.b.c")
	srv, seen := aiExchangeServer(t, 200, aiExchangeOK)
	a, tio := newTestApp(t)

	code := a.run(context.Background(), []string{
		"ai", "exchange", "--base-url", srv.URL,
		"--resource", "https://acme.knoxcall.com/v1/mcp/gh",
	})
	if code != 0 {
		t.Fatalf("exit = %d; want 0 (stderr: %s)", code, tio.err.String())
	}
	body, _ := (*seen)["body"].(map[string]any)
	if body["resource"] != "https://acme.knoxcall.com/v1/mcp/gh" {
		t.Fatalf("resource = %v", body["resource"])
	}
	if !strings.Contains(tio.err.String(), "tool (MCP, resource-bound)") {
		t.Fatalf("stderr = %q; want the tool-kind line", tio.err.String())
	}
}

func TestAiExchangeExitsOneOnAServerRefusal(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "a.b.c")
	srv, _ := aiExchangeServer(t, 400,
		`{"error":"invalid_grant","error_description":"No tenant bindings registered"}`)
	a, tio := newTestApp(t)

	if code := a.run(context.Background(), []string{"ai", "exchange", "--base-url", srv.URL}); code != 1 {
		t.Fatalf("exit = %d; want 1", code)
	}
	if !strings.HasPrefix(tio.err.String(), "error: ") ||
		!strings.Contains(tio.err.String(), "No tenant bindings") {
		t.Fatalf("stderr = %q", tio.err.String())
	}
}

func TestAiExchangeNeverPrintsTheTokenToStderr(t *testing.T) {
	isolateEnv(t)
	t.Setenv(subjectTokenEnv, "a.b.c")
	srv, _ := aiExchangeServer(t, 200, aiExchangeOK)
	a, tio := newTestApp(t)

	a.run(context.Background(), []string{"ai", "exchange", "--base-url", srv.URL})
	if strings.Contains(tio.err.String(), "kc_live_agt_deadbeef") {
		t.Fatalf("stderr leaked the token: %q", tio.err.String())
	}
}

func TestAiSubcommandDispatch(t *testing.T) {
	isolateEnv(t)

	t.Run("no sub-command is a usage error", func(t *testing.T) {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), []string{"ai"}); code != 2 {
			t.Fatalf("exit = %d; want 2", code)
		}
		if !strings.Contains(tio.err.String(), "{exchange}") {
			t.Fatalf("stderr = %q", tio.err.String())
		}
	})

	t.Run("an unknown sub-command is a usage error", func(t *testing.T) {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), []string{"ai", "nope"}); code != 2 {
			t.Fatalf("exit = %d; want 2", code)
		}
		if !strings.Contains(tio.err.String(), `invalid choice: "nope"`) {
			t.Fatalf("stderr = %q", tio.err.String())
		}
	})

	t.Run("ai --help exits 0", func(t *testing.T) {
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), []string{"ai", "--help"}); code != 0 {
			t.Fatalf("exit = %d; want 0", code)
		}
		// AIGW-162 added the five control-plane sub-commands; the choice list
		// is pinned here and in ai_control_test.go's help test.
		if !strings.Contains(tio.out.String(), "usage: knoxcall ai [-h] {exchange,gateways,agents,create-agent,mint,usage} ...") {
			t.Fatalf("stdout = %q", tio.out.String())
		}
	})

	t.Run("there is no --subject-token flag", func(t *testing.T) {
		// An argv value lands in shell history, ps output and the CI log line,
		// so there must be no way to pass one. This asserts the ABSENCE of a
		// flag — adding `--subject-token` later would fail here.
		a, tio := newTestApp(t)
		if code := a.run(context.Background(), []string{"ai", "exchange", "--subject-token", "a.b.c"}); code != 2 {
			t.Fatalf("exit = %d; want 2 (stderr: %s)", code, tio.err.String())
		}
	})
}
