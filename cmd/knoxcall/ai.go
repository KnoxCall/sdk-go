package main

// `knoxcall ai exchange` — RFC 8693 workload federation from a terminal.
//
// Mirrors knoxcall-python's knoxcall/cli/ai.py (the PARITY §13 reference):
// same flags, same messages, same exit codes.
//
// The one KnoxCall command that needs no `knoxcall login` and no KnoxCall
// credential at all: the CI workload's own OIDC id_token IS the credential, and
// the server verifies it against the issuer's published JWKS.
//
//	export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"
//
// Two rules this command exists to enforce, because both are easy to get wrong
// in a CI script and neither fails in a way that names itself:
//
//  1. The subject token is read from the environment, NEVER a flag. An argv
//     value lands in shell history, in `ps` output, and in the CI log line that
//     echoes the command. Same rule `knoxcall init` applies to
//     KNOXCALL_WRAP_SECRET.
//  2. The host is the tenant data plane, and there is no default. On
//     api.knoxcall.com this endpoint answers 401, which reads as "my CI token
//     was rejected" and sends people hunting through their issuer's JWKS.
//
// Only the token goes to stdout, so `$(...)` captures exactly the token.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/knoxcall/sdk-go/knoxcall"
)

// subjectTokenEnv is where the subject token is read from, never from argv.
const subjectTokenEnv = "KNOXCALL_SUBJECT_TOKEN"

// aiChoices / aiChoiceList render the sub-command set the two ways argparse
// does, so the message is byte-identical to the python reference's.
const (
	aiChoices    = "exchange,gateways,agents,create-agent,mint,usage"
	aiChoiceList = "'exchange', 'gateways', 'agents', 'create-agent', 'mint', 'usage'"
)

// cmdAi dispatches the `ai` sub-command. It is the only command group with
// sub-commands of its own; keeping the dispatch here rather than generalising
// run() means the top-level switch stays a flat list of commands.
//
// `exchange` lives in this file — it is the data-plane door and needs no login.
// The other five are the CONTROL plane (ai_control.go): they act as the
// signed-in tenant, so they resolve the credentials file exactly as `whoami`
// does. Each parses its OWN FlagSet, because one shared table would accept
// `ai exchange --period 30d` and silently ignore it.
func (a *app) cmdAi(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return &usageErr{msg: "the following arguments are required: {exchange}", usage: aiHelp}
	}
	switch argv[0] {
	case "-h", "--help":
		fmt.Fprint(a.stdout, aiHelp)
		return errHelp
	case "exchange":
		return a.cmdAiExchange(ctx, argv[1:])
	case "gateways":
		return a.cmdAiGateways(ctx, argv[1:])
	case "agents":
		return a.cmdAiAgents(ctx, argv[1:])
	case "create-agent":
		return a.cmdAiCreateAgent(ctx, argv[1:])
	case "mint":
		return a.cmdAiMint(ctx, argv[1:])
	case "usage":
		return a.cmdAiUsage(ctx, argv[1:])
	default:
		return &usageErr{
			msg: fmt.Sprintf("argument {%s}: invalid choice: %q (choose from %s)",
				aiChoices, argv[0], aiChoiceList),
			usage: aiHelp,
		}
	}
}

func (a *app) cmdAiExchange(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai exchange", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "")
	sandbox := fs.Bool("sandbox", false, "")
	baseURL := fs.String("base-url", "", "")
	resource := fs.String("resource", "", "")
	audience := fs.String("audience", "", "")
	if err := parseFlags(fs, argv, aiExchangeHelp, a.stdout); err != nil {
		return err
	}
	// Distinguish "--resource was given" from "--resource is empty": the SDK
	// sends an empty resource through and the server refuses it, which is the
	// correct behaviour — treating empty as absent would hand back an
	// UNCONFINED agent token to a caller who asked for a confined one.
	resourceGiven := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "resource" {
			resourceGiven = true
		}
	})

	subjectToken := strings.TrimSpace(os.Getenv(subjectTokenEnv))
	if subjectToken == "" {
		return errors.New(subjectTokenEnv + " is not set — put your CI provider's OIDC id_token there " +
			"(a flag would land in shell history, ps output and the CI log). GitHub Actions: " +
			"request one with `id-token: write` and the ACTIONS_ID_TOKEN_REQUEST_URL endpoint, " +
			`audience "knoxcall:gateway".`)
	}

	if *tenant == "" && *baseURL == "" {
		return errors.New("one of --tenant or --base-url is required: POST /v1/oauth/token is served only on " +
			"the tenant data-plane host (https://{tenant}.knoxcall.com). Pointing it at " +
			"api.knoxcall.com answers 401, which reads like a rejected subject_token but means " +
			"the endpoint is not there.")
	}

	input := knoxcall.ExchangeTokenInput{SubjectToken: subjectToken, Audience: *audience}
	if resourceGiven {
		input.Resource = resource
	}

	res, err := knoxcall.ExchangeToken(ctx, input, &knoxcall.ExchangeTokenOptions{
		Tenant:     *tenant,
		Sandbox:    *sandbox,
		BaseURL:    *baseURL,
		HTTPClient: a.http,
	})
	if err != nil {
		return err
	}
	if res.AccessToken == "" {
		return errors.New("the exchange returned no access_token")
	}

	// stdout: the token, nothing else. stderr: everything a human wants.
	fmt.Fprintln(a.stdout, res.AccessToken)
	kind := "agent"
	if resourceGiven {
		kind = "tool (MCP, resource-bound)"
	}
	if res.ExpiresIn > 0 {
		fmt.Fprintf(a.stderr, "exchanged for a %s token, valid %ds\n", kind, res.ExpiresIn)
	} else {
		fmt.Fprintf(a.stderr, "exchanged for a %s token\n", kind)
	}
	return nil
}
