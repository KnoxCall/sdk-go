// Command knoxcall is the KnoxCall CLI — `knoxcall login` / `logout` /
// `whoami` / `init` / `ai`.
//
// Install with:
//
//	go install github.com/knoxcall/sdk-go/cmd/knoxcall@latest
//
// Credentials are stored in the cross-SDK ~/.knoxcall/credentials.json file
// and picked up automatically by every KnoxCall SDK (auto-detect slot 2).
// The command surface is identical across all SDK ecosystems (see
// ../../../PARITY.md §13); the Python package's knoxcall.cli is the
// reference implementation.
//
// Error contract: expected failures print `error: <message>` to stderr and
// exit 1 (no stack traces); an interrupt prints `aborted` and exits 1;
// success exits 0. Secrets never appear in output.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

const rootHelp = `usage: knoxcall [-h] {login,logout,whoami,init,ai} ...

KnoxCall command-line interface — sign in once, every SDK on this machine
picks it up.

positional arguments:
  {login,logout,whoami,init,ai}
    login               sign in with your browser and store credentials locally
    logout              revoke and remove stored credentials
    whoami              show the signed-in tenant
    init                get started wrapping a provider SDK (escrow a key)
    ai                  AI gateway operations

options:
  -h, --help            show this help message and exit
`

const loginHelp = `usage: knoxcall login [-h] [--tenant TENANT] [--base-url BASE_URL] [--sandbox]
                      [--profile PROFILE] [--device] [--no-browser]

sign in with your browser and store credentials locally

options:
  -h, --help           show this help message and exit
  --tenant TENANT      tenant slug hint for the sign-in page
  --base-url BASE_URL  management API base URL (default
                       https://api.knoxcall.com, or KNOXCALL_BASE_URL)
  --sandbox            log in against the sandbox environment
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE
                       or 'default')
  --device             use the device-code flow (headless/SSH machines)
  --no-browser         never open a browser (implies the device-code flow)
`

const logoutHelp = `usage: knoxcall logout [-h] [--profile PROFILE]

revoke and remove stored credentials

options:
  -h, --help         show this help message and exit
  --profile PROFILE  credentials profile name (default: KNOXCALL_PROFILE or
                     'default')
`

const whoamiHelp = `usage: knoxcall whoami [-h] [--profile PROFILE]

show the signed-in tenant

options:
  -h, --help         show this help message and exit
  --profile PROFILE  credentials profile name (default: KNOXCALL_PROFILE or
                     'default')
`

const initHelp = `usage: knoxcall init [-h] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]
                     [--provider PROVIDER] [--secret-name NAME] [--host HOST]

get started wrapping a provider SDK through KnoxCall (escrow a key)

Works against the tenant you are already signed in to — it does NOT provision a
tenant. With no --provider it prints a two-step wrap quickstart; with --provider
it escrows a key (read from the KNOXCALL_WRAP_SECRET env var, never a flag) and
prints the gateway base_url.

options:
  -h, --help           show this help message and exit
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE or
                       'default')
  --base-url BASE_URL  management API base URL (default
                       https://api.knoxcall.com)
  --sandbox            operate against the sandbox environment
  --provider PROVIDER  provider to escrow a key for (e.g. stripe); enables
                       escrow mode
  --secret-name NAME   name for the escrowed credential (required with
                       --provider)
  --host HOST          upstream host to pin the credential to (required with
                       --provider)
`

const aiHelp = `usage: knoxcall ai [-h] {` + aiChoices + `} ...

AI-gateway operations.

From a tenant with nothing in it to a real streamed call, in two commands:

    export ANTHROPIC_API_KEY=sk-ant-...
    knoxcall ai create-agent --name copilot --slug copilot \
        --provider anthropic --secret-from-env ANTHROPIC_API_KEY
    knoxcall ai mint --agent <id>

positional arguments:
  {` + aiChoices + `}
    exchange            exchange a CI OIDC token for a capability token (no login needed)
    gateways            list AI gateways
    agents              list a gateway’s agents
    create-agent        create an agent with its upstream credential
    mint                mint a capability token (shown once)
    usage               cost + token usage by model

options:
  -h, --help            show this help message and exit
`

const aiExchangeHelp = `usage: knoxcall ai exchange [-h] [--tenant TENANT] [--sandbox]
                            [--base-url BASE_URL] [--resource RESOURCE]
                            [--audience AUDIENCE]

Exchange a CI workload's OIDC id_token for a short-lived AI-gateway capability
token (RFC 8693). Needs no KnoxCall credential and no ` + "`knoxcall login`" + `: the
subject token IS the credential.

The subject token is read from the KNOXCALL_SUBJECT_TOKEN environment variable,
never a flag — an argv value lands in shell history, ps output and the CI log.

Only the token is printed to stdout, so it can be captured:
    export KC_TOKEN="$(knoxcall ai exchange --tenant acme)"

options:
  -h, --help           show this help message and exit
  --tenant TENANT      tenant slug; the data-plane host is
                       https://{tenant}.knoxcall.com
  --sandbox            use the Test data space (sandbox-{tenant}.knoxcall.com)
  --base-url BASE_URL  full data-plane origin; overrides --tenant
  --resource RESOURCE  RFC 8707 resource indicator (an MCP server's
                       ` + "`resource`" + `); narrows the token to that one MCP server
  --audience AUDIENCE  defaults to knoxcall:gateway
`

// app carries the CLI's injectable dependencies so tests can capture output,
// mock HTTP, record sleeps, and fake the browser launcher.
type app struct {
	stdout      io.Writer
	stderr      io.Writer
	http        *http.Client
	sleep       func(ctx context.Context, d time.Duration) error
	openBrowser func(url string) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	a := &app{
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		http:        &http.Client{Timeout: 30 * time.Second},
		sleep:       sleepCtx,
		openBrowser: openBrowser,
	}
	os.Exit(a.run(ctx, os.Args[1:]))
}

// run dispatches the subcommand and applies the error contract: 0 on
// success (and on -h/--help), 1 with `error: <message>` on expected
// failures, 1 with `aborted` on interrupt, 2 on usage errors.
func (a *app) run(ctx context.Context, argv []string) int {
	if len(argv) == 0 {
		fmt.Fprint(a.stderr, rootHelp)
		return 2
	}

	var err error
	switch argv[0] {
	case "-h", "--help", "help":
		fmt.Fprint(a.stdout, rootHelp)
		return 0
	case "login":
		err = a.cmdLogin(ctx, argv[1:])
	case "logout":
		err = a.cmdLogout(ctx, argv[1:])
	case "whoami":
		err = a.cmdWhoami(ctx, argv[1:])
	case "init":
		err = a.cmdInit(ctx, argv[1:])
	case "ai":
		err = a.cmdAi(ctx, argv[1:])
	default:
		fmt.Fprintf(a.stderr, "error: unknown command %q\n\n%s", argv[0], rootHelp)
		return 2
	}

	var ue *usageErr
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errHelp):
		return 0 // help text already printed to stdout
	case errors.As(err, &ue):
		fmt.Fprintf(a.stderr, "error: %s\n\n%s", ue.msg, ue.usage)
		return 2
	case errors.Is(err, context.Canceled) || ctx.Err() != nil:
		fmt.Fprintln(a.stderr, "aborted")
		return 1
	default:
		fmt.Fprintf(a.stderr, "error: %s\n", err)
		return 1
	}
}

// errHelp signals that -h/--help was handled (help already printed, exit 0).
var errHelp = errors.New("help requested")

// usageErr is a bad-invocation error: printed with the subcommand's usage
// text and exit code 2 (mirroring argparse in the Python reference).
type usageErr struct {
	msg   string
	usage string
}

func (e *usageErr) Error() string { return e.msg }

// parseFlags parses a subcommand FlagSet with the shared help/usage
// semantics: -h/--help prints the given help text to stdout and returns
// errHelp; unknown flags and stray positional arguments become usage errors.
func parseFlags(fs *flag.FlagSet, args []string, help string, stdout io.Writer) error {
	fs.SetOutput(io.Discard) // we render errors and help ourselves
	fs.Usage = func() {}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, help)
			return errHelp
		}
		return &usageErr{msg: err.Error(), usage: help}
	}
	if fs.NArg() > 0 {
		return &usageErr{
			msg:   "unrecognized arguments: " + strings.Join(fs.Args(), " "),
			usage: help,
		}
	}
	return nil
}

// sleepCtx sleeps for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
