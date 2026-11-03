package main

// `knoxcall ai` — the AI-gateway CONTROL plane from a terminal (AIGW-162).
//
// Mirrors knoxcall-node's src/cli/ai-control.ts flag for flag and message for
// message; PARITY §13's whole premise is that `knoxcall` has the SAME surface
// whichever SDK put it on your PATH.
//
// `ai exchange` (ai.go) is the data-plane door: it needs no login, because the
// CI workload's OIDC token is the credential. Everything here is the opposite —
// it acts as the signed-in tenant, through the same ~/.knoxcall/credentials.json
// profile `login` writes and `whoami` reads.
//
// WHY THIS EXISTS. Until now the five SDK CLIs shipped exactly one `ai`
// subcommand, `exchange`. A capable `knoxcall ai gateways|agents|mint|usage`
// lived in a standalone `cli/` package that was never published, never tested,
// never in CI and not in the workspaces — and it could not create a secret, a
// gateway or an agent, so it could not get you to a first call either. So there
// was no CLI golden path at all: the only way from "I have an API key" to "my
// app is calling an LLM through KnoxCall" was the browser or hand-written HTTP.
//
// The golden path these commands exist to make true, from a tenant with
// nothing in it:
//
//	export ANTHROPIC_API_KEY=sk-ant-...
//	knoxcall ai create-agent --name copilot --slug copilot \
//	    --provider anthropic --secret-from-env ANTHROPIC_API_KEY
//	knoxcall ai mint --agent <id>
//	curl "$AGENT_URL/v1/messages" -H "Authorization: Bearer $TOKEN" ...
//
// Two commands, then a real streamed call. `create-agent` prints the agent id,
// the agent_url and the exact next command, so the path is discoverable without
// re-reading the docs.
//
// THREE RULES, each one a bug this shape invites:
//
//  1. A PROVIDER KEY IS NEVER AN ARGV VALUE. `--secret-from-env NAME` names the
//     environment variable to read; there is deliberately no `--secret-value`.
//     An argv value lands in shell history, in `ps` output and in the CI log
//     line that echoes the command. Same rule `ai exchange` applies to the
//     subject token and `init` to KNOXCALL_WRAP_SECRET.
//
//  2. NO POSITIONAL ARGUMENTS. Four of the five SDK CLIs hand-roll their parser
//     and reject positionals outright; only python gets them free from argparse.
//     Ids are flags (`--gateway`, `--agent`) so the surface is the same in all
//     five rather than "the same except in Go". Here that falls out of
//     parseFlags refusing fs.NArg() > 0 — which matters, because Go's flag
//     package STOPS at the first non-flag argument, so a positional would
//     otherwise silently swallow every flag after it.
//
//  3. AN AGENT WITHOUT AN UPSTREAM IS REFUSED HERE, not at its first call. The
//     API accepts CreateAgent with no Provider/UpstreamSecretID and stores an
//     agent whose first data-plane request 502s (AIGW-161). A command whose
//     entire purpose is "get me to a working call" must not be able to produce
//     that, so --provider and one of --secret / --secret-from-env are required
//     together.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/knoxcall/sdk-go/internal/credfile"
	"github.com/knoxcall/sdk-go/knoxcall"
)

// ── help text ───────────────────────────────────────────────────────────────

// aiCommonHelp is the options block every control-plane sub-command shares:
// these three select WHICH tenant and WHICH stored login is acting.
const aiCommonHelp = `  -h, --help           show this help message and exit
  --profile PROFILE    credentials profile name (default: KNOXCALL_PROFILE or
                       'default')
  --base-url BASE_URL  management API base URL (default https://api.knoxcall.com)
  --sandbox            operate against the Test data space
`

const aiGatewaysUsage = "usage: knoxcall ai gateways [-h] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]"

const aiGatewaysHelp = aiGatewaysUsage + `

List this tenant’s AI gateways as ` + "`id  slug  name`" + `.

options:
` + aiCommonHelp

const aiAgentsUsage = "usage: knoxcall ai agents [-h] --gateway GATEWAY [--profile PROFILE] [--base-url BASE_URL] [--sandbox]"

const aiAgentsHelp = aiAgentsUsage + `

List a gateway’s agents as ` + "`id  slug  agent_url`" + `. The third column is the
base_url to point an AI SDK at, so this is enough to wire up an existing
agent without a second call.

options:
  --gateway GATEWAY    gateway id
` + aiCommonHelp

const aiCreateAgentUsage = `usage: knoxcall ai create-agent [-h] --slug SLUG --provider PROVIDER
                                (--secret SECRET | --secret-from-env VAR)
                                [--name NAME] [--gateway GATEWAY] [--model MODEL]
                                [--upstream URL] [--profile PROFILE]
                                [--base-url BASE_URL] [--sandbox]`

const aiCreateAgentHelp = aiCreateAgentUsage + `

Create an agent wired to a provider credential, and print the command that
follows. Works on a tenant with nothing in it: with no --gateway it uses your
only gateway, or creates one when you have none. With several it refuses and
lists them rather than picking one for you.

The provider key is read from the environment named by --secret-from-env,
never from a flag — an argv value lands in shell history, ps output and the CI
log. There is deliberately no --secret-value.

--provider and a credential are both required: the API accepts an agent with
neither and stores one whose first data-plane call 502s.

Only the agent id goes to stdout, so it can be captured:
    AGENT="$(knoxcall ai create-agent --slug copilot --provider anthropic \
        --secret-from-env ANTHROPIC_API_KEY)"

options:
  --slug SLUG          url slug; the agent is served at /v1/ai/{slug}
  --provider PROVIDER  provider id (anthropic, openai, groq, bedrock, …). The
                       catalog is server-side; an unknown value is a 400 that
                       names the valid set.
  --secret SECRET      id of an existing KnoxCall secret holding the key
  --secret-from-env VAR  environment variable holding the key; escrows it as a
                       new secret, reusing one of the same name if present
  --name NAME          display name (defaults to --slug)
  --gateway GATEWAY    gateway id or slug to create under
  --model MODEL        default model (required for openai-compatible)
  --upstream URL       upstream base URL; required for azure-openai, ollama,
                       bedrock and openai-compatible
` + aiCommonHelp

const aiMintUsage = "usage: knoxcall ai mint [-h] --agent AGENT [--kind KIND] [--name NAME] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]"

const aiMintHelp = aiMintUsage + `

Mint a capability token for an agent. The plaintext is returned ONCE and is
the only thing on stdout, so it can be captured:
    TOKEN="$(knoxcall ai mint --agent ag_123)"

options:
  --agent AGENT        agent id
  --kind KIND          agent | read | tool | oneshot (default agent)
  --name NAME          label for the token
` + aiCommonHelp

const aiUsageUsage = "usage: knoxcall ai usage [-h] [--period PERIOD] [--agent AGENT] [--profile PROFILE] [--base-url BASE_URL] [--sandbox]"

const aiUsageHelp = aiUsageUsage + `

Cost and token usage by model.

options:
  --period PERIOD      7d | 30d | 90d (default 30d)
  --agent AGENT        scope to one agent
` + aiCommonHelp

// ── shared plumbing ─────────────────────────────────────────────────────────

// aiCommonFlags holds the three flags every control-plane sub-command accepts.
// They are registered per sub-command rather than once on the `ai` group: a
// single flat FlagSet would accept `ai gateways --agent ag_1` and ignore it,
// which is the opposite of what every other command here does with an unknown
// flag (usage error, exit 2).
type aiCommonFlags struct {
	profile *string
	baseURL *string
	sandbox *bool
}

func addAiCommonFlags(fs *flag.FlagSet) aiCommonFlags {
	return aiCommonFlags{
		profile: fs.String("profile", "", "credentials profile name (default: KNOXCALL_PROFILE or 'default')"),
		baseURL: fs.String("base-url", "", "management API base URL (default https://api.knoxcall.com)"),
		sandbox: fs.Bool("sandbox", false, "operate against the Test data space"),
	}
}

// aiClient builds a client acting as the signed-in tenant, or returns the error
// that tells them to log in. Same resolution as `whoami` and `init`: the
// cross-SDK credentials file, the named profile, no provisioning.
func (a *app) aiClient(common aiCommonFlags) (*knoxcall.Client, error) {
	path := credfile.ResolvePath("")
	profile := credfile.ResolveProfile(*common.profile)
	if credfile.ReadProfile(path, profile) == nil {
		return nil, fmt.Errorf("not logged in (profile '%s') — run `knoxcall login`", profile)
	}
	opts := knoxcall.Options{
		Credentials: knoxcall.StoredCredentials{Path: path, Profile: profile},
		HTTPClient:  a.http,
	}
	if *common.baseURL != "" {
		opts.BaseURL = *common.baseURL
	}
	if *common.sandbox {
		opts.Sandbox = true
	}
	return knoxcall.New(opts)
}

// aiListPage asks for the biggest page the server allows, so the single-gateway
// and reuse-by-name lookups below see the whole set in one round trip.
func aiListPage() *knoxcall.ListParams { return &knoxcall.ListParams{PerPage: 100} }

// ── knoxcall ai gateways ────────────────────────────────────────────────────

func (a *app) cmdAiGateways(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai gateways", flag.ContinueOnError)
	common := addAiCommonFlags(fs)
	if err := parseFlags(fs, argv, aiGatewaysHelp, a.stdout); err != nil {
		return err
	}

	client, err := a.aiClient(common)
	if err != nil {
		return err
	}
	page, err := client.AIGateway.ListGateways(ctx, aiListPage())
	if err != nil {
		return err
	}
	if len(page.Data) == 0 {
		fmt.Fprintln(a.stderr, "No AI gateways. `knoxcall ai create-agent` will create one for you.")
		return nil
	}
	for _, g := range page.Data {
		fmt.Fprintf(a.stdout, "%s  %s  %s\n", g.ID, g.Slug, g.Name)
	}
	return nil
}

// ── knoxcall ai agents --gateway ID ─────────────────────────────────────────

func (a *app) cmdAiAgents(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai agents", flag.ContinueOnError)
	common := addAiCommonFlags(fs)
	gateway := fs.String("gateway", "", "gateway id")
	if err := parseFlags(fs, argv, aiAgentsHelp, a.stdout); err != nil {
		return err
	}
	// Required flags are checked BEFORE the credentials file is touched, so a
	// missing flag reports the missing flag rather than "not logged in".
	if *gateway == "" {
		return errors.New("--gateway is required")
	}

	client, err := a.aiClient(common)
	if err != nil {
		return err
	}
	page, err := client.AIGateway.ListAgents(ctx, *gateway, aiListPage())
	if err != nil {
		return err
	}
	if len(page.Data) == 0 {
		fmt.Fprintln(a.stderr, "No agents in that gateway.")
		return nil
	}
	// AgentURL is on every projection since AIGW-161, so a list is enough to
	// point an SDK at an existing agent — no follow-up GET.
	for _, ag := range page.Data {
		fmt.Fprintf(a.stdout, "%s  %s  %s\n", ag.ID, ag.Slug, ag.AgentURL)
	}
	return nil
}

// ── knoxcall ai create-agent ────────────────────────────────────────────────

// describeGateways renders "slug (id), slug (id)" for the refusal messages.
func describeGateways(gateways []knoxcall.AIGateway) string {
	parts := make([]string, 0, len(gateways))
	for _, g := range gateways {
		parts = append(parts, fmt.Sprintf("%s (%s)", g.Slug, g.ID))
	}
	return strings.Join(parts, ", ")
}

// resolveGateway picks the gateway to create under.
//
// --gateway takes an id OR a slug. With no --gateway: use the tenant's only
// gateway, or create one when they have none — that is what makes the command
// work on a fresh tenant, which is the whole point. With SEVERAL and no flag it
// refuses and lists them rather than picking: "whichever sorts first" is how the
// quickstart wizard silently landed a second agent in the wrong gateway.
func (a *app) resolveGateway(ctx context.Context, client *knoxcall.Client, wanted string) (string, error) {
	page, err := client.AIGateway.ListGateways(ctx, aiListPage())
	if err != nil {
		return "", err
	}
	if wanted != "" {
		for _, g := range page.Data {
			if g.ID == wanted || g.Slug == wanted {
				return g.ID, nil
			}
		}
		known := describeGateways(page.Data)
		if known == "" {
			known = "none"
		}
		return "", fmt.Errorf("no gateway '%s' — this tenant has: %s", wanted, known)
	}
	switch len(page.Data) {
	case 1:
		return page.Data[0].ID, nil
	case 0:
		created, err := client.AIGateway.CreateGateway(ctx, knoxcall.CreateAIGatewayInput{
			Name: "Default",
			Slug: "default",
		})
		if err != nil {
			return "", err
		}
		fmt.Fprintf(a.stderr, "created gateway %s (%s)\n", created.Slug, created.ID)
		return created.ID, nil
	default:
		return "", fmt.Errorf(
			"--gateway is required: this tenant has %d gateways (%s). "+
				"Picking one for you would put the agent somewhere you did not choose.",
			len(page.Data), describeGateways(page.Data))
	}
}

// resolveSecret returns the upstream secret id, escrowing one from the
// environment if asked.
//
// The key is read from os.Getenv(NAME), never from a flag — see rule 1.
// Re-running with the same --secret-from-env reuses the existing secret by name
// rather than creating a second copy of the same credential.
func (a *app) resolveSecret(ctx context.Context, client *knoxcall.Client, secretID, envName, slug string) (string, error) {
	if secretID != "" {
		return secretID, nil
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return "", fmt.Errorf(
			"%s is not set — put your provider key there. There is deliberately no "+
				"--secret-value flag: an argv value lands in shell history, ps output and the CI log.",
			envName)
	}
	if slug == "" {
		slug = "agent"
	}
	name := "ai-gateway-" + slug + "-key"
	existing, err := client.Secrets.List(ctx, aiListPage())
	if err != nil {
		return "", err
	}
	for _, s := range existing.Data {
		if s.Name == name {
			fmt.Fprintf(a.stderr, "reusing secret '%s' (%s)\n", name, s.ID)
			return s.ID, nil
		}
	}
	created, err := client.Secrets.Create(ctx, knoxcall.CreateSecretInput{Name: name, Value: value})
	if err != nil {
		return "", err
	}
	fmt.Fprintf(a.stderr, "escrowed secret '%s' (%s) — the key is now in KnoxCall custody\n", name, created.ID)
	return created.ID, nil
}

func (a *app) cmdAiCreateAgent(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai create-agent", flag.ContinueOnError)
	common := addAiCommonFlags(fs)
	gateway := fs.String("gateway", "", "gateway id or slug to create under")
	name := fs.String("name", "", "display name (defaults to --slug)")
	slug := fs.String("slug", "", "url slug; the agent is served at /v1/ai/{slug}")
	provider := fs.String("provider", "", "provider id (anthropic, openai, groq, bedrock, …)")
	secret := fs.String("secret", "", "id of an existing KnoxCall secret holding the key")
	secretFromEnv := fs.String("secret-from-env", "", "environment variable holding the key")
	upstream := fs.String("upstream", "", "upstream base URL")
	model := fs.String("model", "", "default model")
	if err := parseFlags(fs, argv, aiCreateAgentHelp, a.stdout); err != nil {
		return err
	}

	if *slug == "" {
		return errors.New("--slug is required")
	}
	// Rule 3: refuse here rather than let the API store an agent with no
	// upstream whose first data-plane call 502s.
	if *provider == "" {
		return errors.New("--provider is required")
	}
	if *secret == "" && *secretFromEnv == "" {
		return errors.New("one of --secret or --secret-from-env is required: an agent created without an " +
			"upstream credential is accepted by the API and 502s on its first call.")
	}

	client, err := a.aiClient(common)
	if err != nil {
		return err
	}
	gatewayID, err := a.resolveGateway(ctx, client, *gateway)
	if err != nil {
		return err
	}
	secretID, err := a.resolveSecret(ctx, client, *secret, *secretFromEnv, *slug)
	if err != nil {
		return err
	}

	displayName := *name
	if displayName == "" {
		displayName = *slug
	}
	agent, err := client.AIGateway.CreateAgent(ctx, gatewayID, knoxcall.CreateAIGatewayAgentInput{
		Name:             displayName,
		Slug:             *slug,
		Provider:         *provider,
		UpstreamSecretID: secretID,
		// Both are `omitempty`, so an unset flag is an absent field.
		Upstream:     *upstream,
		DefaultModel: *model,
	})
	if err != nil {
		return err
	}

	// stdout: the agent id, so $(...) captures exactly that. Everything a human
	// needs next goes to stderr, including the command that follows.
	fmt.Fprintln(a.stdout, agent.ID)
	fmt.Fprintf(a.stderr, "\n  agent:     %s (%s)\n", agent.Slug, agent.ID)
	fmt.Fprintf(a.stderr, "  gateway:   %s\n", gatewayID)
	fmt.Fprintf(a.stderr, "  provider:  %s\n", *provider)
	if agent.AgentURL != "" {
		fmt.Fprintf(a.stderr, "  base_url:  %s\n", agent.AgentURL)
	}
	fmt.Fprintf(a.stderr, "\n  Next:  knoxcall ai mint --agent %s\n", agent.ID)
	return nil
}

// ── knoxcall ai mint --agent ID ─────────────────────────────────────────────

func (a *app) cmdAiMint(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai mint", flag.ContinueOnError)
	common := addAiCommonFlags(fs)
	agentID := fs.String("agent", "", "agent id")
	kind := fs.String("kind", "", "agent | read | tool | oneshot (default agent)")
	name := fs.String("name", "", "label for the token")
	if err := parseFlags(fs, argv, aiMintHelp, a.stdout); err != nil {
		return err
	}
	if *agentID == "" {
		return errors.New("--agent is required")
	}

	client, err := a.aiClient(common)
	if err != nil {
		return err
	}
	minted, err := client.AIGateway.MintToken(ctx, *agentID, knoxcall.MintAIGatewayTokenInput{
		Kind: *kind,
		Name: *name,
	})
	if err != nil {
		return err
	}

	// The plaintext is returned ONCE. stdout carries only the token so
	// `> token.txt` captures the token and nothing else; the metadata and the
	// warning go to stderr.
	fmt.Fprintln(a.stdout, minted.Token)
	fmt.Fprintf(a.stderr, "\n  id:       %s\n", minted.ID)
	fmt.Fprintf(a.stderr, "  kind:     %s\n", minted.Kind)
	fmt.Fprintf(a.stderr, "  prefix:   %s\n", minted.Prefix)
	fmt.Fprintf(a.stderr, "  dpop:     %t\n", minted.DPoPRequired)
	expires := "never"
	if minted.ExpiresAt != nil {
		expires = *minted.ExpiresAt
	}
	fmt.Fprintf(a.stderr, "  expires:  %s\n", expires)
	fmt.Fprintln(a.stderr, "\n  Save this token now — it will not be shown again.")
	return nil
}

// ── knoxcall ai usage ───────────────────────────────────────────────────────

func (a *app) cmdAiUsage(ctx context.Context, argv []string) error {
	fs := flag.NewFlagSet("ai usage", flag.ContinueOnError)
	common := addAiCommonFlags(fs)
	period := fs.String("period", "", "7d | 30d | 90d (default 30d)")
	agentID := fs.String("agent", "", "scope to one agent")
	if err := parseFlags(fs, argv, aiUsageHelp, a.stdout); err != nil {
		return err
	}

	client, err := a.aiClient(common)
	if err != nil {
		return err
	}
	window := *period
	if window == "" {
		window = "30d"
	}
	usage, err := client.AIGateway.Usage(ctx, &knoxcall.AIGatewayUsageParams{
		Period:  window,
		AgentID: *agentID,
	})
	if err != nil {
		return err
	}

	scope := ""
	if *agentID != "" {
		scope = fmt.Sprintf(" (agent %s)", *agentID)
	}
	fmt.Fprintf(a.stdout, "Usage — last %d days%s\n", usage.PeriodDays, scope)
	fmt.Fprintf(a.stdout, "  requests:      %d\n", usage.Totals.Requests)
	fmt.Fprintf(a.stdout, "  input tokens:  %d\n", usage.Totals.InputTokens)
	fmt.Fprintf(a.stdout, "  output tokens: %d\n", usage.Totals.OutputTokens)
	fmt.Fprintf(a.stdout, "  cost (USD):    %.4f\n", usage.Totals.CostUSD)
	fmt.Fprintf(a.stdout, "  unpriced:      %d\n", usage.Totals.UnpricedRequests)
	if len(usage.ByModel) == 0 {
		fmt.Fprintln(a.stdout, "\nNo usage in this period.")
		return nil
	}
	fmt.Fprintln(a.stdout, "\nBy model:")
	for _, m := range usage.ByModel {
		fmt.Fprintf(a.stdout, "  %s/%s  %d req  in %d  out %d  $%.4f\n",
			m.Provider, m.Model, m.Requests, m.InputTokens, m.OutputTokens, m.CostUSD)
	}
	return nil
}
