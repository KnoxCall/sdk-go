// `knoxcall init` — get started wrapping a provider SDK through KnoxCall
// (sdk-wrapping #17.4; mirrors knoxcall-node/src/cli/init.ts).
//
// SAFE BY DESIGN — this does NOT provision a tenant. It works against the tenant
// you are already signed in to (`knoxcall login`). Two modes:
//
//	knoxcall init
//	    Scaffold mode: confirm who you're signed in as and print a two-step
//	    wrap quickstart. No writes.
//
//	knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com
//	    One-shot escrow: move a provider key into KnoxCall custody and print the
//	    gateway base_url to point your SDK at. The KEY is read from the
//	    KNOXCALL_WRAP_SECRET env var (never a flag) so it stays out of your shell
//	    history/argv. Escrow is idempotent-ish server-side (409 on a dup name).
//
// Tenant provisioning + a fully headless one-shot flow are a deliberate
// follow-up — a CLI that mints tenants is a bigger, riskier surface.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/knoxcall/sdk-go/internal/credfile"
	"github.com/knoxcall/sdk-go/knoxcall"
)

func (a *app) cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	profileFlag := fs.String("profile", "", "credentials profile name (default: KNOXCALL_PROFILE or 'default')")
	baseURLFlag := fs.String("base-url", "", "management API base URL (default https://api.knoxcall.com)")
	sandbox := fs.Bool("sandbox", false, "operate against the sandbox environment")
	provider := fs.String("provider", "", "provider to escrow a key for (e.g. stripe); enables escrow mode")
	secretName := fs.String("secret-name", "", "name for the escrowed credential (required with --provider)")
	host := fs.String("host", "", "upstream host to pin the credential to (required with --provider)")
	if err := parseFlags(fs, args, initHelp, a.stdout); err != nil {
		return err
	}

	// Auth: reuse the stored login. Never provision.
	path := credfile.ResolvePath("")
	profile := credfile.ResolveProfile(*profileFlag)
	if credfile.ReadProfile(path, profile) == nil {
		return fmt.Errorf("not logged in (profile '%s') — run `knoxcall login` first", profile)
	}

	opts := knoxcall.Options{
		Credentials: knoxcall.StoredCredentials{Path: path, Profile: profile},
		HTTPClient:  a.http,
	}
	if *baseURLFlag != "" {
		opts.BaseURL = *baseURLFlag
	}
	if *sandbox {
		opts.Sandbox = true
	}
	client, err := knoxcall.New(opts)
	if err != nil {
		return err
	}

	account, err := client.Account.Get(ctx)
	if err != nil {
		return err
	}
	tenant := account.Name
	if tenant == "" {
		tenant = account.Slug
	}
	if tenant == "" {
		tenant = "(unknown)"
	}
	fmt.Fprintf(a.stdout, "Signed in as %s.\n", tenant)

	// One-shot escrow mode: --provider selects it; the other bits are then required.
	if *provider != "" {
		name := strings.TrimSpace(*secretName)
		pinHost := strings.ToLower(strings.TrimSpace(*host))
		// The raw key comes from the environment, NEVER a flag/argv — so it stays
		// out of shell history and the process argument list.
		value := os.Getenv("KNOXCALL_WRAP_SECRET")
		if name == "" {
			return fmt.Errorf("--secret-name is required with --provider")
		}
		if pinHost == "" {
			return fmt.Errorf("--host is required with --provider")
		}
		if value == "" {
			return fmt.Errorf("set the provider key in the KNOXCALL_WRAP_SECRET env var (not a flag)")
		}

		if _, err := client.Wrap.Escrow(ctx, knoxcall.WrapCredentialInput{
			Provider: *provider,
			Name:     name,
			Value:    value,
			Hosts:    []string{pinHost},
		}); err != nil {
			return err
		}
		res, err := client.Wrap.GatewayURL(ctx, knoxcall.GatewayURLInput{Secret: name, Host: pinHost})
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "")
		fmt.Fprintf(a.stdout, "Escrowed '%s' for %s — your provider key is now in KnoxCall custody.\n", name, pinHost)
		fmt.Fprintln(a.stdout, "Point a base-URL-only SDK at:")
		fmt.Fprintf(a.stdout, "  %s\n", res.BaseURL)
		fmt.Fprintln(a.stdout, "")
		fmt.Fprintln(a.stdout, "…or transport-wrap an SDK that takes an *http.Client:")
		fmt.Fprintln(a.stdout, "  client, _ := knoxcall.New(knoxcall.Options{ /* your KnoxCall key */ })")
		fmt.Fprintln(a.stdout, "  hc := &http.Client{Transport: client.Wrap.RoundTripper()}")
		return nil
	}

	// Scaffold mode: print the two-step quickstart, no writes.
	fmt.Fprintln(a.stdout, "")
	fmt.Fprintln(a.stdout, "Wrap a provider SDK through KnoxCall in two steps:")
	fmt.Fprintln(a.stdout, "")
	fmt.Fprintln(a.stdout, "1) Move the provider key into custody (key via KNOXCALL_WRAP_SECRET):")
	fmt.Fprintln(a.stdout, "   KNOXCALL_WRAP_SECRET=sk_live_… \\")
	fmt.Fprintln(a.stdout, "   knoxcall init --provider stripe --secret-name wrap-stripe --host api.stripe.com")
	fmt.Fprintln(a.stdout, "")
	fmt.Fprintln(a.stdout, "2) Route your SDK through KnoxCall (the key never re-enters your process):")
	fmt.Fprintln(a.stdout, "   client, _ := knoxcall.New(knoxcall.Options{ /* your KnoxCall key */ })")
	fmt.Fprintln(a.stdout, "   hc := &http.Client{Transport: client.Wrap.RoundTripper()}")
	fmt.Fprintln(a.stdout, "   // …or point a base-URL-only SDK at the base_url that step 1 prints.")
	return nil
}
