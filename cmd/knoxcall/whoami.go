// `knoxcall whoami` — show the signed-in tenant via the SDK client.
package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/knoxcall/sdk-go/internal/credfile"
	"github.com/knoxcall/sdk-go/knoxcall"
)

func (a *app) cmdWhoami(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	profileFlag := fs.String("profile", "", "credentials profile name (default: KNOXCALL_PROFILE or 'default')")
	if err := parseFlags(fs, args, whoamiHelp, a.stdout); err != nil {
		return err
	}

	path := credfile.ResolvePath("")
	profile := credfile.ResolveProfile(*profileFlag)
	if credfile.ReadProfile(path, profile) == nil {
		return fmt.Errorf("not logged in (profile '%s') — run `knoxcall login`", profile)
	}

	client, err := knoxcall.New(knoxcall.Options{
		Credentials: knoxcall.StoredCredentials{Path: path, Profile: profile},
		HTTPClient:  a.http,
	})
	if err != nil {
		return err
	}
	account, err := client.Account.Get(ctx)
	if err != nil {
		return err
	}

	display := account.Name
	if display == "" {
		display = account.Slug
	}
	if display == "" {
		display = "(unknown)"
	}
	fmt.Fprintf(a.stdout, "Tenant: %s\n", display)
	if account.Slug != "" {
		fmt.Fprintf(a.stdout, "Slug:   %s\n", account.Slug)
	}
	if account.SubscriptionPlan != "" {
		fmt.Fprintf(a.stdout, "Plan:   %s\n", account.SubscriptionPlan)
	}
	fmt.Fprintf(a.stdout, "Profile: %s (%s)\n", profile, path)
	return nil
}
