// `knoxcall logout` — best-effort revoke, then remove the stored profile.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"strings"

	"github.com/knoxcall/sdk-go/internal/credfile"
)

func (a *app) cmdLogout(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	profileFlag := fs.String("profile", "", "credentials profile name (default: KNOXCALL_PROFILE or 'default')")
	if err := parseFlags(fs, args, logoutHelp, a.stdout); err != nil {
		return err
	}

	path := credfile.ResolvePath("")
	profile := credfile.ResolveProfile(*profileFlag)
	record := credfile.ReadProfile(path, profile)
	if record == nil {
		fmt.Fprintf(a.stdout, "No stored credentials for profile '%s' — nothing to do.\n", profile)
		return nil
	}

	refreshToken := strVal(record, "refresh_token")
	baseURL := strings.TrimRight(strVal(record, "base_url"), "/")
	if refreshToken != "" && baseURL != "" {
		clientID := strVal(record, "client_id")
		if clientID == "" {
			clientID = cliClientID
		}
		// Best-effort: removal proceeds even when revocation is unreachable.
		_, _, _ = a.postForm(ctx, baseURL+"/oauth/revoke", url.Values{
			"token":           {refreshToken},
			"token_type_hint": {"refresh_token"},
			"client_id":       {clientID},
		})
	}

	lock := credfile.NewLock(path)
	if err := lock.Acquire(ctx); err != nil {
		return err
	}
	defer lock.Release()
	if _, err := credfile.RemoveProfile(path, profile); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Logged out — removed profile '%s' from %s.\n", profile, path)
	return nil
}
