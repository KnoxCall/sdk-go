// `knoxcall login` — auth-code+PKCE via loopback redirect, or device flow.
// The flow itself lives in internal/clilogin (shared with knoxcall.Login);
// this file is just the command wiring.
package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/knoxcall/sdk-go/internal/clilogin"
	"github.com/knoxcall/sdk-go/internal/credfile"
)

func (a *app) cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant slug hint for the sign-in page")
	baseURLFlag := fs.String("base-url", "", "management API base URL (default https://api.knoxcall.com, or KNOXCALL_BASE_URL)")
	sandbox := fs.Bool("sandbox", false, "log in against the sandbox environment")
	profileFlag := fs.String("profile", "", "credentials profile name (default: KNOXCALL_PROFILE or 'default')")
	device := fs.Bool("device", false, "use the device-code flow (headless/SSH machines)")
	noBrowser := fs.Bool("no-browser", false, "never open a browser (implies the device-code flow)")
	if err := parseFlags(fs, args, loginHelp, a.stdout); err != nil {
		return err
	}

	baseURL := strings.TrimRight(clilogin.DefaultBaseURL(*baseURLFlag, *sandbox), "/")
	path := credfile.ResolvePath("")
	profile := credfile.ResolveProfile(*profileFlag)

	var tokenBody map[string]any
	var err error
	if *device || *noBrowser {
		tokenBody, err = a.deviceFlow(ctx, baseURL)
	} else {
		tokenBody, err = a.authCodeFlow(ctx, baseURL, *tenant, clilogin.DefaultBrowserTimeout)
	}
	if err != nil {
		return err
	}

	record, err := persistLogin(ctx, path, profile, baseURL, tokenBody, *tenant)
	if err != nil {
		return err
	}

	tenantName := strVal(record, "tenant")
	if tenantName == "" {
		tenantName = "(tenant not reported)"
	}
	fmt.Fprintf(a.stdout, "\nLogged in to %s (%s)\n", tenantName, baseURL)
	if scope := strVal(record, "scope"); scope != "" {
		fmt.Fprintf(a.stdout, "Scopes: %s\n", scope)
	}
	fmt.Fprintf(a.stdout, "Credentials written to %s (profile '%s')\n", path, profile)
	if strVal(record, "refresh_token") == "" {
		fmt.Fprintln(a.stdout, "Warning: no refresh token was issued — access will expire without renewal.")
	}
	return nil
}
