package main

import "github.com/knoxcall/sdk-go/internal/clilogin"

// openBrowser launches the platform's URL opener. It delegates to
// clilogin.OpenBrowser (the shared implementation); callers ALWAYS print the
// URL first, so a broken or headless launcher is never fatal.
func openBrowser(url string) error { return clilogin.OpenBrowser(url) }
