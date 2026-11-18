package knoxcall

import "fmt"

// Credentials is a bootstrap credential used to mint access tokens.
// Implementations: ClientCredentials, AccessToken, OIDCTokenExchange, and
// StoredCredentials (the `knoxcall login` credentials file — see
// credentials_file.go).
//
// All implementations redact their secret fields from fmt output
// (%v, %+v, %#v) so accidental logging can never leak them.
type Credentials interface {
	isCredentials()
}

// ClientCredentials authenticates with an OAuth 2.1 client_credentials grant
// against the KnoxCall token endpoint.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

func (ClientCredentials) isCredentials() {}

// String implements fmt.Stringer, redacting ClientSecret so %v / %+v / %s
// can never leak it.
func (c ClientCredentials) String() string {
	return fmt.Sprintf("knoxcall.ClientCredentials{ClientID:%q, ClientSecret:%s}", c.ClientID, redacted)
}

// GoString implements fmt.GoStringer, redacting ClientSecret from %#v.
func (c ClientCredentials) GoString() string { return c.String() }

// AccessToken authenticates with a pre-acquired access token or static
// KnoxCall API key, used directly as the Bearer token.
type AccessToken struct {
	Token string
}

func (AccessToken) isCredentials() {}

// String implements fmt.Stringer, redacting the token from %v / %+v / %s.
func (a AccessToken) String() string {
	return fmt.Sprintf("knoxcall.AccessToken{Token:%s}", redacted)
}

// GoString implements fmt.GoStringer, redacting the token from %#v.
func (a AccessToken) GoString() string { return a.String() }

// OIDCTokenExchange exchanges a workload OIDC identity token (e.g. from
// GitHub Actions, GCP, AWS IRSA, Azure MI, Vercel, CircleCI) for a KnoxCall
// access token via the RFC 8693 token-exchange grant.
type OIDCTokenExchange struct {
	SubjectToken string
	Issuer       string
}

func (OIDCTokenExchange) isCredentials() {}

// String implements fmt.Stringer, redacting the subject token from
// %v / %+v / %s. Issuer is not sensitive and is shown.
func (o OIDCTokenExchange) String() string {
	return fmt.Sprintf("knoxcall.OIDCTokenExchange{SubjectToken:%s, Issuer:%q}", redacted, o.Issuer)
}

// GoString implements fmt.GoStringer, redacting the subject token from %#v.
func (o OIDCTokenExchange) GoString() string { return o.String() }

const redacted = "[REDACTED]"

func redactIfSet(s string) string {
	if s == "" {
		return `""`
	}
	return redacted
}
