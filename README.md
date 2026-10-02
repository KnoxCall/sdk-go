# sdk-go

Official KnoxCall API client for Go. Standards-based OAuth 2.1 under the hood, zero dependencies (stdlib only) — your code just calls methods.

## Install

```bash
go get github.com/knoxcall/sdk-go@v1.1.0
```

## Quickstart

```go
import "github.com/knoxcall/sdk-go/knoxcall"

// Credentials inline — tenant auto-discovered from the credential.
client, err := knoxcall.New(knoxcall.Options{ClientID: "tk_xxxxxxxx", ClientSecret: "..."})

// Or zero-option with the environment configured
// (KNOXCALL_TENANT, KNOXCALL_CLIENT_ID, KNOXCALL_CLIENT_SECRET):
client, err = knoxcall.New(knoxcall.Options{})

ctx := context.Background()

// A management call…
page, err := client.Routes.List(ctx, nil)
fmt.Println(page.Meta.Total, "routes")

// …and a data-plane call through a route (slug preferred).
resp, err := client.Call(ctx, "api-orders", &knoxcall.CallOptions{Path: "/v1/customers"})
defer resp.Body.Close()
```

## Authentication

Pass credentials as plain `Options` fields:

| Option | Use |
|---|---|
| `ClientID` + `ClientSecret` | OAuth client-credentials grant (recommended for servers) |
| `APIKey` | a pre-acquired token or key — works with `kc_…` tokens and legacy `tk_…`/`AKE…` keys |
| `Credentials` | advanced: `ClientCredentials`, `AccessToken`, `OIDCTokenExchange` (workload identity), `StoredCredentials` (the `knoxcall login` file) |

Passing conflicting credential options (e.g. `APIKey` and `ClientID`) is a construction error. Explicit options always beat the environment.

> **A pre-acquired `APIKey` is not auto-renewed.** It has no refresh token, so
> the SDK uses it until it expires server-side, then surfaces a 401
> `AuthenticationError`. For long-lived processes that should re-auth on their
> own, use `ClientID` + `ClientSecret` (or `knoxcall login`), which mint and
> refresh tokens for you.
>
> **Transport & storage:** a plaintext `http://` base or proxy URL pointing at a
> non-loopback host emits a one-time warning to stderr — credentials would
> travel unencrypted; use `https://` (plain `http://` is only for localhost). On
> POSIX, the SDK also warns once if `~/.knoxcall/credentials.json` is
> group/other-accessible (`chmod 600` it — it holds a refresh token). Both
> warnings are non-blocking and never change behavior.

With no explicit credentials, the SDK resolves from the environment in priority order:

1. `KNOXCALL_ACCESS_TOKEN` (or `KNOXCALL_API_KEY`) env var
2. Credentials file written by `knoxcall login` (`~/.knoxcall/credentials.json`)
3. `KNOXCALL_CLIENT_ID` + `KNOXCALL_CLIENT_SECRET`

### Log in once with the CLI

The `knoxcall` CLI ships with this module as `cmd/knoxcall`:

```bash
go install github.com/knoxcall/sdk-go/cmd/knoxcall@latest
```

(Every KnoxCall SDK ships the same `knoxcall` CLI — pip, npm, composer, gem, and this Go module. They all have the same command surface and write the same file, so it doesn't matter which one is on your PATH.)

It signs you in once in your browser; after that, every program on the machine — every KnoxCall SDK, not just Go — picks the credential up automatically: no env vars, no keys in code:

```bash
knoxcall login                    # opens your browser (PKCE); prints the URL too
knoxcall login --device           # headless/SSH machines: device-code flow
knoxcall login --sandbox          # log in against the sandbox environment
knoxcall login --profile staging  # keep multiple accounts side by side
knoxcall whoami                   # show the signed-in tenant
knoxcall logout                   # revoke + remove the stored credential
```

```go
client, err := knoxcall.New(knoxcall.Options{}) // zero config — tenant and base URL come from the login
```

Credentials are stored in `~/.knoxcall/credentials.json` (file mode 0600).
The stored tenant and base URL seed the client automatically; explicit
`Options` fields or env vars always win. Access tokens refresh themselves,
and refreshes are cross-process safe (file lock + atomic rotation of the
single-use refresh token). If a refresh fails because the credential was
revoked or expired, the SDK returns an `AuthenticationError` telling you to
run `knoxcall login` again. Select a non-default profile with
`KNOXCALL_PROFILE` (or `Credentials: knoxcall.StoredCredentials{Profile: "staging"}`).

### Environment variables

| Variable | Meaning |
|---|---|
| `KNOXCALL_TENANT` | tenant slug (optional — auto-discovered from the credential when unset) |
| `KNOXCALL_ENVIRONMENT` | default environment for data-plane calls |
| `KNOXCALL_CLIENT_ID` / `KNOXCALL_CLIENT_SECRET` | client-credentials grant |
| `KNOXCALL_ACCESS_TOKEN` / `KNOXCALL_API_KEY` | pre-acquired token (ACCESS_TOKEN wins) |
| `KNOXCALL_BASE_URL` | management API base override (legacy alias: `KNOXCALL_API_BASE_URL`) |
| `KNOXCALL_PROXY_BASE_URL` | data-plane base override |
| `KNOXCALL_CREDENTIALS_FILE` | credentials-file path override (default `~/.knoxcall/credentials.json`) |
| `KNOXCALL_PROFILE` | credentials-file profile (default `default`) |

Set `Sandbox: true` to target the isolated Test data plane (`sandbox.knoxcall.com` management host, `sandbox-{tenant}.knoxcall.com` proxy host) with a `tk_test_` key.

## Data plane

`client.Call()` proxies a request through a KnoxCall route to your upstream and returns the raw `*http.Response` — the upstream's status belongs to you; the SDK never turns it into an error. Reference routes by **slug** — the write-once machine handle set on the route. Slugs are immutable (rename-proof, unlike names) and portable across tenants (unlike UUIDs). UUIDs also work; bare names are legacy.

```go
// GET
resp, err := client.Call(ctx, "api-orders", &knoxcall.CallOptions{Path: "/users"})

// POST with a body, targeting a specific environment
resp, err = client.Call(ctx, "api-orders", &knoxcall.CallOptions{
    Method:      "POST",
    Path:        "/v1/charges",
    Body:        map[string]any{"amount": 2000, "currency": "usd"},
    Environment: "staging",
})
```

`path` is the **upstream** path. On a KnoxCall cloud tenant host the data plane is served under `/api` (`https://{tenant}.knoxcall.com/api/<path>`); the SDK adds that prefix itself whenever the proxy base is a cloud tenant host with no path of its own, and uses any other base verbatim (self-hosted, or an override that already carries a path). So `/api/v2/tickets` reaches an upstream path that itself begins with `/api`.

For a per-call timeout, pass a context with a deadline (`context.WithTimeout`).

### Bound routes

State the route (and optional defaults) once with `client.Route()`, then use plain HTTP verbs:

```go
printnode := client.Route("api-printnode", &knoxcall.BoundRouteOptions{Environment: "production"})

resp, err := printnode.Get(ctx, "/computers", nil)
resp, err = printnode.Post(ctx, "/printjobs", &knoxcall.CallOptions{Body: job})
resp, err = printnode.Request(ctx, "DELETE", "/printjobs/42", nil)
// per-call options still override the bound defaults:
resp, err = printnode.Get(ctx, "/computers", &knoxcall.CallOptions{Environment: "staging"})
```

The handle holds no state beyond the defaults — retries, token refresh, and 401 re-mint behave exactly as on `Call()`.

### Ephemeral proxy

One-shot proxying without a pre-configured route — the proxy resolves `{{ token: "..." }}` expressions in flight:

```go
resp, err := client.Ephemeral(ctx, "https://api.stripe.com/v1/charges", &knoxcall.EphemeralOptions{
    Method: "POST",
    Body:   payload,
})
```

### Route-aware interception (preview)

Send an untouched third-party SDK's traffic through the Route that covers it —
and through the ephemeral proxy where no Route does — with no per-SDK wiring:

```go
client, _ := knoxcall.New(knoxcall.Options{APIKey: apiKey})
stop, err := client.Wrap.Intercept(ctx, knoxcall.WithHosts("api.resend.com")) // hosts with NO Route still covered (ephemeral)
if err != nil {
    log.Fatal(err)
}
defer stop.Stop()
<-stop.Ready() // first manifest loaded

// Any code — or SDK — on http.DefaultClient, untouched:
res, err := http.DefaultClient.Get("https://api.hubapi.com/crm/v3/objects/contacts") // via the Route that covers api.hubapi.com
```

Per request: the kill switch (`KNOXCALL_INTERCEPT=off`), KnoxCall's own hosts
and route-around rules go direct; a Route in the manifest covering host + path
goes through that Route (the Route injects the stored secret — no provider
credential travels); a host in `WithHosts` with no Route goes through the
ephemeral proxy; everything else goes to the previous transport untouched. Turn
a Route's **Intercept** toggle on and it takes effect on the next poll (60 s)
or the next refusal, with no code change. Per-host options:
`knoxcall.WithHost("api.resend.com", knoxcall.HostEscrow("resend-key"))`
(escrow) or `knoxcall.HostUnavailableDirect()` (transit only: send direct when
KnoxCall is unreachable; the default is fail closed). `knoxcall.WithRequireContext()`
limits interception to requests whose context descends from `client.Wrap.Routed(ctx)`.

Reached: `http.DefaultClient` and any `*http.Client` with a nil `Transport`
(most SDK defaults). Not reached: a client built with its own `Transport` —
hand those `client.Wrap.RoundTripper(knoxcall.WithRoutes())` instead, which
makes the same decisions for an explicit transport (`Ready()`, `Refresh(ctx)`,
`Manifest()`, `Stop()`); without `WithRoutes` it is the ephemeral-only
transport it always was (transit lifts the SDK's own `Authorization`
out-of-band; `WithEscrow` sends a named escrowed credential instead).

This is a convenience, not a security boundary: it replaces a process global
(`http.DefaultTransport`) and composes with APM transports in install order.
Route mode is the custody path — the key never enters your process.

#### What the SDK reports about uncovered calls, and how to turn it off

**Reporting is on by default.** When the interceptor sends a call direct
because no Route covers its host and you did not list the host, and that call
carries a credential header (`Authorization`, `X-Api-Key`, or any name ending
in `-api-key`, `-token`, `-secret` or `-auth`), the SDK counts it. About once a
minute, the SDK reports the counts to KnoxCall
(`POST /v1/wrap/egress-observations`) with its own credential. The dashboard
uses the report to show which credentials still leave your process outside
KnoxCall custody.

**What is sent.** Each report carries the host, the first path segment, the
method, the credential header's **name**, a count, and first/last-seen times.
The header's **value** is never sent, and neither are the query string, the
body, or any deeper path.

**How to turn it off.** Pass `knoxcall.WithObserveUncovered(false)` when you install, or set
`KNOXCALL_OBSERVE_UNCOVERED=off` in the environment. Nothing is reported while
`KNOXCALL_INTERCEPT=off`. If your key lacks `routes:read`, the first report is
refused, you get one warning, and reporting stops. `knoxcall.WithOnObservationFlush` receives the
server's `{accepted, dropped}` after each report.

## Pagination

The server wraps every JSON response in `{data, meta}` and paginates with `page`/`per_page` (default 20, cap 100). Single-object methods return the unwrapped object; paginated lists return a typed `Page[T]` mirroring the envelope; a few endpoints (environments, agents, crypto keys, PKI, dynamic-DB, OAuth clients, client credentials, route environments) return plain slices and take no page params.

```go
page, err := client.Secrets.List(ctx, &knoxcall.ListParams{Page: 2, PerPage: 50})
fmt.Println(page.Meta.Total, page.Meta.TotalPages, page.Meta.RequestID)

// Walk every page in one call:
all, err := client.Secrets.ListAll(ctx, nil)

// Or stream lazily, one item at a time (Go 1.23+ range-over-func) — fetches the
// next page only as you consume it, so large audit-log / token lists never
// buffer in full. The second range value carries any per-page error:
for secret, err := range client.Secrets.Iterate(ctx, nil) {
    if err != nil {
        // handle and break — the range ends after an error
        break
    }
    fmt.Println(secret.ID)
}
```

`ListAll` fetches page by page until `page >= meta.total_pages` (or an empty page), buffering everything into one slice. `Iterate` uses the same paging but yields one item at a time and stops fetching the moment your loop breaks — prefer it for unbounded lists (`AuditLogs.Iterate`, `Vaults.IterateTokens`, `AIGateway.IterateTokens`, …). Every resource with a `ListAll*` has a matching `Iterate*`. Log endpoints (`Routes.GetLogs`, `Webhooks.GetLogs`) are unbounded time-series, so they expose only the page form — loop on `Meta.TotalPages` yourself if you really need everything.

## Resources

One-liner per area (all methods take a `context.Context` first):

```go
// Routes
route, err := client.Routes.Create(ctx, knoxcall.CreateRouteInput{Name: "orders", TargetBaseURL: "https://api.example.com"})
logs, err := client.Routes.GetLogs(ctx, route.ID, nil)

// Route field-actions (declarative field-level encrypt/tokenize on the proxy path)
action, err := client.Routes.CreateAction(ctx, route.ID, knoxcall.CreateRouteActionInput{
    Direction: "request", Action: "tokenize", Selectors: []string{"$.card.number"}, KeyName: "cards-vault",
})

// Secrets (string, OAuth2-provider, and certificate/mTLS types)
secret, err := client.Secrets.Create(ctx, knoxcall.CreateSecretInput{Name: "STRIPE_KEY", Value: "sk_live_..."})
_, err = client.Secrets.SetValue(ctx, secret.ID, "sk_live_rotated", "production")
oauth, err := client.Secrets.CreateOAuth2(ctx, knoxcall.CreateOAuth2SecretInput{
    Name: "salesforce", Provider: "custom", ClientID: "cid", ClientSecret: "csecret",
    Scopes: []string{"api"}, TokenURL: "https://login.example/token",
})
cert, err := client.Secrets.CreateCertificate(ctx, knoxcall.CreateCertificateSecretInput{
    Name: "upstream-mtls", CertificateContent: pemText, PrivateKey: keyPEM,
})

// Webhooks (Create returns the once-only SecretKey — store it)
wh, err := client.Webhooks.Create(ctx, knoxcall.CreateWebhookInput{
    Name: "orders-hook", URL: "https://hooks.example.com/knox", EventTypes: []string{"request.error"},
})
types, err := client.Webhooks.ListEventTypes(ctx)
result, err := client.Webhooks.Test(ctx, wh.ID)

// Clients (calling machines) + credentials
kc, err := client.Clients.Create(ctx, knoxcall.CreateClientInput{Name: "ci-runner", Type: "server", IPAddress: "203.0.113.9"})
creds, err := client.Clients.ListCredentials(ctx, kc.ID)

// OAuth clients (ClientSecret shown once; Warning carries the server's top-level warning)
oc, err := client.OAuthClients.Create(ctx, knoxcall.CreateOAuthClientInput{Name: "svc"})

// Environments (bare array — no pagination)
envs, err := client.Environments.List(ctx)

// API keys (Create returns the once-only plaintext key)
key, err := client.APIKeys.Create(ctx, knoxcall.CreateAPIKeyInput{Name: "deploy-bot"})

// Account
acct, err := client.Account.Get(ctx)
usage, err := client.Account.GetUsage(ctx)

// Audit logs
audit, err := client.AuditLogs.ListAll(ctx, &knoxcall.AuditLogParams{Action: "secret.create"})

// Agents (AgentSecret shown once)
agent, err := client.Agents.Create(ctx, "warehouse-agent")

// Crypto — keyed transit encryption
encRes, err := client.Crypto.Encrypt(ctx, "payments-key", knoxcall.EncryptInput{Plaintext: "hello"})
decRes, err := client.Crypto.Decrypt(ctx, "payments-key", encRes.Ciphertext, "utf8")

// Crypto — portable kc: encryption (structure-preserving, zero-config default key)
enc, err := client.Crypto.EncryptData(ctx, map[string]any{"card": "4242..."}, nil)
dec, err := client.Crypto.DecryptData(ctx, json.RawMessage(enc.Ciphertext), nil)
meta, err := client.Crypto.Inspect(ctx, "kc:1:enc:...")
bundle, err := client.Crypto.GetSealingBundle(ctx, "") // public bits for browser-side sealing
capTok, err := client.Crypto.MintClientToken(ctx, knoxcall.MintClientTokenInput{Action: "decrypt", Data: "kc:1:enc:..."})

// PKI (cert + CRL are raw text, not JSON)
root, err := client.PKI.CreateRoot(ctx, "internal", map[string]any{"common_name": "Acme Internal CA"})
pem, err := client.PKI.GetRootCert(ctx, "internal")
leaf, err := client.PKI.IssueCert(ctx, "internal", "servers", knoxcall.IssueCertInput{Subject: map[string]any{"common_name": "db.acme.internal"}})

// Vaults (tokenization)
vault, err := client.Vaults.Create(ctx, knoxcall.CreateVaultInput{Name: "cards-vault"})
tok, err := client.Vaults.Tokenize(ctx, "cards-vault", knoxcall.TokenizeInput{Value: "4242424242424242"})
val, err := client.Vaults.Detokenize(ctx, "cards-vault", tok.Token)

// AI Gateway (secret -> gateway -> agent -> capability token).
// Provider + UpstreamSecretID compose the upstream route. An agent created
// with NEITHER those nor PrimaryRouteID has no upstream and 502s on its first
// data-plane call. Provider is a plain string: the catalog is server-side and
// a bad value comes back as a 400 naming the valid set.
secret, err := client.Secrets.Create(ctx, knoxcall.CreateSecretInput{
	Name: "anthropic-key", Value: os.Getenv("ANTHROPIC_API_KEY"),
})
gw, err := client.AIGateway.CreateGateway(ctx, knoxcall.CreateAIGatewayInput{Name: "Prod", Slug: "prod"})
agent, err := client.AIGateway.CreateAgent(ctx, gw.ID, knoxcall.CreateAIGatewayAgentInput{
	Name: "copilot", Slug: "copilot",
	Provider: "anthropic", UpstreamSecretID: secret.ID,
	DefaultModel: "claude-sonnet-5",
})
minted, err := client.AIGateway.MintToken(ctx, agent.ID, knoxcall.MintAIGatewayTokenInput{Kind: "agent"})
// minted.Token is the plaintext capability token — shown exactly once.
// agent.AgentURL is the base_url to point an AI SDK at.

// Dynamic DB credentials
minted, err := client.DynamicDB.Mint(ctx, "main-pg", "readonly", nil)
leases, err := client.DynamicDB.ListLeases(ctx, nil)

// Signup — credential-less, no client needed. TWO steps: signup never returns
// a credential, it returns a claim handle and emails a sign-in link.
accepted, err := knoxcall.Signup(ctx, knoxcall.SignupInput{Email: "dev@example.com", TenantName: "Acme Inc"}, nil)
// …the account owner clicks the emailed sign-in link…
claim, err := knoxcall.ClaimSignup(ctx, accepted.ClaimHandle, nil)
for claim.Status == "pending" {
    time.Sleep(time.Duration(accepted.PollAfterSeconds) * time.Second)
    claim, err = knoxcall.ClaimSignup(ctx, accepted.ClaimHandle, nil)
}
// claim.Starter.APIKey.APIKey is shown exactly once — store it now.
```

## Webhook verification

`ConstructWebhookEvent` (also available as `client.Webhooks.ConstructEvent`) verifies the delivery's HMAC-SHA256 signature and parses it into a typed event in one step. Pass the raw body bytes — never re-serialized JSON.

```go
func handler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    event, err := knoxcall.ConstructWebhookEvent(body, r.Header, endpointSecret, nil)
    if err != nil {
        var ve *knoxcall.WebhookSignatureVerificationError
        if errors.As(err, &ve) {
            http.Error(w, "bad signature", http.StatusBadRequest)
            return
        }
    }
    switch event.Event {
    case "audit.event":
        audit, _ := event.AuditData()
        log.Println("audit:", audit.Action)
    default: // request.*
        data, _ := event.RequestData()
        log.Println(data.RouteName, data.Response.Status)
    }
}
```

Formats beyond the default `legacy` header (`stripe`, `github`, `slack`, `aws-sns`, `custom`) are selected with `&knoxcall.ConstructEventOptions{Format: "stripe"}`; the replay window defaults to 300s (`ToleranceSeconds` pointer-to-0 disables it); `custom` requires `HeaderName`. The boolean `VerifySignature` helper remains for existing code.

## Errors

All API failures are typed and unwrap to `*APIError` (status, machine-readable type in `Message`, human message in `Detail`, `RequestID` for support):

```go
_, err := client.Routes.Create(ctx, input)
var rl *knoxcall.RateLimitError
var ve *knoxcall.ValidationError
switch {
case errors.As(err, &rl):
    time.Sleep(time.Duration(rl.RetryAfter) * time.Second)
case errors.As(err, &ve):
    log.Println("validation failed:", ve.Fields)
}
```

Hierarchy: `AuthenticationError` (401), `PermissionDeniedError` (403), `NotFoundError` (404), `ConflictError` (409), `ValidationError` (422), `RateLimitError` (429), `ServerError` (5xx), plus `SignupError`, `WebhookSignatureVerificationError`, and `ConnectionError`/`ConnectionTimeoutError` for transport failures.

## Retries & idempotency

Management requests retry automatically on transport errors and HTTP 408/429/500/502/503/504 (never 409 — a real conflict does not resolve by replaying), with exponential half-jitter backoff and `Retry-After` honored up to 30s. Every mutating request carries a ULID `X-Idempotency-Key` that stays stable across retries, so replays are safe. A 401 purges the cached token and retries once with fresh credentials. Tune with `Options{RetryMaxAttempts, RetryBaseDelay, RetryMaxDelay}`.

## DPoP — sender-constrained tokens

For higher-security tenants, enable DPoP (RFC 9449):

```go
client, err := knoxcall.New(knoxcall.Options{Tenant: "acme", DPoP: "always"})
```

The SDK generates an ES256 keypair, binds the access token to it via the `cnf.jkt` claim, and signs a fresh proof JWT per request — token, management, and data-plane alike. Stolen tokens become useless without the keypair.

In the default `"auto"` mode the SDK starts with plain Bearer tokens and upgrades to DPoP automatically when the OAuth client record has `require_dpop` set (the token endpoint answers `invalid_dpop_proof`; the SDK generates a keypair, retries once, and operates as DPoP from then on). `DPoP: "never"` opts out — if the server issues a DPoP-bound token anyway, the SDK returns a typed error rather than 401-looping.
