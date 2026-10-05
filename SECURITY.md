# Security Policy

KnoxCall is a credential-custody platform; the security of this SDK is part of
that promise. We appreciate reports from the community.

## Supported versions

| Package | Version | Supported |
|---|---|---|
| `github.com/knoxcall/sdk-go` on the Go module proxy | 1.x | yes — security fixes are released as a new patch version |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
GitHub issue for a security report.

- Email: **security@knoxcall.com**
- Or use GitHub's private "Report a vulnerability" advisory flow on this
  repository.

Include the affected version, the SDK surface involved (credential resolution,
OAuth / PKCE / device flows, DPoP, the data-plane `call()` path, request
interception, webhook verification, …) and a proof of concept where possible.
Please do not include real customer secrets or tokens in your report.

| Timeline | Action |
|---|---|
| Within 24 hours | Acknowledgement of your report |
| Within 72 hours | Initial assessment and severity classification |
| Within 14 days | Remediation plan confirmed and shared with you |
| Within 90 days | Fix released (critical / high); coordinated disclosure |

We support coordinated disclosure and credit reporters who wish to be named
once a fix is released.

## Scope

In scope: credential resolution and storage (`~/.knoxcall/credentials.json`,
its file lock and refresh-token rotation), OAuth / PKCE / device flows, DPoP
proof generation, the data-plane credential-transmission rules, route-aware
request interception, webhook signature verification, and secret redaction in
logs and errors.

Out of scope: vulnerabilities in your own application code, third-party
transport libraries (report those upstream), and issues that require a
pre-compromised local machine or a maliciously modified credentials file.

## How this SDK handles secrets

These are guarantees every KnoxCall SDK keeps (the SDK parity spec):

- Client secrets, access tokens, refresh tokens and OIDC subject tokens never
  appear in debug output: tokens are held in redacting wrappers, and bootstrap
  credential fields are excluded from string / inspect output.
- Refresh tokens are single-use and rotated on every refresh, under a file
  lock with an atomic write-back; suspected reuse revokes the token family
  server-side.
- Credential values are never sent to a destination outside KnoxCall; the
  uncovered-egress reporter sends header NAMES and counts only, never values.

## Automated checks

Dependency updates are proposed by Dependabot on this repository. The SDK's
source of truth is the KnoxCall monorepo, whose CI runs this SDK's test suite
and a dependency audit (`govulncheck`) on every change, plus CodeQL and Trivy.
