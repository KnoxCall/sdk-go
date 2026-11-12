package knoxcall

// Workload-identity credential provider — WIF plan Phase 4.3.
//
// Mirrors auth/workload-provider.ts in the Node SDK; ../../PARITY.md is the
// authoritative contract for every language.
//
// ExchangeToken is one-shot: it trades one OIDC assertion for one capability
// token and hands the caller an ExpiresIn to manage. That is fine for a program
// that makes one call and exits, and wrong for anything long-lived — a polling
// worker, a long CI job, an agent process — where the token silently expires
// mid-run and the caller discovers it as a 401 they then have to interpret.
//
// This provider owns that lifecycle: cache the token, refresh it before it
// dies, and never hand out one that is about to expire.
//
// ── THE PART THAT IS NOT LIKE OTHER REFRESH LOOPS ───────────────────────────
//
// A KnoxCall workload assertion is SINGLE-USE. The exchange spends the whole
// assertion — the server claims a hash of it before minting (WIF Phase 1.2), so
// presenting the same bytes twice is refused with "subject_token has already
// been exchanged". A refresh therefore cannot re-send the assertion it used
// last time; it needs a FRESH one from the platform every single time.
//
// That makes the obvious implementation — capture the assertion once, reuse it
// on refresh — not merely suboptimal but broken, and broken in a way that only
// shows up when the first refresh fires, i.e. minutes into production rather
// than in anyone's smoke test. So the provider takes a SOURCE it calls before
// every exchange, and refuses to send an assertion whose bytes it has already
// spent (*StaleAssertionError). It fails loudly at the real cause rather than
// forwarding a doomed request and surfacing the server's replay refusal, which
// reads as "my credentials were rejected" and sends the reader hunting in the
// wrong place.
//
// ── THE TWO-TIER SCHEDULE ───────────────────────────────────────────────────
//
// ADVISORY (expiry − 120s): refresh opportunistically. If it fails, the token
// in hand is still valid, so the caller is served and the failure is a warning,
// not an error. A transient blip near a refresh boundary must not take down a
// worker that has two minutes of perfectly good credential left.
//
// MANDATORY (expiry − 30s): refresh or fail. Below this line the token may die
// in flight — between the provider handing it over and the request reaching the
// server — and a 401 from an expired capability token is exactly the confusing
// failure this provider exists to prevent.
//
// The gap between the two tiers is the whole point: it buys 90 seconds in which
// a failing token source or a flaky network is survivable rather than fatal.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// AdvisoryRefresh is the remaining-life threshold below which the provider
	// refreshes opportunistically. A failure here is survivable.
	AdvisoryRefresh = 120 * time.Second
	// MandatoryRefresh is the remaining-life threshold below which the provider
	// must refresh or fail: the token may die in flight.
	MandatoryRefresh = 30 * time.Second
)

// WorkloadAssertionSource produces the workload's CURRENT OIDC assertion.
//
// Called before EVERY exchange, never cached by the provider. On GitHub Actions
// this is a fetch of ACTIONS_ID_TOKEN_REQUEST_URL; on GCP or EKS a read of the
// metadata service or the projected token file. Whatever it is, it must mint or
// re-read — returning a value captured once at startup is the failure this
// provider detects rather than tolerates.
type WorkloadAssertionSource func(ctx context.Context) (string, error)

// StaleAssertionError means the source returned bytes already spent on a
// previous exchange, so sending them could only have been refused.
//
// This is a caller-side configuration error, not a credential rejection, and it
// says so: the message names the cause and what to do, because the alternative
// is a replay refusal from the server that reads like "your CI identity is not
// trusted".
type StaleAssertionError struct{ Message string }

func (e *StaleAssertionError) Error() string { return e.Message }

// WorkloadCredentialProviderOptions configures NewWorkloadCredentialProvider.
// The exchange fields carry the same meaning as ExchangeTokenInput /
// ExchangeTokenOptions, because they are passed straight through.
type WorkloadCredentialProviderOptions struct {
	// Assertion is called before every exchange and must return a FRESH
	// assertion each time. Required.
	Assertion WorkloadAssertionSource
	// Resource is the RFC 8707 resource indicator — a POINTER for the same
	// reason as ExchangeTokenInput.Resource: an empty string must reach the
	// server and be refused invalid_target, never be treated as absent.
	Resource *string
	// Audience defaults to KnoxCallAudience.
	Audience string
	// Tenant is the tenant slug. One of Tenant or BaseURL is REQUIRED: the
	// endpoint is served only on the tenant data-plane host.
	Tenant string
	// Sandbox selects the Test data space. Carried through verbatim: dropping
	// it would send a Test-mode workload's assertion to the Live host, where it
	// matches no binding — a confusing refusal produced by the provider rather
	// than by the caller's configuration.
	Sandbox bool
	// BaseURL is the full data-plane origin; wins over Tenant.
	BaseURL string
	// HTTPClient overrides the default 30s-timeout client.
	HTTPClient *http.Client
}

// WorkloadCredentialProvider caches a workload capability token and refreshes
// it on the two-tier schedule.
//
// The mutex gives single-flight semantics, exactly as (*Client).getToken does —
// which matters more here than in an ordinary refresh loop: each exchange
// spends an assertion, and a thundering herd would burn N of them and have N−1
// refused. Safe for concurrent use by multiple goroutines.
//
//	p, err := knoxcall.NewWorkloadCredentialProvider(knoxcall.WorkloadCredentialProviderOptions{
//	    Assertion: mintGitHubIDToken,
//	    Tenant:    "acme",
//	})
//	token, err := p.AccessToken(ctx)
type WorkloadCredentialProvider struct {
	opts WorkloadCredentialProviderOptions

	mu     sync.Mutex
	cached *cachedToken
	// spent holds the sha256 of every assertion this provider has exchanged.
	// Never the assertion itself.
	spent map[string]struct{}

	// now is a clock seam for tests; nil means time.Now.
	now func() time.Time
}

// NewWorkloadCredentialProvider validates the options and returns a provider.
//
// It does not perform an exchange: the first AccessToken call does, so a
// provider can be constructed at startup before the workload's token endpoint
// is reachable.
func NewWorkloadCredentialProvider(opts WorkloadCredentialProviderOptions) (*WorkloadCredentialProvider, error) {
	if opts.Assertion == nil {
		return nil, &BootstrapError{Message: "NewWorkloadCredentialProvider needs an Assertion source: " +
			"a func(ctx) (string, error) returning the workload's CURRENT OIDC id_token. " +
			"KnoxCall assertions are single-use, so it is called before every exchange."}
	}
	// Fail at construction rather than at the first refresh, which may be
	// minutes into a long-running process.
	if _, err := resolveExchangeBaseURL(&ExchangeTokenOptions{
		Tenant:  opts.Tenant,
		Sandbox: opts.Sandbox,
		BaseURL: opts.BaseURL,
	}); err != nil {
		return nil, err
	}
	return &WorkloadCredentialProvider{opts: opts, spent: map[string]struct{}{}}, nil
}

func (p *WorkloadCredentialProvider) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// AccessToken returns a capability token with more than MandatoryRefresh of
// life left, exchanging a fresh assertion when the cached one is too close to
// expiry.
func (p *WorkloadCredentialProvider) AccessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if tok := p.cached; tok != nil {
		remaining := tok.expiresAt.Sub(p.clock())
		if remaining > AdvisoryRefresh {
			return tok.accessToken, nil
		}
		if remaining > MandatoryRefresh {
			// ADVISORY tier: try, but the token in hand is still good.
			fresh, err := p.refreshLocked(ctx)
			if err != nil {
				// best-effort: the caller still has a valid credential, and
				// failing here would convert a survivable blip into an outage.
				// The MANDATORY tier raises it for real if it persists.
				warnOnce("KNOXCALL_WORKLOAD_ADVISORY_REFRESH", fmt.Sprintf(
					"KnoxCall: advisory token refresh failed (%v); continuing with the current "+
						"token, which expires in %ds", err, int(remaining.Seconds())))
				return tok.accessToken, nil
			}
			return fresh, nil
		}
	}

	// MANDATORY tier, or nothing cached at all.
	return p.refreshLocked(ctx)
}

// refreshLocked exchanges a fresh assertion. The caller holds p.mu, which is
// what makes the exchange single-flight.
func (p *WorkloadCredentialProvider) refreshLocked(ctx context.Context) (string, error) {
	assertion, err := p.opts.Assertion(ctx)
	if err != nil {
		return "", err
	}
	if assertion == "" {
		return "", &StaleAssertionError{Message: "the workload assertion source returned nothing. " +
			"It must return the workload's current OIDC id_token on every call."}
	}

	sum := sha256.Sum256([]byte(assertion))
	fingerprint := hex.EncodeToString(sum[:])
	if _, spent := p.spent[fingerprint]; spent {
		return "", &StaleAssertionError{Message: "the workload assertion source returned an assertion " +
			"that has already been exchanged. KnoxCall assertions are single-use, so each refresh " +
			"needs a NEWLY minted one — call the platform's token endpoint inside the source (for " +
			"example re-fetch ACTIONS_ID_TOKEN_REQUEST_URL, or re-read the projected service-account " +
			"token file) rather than capturing one value at startup."}
	}

	res, err := ExchangeToken(ctx,
		ExchangeTokenInput{
			SubjectToken: assertion,
			Resource:     p.opts.Resource,
			Audience:     p.opts.Audience,
		},
		&ExchangeTokenOptions{
			Tenant:     p.opts.Tenant,
			Sandbox:    p.opts.Sandbox,
			BaseURL:    p.opts.BaseURL,
			HTTPClient: p.opts.HTTPClient,
		})
	if err != nil {
		return "", err
	}

	// Recorded only after the exchange returns, so a network failure does not
	// burn a fingerprint the caller could legitimately retry with. The server
	// claims the assertion before it mints, so a SUCCESS is what makes those
	// bytes unusable.
	p.spent[fingerprint] = struct{}{}

	lifetime := time.Duration(res.ExpiresIn) * time.Second
	p.cached = &cachedToken{
		accessToken: res.AccessToken,
		tokenType:   "Bearer",
		expiresAt:   p.clock().Add(lifetime),
		lifetime:    lifetime,
	}
	return res.AccessToken, nil
}
