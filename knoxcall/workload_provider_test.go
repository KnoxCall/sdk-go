package knoxcall

// WorkloadCredentialProvider — WIF Phase 4.3. Twin of the Node SDK's
// test/workload-provider.test.ts; ../../PARITY.md is the shared contract.
//
// The contract worth testing is not "it caches a token". It is the two rules
// that come from KnoxCall assertions being SINGLE-USE:
//
//  1. every exchange reads a FRESH assertion from the source, and an assertion
//     whose bytes were already spent is refused locally with an error that names
//     the real cause — rather than forwarded to be refused as a replay, which
//     reads as "your CI identity was rejected";
//  2. N concurrent callers cause ONE exchange, because each exchange spends an
//     assertion and a herd would burn N of them to have N−1 refused.
//
// Plus the two-tier boundary: advisory failures are survivable, mandatory ones
// are not, and the 90 seconds between them is the point of having two tiers.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const providerLifetime = 900 * time.Second // expires_in, what the gateway mints today

// providerExchange is a fake POST /v1/oauth/token that records every request.
type providerExchange struct {
	mu       sync.Mutex
	bodies   []map[string]any
	failNext error
	n        int
	srv      *httptest.Server
}

func newProviderExchange(t *testing.T) *providerExchange {
	t.Helper()
	ex := &providerExchange{}
	ex.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ex.mu.Lock()
		defer ex.mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		ex.bodies = append(ex.bodies, body)
		if ex.failNext != nil {
			ex.failNext = nil
			// A 500 with no RFC 6749 body is the closest a test server can get
			// to "the token endpoint is having a bad minute".
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"server_error","error_description":"token endpoint 503"}`))
			return
		}
		ex.n++
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"kp_live_tok%d","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900}`, ex.n)
	}))
	t.Cleanup(ex.srv.Close)
	return ex
}

func (e *providerExchange) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.bodies)
}

func (e *providerExchange) body(i int) map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bodies[i]
}

func (e *providerExchange) failOnce() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failNext = errors.New("fail")
}

// freshSource returns a distinct assertion per call, as a real platform token
// endpoint produces.
func freshSource() (WorkloadAssertionSource, *int) {
	n := 0
	return func(context.Context) (string, error) {
		n++
		return fmt.Sprintf("assertion-%d", n), nil
	}, &n
}

func newTestProvider(t *testing.T, ex *providerExchange, clock *time.Time, src WorkloadAssertionSource, mutate ...func(*WorkloadCredentialProviderOptions)) *WorkloadCredentialProvider {
	t.Helper()
	opts := WorkloadCredentialProviderOptions{
		Assertion: src,
		BaseURL:   ex.srv.URL,
	}
	for _, m := range mutate {
		m(&opts)
	}
	p, err := NewWorkloadCredentialProvider(opts)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	p.now = func() time.Time { return *clock }
	return p
}

// -- the single-use rule -----------------------------------------------------

func TestWorkloadProviderReadsAFreshAssertionForEveryExchange(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, calls := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(providerLifetime - MandatoryRefresh/2) // past the mandatory line
	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}

	if ex.count() != 2 || *calls != 2 {
		t.Fatalf("want 2 exchanges from 2 assertions, got %d exchanges / %d source calls", ex.count(), *calls)
	}
	if got := ex.body(0)["subject_token"]; got != "assertion-1" {
		t.Errorf("first subject_token = %v", got)
	}
	if got := ex.body(1)["subject_token"]; got != "assertion-2" {
		t.Errorf("second subject_token = %v, the provider reused the first assertion", got)
	}
}

func TestWorkloadProviderRefusesARepeatedAssertionWithoutSendingIt(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	stuck := func(context.Context) (string, error) { return "captured-once-at-startup", nil }
	p := newTestProvider(t, ex, &clock, stuck)

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if ex.count() != 1 {
		t.Fatalf("want 1 exchange, got %d", ex.count())
	}

	clock = clock.Add(providerLifetime) // force a mandatory refresh
	_, err := p.AccessToken(context.Background())
	var stale *StaleAssertionError
	if !errors.As(err, &stale) {
		t.Fatalf("want *StaleAssertionError, got %T: %v", err, err)
	}
	// The doomed request is never made: the whole point is to fail at the real
	// cause instead of surfacing the server's replay refusal.
	if ex.count() != 1 {
		t.Errorf("a spent assertion was sent to the server (%d exchanges)", ex.count())
	}
	for _, want := range []string{"single-use", "NEWLY minted"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q: %s", want, err.Error())
		}
	}
}

func TestWorkloadProviderRefusesAnEmptyAssertionBeforeAnyExchange(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	p := newTestProvider(t, ex, &clock, func(context.Context) (string, error) { return "", nil })

	_, err := p.AccessToken(context.Background())
	var stale *StaleAssertionError
	if !errors.As(err, &stale) {
		t.Fatalf("want *StaleAssertionError, got %T: %v", err, err)
	}
	if ex.count() != 0 {
		t.Errorf("an empty assertion reached the server")
	}
}

func TestWorkloadProviderDoesNotBurnTheAssertionOnAFailedExchange(t *testing.T) {
	// The server claims the assertion before minting, so only a SUCCESS makes
	// those bytes unusable. Burning the fingerprint on a transport error would
	// strand a caller whose assertion is still perfectly good.
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	p := newTestProvider(t, ex, &clock, func(context.Context) (string, error) { return "retryable-assertion", nil })

	ex.failOnce()
	if _, err := p.AccessToken(context.Background()); err == nil {
		t.Fatal("want the exchange failure to surface")
	}

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("retry with the same assertion was refused: %v", err)
	}
	if ex.count() != 2 {
		t.Fatalf("want 2 exchanges, got %d", ex.count())
	}
	if got := ex.body(1)["subject_token"]; got != "retryable-assertion" {
		t.Errorf("retry sent %v", got)
	}
}

func TestWorkloadProviderPropagatesASourceError(t *testing.T) {
	// A metadata service that is down must surface as itself, not as a stale
	// assertion: the two have completely different fixes.
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	boom := errors.New("metadata service refused connection")
	p := newTestProvider(t, ex, &clock, func(context.Context) (string, error) { return "", boom })

	_, err := p.AccessToken(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("want the source error, got %T: %v", err, err)
	}
}

// -- the two-tier schedule ---------------------------------------------------

func TestWorkloadProviderServesTheCachedTokenWhileComfortablyAlive(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	first, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(providerLifetime - AdvisoryRefresh - 10*time.Second)

	again, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if again != first || ex.count() != 1 {
		t.Fatalf("a live token was re-exchanged (%d exchanges)", ex.count())
	}
}

func TestWorkloadProviderRefreshesInsideTheAdvisoryWindow(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(providerLifetime - AdvisoryRefresh + 10*time.Second)
	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if ex.count() != 2 {
		t.Fatalf("want an opportunistic refresh, got %d exchanges", ex.count())
	}
}

func TestWorkloadProviderSurvivesAnAdvisoryWindowFailure(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	first, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(providerLifetime - AdvisoryRefresh + 10*time.Second)

	ex.failOnce()
	served, err := p.AccessToken(context.Background())
	if err != nil {
		t.Fatalf("a survivable blip took down a caller with valid credentials: %v", err)
	}
	if served != first {
		t.Errorf("want the still-valid cached token, got a different one")
	}
}

func TestWorkloadProviderFailsInTheMandatoryWindow(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	clock = clock.Add(providerLifetime - MandatoryRefresh + 10*time.Second)

	ex.failOnce()
	if _, err := p.AccessToken(context.Background()); err == nil {
		t.Fatal("want the mandatory refresh failure to surface — the token may die in flight")
	}
}

// -- concurrency -------------------------------------------------------------

func TestWorkloadProviderSpendsOneAssertionForNCallers(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	calls := 0
	src := func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return fmt.Sprintf("assertion-%d", calls), nil
	}
	p := newTestProvider(t, ex, &clock, src)

	var wg sync.WaitGroup
	tokens := make([]string, 8)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := p.AccessToken(context.Background())
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
				return
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()

	if ex.count() != 1 || calls != 1 {
		t.Fatalf("a thundering herd burned one assertion per caller: %d exchanges / %d source calls", ex.count(), calls)
	}
	for i, tok := range tokens {
		if tok != tokens[0] {
			t.Fatalf("caller %d got a different token from one exchange", i)
		}
	}
}

// -- what reaches the exchange ----------------------------------------------

func TestWorkloadProviderPassesResourceAndAudienceThrough(t *testing.T) {
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	resource := "https://mcp.example/servers/s1"
	p := newTestProvider(t, ex, &clock, src, func(o *WorkloadCredentialProviderOptions) {
		o.Resource = &resource
		o.Audience = KnoxCallAudience
	})

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	body := ex.body(0)
	if body["resource"] != resource {
		t.Errorf("resource = %v", body["resource"])
	}
	if body["audience"] != KnoxCallAudience {
		t.Errorf("audience = %v", body["audience"])
	}
	if body["subject_token_type"] != IDTokenType {
		t.Errorf("subject_token_type = %v", body["subject_token_type"])
	}
}

func TestWorkloadProviderOmitsResourceWhenNotAskedFor(t *testing.T) {
	// Sending resource="" would be refused invalid_target; sending nothing
	// mints an unconfined agent token. The provider must not turn one into the
	// other — the pointer is what keeps them distinct.
	ex := newProviderExchange(t)
	clock := time.Unix(1_000_000, 0)
	src, _ := freshSource()
	p := newTestProvider(t, ex, &clock, src)

	if _, err := p.AccessToken(context.Background()); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, present := ex.body(0)["resource"]; present {
		t.Error("resource was sent for a caller who asked for an agent token")
	}
}

func TestWorkloadProviderRequiresAnAssertionSourceAndAHost(t *testing.T) {
	// Both failures belong at construction, not minutes into a long process.
	if _, err := NewWorkloadCredentialProvider(WorkloadCredentialProviderOptions{Tenant: "acme"}); err == nil {
		t.Error("want a refusal with no Assertion source")
	}
	src, _ := freshSource()
	if _, err := NewWorkloadCredentialProvider(WorkloadCredentialProviderOptions{Assertion: src}); err == nil {
		t.Error("want a refusal with neither Tenant nor BaseURL — /v1/oauth/token has no default host")
	}
}
