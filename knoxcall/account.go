package knoxcall

import "context"

// Account is the GET /v1/account result.
type Account struct {
	ID                             string  `json:"id"`
	Slug                           string  `json:"slug"`
	Name                           string  `json:"name"`
	Region                         string  `json:"region"`
	SubscriptionPlan               string  `json:"subscription_plan"`
	SubscriptionStatus             string  `json:"subscription_status"`
	TrialStartAt                   *string `json:"trial_start_at"`
	TrialEndAt                     *string `json:"trial_end_at"`
	SubscriptionCurrentPeriodStart *string `json:"subscription_current_period_start"`
	SubscriptionCurrentPeriodEnd   *string `json:"subscription_current_period_end"`
	SubscriptionCancelAt           *string `json:"subscription_cancel_at"`
	CreatedAt                      string  `json:"created_at"`
}

// AccountUsage is the GET /v1/account/usage result.
type AccountUsage struct {
	BillingPeriod BillingPeriod `json:"billing_period"`
	APICalls      APICallUsage  `json:"api_calls"`
	Resources     ResourceUsage `json:"resources"`
	Plan          string        `json:"plan"`
	Status        string        `json:"status"`
}

// BillingPeriod is the current billing window.
type BillingPeriod struct {
	Year  int     `json:"year"`
	Month int     `json:"month"`
	Start *string `json:"start"`
	End   *string `json:"end"`
}

// APICallUsage reports API-call consumption against the plan limit
// (Limit is nil when unlimited).
type APICallUsage struct {
	Used       int  `json:"used"`
	Limit      *int `json:"limit"`
	Percentage int  `json:"percentage"`
}

// UsageCounter is a used/limit pair (Limit nil = unlimited).
type UsageCounter struct {
	Used  int  `json:"used"`
	Limit *int `json:"limit"`
}

// ResourceUsage reports per-resource consumption.
type ResourceUsage struct {
	Routes       UsageCounter `json:"routes"`
	Secrets      UsageCounter `json:"secrets"`
	Clients      UsageCounter `json:"clients"`
	Environments UsageCounter `json:"environments"`
}

type AccountResource struct{ c *Client }

func (r *AccountResource) Get(ctx context.Context) (*Account, error) {
	return doUnwrap[Account](ctx, r.c, requestOpts{method: "GET", path: "/v1/account"})
}

func (r *AccountResource) GetUsage(ctx context.Context) (*AccountUsage, error) {
	return doUnwrap[AccountUsage](ctx, r.c, requestOpts{method: "GET", path: "/v1/account/usage"})
}
