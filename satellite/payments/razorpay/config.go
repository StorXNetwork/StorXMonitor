// Copyright (C) 2026 StorX Network.
// See LICENSE for copying information.

package razorpay

// Config holds Razorpay credentials and checkout settings.
type Config struct {
	Enabled            bool   `help:"enable Razorpay plan checkout" default:"false"`
	KeyID              string `help:"Razorpay API key id" default:""`
	KeySecret          string `help:"Razorpay API key secret" default:""`
	WebhookSecret      string `help:"Razorpay webhook secret for signature verification" default:""`
	Currency           string `help:"ISO currency for Razorpay charges; plan price is treated as major units of this currency" default:"INR"`
	SuccessRedirectURL string `help:"URL customers are redirected to after successful Razorpay payment" default:""`
	FailedRedirectURL  string `help:"URL customers are redirected to after failed Razorpay payment" default:""`
	APIBaseURL         string `help:"Razorpay API base URL" default:"https://api.razorpay.com/v1"`
}
