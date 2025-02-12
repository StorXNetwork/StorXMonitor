package socialmedia

type Config struct {
	ClientOrigin string `mapstructure:"CLIENT_ORIGIN"`

	GoogleClientID                  string `mapstructure:"GOOGLE_OAUTH_CLIENT_ID"`
	GoogleClientSecret              string `mapstructure:"GOOGLE_OAUTH_CLIENT_SECRET"`
	GoogleOAuthRedirectUrl_register string `mapstructure:"GOOGLE_OAUTH_REDIRECT_URL_REGISTER"`
	GoogleOAuthRedirectUrl_login    string `mapstructure:"GOOGLE_OAUTH_REDIRECT_URL_LOGIN"`

	FacebookClientID                  string `mapstructure:"FACEBOOK_CLIENT_ID"`
	FacebookClientSecret              string `mapstructure:"FACEBOOK_CLIENT_SECRET"`
	FacebookOAuthRedirectUrl_register string `mapstructure:"FACEBOOK_REDIRECT_URL_REGISTER"`
	FacebookOAuthRedirectUrl_login    string `mapstructure:"FACEBOOK_REDIRECT_URL_LOGIN"`

	LinkedinClientID                  string `mapstructure:"LINKEDIN_CLIENT_ID"`
	LinkedinClientSecret              string `mapstructure:"LINKEDIN_CLIENT_SECRET"`
	LinkedinOAuthRedirectUrl_register string `mapstructure:"LINKEDIN_REDIRECT_URL_REGISTER"`
	LinkedinOAuthRedirectUrl_idToken  string `mapstructure:"LINKEDIN_REDIRECT_URL_ID_TOKEN"`
	LinkedinOAuthRedirectUrl_login    string `mapstructure:"LINKEDIN_REDIRECT_URL_LOGIN"`

	UnstoppableDomainClientID             string `mapstructure:"UNSTOPPABLE_DOMAIN_CLIENT_ID"`
	UnstoppableDomainRedirectUrl_register string `mapstructure:"UNSTOPPABLE_DOMAIN_REDIRECT_URL_REGISTER"`
	UnstoppableDomainRedirectUrl_login    string `mapstructure:"UNSTOPPABLE_DOMAIN_REDIRECT_URL_LOGIN"`
	UnstoppableDomainClientSecret         string `mapstructure:"UNSTOPPABLE_DOMAIN_CLIENT_SECRET"`

	TwitterAPIKey               string `mapstructure:"TWITTER_API_KEY"`
	TwitterAPISecret            string `mapstructure:"TWITTER_API_SECRET"`
	TwitterRedirectUrl_register string `mapstructure:"TWITTER_REDIRECT_URL_REGISTER"`
	TwitterRedirectUrl_login    string `mapstructure:"TWITTER_REDIRECT_URL_LOGIN"`

	XClientID          string `mapstrcuture:"X_CLIENT_ID"`
	XClientSecret      string `mapstructure:"X_CLIENT_SECRET"`
	XSignupRedirectURL string `mapstructure:"X_SIGNUP_REDIRECT_URL"`
	XLoginRedirectURL  string `mapstructure:"X_LOGIN_REDIRECT_URL"`

	PipeDriveClientID     string `mapstructure:"PIPEDRIVE_CLIENT_ID"`
	PipeDriveClientSecret string `mapstructure:"PIPEDRIVE_CLIENT_SECRET"`
	PipeDriveRedirectUrl  string `mapstructure:"PIPEDRIVE_REDIRECT_URL"`
}

var configVal = &Config{}

func GetConfig() *Config {
	return configVal
}

func SetClientOrigin(origin string) {
	configVal.ClientOrigin = origin
}

func SetGoogleSocialMediaConfig(clientID string, clientSecret string, redirectUrl_register string, redirectUrl_login string) {
	configVal.GoogleClientID = clientID
	configVal.GoogleClientSecret = clientSecret
	configVal.GoogleOAuthRedirectUrl_register = redirectUrl_register
	configVal.GoogleOAuthRedirectUrl_login = redirectUrl_login
}

func SetFacebookSocialMediaConfig(clientID string, clientSecret string, redirectUrl_register string, redirectUrl_login string) {
	configVal.FacebookClientID = clientID
	configVal.FacebookClientSecret = clientSecret
	configVal.FacebookOAuthRedirectUrl_register = redirectUrl_register
	configVal.FacebookOAuthRedirectUrl_login = redirectUrl_login
}

func SetLinkedinSocialMediaConfig(clientID string, clientSecret string, redirectUrl_register string, redirectUrl_login string, redirectUrl_idToken string) {
	configVal.LinkedinClientID = clientID
	configVal.LinkedinClientSecret = clientSecret
	configVal.LinkedinOAuthRedirectUrl_register = redirectUrl_register
	configVal.LinkedinOAuthRedirectUrl_idToken = redirectUrl_idToken
	configVal.LinkedinOAuthRedirectUrl_login = redirectUrl_login
}

func SetUnstoppableDomainSocialMediaConfig(clientID, clientSecret, redirectUrl_register, redirectUrl_login string) {
	configVal.UnstoppableDomainClientID = clientID
	configVal.UnstoppableDomainRedirectUrl_register = redirectUrl_register
	configVal.UnstoppableDomainRedirectUrl_login = redirectUrl_login
	configVal.UnstoppableDomainClientSecret = clientSecret
}

func SetTwitterSocialMediaConfig(apiKey, apiSecret, redirectUrl_register, redirectUrl_login string) {
	configVal.TwitterAPIKey = apiKey
	configVal.TwitterRedirectUrl_register = redirectUrl_register
	configVal.TwitterRedirectUrl_login = redirectUrl_login
	configVal.TwitterAPISecret = apiSecret
}

func SetXSocialMediaConfig(clientID, clientSecret, sru, lru string) {
	configVal.XClientID = clientID
	configVal.XClientSecret = clientSecret
	configVal.XSignupRedirectURL = sru
	configVal.XLoginRedirectURL = lru
}

func SetPipeDriveSocialMediaConfig(clientID, clientSecret, redirectUrl string) {
	configVal.PipeDriveClientID = clientID
	configVal.PipeDriveClientSecret = clientSecret
	configVal.PipeDriveRedirectUrl = redirectUrl
}

func SetConfig(config *Config) {
	configVal = config
}
