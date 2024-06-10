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
	LinkedinOAuthRedirectUrl_login    string `mapstructure:"LINKEDIN_REDIRECT_URL_LOGIN"`

	UnstoppableDomainClientID             string `mapstructure:"UNSTOPPABLE_DOMAIN_CLIENT_ID"`
	UnstoppableDomainRedirectUrl_register string `mapstructure:"UNSTOPPABLE_DOMAIN_REDIRECT_URL_REGISTER"`
	UnstoppableDomainRedirectUrl_login    string `mapstructure:"UNSTOPPABLE_DOMAIN_REDIRECT_URL_LOGIN"`
	UnstoppableDomainClientSecret         string `mapstructure:"UNSTOPPABLE_DOMAIN_CLIENT_SECRET"`

	TwitterAPIKey               string `mapstructure:"TWITTER_API_KEY"`
	TwitterAPISecret            string `mapstructure:"TWITTER_API_SECRET"`
	TwitterRedirectUrl_register string `mapstructure:"TWITTER_REDIRECT_URL_REGISTER"`
	TwitterRedirectUrl_login    string `mapstructure:"TWITTER_REDIRECT_URL_LOGIN"`
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

func SetLinkedinSocialMediaConfig(clientID string, clientSecret string, redirectUrl_register string, redirectUrl_login string) {
	configVal.LinkedinClientID = clientID
	configVal.LinkedinClientSecret = clientSecret
	configVal.LinkedinOAuthRedirectUrl_register = redirectUrl_register
	configVal.LinkedinOAuthRedirectUrl_login = redirectUrl_login
}

func SetUnstoppableDomainSocialMediaConfig(clientID, clientSecret, redirectUrl_register, redirectUrl_login string) {
	configVal.UnstoppableDomainClientID = clientID
	configVal.UnstoppableDomainRedirectUrl_register = redirectUrl_register
	configVal.UnstoppableDomainRedirectUrl_login = redirectUrl_login
	configVal.UnstoppableDomainClientSecret = clientSecret
}

func SetTwitterSocialMediaConfig(apiKey, apiSecret, redirectUrl_register, redirectUrl_login string){
	configVal.TwitterAPIKey = apiKey
	configVal.TwitterRedirectUrl_register= redirectUrl_register
	configVal.TwitterRedirectUrl_login = redirectUrl_login
	configVal.TwitterAPISecret = apiSecret
	// Restart the client after these are set. Uncomment
	TwitterClient = New(configVal.TwitterAPIKey, configVal.TwitterAPISecret)
}
func SetConfig(config *Config) {
	configVal = config
}
