package socialmedia


import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/gomodule/oauth1/oauth"
)

func New(apiKey, apiSecret string) *XClient {
	cli := &oauth.Client{
		TemporaryCredentialRequestURI: "https://api.twitter.com/oauth/request_token",
		ResourceOwnerAuthorizationURI: "https://api.twitter.com/oauth/authorize",
		TokenRequestURI:               "https://api.twitter.com/oauth/access_token",
		Credentials: oauth.Credentials{
			Token:  apiKey,
			Secret: apiSecret,
		},
	}
	return &XClient{
		appID:     apiKey,
		appSecret: apiSecret,
		cli:       cli,
	}
}

type XClient struct {
	appID     string
	appSecret string
	cli       *oauth.Client
	tempCred  *oauth.Credentials
	cred      *oauth.Credentials
}

func (c *XClient) GetXAuthURL(callback string) (string, error) {
	tempCred, err := c.cli.RequestTemporaryCredentials(nil, callback, nil)
	if err != nil {
		return "", err
	}
	c.tempCred = tempCred
	url := c.cli.AuthorizationURL(tempCred, nil)
	return url, nil
}

func (c *XClient) GetAccessToken(oauthToken string, oauthVerifier string) (string, error) {
	if c.tempCred == nil || c.tempCred.Token != oauthToken {
		return "", ErrInvalidRequest
	}
	cred, _, err := c.cli.RequestToken(nil, c.tempCred, oauthVerifier)
	c.cred = cred
	return cred.Token, err
}

func (c *XClient) Verify() (*User, error) {
	v := url.Values{}
	v.Set("include_email", "true")
	resp, err := c.cli.Get(nil, c.cred, "https://api.twitter.com/1.1/account/verify_credentials.json", v)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 500 || resp.StatusCode >= 400 {
		terr := ErrorWrapper{}
		if err := json.Unmarshal(respData, &terr); err != nil {
			return nil, err
		}

		if len(terr.Errors) != 0 {
			return nil, &terr
		}

		return nil, ErrTwitterServerError
	}

	var user User
	if err := json.Unmarshal(respData, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

type User struct {
	ContributorsEnabled            bool                   `json:"contributors_enabled"`
	CreatedAt                      string                 `json:"created_at"`
	DefaultProfile                 bool                   `json:"default_profile"`
	DefaultProfileImage            bool                   `json:"default_profile_image"`
	Description                    string                 `json:"description"`
	Entities                       map[string]interface{} `json:"entities"`
	FavouritesCount                int                    `json:"favourites_count"`
	FollowRequestSent              bool                   `json:"follow_request_sent"`
	FollowersCount                 int                    `json:"followers_count"`
	Following                      bool                   `json:"following"`
	FriendsCount                   int                    `json:"friends_count"`
	GeoEnabled                     bool                   `json:"geo_enabled"`
	HasExtendedProfile             bool                   `json:"has_extended_profile"`
	ID                             float64                `json:"id"`
	IDStr                          string                 `json:"id_str"`
	IsTranslationEnabled           bool                   `json:"is_translation_enabled"`
	IsTranslator                   bool                   `json:"is_translator"`
	Lang                           interface{}            `json:"lang"`
	ListedCount                    int                    `json:"listed_count"`
	Location                       string                 `json:"location"`
	Name                           string                 `json:"name"`
	NeedsPhoneVerification         bool                   `json:"needs_phone_verification"`
	Notifications                  bool                   `json:"notifications"`
	ProfileBackgroundColor         string                 `json:"profile_background_color"`
	ProfileBackgroundImageURL      string                 `json:"profile_background_image_url"`
	ProfileBackgroundImageURLHTTPS string                 `json:"profile_background_image_url_https"`
	ProfileBackgroundTile          bool                   `json:"profile_background_tile"`
	ProfileImageURL                string                 `json:"profile_image_url"`
	ProfileImageURLHTTPS           string                 `json:"profile_image_url_https"`
	ProfileLinkColor               string                 `json:"profile_link_color"`
	ProfileSidebarBorderColor      string                 `json:"profile_sidebar_border_color"`
	ProfileSidebarFillColor        string                 `json:"profile_sidebar_fill_color"`
	ProfileTextColor               string                 `json:"profile_text_color"`
	ProfileUseBackgroundImage      bool                   `json:"profile_use_background_image"`
	Protected                      bool                   `json:"protected"`
	ScreenName                     string                 `json:"screen_name"`
	StatusesCount                  int                    `json:"statuses_count"`
	Suspended                      bool                   `json:"suspended"`
	TimeZone                       interface{}            `json:"time_zone"`
	TranslatorType                 string                 `json:"translator_type"`
	URL                            string                 `json:"url"`
	UtcOffset                      interface{}            `json:"utc_offset"`
	Verified                       bool                   `json:"verified"`
	WithheldInCountries            []interface{}          `json:"withheld_in_countries"`
	Email                          string                 `json:"email"`
}

var (
	ErrTwitterServerError = errors.New("twitter is unavailable")
	ErrInvalidRequest     = errors.New("twitter request is invalid")
)

type ErrorWrapper struct {
	error  `json:"-"`
	Errors []struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"errors"`
}

func (e *ErrorWrapper) Error() string {
	return fmt.Sprintf("twitter errors: %+v", e.Errors)
}

var TwitterClient *XClient
func init(){
	// Shoule be removed
	//TwitterClient = New("IeLmLAAzAOxDvuL77ovt1vBvG", "T4yyfkHRkqAhAkYn1qUAMWJEYJeCVcAxOZNSApNVOGZVdiq6cp")
	// Uncomment
	TwitterClient = New(configVal.TwitterAPIKey, configVal.TwitterAPISecret)
}