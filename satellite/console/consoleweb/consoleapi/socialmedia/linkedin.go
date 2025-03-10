package socialmedia

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

type LinkedinUserDetails struct {
	Sub        string `json:"sub"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Picture    string `json:"picture"`
	// Locale     string `json:"locale"`
	Email string `json:"email"`
	// EmailVerified bool   `json:"email_verified"`
}

// **** LinkedIn ****//
func GetLinkedinOAuthConfig_Register() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_register,
		Endpoint:     linkedin.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func GetLinkedinOAuthConfig_IdToken_Register() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_idToken_register,
		Endpoint:     linkedin.Endpoint,
	}
}

func GetLinkedinOAuthConfig_IdToken_Login() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_idToken_login,
		Endpoint:     linkedin.Endpoint,
	}
}

func GetLinkedinOAuthConfig_Login() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     configVal.LinkedinClientID,
		ClientSecret: configVal.LinkedinClientSecret,
		RedirectURL:  configVal.LinkedinOAuthRedirectUrl_login,
		Endpoint:     linkedin.Endpoint,
		Scopes:       []string{"openid", "profile", "email"},
	}
}

func GetLinkedinUserByAccessToken(ctx context.Context, token string, zohoInsert bool) (*LinkedinUserDetails, error) {
	var OAuth2Config = GetLinkedinOAuthConfig_Register()
	if zohoInsert {
		OAuth2Config.RedirectURL += "?zoho-insert"
	}

	client := OAuth2Config.Client(context.TODO(), &oauth2.Token{
		AccessToken: token,
		TokenType:   "bearer",
	})
	req, err := http.NewRequest("GET", "https://api.linkedin.com/v2/userinfo", nil)

	if err != nil {
		return nil, err
	}
	req.Header.Set("Bearer", token)
	response, err := client.Do(req)

	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	str, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var LinkedinUserDetails LinkedinUserDetails
	err = json.Unmarshal(str, &LinkedinUserDetails)
	if err != nil {
		return nil, err
	}

	if LinkedinUserDetails.Email == "" {
		return nil, errors.New("email not found in LinkedIn response " + string(str))
	}

	return &LinkedinUserDetails, nil
}
