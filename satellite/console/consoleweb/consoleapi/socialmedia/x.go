package socialmedia

import (
	"context"
	"encoding/json"
	"net/http"

	pcke "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

type XUser struct {
	Data struct {
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"data"`
}

func GetXUser(ctx context.Context, code string, codeVerifier string, t string, zohoInsert bool) (*XUser, error) {
	cnf := GetConfig()
	conf := &oauth2.Config{
		ClientID:     cnf.XClientID,
		ClientSecret: cnf.XClientSecret,
		RedirectURL:  cnf.XSignupRedirectURL,
		Scopes:       []string{"users.read", "offline.access", "tweet.read"},
		Endpoint:     oauth2.Endpoint{TokenURL: "https://api.twitter.com/2/oauth2/token", AuthURL: "https://twitter.com/i/oauth2/authorize", AuthStyle: oauth2.AuthStyleAutoDetect},
	}
	if t == "login" {
		conf.RedirectURL = cnf.XLoginRedirectURL
	}

	if zohoInsert {
		conf.RedirectURL += "/zoho"
	}
	token, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, err
	}

	client := conf.Client(ctx, token)

	userInfo, err := client.Get("https://api.twitter.com/2/users/me")
	if err != nil {
		return nil, err
	}
	var user XUser
	if err := json.NewDecoder(userInfo.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func GetXUserFromAuthCode(ctx context.Context, token string) (*XUser, error) {
	client := (&oauth2.Config{}).Client(ctx, &oauth2.Token{
		AccessToken: token,
		TokenType:   "bearer",
	})

	userInfo, err := client.Get("https://api.twitter.com/2/users/me")
	if err != nil {
		return nil, err
	}
	var user XUser
	if err := json.NewDecoder(userInfo.Body).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func RedirectURL(t string, r *http.Request) (string, error) {
	cnf := GetConfig()
	state, err := EncodeState(nil)
	if err != nil {
		return "", err
	}
	codeVerifier, err := pcke.CreateCodeVerifier()
	if err != nil {
		return "", err
	}
	codeChallenge := codeVerifier.CodeChallengeS256()
	SaveReqOptions(state, NewVerifierData(r).SetVerifier(codeVerifier.String()))
	conf := &oauth2.Config{
		ClientID:     cnf.XClientID,
		ClientSecret: cnf.XClientSecret,
		RedirectURL:  cnf.XSignupRedirectURL,
		Scopes:       []string{"users.read", "offline.access", "tweet.read"},
		Endpoint:     oauth2.Endpoint{TokenURL: "https://api.twitter.com/2/oauth2/token", AuthURL: "https://twitter.com/i/oauth2/authorize", AuthStyle: oauth2.AuthStyleAutoDetect},
	}
	if t == "login" {
		conf.RedirectURL = cnf.XLoginRedirectURL
	}

	if r.URL.Query().Has("zoho-insert") {
		conf.RedirectURL += "/zoho"
	}

	requestUrl := conf.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("redirect_url", conf.RedirectURL),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	return requestUrl, nil
}
