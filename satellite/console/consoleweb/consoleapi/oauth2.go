package consoleapi

import (
	"encoding/json"
	"net/http"

	"storj.io/common/uuid"
	"storj.io/storj/satellite/console"
)

// OAuth2API is an API controller for OAuth2 endpoints.
type OAuth2API struct {
	Service *console.Service
}

// NewOAuth2API constructs a new OAuth2API handler.
func NewOAuth2API(service *console.Service) *OAuth2API {
	return &OAuth2API{Service: service}
}

// CreateOAuth2Request handles POST /api/v0/oauth2/request
func (a *OAuth2API) CreateOAuth2Request(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		ClientID    string   `json:"client_id"`
		RedirectURI string   `json:"redirect_uri"`
		Scope       []string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if req.ClientID == "" || req.RedirectURI == "" || len(req.Scope) == 0 {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	resp, err := a.Service.CreateOAuth2Request(ctx, console.CreateOAuth2Request{
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scopes:      req.Scope,
	})
	if err != nil {
		status := http.StatusBadRequest
		errMsg := err.Error()
		if errMsg == "invalid_client_id" || errMsg == "client_inactive" || errMsg == "invalid_redirect_uri" {
			status = http.StatusBadRequest
		} else {
			status = http.StatusInternalServerError
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"request_id":      resp.RequestID,
		"current_access":  resp.CurrentAccess,
		"needed_access":   resp.NeededAccess,
		"required_scopes": resp.RequiredScopes,
		"optional_scopes": resp.OptionalScopes,
	})
}

// ConsentOAuth2Request handles POST /api/v0/oauth2/consent
func (a *OAuth2API) ConsentOAuth2Request(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Approve        bool     `json:"approve"`
		RequestID      string   `json:"request_id"`
		ApprovedScopes []string `json:"approved_scopes"`
		RejectedScopes []string `json:"rejected_scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	requestID, err := uuid.FromString(req.RequestID)
	if err != nil {
		http.Error(w, `{"error":"invalid_request_id"}`, http.StatusBadRequest)
		return
	}
	resp, err := a.Service.ConsentOAuth2Request(ctx, console.ConsentOAuth2Request{
		RequestID:      requestID,
		Approve:        req.Approve,
		ApprovedScopes: req.ApprovedScopes,
		RejectedScopes: req.RejectedScopes,
	})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ExchangeOAuth2CodeRequest represents the request body for token exchange
type ExchangeOAuth2CodeRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
	Code         string `json:"code"`
}

// ExchangeOAuth2CodeResponse represents the response body for token exchange
type ExchangeOAuth2CodeResponse struct {
	AccessGrant string   `json:"access_grant"`
	Scopes      []string `json:"scopes"`
}

// ExchangeOAuth2Code handles POST /api/v0/oauth2/token
func (a *OAuth2API) ExchangeOAuth2Code(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
		Code         string `json:"code"`
		Passphrase   string `json:"passphrase"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	if req.ClientID == "" || req.ClientSecret == "" || req.RedirectURI == "" || req.Code == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	resp, err := a.Service.ExchangeOAuth2Code(ctx, console.ExchangeOAuth2CodeRequest{
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		RedirectURI:  req.RedirectURI,
		Code:         req.Code,
		Passphrase:   req.Passphrase,
	})
	if err != nil {
		status := http.StatusBadRequest
		errMsg := err.Error()
		switch errMsg {
		case "invalid_client":
			status = http.StatusUnauthorized
		case "invalid_code", "code_expired", "code_already_used":
			status = http.StatusBadRequest
		case "invalid_redirect_uri":
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
