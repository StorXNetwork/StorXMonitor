package consoleapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"github.com/StorXNetwork/StorXMonitor/private/web"
	"github.com/StorXNetwork/StorXMonitor/satellite/console"
	"github.com/StorXNetwork/StorXMonitor/satellite/console/consoleweb/consolewebauth"
)

// Package-level Counter definitions - ensures they're registered with monkit at package load time
var (
	web3authUploadBackupShareErrorUploadingShare    = mon.Counter("web3auth_upload_backup_share_error_uploading_share")
	web3authTokenErrorInvalidSignature              = mon.Counter("web3auth_token_error_invalid_signature")
	web3authTokenErrorAuthenticationFailed          = mon.Counter("web3auth_token_error_authentication_failed")
	web3authGetBackupShareErrorRetrieving           = mon.Counter("web3auth_get_backup_share_error_retrieving")
	web3authUploadSocialShareAttempts               = mon.Counter("web3auth_upload_social_share_attempts")
	web3authUploadSocialShareErrorUpdate            = mon.Counter("web3auth_upload_social_share_error_update")
	web3authUploadSocialShareErrorCreate            = mon.Counter("web3auth_upload_social_share_error_create")
	web3authUploadSocialShareSuccess                = mon.Counter("web3auth_upload_social_share_success")
	web3authGetSocialShareErrorRetrieving           = mon.Counter("web3auth_get_social_share_error_retrieving")
	web3authGetPaginatedSocialSharesErrorRetrieving = mon.Counter("web3auth_get_paginated_social_shares_error_retrieving")
	web3authGetTotalSocialSharesErrorRetrieving     = mon.Counter("web3auth_get_total_social_shares_error_retrieving")
)

type Web3Auth struct {
	log     *zap.Logger
	service *console.Service

	cookieAuth *consolewebauth.CookieAuth

	secreteKey string
}

func NewWeb3Auth(log *zap.Logger, service *console.Service,
	cookieAuth *consolewebauth.CookieAuth, secreteKey string) *Web3Auth {
	return &Web3Auth{
		log:        log,
		service:    service,
		secreteKey: secreteKey,
		cookieAuth: cookieAuth,
	}
}

func (a *Web3Auth) UploadBackupShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	backupIDStr := r.URL.Query().Get("backup_id")
	share, err := io.ReadAll(r.Body)
	if err != nil {
		a.sendError(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if len(share) == 0 || backupIDStr == "" {
		a.sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Track data size
	mon.IntVal("web3auth_upload_backup_share_size_bytes").Observe(int64(len(share)))

	err = a.service.UploadBackupShare(r.Context(), backupIDStr, share)
	if err != nil {
		a.sendError(w, "Error uploading backup share: "+err.Error(), http.StatusInternalServerError)
		web3authUploadBackupShareErrorUploadingShare.Inc(1)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	type Web3AuthRequest struct {
		Email           string `json:"email"`
		Payload         string `json:"payload"`
		Signature       string `json:"signature"`
		Key             string `json:"key"`
		MFAPasscode     string `json:"mfaPasscode"`
		MFARecoveryCode string `json:"mfaRecoveryCode"`
	}

	var request Web3AuthRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		a.log.Error("Failed to decode request body", zap.Error(err))
		a.sendError(w, "Failed to decode request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if request.Email == "" {
		a.sendError(w, "Email is required", http.StatusBadRequest)
		return
	}

	if request.Signature == "" {
		a.sendError(w, "Signature is required", http.StatusBadRequest)
		return
	}

	user, unverified, err := a.service.GetUsers().GetByEmailWithUnverified(ctx, request.Email)
	if err != nil {
		a.sendError(w, "Failed to get user", http.StatusInternalServerError)
		return
	}

	if len(unverified) > 0 {
		// update verification status of user
		status := console.Active
		for _, u := range unverified {
			err = a.service.GetUsers().Update(ctx, u.ID, console.UpdateUserRequest{
				Status: &status,
			})
			if err != nil {
				a.sendError(w, "Failed to update user", http.StatusInternalServerError)
				return
			}

			user = &u
		}
	}

	if user == nil {
		a.sendError(w, "User not found", http.StatusNotFound)
		return
	}

	if user.Status != console.Active {
		a.sendError(w, "User not active", http.StatusUnauthorized)
		return
	}

	ip, err := web.GetRequestIP(r)
	if err != nil {
		a.sendError(w, "Failed to get request IP", http.StatusInternalServerError)
		return
	}

	pubKey, err := getPublicKey(request.Payload, request.Signature)
	if err != nil {
		a.sendError(w, "Failed to get public key", http.StatusBadRequest)
		return
	}

	if !bytes.Equal([]byte(pubKey), []byte(user.WalletId)) {
		a.sendError(w, "invalid signature", http.StatusBadRequest)
		web3authTokenErrorInvalidSignature.Inc(1)
		return
	}

	token, err := jwt.Parse(request.Payload, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(a.secreteKey), nil
	})
	if err != nil {
		a.sendError(w, "Failed to parse jwt"+err.Error(), http.StatusBadRequest)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	exp, ok := claims["exp"]
	if !ok {
		a.sendError(w, "JWT does not contain expiration", http.StatusBadRequest)
		return
	}
	expInt, ok := exp.(float64)
	if !ok {
		a.sendError(w, "JWT expiration is not a number", http.StatusBadRequest)
		return
	}

	if time.Now().Unix() > int64(expInt) {
		a.sendError(w, "JWT expired", http.StatusUnauthorized)
		return
	}

	tokenInfo, err := a.service.TokenWithoutPassword(ctx, console.AuthWithoutPassword{
		Email:           request.Email,
		IP:              ip,
		UserAgent:       r.UserAgent(),
		MFAPasscode:     request.MFAPasscode,
		MFARecoveryCode: request.MFARecoveryCode,
	})
	if err != nil {
		if console.ErrMFAMissing.Has(err) {
			a.sendError(w, "MFA is missing", http.StatusOK)
		} else {
			a.log.Info("Error authenticating token request", zap.String("email", request.Email), zap.Error(ErrAuthAPI.Wrap(err)))
			a.sendError(w, "Failed to authenticate token request", http.StatusInternalServerError)
			web3authTokenErrorAuthenticationFailed.Inc(1)
		}
		return
	}

	tokenInfo.Token.Key = request.Key

	a.cookieAuth.SetTokenCookie(w, *tokenInfo)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(struct {
		console.TokenInfo
		Token string `json:"token"`
	}{*tokenInfo, tokenInfo.Token.String()})
	if err != nil {
		a.log.Error("token handler could not encode token response", zap.Error(ErrAuthAPI.Wrap(err)))
		return
	}
}

func (a *Web3Auth) GetBackupShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	backupIDStr := r.URL.Query().Get("backup_id")

	share, err := a.service.GetBackupShare(r.Context(), backupIDStr)
	if err != nil {
		a.sendError(w, "Error getting backup share: "+err.Error(), http.StatusInternalServerError)
		web3authGetBackupShareErrorRetrieving.Inc(1)
		return
	}

	// Track data size
	mon.IntVal("web3auth_get_backup_share_size_bytes").Observe(int64(len(share)))

	err = json.NewEncoder(w).Encode(map[string]string{
		"share":     string(share),
		"backup_id": backupIDStr,
	})
	if err != nil {
		a.sendError(w, "Error encoding backup share", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *Web3Auth) UploadSocialShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	web3authUploadSocialShareAttempts.Inc(1)

	id := r.URL.Query().Get("id")
	share, err := io.ReadAll(r.Body)
	if err != nil {
		a.sendError(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if id == "" || len(share) == 0 {
		a.sendError(w, "Invalid request: id and share body must be provided", http.StatusBadRequest)
		return
	}

	// Track data size
	mon.IntVal("web3auth_upload_social_share_size_bytes").Observe(int64(len(share)))

	exists, err := a.service.SocialShareKeyExists(ctx, id)
	if err != nil {
		a.sendError(w, "Error checking social share: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		err = a.service.UpdateSocialShare(ctx, id, string(share))
		if err != nil {
			a.sendError(w, "Error uploading social share: "+err.Error(), http.StatusInternalServerError)
			web3authUploadSocialShareErrorUpdate.Inc(1)
			return
		}
	} else {
		err = a.service.CreateSocialShare(ctx, id, string(share))
		if err != nil {
			a.sendError(w, "Error uploading social share: "+err.Error(), http.StatusInternalServerError)
			web3authUploadSocialShareErrorCreate.Inc(1)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)

	// Send push notification for data shared (vault category)
	consoleUser, err := console.GetUser(ctx)
	if err == nil {
		variables := map[string]interface{}{
			"share_id": id,
		}
		a.service.SendNotificationAsync(consoleUser.ID, consoleUser.Email, "data_shared", "vault", variables)
	}
	web3authUploadSocialShareSuccess.Inc(1)
}

func (a *Web3Auth) GetSocialShare(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	id := r.URL.Query().Get("id")
	if id == "" {
		a.sendError(w, "Invalid request: id must be provided", http.StatusBadRequest)
		return
	}

	share, err := a.service.GetSocialShare(ctx, id)
	if err != nil {
		a.sendError(w, "Error getting social share: "+err.Error(), http.StatusInternalServerError)
		web3authGetSocialShareErrorRetrieving.Inc(1)
		return
	}

	// Track data size
	mon.IntVal("web3auth_get_social_share_size_bytes").Observe(int64(len(share)))

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]string{
		"share": string(share),
	})
	if err != nil {
		a.sendError(w, "Error encoding social share", http.StatusInternalServerError)
		return
	}
}

func (a *Web3Auth) GetPaginatedSocialShares(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	startIndexStr := r.URL.Query().Get("startIndex")
	countStr := r.URL.Query().Get("count")

	startIndex, err := strconv.ParseUint(startIndexStr, 10, 64)
	if err != nil {
		a.sendError(w, "Invalid startIndex", http.StatusBadRequest)
		return
	}

	count, err := strconv.ParseUint(countStr, 10, 64)
	if err != nil {
		a.sendError(w, "Invalid count", http.StatusBadRequest)
		return
	}

	keys, values, versionIds, err := a.service.GetPaginatedSocialShares(ctx, startIndex, count)
	if err != nil {
		a.sendError(w, "Error getting paginated social shares: "+err.Error(), http.StatusInternalServerError)
		web3authGetPaginatedSocialSharesErrorRetrieving.Inc(1)
		return
	}

	// Track data count
	mon.IntVal("web3auth_get_paginated_social_shares_count").Observe(int64(len(keys)))

	type responseItem struct {
		Key       string `json:"key"`
		Value     string `json:"value"`
		VersionID string `json:"versionId"`
	}
	response := make([]responseItem, len(keys))
	for i := range keys {
		response[i] = responseItem{
			Key:       keys[i],
			Value:     values[i],
			VersionID: versionIds[i],
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		a.sendError(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func (a *Web3Auth) GetTotalSocialShares(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	total, err := a.service.GetTotalSocialShares(ctx)
	if err != nil {
		a.sendError(w, "Error getting total social shares: "+err.Error(), http.StatusInternalServerError)
		web3authGetTotalSocialSharesErrorRetrieving.Inc(1)
		return
	}

	// Track total value
	mon.IntVal("web3auth_get_total_social_shares_value").Observe(int64(total))

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]uint64{
		"total": total,
	})
	if err != nil {
		a.sendError(w, "Error encoding response", http.StatusInternalServerError)
		return
	}
}

func (a *Web3Auth) GetSignMessage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	email := r.URL.Query().Get("email")
	if email == "" {
		a.sendError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Use GetByEmailWithUnverified to also check for unverified users
	user, unverified, err := a.service.GetUsers().GetByEmailWithUnverified(ctx, email)
	if err != nil {
		// Check if it's a "not found" error (user doesn't exist yet)
		if console.ErrEmailNotFound.Has(err) {
			a.sendError(w, "User not found", http.StatusNotFound)
			return
		}
		a.sendError(w, "Error getting user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If user is nil, check unverified users
	if user == nil {
		if len(unverified) > 0 {
			// Use the first unverified user
			user = &unverified[0]
		} else {
			a.sendError(w, "User not found", http.StatusNotFound)
			return
		}
	}

	// Check if user account is deactivated (Inactive status)
	if user.Status == console.Inactive {
		a.sendError(w, "Account Deactivated please contact Storx Admin at support@storx.io", http.StatusUnauthorized)
		return
	}

	// Check if user is active (allow Active status only)
	if user.Status != console.Active {
		a.sendError(w, "User not active", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":                  email,
		"wallet_id":              user.WalletId,
		"nonce":                  strconv.FormatInt(time.Now().Unix(), 10),
		"exp":                    time.Now().Add(time.Minute * 5).Unix(),
		"source":                 user.Source,
		"mfaEnabled":             user.MFAEnabled,
		"loginLockoutExpiration": user.LoginLockoutExpiration,
	})
	tokenString, err := token.SignedString([]byte(a.secreteKey))
	if err != nil {
		a.sendError(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
	if err != nil {
		a.sendError(w, "Error encoding sign message", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *Web3Auth) sendError(w http.ResponseWriter, err string, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": err,
	})
}

func getPublicKey(payload, signature string) (string, error) {
	// Step 1: Ethereum Signed Message Hash
	prefixedMessage := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(payload), payload)
	hash := crypto.Keccak256Hash([]byte(prefixedMessage))
	fmt.Println("Hash:", hash.Hex())

	// Step 2: Decode Signature
	sigBytes, err := hexutil.Decode(signature)
	if err != nil {
		return "", fmt.Errorf("invalid signature format: %w", err)
	}

	// Step 3: Fix V value (Ethereum adds 27 to v)
	if sigBytes[64] < 27 {
		sigBytes[64] += 27
	} else {
		sigBytes[64] -= 27 // Ensure v is in the correct range
	}
	// Step 4: Recover Public Key
	publicKey, err := crypto.Ecrecover(hash.Bytes(), sigBytes)
	if err != nil {
		return "", fmt.Errorf("ecrecover failed: %w", err)
	}

	// Step 5: Convert Public Key to Address
	pubKey, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key: %w", err)
	}

	recoveredAddress := crypto.PubkeyToAddress(*pubKey)
	return recoveredAddress.Hex(), nil
}
