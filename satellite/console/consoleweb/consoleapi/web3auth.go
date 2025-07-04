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
	"storj.io/storj/private/web"
	"storj.io/storj/satellite/console"
	"storj.io/storj/satellite/console/consoleweb/consolewebauth"
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

	err = a.service.UploadBackupShare(r.Context(), backupIDStr, share)
	if err != nil {
		a.sendError(w, "Error uploading backup share: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (a *Web3Auth) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	// Add logging to help debug
	a.log.Debug("Web3Auth Token request received")

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
	backupIDStr := r.URL.Query().Get("backup_id")

	share, err := a.service.GetBackupShare(r.Context(), backupIDStr)
	if err != nil {
		a.sendError(w, "Error getting backup share: "+err.Error(), http.StatusInternalServerError)
		return
	}

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

	exists, err := a.service.SocialShareKeyExists(ctx, id)
	if err != nil {
		a.sendError(w, "Error checking social share: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if exists {
		err = a.service.UpdateSocialShare(ctx, id, string(share))
	} else {
		err = a.service.CreateSocialShare(ctx, id, string(share))
	}

	if err != nil {
		a.sendError(w, "Error uploading social share: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
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
		return
	}

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
		return
	}

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
		return
	}

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

	user, err := a.service.GetUsers().GetByEmail(ctx, email)
	if err != nil {
		a.sendError(w, "Error getting user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if user == nil {
		a.sendError(w, "User not found", http.StatusNotFound)
		return
	}

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
