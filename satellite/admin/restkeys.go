// Copyright (C) 2020 Storj Labs, Inc.
// See LICENSE for copying information.

package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func (server *Server) addRESTKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONError(w, "failed to read body",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var input struct {
		Expiration string `json:"expiration"`
		Name       string `json:"name"`
	}

	err = json.Unmarshal(body, &input)
	if err != nil {
		sendJSONError(w, "failed to unmarshal request",
			err.Error(), http.StatusBadRequest)
		return
	}

	var expiration time.Duration
	if input.Expiration != "" {
		expiration, err = time.ParseDuration(input.Expiration)
		if err != nil {
			sendJSONError(
				w,
				"failed to parse expiration. It accepts any non-negative value according the format rules of https://pkg.go.dev/time#ParseDuration",
				err.Error(),
				http.StatusBadRequest,
			)
			return
		}

		if expiration < 0 {
			sendJSONError(
				w,
				"invalid expiration value",
				"value must result in a greater or equal than 0 duration",
				http.StatusBadRequest,
			)
		}
	}

	apiKey, expiresAt, err := server.restKeys.Create(ctx, input.Name, &expiration)
	if err != nil {
		sendJSONError(w, "api key creation failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	var output struct {
		APIKey    string    `json:"apikey"`
		ExpiresAt time.Time `json:"expiresAt"`
	}

	output.APIKey = apiKey
	output.ExpiresAt = *expiresAt

	data, err := json.Marshal(output)
	if err != nil {
		sendJSONError(w, "json encoding failed",
			err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONData(w, http.StatusOK, data)
}

func (server *Server) revokeRESTKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var err error
	defer mon.Task()(&ctx)(&err)

	vars := mux.Vars(r)
	apiKey, ok := vars["apikey"]
	if !ok {
		sendJSONError(w, "api key missing",
			"", http.StatusBadRequest)
		return
	}

	err = server.restKeys.Revoke(ctx, apiKey)
	if err != nil {
		sendJSONError(w, "failed to revoke api key",
			err.Error(), http.StatusNotFound)
		return
	}
}
