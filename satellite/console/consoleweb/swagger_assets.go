// Copyright (C) 2026 StorX Network, Inc.
// See LICENSE for copying information.

package consoleweb

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:swaggerui
var swaggerUI embed.FS

func swaggerUIHandler() (http.Handler, error) {
	sub, err := fs.Sub(swaggerUI, "swaggerui")
	if err != nil {
		return nil, err
	}
	return http.StripPrefix("/swagger/", http.FileServer(http.FS(sub))), nil
}
