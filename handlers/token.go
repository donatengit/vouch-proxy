/*

Copyright 2022 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package handlers

import (
	"fmt"
	"net/http"

	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
)

func renderResponse(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(msg))
}


// TokenRequestHandler /token
func TokenRequestHandler(w http.ResponseWriter, r *http.Request) {
	fastlog.Debug("/token")

	jwt := jwtmanager.FindJWT(r)
	if jwt == "" {
		renderResponse(w, "Error: no JWT")
		return
	}

	claims, err := jwtmanager.ClaimsFromJWT(jwt)
	if err != nil {
		renderResponse(w, "Error: unexpected JWT contents")
		return
	}

	if claims.Username == "" {
		renderResponse(w, "Error: no username in JWT")
		return
	}

	if !cfg.Cfg.AllowAllUsers {
		if !claims.SiteInAudience(r.Host) {
			renderResponse(w,
				fmt.Sprintf("Error: http header 'Host: %s' not authorized for configured `vouch.domains` (is Host being sent properly?)", r.Host))
			return
		}
	}


	renderResponse(w, "User: "+claims.Username+"\nToken: "+jwt)
	
}
