// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() { caddy.RegisterModule(AuthorizationHandler{}) }

// AuthorizationHandler preserves the gatekeeper's three outcomes. Caddy's
// generic authentication chain cannot represent a handled callback or denial;
// keep the legacy provider available for JSON consumers, and use this handler
// for the authorize directive.
type AuthorizationHandler struct{ AuthzMiddleware }

// CaddyModule identifies the route handler separately from the legacy provider.
func (AuthorizationHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authorization",
		New: func() caddy.Module { return new(AuthorizationHandler) },
	}
}

// ServeHTTP only runs downstream after explicit authorization or bypass.
func (m AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	response := caddyhttp.NewResponseRecorder(w, nil, nil)
	user, authorized, err := m.Authenticate(response, r)
	if response.Status() != 0 {
		return nil // Preserve handled status, cookies, body and protocol failures.
	}
	if err != nil || !authorized {
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			// Retain the authentication provider's error placeholder for existing
			// handle_errors routes when no response has already been handled.
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			repl.Set("http.auth."+authzPluginName+".error", err.Error())
		}
		if err == nil {
			err = fmt.Errorf("not authenticated")
		}
		return caddyhttp.Error(http.StatusUnauthorized, err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.auth.user.id", user.ID)
	for key, value := range user.Metadata {
		repl.Set("http.auth.user."+key, value)
	}
	return next.ServeHTTP(w, r)
}

var (
	_ caddy.Provisioner           = (*AuthorizationHandler)(nil)
	_ caddy.Validator             = (*AuthorizationHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthorizationHandler)(nil)
)
