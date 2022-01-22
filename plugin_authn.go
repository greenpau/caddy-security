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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/caddy-security/pkg/util"
)

const (
	authnPluginName = "authenticator"
)

func init() {
	caddy.RegisterModule(AuthnMiddleware{})
}

// AuthnMiddleware implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type AuthnMiddleware struct {
	Authenticator *authn.Authenticator `json:"authenticator,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthnMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.authenticator",
		New: func() caddy.Module { return new(AuthnMiddleware) },
	}
}

// Provision provisions Authenticator.
func (m *AuthnMiddleware) Provision(ctx caddy.Context) error {
	appModule, err := ctx.App("security")
	if err != nil {
		return err
	}

	secApp := appModule.(*App)
	if secApp == nil {
		return fmt.Errorf("security app is nil")
	}
	if secApp.Config == nil {
		return fmt.Errorf("security app config is nil")
	}

	var foundRef bool
	for _, cfg := range secApp.Config.Portals {
		if cfg.Name == m.Authenticator.PortalName {
			foundRef = true
			break
		}
	}
	if !foundRef {
		return fmt.Errorf("security app has no %q authentication portal", m.Authenticator.PortalName)
	}

	return m.Authenticator.Provision(ctx.Logger(m))
}

// UnmarshalCaddyfile unmarshals a caddyfile.
func (m *AuthnMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	a, err := parseAuthnPluginCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.Authenticator = a
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthnMiddleware) Validate() error {
	return m.Authenticator.Validate()
}

// ServeHTTP serves authentication portal.
func (m *AuthnMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	rr := requests.NewRequest()
	rr.ID = util.GetRequestID(r)
	return m.Authenticator.ServeHTTP(r.Context(), w, r, rr)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthnMiddleware)(nil)
	_ caddy.Validator             = (*AuthnMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthnMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AuthnMiddleware)(nil)
)
