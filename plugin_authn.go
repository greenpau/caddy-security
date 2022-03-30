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
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/requests"
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
	RouteMatcher string `json:"route_matcher,omitempty" xml:"route_matcher,omitempty" yaml:"route_matcher,omitempty"`
	PortalName   string `json:"portal_name,omitempty" xml:"portal_name,omitempty" yaml:"portal_name,omitempty"`
	portal       *authn.Portal
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

	app := appModule.(*App)
	if app == nil {
		return fmt.Errorf("security app is nil")
	}
	if app.Config == nil {
		return fmt.Errorf("security app config is nil")
	}

	portal, err := app.getPortal(m.PortalName)
	if err != nil {
		return fmt.Errorf("security app erred with %q authentication portal: %v", m.PortalName, err)
	}
	m.portal = portal

	return nil
}

// UnmarshalCaddyfile unmarshals a caddyfile.
func (m *AuthnMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	cfg, err := parseAuthnPluginCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.RouteMatcher = cfg["path"]
	m.PortalName = cfg["portal_name"]
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthnMiddleware) Validate() error {
	if m.RouteMatcher == "" {
		return fmt.Errorf("empty route matcher")
	}
	if m.PortalName == "" {
		return fmt.Errorf("empty portal name")
	}
	if m.portal == nil {
		return fmt.Errorf("portal is nil")
	}

	return nil
}

// ServeHTTP serves authentication portal.
func (m *AuthnMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	rr := requests.NewRequest()
	rr.ID = util.GetRequestID(r)
	return m.portal.ServeHTTP(r.Context(), w, r, rr)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthnMiddleware)(nil)
	_ caddy.Validator             = (*AuthnMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthnMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AuthnMiddleware)(nil)
)
