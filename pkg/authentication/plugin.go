// Copyright 2020 Paul Greenberg greenpau@outlook.com
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

package authentication

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/aaasf/pkg/authn"
	"github.com/greenpau/aaasf/pkg/requests"
	"github.com/greenpau/caddy-security/pkg/util"
)

const (
	pluginName = "authenticator"
)

//func init() {
//	caddy.RegisterModule(Middleware{})
//}

// Middleware implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type Middleware struct {
	Authenticator *authn.Authenticator `json:"authenticator,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers." + pluginName,
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision provisions Authenticator.
func (m *Middleware) Provision(ctx caddy.Context) error {
	return m.Authenticator.Provision(ctx.Logger(m))
}

// UnmarshalCaddyfile unmarshals a caddyfile.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	a, err := parseCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.Authenticator = a
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return m.Authenticator.Validate()
}

// ServeHTTP serves authentication portal.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	rr := requests.NewRequest()
	rr.ID = util.GetRequestID(r)
	return m.Authenticator.ServeHTTP(r.Context(), w, r, rr)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
