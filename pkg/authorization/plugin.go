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

package authorization

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/aaasf/pkg/authz"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/aaasf/pkg/requests"
	"github.com/greenpau/caddy-security/pkg/util"
)

const (
	pluginName = "authorizer"
)

// func init() {
//	caddy.RegisterModule(Middleware{})
// }

// Middleware authorizes access to endpoints based on
// the presense and content of JWT token.
type Middleware struct {
	Authorizer *authz.Authorizer `json:"authorizer,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers." + pluginName,
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision provisions Authorizer.
func (m *Middleware) Provision(ctx caddy.Context) error {
	return m.Authorizer.Provision(ctx.Logger(m))
}

// UnmarshalCaddyfile unmarshals caddyfile.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	a, err := parseCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.Authorizer = a
	return nil
}

// Validate implements caddy.Validator.
func (m *Middleware) Validate() error {
	return m.Authorizer.Validate()
}

// Authenticate authorizes access based on the presense and content of
// authorization token.
func (m Middleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	rr := requests.NewAuthorizationRequest()
	rr.ID = util.GetRequestID(r)
	if err := m.Authorizer.Authenticate(w, r, rr); err != nil {
		return caddyauth.User{}, false, errors.ErrAuthorizationFailed
	}

	if rr.Response.User == nil {
		return caddyauth.User{}, false, errors.ErrAuthorizationFailed
	}

	u := caddyauth.User{
		Metadata: map[string]string{
			"roles": rr.Response.User["roles"].(string),
		},
	}
	if v, exists := rr.Response.User["id"]; exists {
		u.ID = v.(string)
	}
	for _, k := range []string{"claim_id", "sub", "email", "name"} {
		if v, exists := rr.Response.User[k]; exists {
			u.Metadata[k] = v.(string)
		}
	}
	return u, rr.Response.Authorized, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*Middleware)(nil)
	_ caddy.Validator         = (*Middleware)(nil)
	_ caddyauth.Authenticator = (*Middleware)(nil)
	_ caddyfile.Unmarshaler   = (*Middleware)(nil)
)
