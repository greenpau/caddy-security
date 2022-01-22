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
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/caddy-security/pkg/util"
)

const (
	authzPluginName = "authorizer"
)

func init() {
	caddy.RegisterModule(AuthzMiddleware{})
}

// AuthzMiddleware authorizes access to endpoints based on
// the presense and content of JWT token.
type AuthzMiddleware struct {
	Authorizer *authz.Authorizer `json:"authorizer,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthzMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.authorizer",
		New: func() caddy.Module { return new(AuthzMiddleware) },
	}
}

// Provision provisions Authorizer.
func (m *AuthzMiddleware) Provision(ctx caddy.Context) error {
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
	for _, cfg := range secApp.Config.Policies {
		if cfg.Name == m.Authorizer.GatekeeperName {
			foundRef = true
			break
		}
	}
	if !foundRef {
		return fmt.Errorf("security app has no %q authorization policy", m.Authorizer.GatekeeperName)
	}

	return m.Authorizer.Provision(ctx.Logger(m))
}

// UnmarshalCaddyfile unmarshals caddyfile.
func (m *AuthzMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	a, err := parseAuthzPluginCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.Authorizer = a
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthzMiddleware) Validate() error {
	return m.Authorizer.Validate()
}

// Authenticate authorizes access based on the presense and content of
// authorization token.
func (m AuthzMiddleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
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
	_ caddy.Provisioner       = (*AuthzMiddleware)(nil)
	_ caddy.Validator         = (*AuthzMiddleware)(nil)
	_ caddyauth.Authenticator = (*AuthzMiddleware)(nil)
	_ caddyfile.Unmarshaler   = (*AuthzMiddleware)(nil)
)
