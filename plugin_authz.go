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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
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
	RouteMatcher   string `json:"route_matcher,omitempty" xml:"route_matcher,omitempty" yaml:"route_matcher,omitempty"`
	GatekeeperName string `json:"gatekeeper_name,omitempty" xml:"gatekeeper_name,omitempty" yaml:"gatekeeper_name,omitempty"`
	gatekeeper     *authz.Gatekeeper
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

	app := appModule.(*App)
	if app == nil {
		return fmt.Errorf("security app is nil")
	}
	if app.Config == nil {
		return fmt.Errorf("security app config is nil")
	}

	gatekeeper, err := app.getGatekeeper(m.GatekeeperName)
	if err != nil {
		return fmt.Errorf("security app erred with %q authorization policy: %v", m.GatekeeperName, err)
	}
	m.gatekeeper = gatekeeper

	return nil
}

// UnmarshalCaddyfile unmarshals caddyfile.
func (m *AuthzMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) (err error) {
	cfg, err := parseAuthzPluginCaddyfile(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		return err
	}
	m.RouteMatcher = cfg["path"]
	m.GatekeeperName = cfg["gatekeeper_name"]
	return nil
}

// Validate implements caddy.Validator.
func (m *AuthzMiddleware) Validate() error {
	if m.RouteMatcher == "" {
		return fmt.Errorf("empty route matcher")
	}
	if m.GatekeeperName == "" {
		return fmt.Errorf("empty gatekeeper name")
	}
	if m.gatekeeper == nil {
		return fmt.Errorf("gatekeeper is nil")
	}
	return nil
}

// Authenticate authorizes access based on the presense and content of
// authorization token.
func (m AuthzMiddleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	ar := requests.NewAuthorizationRequest()
	ar.ID = util.GetRequestID(r)
	if err := m.gatekeeper.Authenticate(w, r, ar); err != nil {
		return caddyauth.User{}, false, errors.ErrAuthorizationFailed.WithArgs(
			getAuthorizationDetails(r, ar), err,
		)
	}

	if ar.Response.Bypassed {
		return caddyauth.User{}, ar.Response.Bypassed, nil
	}

	if ar.Response.User == nil {
		return caddyauth.User{}, false, errors.ErrAuthorizationFailed.WithArgs(
			getAuthorizationDetails(r, ar), "user data not found",
		)
	}

	u := caddyauth.User{
		Metadata: map[string]string{
			"roles": ar.Response.User["roles"].(string),
		},
	}
	if v, exists := ar.Response.User["id"]; exists {
		u.ID = v.(string)
	}
	for _, k := range []string{"claim_id", "sub", "email", "name"} {
		if v, exists := ar.Response.User[k]; exists {
			u.Metadata[k] = v.(string)
		}
	}
	return u, ar.Response.Authorized, nil
}

func getAuthorizationDetails(r *http.Request, ar *requests.AuthorizationRequest) string {
	var details []string
	details = append(details, fmt.Sprintf("src_ip=%s", addrutil.GetSourceAddress(r)))
	details = append(details, fmt.Sprintf("src_conn_ip=%s", addrutil.GetSourceConnAddress(r)))
	if ar.Response.User != nil {
		for k, v := range ar.Response.User {
			switch k {
			case "email", "sub", "name", "jti":
				details = append(details, fmt.Sprintf("%s=%s", k, v.(string)))
			}
		}
	}
	return strings.Join(details, ", ")
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthzMiddleware)(nil)
	_ caddy.Validator         = (*AuthzMiddleware)(nil)
	_ caddyauth.Authenticator = (*AuthzMiddleware)(nil)
	_ caddyfile.Unmarshaler   = (*AuthzMiddleware)(nil)
)
