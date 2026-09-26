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
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
	httpcaddyfile.RegisterHandlerDirective("authorize", parseAuthzCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("authorize", httpcaddyfile.Before, "basicauth")
}

// AuthzMiddleware delegates JWT and direct OAuth authorization to a policy.
// AuthorizationHandler supplies the route-level handled-response contract.
type AuthzMiddleware struct {
	RouteMatcher   string `json:"route_matcher,omitempty" xml:"route_matcher,omitempty" yaml:"route_matcher,omitempty"`
	GatekeeperName string `json:"gatekeeper_name,omitempty" xml:"gatekeeper_name,omitempty" yaml:"gatekeeper_name,omitempty"`
	gatekeeper     *authz.Gatekeeper
	app            *App
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

	repl := caddy.NewReplacer()
	if v, _, err := util.FindReplace(repl, m.GatekeeperName); err == nil {
		m.GatekeeperName = v
	} else {
		return fmt.Errorf("%s config is malformed: %v", authzPluginName, err)
	}

	gatekeeper, err := app.getGatekeeper(m.GatekeeperName)
	if err != nil {
		return fmt.Errorf("security app erred with %q authorization policy: %v", m.GatekeeperName, err)
	}
	m.gatekeeper = gatekeeper
	m.app = app

	return nil
}

// UnmarshalCaddyfile unmarshals caddyfile.
func (m *AuthzMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	switch len(args) {
	case 3:
		m.RouteMatcher = "*"
		if args[1] != "with" {
			return d.Errf("directive must contain %q keyword: %s", "with", strings.Join(args, " "))
		}
		m.GatekeeperName = args[2]
	case 4:
		if args[2] != "with" {
			return d.Errf("directive must contain %q keyword: %s", "with", strings.Join(args, " "))
		}
		m.RouteMatcher = args[1]
		m.GatekeeperName = args[3]
	default:
		return d.Errf("malformed directive: %s", strings.Join(args, " "))
	}
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
	if m.gatekeeper == nil && m.app == nil {
		return fmt.Errorf("gatekeeper is nil")
	}
	return nil
}

// Authenticate translates successful gatekeeper identity into Caddy metadata.
func (m AuthzMiddleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	release, ok := m.app.acquireRequest()
	if !ok {
		w.Header().Set("Cache-Control", "no-store")
		return caddyauth.User{}, false, caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("security app is shutting down"))
	}
	defer release()
	gatekeeper := m.gatekeeper
	if gatekeeper == nil {
		var err error
		gatekeeper, err = m.app.server.GetGatekeeperByName(m.GatekeeperName)
		if err != nil {
			return caddyauth.User{}, false, caddyhttp.Error(http.StatusServiceUnavailable, err)
		}
	}

	normalizeSecurityMetadata(r)
	ar := requests.NewAuthorizationRequest()
	ar.ID = util.GetRequestID(r)
	// Gatekeeper writes only handled denials/redirects, never the protected
	// response. Set no-store before those headers commit, without buffering or
	// changing successful upstream caching behavior.
	response := caddyhttp.NewResponseRecorder(w, nil, func(_ int, header http.Header) bool {
		header.Set("Cache-Control", "no-store")
		return false
	})
	if err := gatekeeper.Authenticate(response, r, ar); err != nil {
		w.Header().Set("Cache-Control", "no-store")
		return caddyauth.User{}, false, errors.ErrAuthorizationFailed.WithArgs(
			getAuthorizationDetails(r, ar), err,
		)
	}

	if ar.Response.Bypassed {
		return caddyauth.User{}, ar.Response.Bypassed, nil
	}

	// A nil error does not imply authorization. A closed gatekeeper, for
	// example, writes a handled 503 with both response flags false.
	if !ar.Response.Authorized {
		w.Header().Set("Cache-Control", "no-store")
		return caddyauth.User{}, false, nil
	}

	if ar.Response.User == nil {
		w.Header().Set("Cache-Control", "no-store")
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
	for _, k := range []string{"claim_id", "sub", "email", "name", "issuer", "origin", "realm"} {
		if v, exists := ar.Response.User[k]; exists {
			u.Metadata[k] = v.(string)
		}
	}

	if v, exists := ar.Response.User["userinfo|preferred_username"]; exists {
		u.Metadata["username"] = v.(string)
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

// parseAuthzCaddyfile attaches a named policy to a Caddy HTTP route.
//
// Syntax:
//
//	authorize [<matcher>] with <policy>
//
// The policy is defined in security. This directive takes arguments only;
// configure its internals in the corresponding security block.
func parseAuthzCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &AuthzMiddleware{}
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &AuthorizationHandler{AuthzMiddleware: *m}, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthzMiddleware)(nil)
	_ caddy.Validator         = (*AuthzMiddleware)(nil)
	_ caddyauth.Authenticator = (*AuthzMiddleware)(nil)
	_ caddyfile.Unmarshaler   = (*AuthzMiddleware)(nil)
)
