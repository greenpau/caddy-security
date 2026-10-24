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
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/portalpath"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func init() {
	caddy.RegisterModule(AuthnMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("authenticate", parseAuthnCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("authenticate", httpcaddyfile.Before, "respond")
}

// AuthnMiddleware implements Form-Based, Basic, Local, LDAP,
// OpenID Connect, OAuth 2.0, SAML Authentication.
type AuthnMiddleware struct {
	RouteMatcher string `json:"route_matcher,omitempty" xml:"route_matcher,omitempty" yaml:"route_matcher,omitempty"`
	PortalName   string `json:"portal_name,omitempty" xml:"portal_name,omitempty" yaml:"portal_name,omitempty"`
	// BasePath declares a literal portal mount. Omission retains legacy inference;
	// a present value must be canonical, including an explicit slash for root.
	BasePath *string `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	portal   *authn.Portal
	app      *App
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
	if err := m.validateMount(); err != nil {
		return err
	}
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
	if v, _, err := util.FindReplace(repl, m.PortalName); err == nil {
		m.PortalName = v
	} else {
		return fmt.Errorf("authenticator config is malformed: %v", err)
	}
	if m.BasePath != nil {
		if err := app.validatePortalMount(m.PortalName, *m.BasePath); err != nil {
			return err
		}
	}

	portal, err := app.getPortal(m.PortalName)
	if err != nil {
		return fmt.Errorf("security app erred with %q authentication portal: %v", m.PortalName, err)
	}
	m.portal = portal
	m.app = app

	return nil
}

// UnmarshalCaddyfile unmarshals a caddyfile.
func (m *AuthnMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	args := d.RemainingArgs()
	m.BasePath = nil
	if len(args) >= 2 && args[len(args)-2] == "at" {
		basePath := args[len(args)-1]
		m.BasePath = &basePath
		if err := m.validateMount(); err != nil {
			return d.Err(err.Error())
		}
		args = args[:len(args)-2]
	}
	switch len(args) {
	case 3:
		m.RouteMatcher = "*"
		if args[1] != "with" {
			return d.Errf("directive must contain %q keyword: %s", "with", strings.Join(args, " "))
		}
		m.PortalName = args[2]
	case 4:
		if args[2] != "with" {
			return d.Errf("directive must contain %q keyword: %s", "with", strings.Join(args, " "))
		}
		m.RouteMatcher = args[1]
		m.PortalName = args[3]
	default:
		return d.Errf("malformed directive: %s", strings.Join(args, " "))
	}
	if d.Next() {
		if d.ValRaw() == "{" {
			return d.Err("authenticate does not accept blocks")
		}
		return d.Err("authenticate does not accept additional lines")
	}
	return nil
}

func (m *AuthnMiddleware) validateMount() error {
	if m.BasePath == nil {
		return nil
	}
	if err := portalpath.Validate(*m.BasePath); err != nil {
		return fmt.Errorf("invalid portal mount: %w", err)
	}
	if m.app != nil {
		return m.app.validatePortalMount(m.PortalName, *m.BasePath)
	}
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
	if err := m.validateMount(); err != nil {
		return err
	}
	if m.portal == nil && m.app == nil {
		return fmt.Errorf("portal is nil")
	}

	return nil
}

// ServeHTTP serves authentication portal.
func (m *AuthnMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	release, ok := m.app.acquireRequest()
	if !ok {
		w.Header().Set("Cache-Control", "no-store")
		return caddyhttp.Error(http.StatusServiceUnavailable, fmt.Errorf("security app is shutting down"))
	}
	defer release()
	portal := m.portal
	if portal == nil {
		// Admission pins the root; cleanup cannot close it before this call ends.
		var err error
		portal, err = m.app.server.GetPortalByName(m.PortalName)
		if err != nil {
			return caddyhttp.Error(http.StatusServiceUnavailable, err)
		}
	}

	if m.BasePath != nil {
		// Caddy retains the wire path independently of prior rewrite handlers.
		// An explicit portal mount requires the original path, including escaping;
		// query-only rewrites do not change this boundary.
		if original, ok := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request); ok && original.URL != nil &&
			(original.URL.Path != r.URL.Path || original.URL.RawPath != r.URL.RawPath) {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return nil
		}
	}
	normalizeSecurityMetadata(r)
	rr := requests.NewRequest()
	rr.ID = util.GetRequestID(r)
	// Preserve the complete mount, body, cookies and protocol headers. ServeHTTP owns
	// OIDC dispatch and refresh/session/logout authentication before ordinary
	// access-token gates, so expired access can renew or log out. It also serves
	// the matching browser coordinator and continuation UI. Do not preauthorize,
	// rewrite, retry or broaden CORS for these requests in Caddy middleware.
	// JSON/native login uses this same dispatch: never synthesize Cookie, Origin
	// or Fetch Metadata headers, or turn its credentials into OIDC login evidence.
	if m.BasePath != nil {
		return portal.ServeHTTPAt(r.Context(), w, r, rr, *m.BasePath)
	}
	return portal.ServeHTTP(r.Context(), w, r, rr)
}

// parseAuthnCaddyfile attaches a named portal to a Caddy HTTP route.
//
// Syntax:
//
//	authenticate [<matcher>] with <portal> [at <base-path>]
//
// The portal is defined in security. This directive takes arguments only;
// configure its internals in the corresponding security block. An explicit mount
// is literal and canonical (/ for root), must agree with enabled mounted features,
// and requires the complete original request path. Omission keeps legacy inference.
func parseAuthnCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &AuthnMiddleware{}
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*AuthnMiddleware)(nil)
	_ caddy.Validator             = (*AuthnMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*AuthnMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*AuthnMiddleware)(nil)
)
