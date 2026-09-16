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
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	authnPrefix = "security.authentication"
)

// parseCaddyfileAuthentication parses an authentication portal in security.
// See the caddyfile_authn_* helpers for the full grammar of each subdirective.
// Cookie and admin API statements are collected across the complete portal and
// validated by their shared go-authcrunch parsers, including alias collisions.
//
// Syntax:
//
//	authentication portal <name> {
//		crypto key sign-verify <shared_secret>
//		oidc provider { ... }
//		ui { ... }
//		transform user { ... }
//		cookie prefix <prefix>
//		cookie access token name <name>
//		validate source address
//		enable source ip tracking
//		<enable|disable> admin api
//		<enable|disable> admin api private key export
//		enable identity store <name> [<name>...]
//		enable identity provider <name> [<name>...]
//		enable sso provider <name> [<name>...]
//		trust <login|logout> redirect uri domain [exact|partial|prefix|suffix|regex] <domain> path [exact|partial|prefix|suffix|regex] <path>
//	}
//
// Registration is configured with user registration in security and attached to
// an identity store; there is no enable user registration portal directive.
//
// The optional, single oidc provider block is collected by
// readCaddyfileOIDCProvider and attached before AddAuthenticationPortal validates
// the completed portal. The global parser registers all applications first,
// including declarations following this portal or expanded from later imports.
func parseCaddyfileAuthentication(d *caddyfile.Dispenser, app *App) error {
	// rootDirective is config key prefix.
	var rootDirective string
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "portal":
		p := &authn.PortalConfig{
			Name: args[1],
			UI: &ui.Parameters{
				Templates: make(map[string]string),
			},
			TokenValidatorOptions: &options.TokenValidatorOptions{},
			TokenGrantorOptions:   &options.TokenGrantorOptions{},
			API: &authn.APIConfig{
				ProfileEnabled: true,
			},
		}
		var cookieStatements []string
		var adminStatements []string
		var oidcStatements []string
		nesting := d.Nesting()
		for d.NextBlock(nesting) {
			k := d.Val()
			v := d.RemainingArgs()
			rootDirective = mkcp(authnPrefix, args[0], k)
			switch k {
			case "oidc":
				if oidcStatements != nil {
					return d.Errf("oidc provider is already configured for portal %q", p.Name)
				}
				statements, err := readCaddyfileOIDCProvider(d, v)
				if err != nil {
					return err
				}
				oidcStatements = statements
			case "crypto":
				if err := parseCaddyfileAuthPortalCrypto(d, p, rootDirective, v); err != nil {
					return err
				}
			case "cookie", "set":
				statement, err := encodePortalCookieDirective(k, v, true)
				if err != nil {
					return d.Errf("%s: %v", rootDirective, err)
				}
				cookieStatements = append(cookieStatements, statement)
			case "ui":
				if err := parseCaddyfileAuthPortalUI(d, p, rootDirective); err != nil {
					return err
				}
			case "transform":
				if err := parseCaddyfileAuthPortalTransform(d, p, rootDirective, v); err != nil {
					return err
				}
			case "enable", "disable":
				if k == "enable" && len(v) > 0 && !strings.HasPrefix(v[0], "admin") {
					if err := parseCaddyfileAuthPortalMisc(d, p, rootDirective, k, v); err != nil {
						return err
					}
					continue
				}
				statement, err := encodePortalAdminAPIDirective(k, v)
				if err != nil {
					return d.Errf("%s: %v", rootDirective, err)
				}
				// Admin settings are statements, never nested blocks.
				if d.Next() {
					hasBlock := d.Val() == "{"
					d.Prev()
					if hasBlock {
						return d.Errf("%s: admin API directives do not accept blocks", rootDirective)
					}
				}
				adminStatements = append(adminStatements, statement)
			case "validate", "trust":
				if err := parseCaddyfileAuthPortalMisc(d, p, rootDirective, k, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, v)
			}
		}
		// NextSegment counts quoted brace-valued arguments as structural tokens.
		// A truncated segment must not let a child's closing brace also satisfy
		// this portal's boundary merely because NextBlock reached EOF.
		if d.Nesting() != nesting {
			return d.Errf("unterminated authentication portal block")
		}

		if err := configurePortalAdminAPI(p, adminStatements); err != nil {
			return d.Errf("%s.portal %q admin API: %v", authnPrefix, p.Name, err)
		}

		// Runtime placeholders must be expanded before the shared parser validates
		// names and domains. Preserve the complete snapshot across Caddy JSON.
		if cookieDirectivesNeedResolution(cookieStatements) {
			if app.PortalCookieDirectives == nil {
				app.PortalCookieDirectives = make(map[string][]string)
			}
			if _, exists := app.PortalCookieDirectives[p.Name]; exists {
				return d.Errf("duplicate cookie portal %q", p.Name)
			}
			app.PortalCookieDirectives[p.Name] = cookieStatements
		} else if err := configurePortalCookies(p, cookieStatements); err != nil {
			return d.Errf("%s.portal %q cookies: %v", authnPrefix, p.Name, err)
		}
		if oidcStatements != nil {
			if err := app.Config.ConfigureOIDCProvider(p, oidcStatements); err != nil {
				return d.Errf("%s.portal %q oidc provider: %v", authnPrefix, p.Name, err)
			}
			if app.OIDCProviderDirectives == nil {
				app.OIDCProviderDirectives = make(map[string][]string)
			}
			app.OIDCProviderDirectives[p.Name] = oidcStatements
		}
		if err := app.Config.AddAuthenticationPortal(p); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authnPrefix, args)
	}
	return nil
}

func mkcp(parts ...string) string {
	return strings.Join(parts, ".")
}
