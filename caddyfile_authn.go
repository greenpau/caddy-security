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

// parseCaddyfileAuthentication parses authentication configuration.
//
// Syntax:
//
//	  authentication portal <name> {
//
//		crypto key sign-verify <shared_secret>
//
//		ui {
//			template <login|portal> <file_path>
//			logo_url <file_path|url_path>
//			logo_description <value>
//			custom css path <path>
//			custom js path <path>
//			custom html header path <path>
//			static_asset <uri> <content_type> <path>
//			allow settings for role <role>
//		}
//
//	    cookie prefix <prefix>
//	    cookie <session id|referer|sandbox id|identity token|access token|refresh token|oidc session id|oidc request id> name <name>
//	    cookie <insecure|strip domain|guess domain> <enabled|disabled>
//	    cookie domain <name> [<attribute> <value>]
//	    cookie path <name>
//	    cookie lifetime <seconds>
//	    cookie samesite <lax|strict|none>
//	    cookie insecure <on|off>
//	    set <session_id|redirect_url|sandbox_id|id_token|access_token|refresh_token> cookie name <name>
//
//	    validate source address
//
//	    enable source ip tracking
//	    enable admin api
//	    enable identity store <name>
//	    enable identity provider <name>
//	    enable sso provider <name>
//	    enable user registration <name>
//
//		trust [login|logout] redirect uri domain [exact|partial|prefix|suffix|regex] <domain_name> path [exact|partial|prefix|suffix|regex] <path>
//
//	}
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
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := d.RemainingArgs()
			rootDirective = mkcp(authnPrefix, args[0], k)
			switch k {
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
			case "enable", "validate", "trust":
				if err := parseCaddyfileAuthPortalMisc(d, p, rootDirective, k, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, v)
			}
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
