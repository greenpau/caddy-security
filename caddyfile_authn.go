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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/registration"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strings"
)

const (
	authnPrefix = "security.authentication"
)

// parseCaddyfileAuthentication parses authentication configuration.
//
// Syntax:
//
//   authentication portal <name> {
//
//     backend local <file/path/to/user/db> <realm/name>
//     backend local {
//       method <local>
//       file <file_path>
//       realm <name>
//     }
//
//     backend oauth2_generic {
//       method oauth2
//       realm generic
//       provider generic
//       base_auth_url <base_url>
//       metadata_url <metadata_url>
//       client_id <client_id>
//       client_secret <client_secret>
//       scopes openid email profile
//       disable metadata_discovery
//       authorization_url <authorization_url>
//       disable key_verification
//       callback_url <callback_url>
//     }
//
//     backend gitlab {
//       method oauth2
//       realm gitlab
//       provider gitlab
//       domain_name <domain>
//       client_id <client_id>
//       client_secret <client_secret>
//       user_group_filters <regex_pattern>
//     }
//
//     backend google <client_id> <client_secret>
//     backend github <client_id> <client_secret>
//     backend facebook <client_id> <client_secret>
//
//	   crypto key sign-verify <shared_secret>
//
//	   ui {
//	     template <login|portal> <file_path>
//	     logo_url <file_path|url_path>
//	     logo_description <value>
//       custom css path <path>
//       custom js path <path>
//       custom html header path <path>
//       static_asset <uri> <content_type> <path>
//       allow settings for role <role>
//	   }
//
//     cookie domain <name>
//     cookie path <name>
//     cookie lifetime <seconds>
//     cookie samesite <lax|strict|none>
//     cookie insecure <on|off>
//
//     registration {
//       disabled <on|off>
//       title "User Registration"
//       code "NY2020"
//       dropbox <file/path/to/registration/dir/>
//       require accept terms
//       require domain mx
//       admin email <email_address> [<email_address_N>]
//     }
//
//     validate source address
//
//     enable source ip tracking
//     enable admin api
//   }
//
func parseCaddyfileAuthentication(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config) error {
	// rootDirective is config key prefix.
	var rootDirective string
	args := util.FindReplaceAll(repl, d.RemainingArgs())
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
			UserRegistrationConfig: &registration.Config{},
			CookieConfig:           &cookie.Config{},
			TokenValidatorOptions:  &options.TokenValidatorOptions{},
			TokenGrantorOptions:    &options.TokenGrantorOptions{},
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := util.FindReplaceAll(repl, d.RemainingArgs())
			rootDirective = mkcp(authnPrefix, args[0], k)
			switch k {
			case "crypto":
				if err := parseCaddyfileAuthPortalCrypto(d, repl, p, rootDirective, v); err != nil {
					return err
				}
			case "cookie":
				if err := parseCaddyfileAuthPortalCookie(d, repl, p, rootDirective, v); err != nil {
					return err
				}
			case "backend":
				if err := parseCaddyfileAuthPortalBackendShortcuts(d, repl, p, rootDirective, v); err != nil {
					return err
				}
			case "backends":
				if err := parseCaddyfileAuthPortalBackends(d, repl, p, rootDirective); err != nil {
					return err
				}
			case "ui":
				if err := parseCaddyfileAuthPortalUI(d, repl, p, rootDirective); err != nil {
					return err
				}
			case "transform":
				if err := parseCaddyfileAuthPortalTransform(d, repl, p, rootDirective, v); err != nil {
					return err
				}
			case "registration":
				if err := parseCaddyfileAuthPortalRegistration(d, repl, p, rootDirective); err != nil {
					return err
				}
			case "enable", "validate":
				if err := parseCaddyfileAuthPortalMisc(d, repl, p, rootDirective, k, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, v)
			}
		}

		if err := cfg.AddAuthenticationPortal(p); err != nil {
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
