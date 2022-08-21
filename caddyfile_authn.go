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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
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
//     validate source address
//
//     enable source ip tracking
//     enable admin api
//     enable identity store <name>
//     enable identity provider <name>
//     enable sso provider <name>
//     enable user registration <name>
//   }
//
func parseCaddyfileAuthentication(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config) error {
	// rootDirective is config key prefix.
	var rootDirective string
	backendHelpURL := "https://github.com/greenpau/caddy-security/issues/83"
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
			CookieConfig:          &cookie.Config{},
			TokenValidatorOptions: &options.TokenValidatorOptions{},
			TokenGrantorOptions:   &options.TokenGrantorOptions{},
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
			case "backend", "backends":
				return fmt.Errorf("The backend directive is no longer supported. Please see %s for details", backendHelpURL)
			case "ui":
				if err := parseCaddyfileAuthPortalUI(d, repl, p, rootDirective); err != nil {
					return err
				}
			case "transform":
				if err := parseCaddyfileAuthPortalTransform(d, repl, p, rootDirective, v); err != nil {
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
