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
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strconv"
	"strings"
)

// parseCaddyfileIdentityProvider parses identity provider configuration.
//
// Syntax:
//
//   oauth identity provider <name> {
//     realm <name>
//     driver <name>
//     base_auth_url <base_url>
//     metadata_url <metadata_url>
//     client_id <client_id>
//     client_secret <client_secret>
//     scopes openid email profile
//     disable metadata_discovery
//     authorization_url <authorization_url>
//     disable key verification
//     disable email claim check
//     region <name>
//     user_pool_id <name>
//     icon <text> [<icon_css_class_name> <icon_color> <icon_background_color>] [priority <number>]
//     enable accept header
//     enable js callback
//     enable id_token cookie [<cookie_name>]
//     enable logout
//     extract <field1> <fieldN> from userinfo
//     extract all from userinfo
//   }
//
//   oauth identity provider <name> {
//     realm gitlab
//     driver gitlab
//     domain_name <domain>
//     client_id <client_id>
//     client_secret <client_secret>
//     user_group_filters <regex_pattern>
//   }
//
//   saml identity provider <name> {
//     realm <name>
//     driver <name>
//   }
//
func parseCaddyfileIdentityProvider(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config, kind, name string, shortcuts []string) error {
	var disabled bool

	m := make(map[string]interface{})
	if len(shortcuts) > 0 {
		switch kind {
		case "oauth":
			switch name {
			case "github", "google", "facebook":
				if len(shortcuts) != 2 {
					return d.Errf("invalid %q shortcut: %v", name, shortcuts)
				}
				m["realm"] = name
				m["driver"] = name
				m["client_id"] = shortcuts[0]
				m["client_secret"] = shortcuts[1]
			default:
				return d.Errf("unsupported %q shortcut: %v", name, shortcuts)
			}
		default:
			return d.Errf("unsupported %q shortcut for %q provider type: %v", name, kind, shortcuts)
		}
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		args := util.FindReplaceAll(repl, d.RemainingArgs())
		rd := mkcp("security."+kind+".identity.provider["+name+"]", k)
		switch k {
		case "disabled":
			disabled = true
		case "realm", "driver", "tenant_id",
			// OAuth
			"domain_name", "client_id", "client_secret", "server_id", "base_auth_url",
			"metadata_url", "identity_token_name", "authorization_url", "token_url",
			"region", "user_pool_id",
			// SAML
			"idp_metadata_location", "idp_sign_cert_location", "idp_login_url",
			"application_id", "application_name", "entity_id":
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single value")
			}
			m[k] = args[0]
		case "acs_url":
			// SAML only.
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single value")
			}
			var acsURLs []string
			if v, exists := m["acs_urls"]; exists {
				acsURLs = v.([]string)
			}
			acsURLs = append(acsURLs, args[0])
			m["acs_urls"] = acsURLs
		case "scopes", "user_group_filters", "user_org_filters", "response_type":
			// OAuth only.
			if v, exists := m[k]; exists {
				values := v.([]string)
				values = append(values, args...)
				m[k] = values
			} else {
				m[k] = args
			}
		case "delay_start", "retry_attempts", "retry_interval":
			// OAuth only.
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single value")
			}
			i, err := strconv.Atoi(args[0])
			if err != nil {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, err)
			}
			m[k] = i
		case "icon":
			icon, err := icons.Parse(args)
			if err != nil {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, err)
			}
			m["login_icon"] = icon
		case "disable":
			// OAuth only.
			v := strings.Join(args, "_")
			switch v {
			case "metadata_discovery", "key_verification", "pass_grant_type",
				"response_type", "scope", "nonce", "email_claim_check":
				m[v+"_disabled"] = true
			case "tls_verification":
				m["tls_insecure_skip_verify"] = true
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported value")
			}
		case "enable":
			// OAuth only.
			v := strings.Join(args, "_")
			switch {
			case (v == "accept_header") || (v == "js_callback") || (v == "logout"):
				m[v+"_enabled"] = true
			case strings.HasPrefix(v, "id_token_cookie"):
				m["identity_token_cookie_enabled"] = true
				if !strings.HasSuffix(v, "id_token_cookie") {
					m["identity_token_cookie_name"] = args[len(args)-1]
				}
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported value")
			}
		case "extract":
			if len(args) < 3 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "too short")
			}
			switch {
			case strings.HasSuffix(strings.Join(args, " "), "from userinfo"):
				m["user_info_fields"] = args[:len(args)-2]
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported value")
			}
		case "required_token_fields":
			// OAuth only.
			if len(args) < 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain one or more values")
			}
			m[k] = args
		case "jwks":
			if len(args) != 3 {
				return errors.ErrMalformedDirective.WithArgs(rd, args)
			}
			if args[0] != "key" {
				return errors.ErrMalformedDirective.WithArgs(rd, args)
			}
			if v, exists := m["jwks_keys"]; exists {
				data := v.(map[string]interface{})
				data[args[1]] = args[2]
				m["jwks_keys"] = data
			} else {
				m["jwks_keys"] = map[string]interface{}{
					args[1]: args[2],
				}
			}
		default:
			return errors.ErrMalformedDirective.WithArgs(rd, args)
		}
	}

	if disabled {
		cfg.AddDisabledIdentityProvider(name)
	} else {
		if err := cfg.AddIdentityProvider(name, kind, m); err != nil {
			return err
		}
	}

	return nil
}
