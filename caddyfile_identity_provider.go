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
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

// parseCaddyfileIdentityProvider dispatches upstream OAuth and SAML providers.
// OAuth body syntax, including logout_url <logout_url> and its shared-validation
// restriction, is documented at parseCaddyfileOAuthIdentityProvider.
// SAML fields pass through go-authcrunch/pkg/idp shared and typed validation.
//
// Syntax (SAML):
//
//	saml identity provider <name> {
//		realm <realm>
//		driver <azure|generic>
//		entity_id <entity_id>
//		acs_url <url>
//		idp_metadata_location <path_or_url>
//		idp_sign_cert_location <path_or_url>
//		idp_login_url <url>
//		tenant_id <id>
//		application_id <id>
//		application_name <name>
//		icon <text> [<class> [<color> [<background>]]] [text <color> [<background>]] [priority <integer>]
//		disable tls verification
//		disabled
//	}
//
// Repeat acs_url for multiple callback URLs. Each scalar takes one value.
// Optional fields depend on the driver. disabled omits registration. TLS
// verification is enabled by default; disabling it is not required for SAML.
func parseCaddyfileIdentityProvider(d *caddyfile.Dispenser, app *App, kind, name string, shortcuts []string) error {
	if kind == "oauth" {
		return parseCaddyfileOAuthIdentityProvider(d, app, name, shortcuts)
	}
	cfg := app.Config
	var disabled bool

	m := make(map[string]interface{})
	if len(shortcuts) > 0 {
		return d.Errf("unsupported %q shortcut for %q provider type: %v", name, kind, shortcuts)
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		args := d.RemainingArgs()
		rd := mkcp("security."+kind+".identity.provider["+name+"]", k)
		switch k {
		case "disabled":
			disabled = true
		case "realm", "driver", "tenant_id",
			// OAuth
			"domain_name", "client_id", "client_secret", "server_id", "base_auth_url",
			"metadata_url", "identity_token_field_name", "authorization_url", "token_url",
			"logout_url",
			"region", "user_pool_id", "user_info_roles_field_name",
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
				"response_type", "scope", "nonce", "pkce", "email_claim_check":
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
				switch {
				case len(args) == 3:
				case len(args) == 4:
					m["identity_token_field_name"] = args[3]
				case len(args) == 5:
					m["identity_token_field_name"] = args[3]
					m["identity_token_cookie_name"] = args[4]
				default:
					return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "missing args")
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
