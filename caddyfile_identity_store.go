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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"strings"
)

// parseCaddyfileIdentityStore parses identity store configuration.
//
// Syntax:
//
//   <local|ldap> identity store <name> {
//     type <local>
//     file <file_path>
//     realm <name>
//     disabled
//
//     user <username> {
//       name <full_name>
//       email <address>
//       password <plain_text_password> [overwrite]
//       password bcrypt:<cost>:<hash> [overwrite]
//       roles <role_name> [<role_name>]
//     }
//
//     enable username recovery
//     enable password recovery
//     enable contact support
//     support link <url>
//     support email <email_address>
//
//     fallback role <role_name> [<role_name>]
//   }
//
func parseCaddyfileIdentityStore(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config, kind, name string, shortcuts []string) error {
	var disabled bool
	m := make(map[string]interface{})

	if len(shortcuts) > 0 {
		switch kind {
		case "local":
			if len(shortcuts) != 1 {
				return d.Errf("invalid %q shortcut: %v", name, shortcuts)
			}
			m["realm"] = "local"
			m["path"] = shortcuts[0]
		default:
			return d.Errf("unsupported %q shortcut for %q store type: %v", name, kind, shortcuts)
		}
	}

	userMaps := []map[string]interface{}{}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		args := util.FindReplaceAll(repl, d.RemainingArgs())
		rd := mkcp("security.identity.store["+name+"]", k)
		switch k {
		case "disabled":
			disabled = true
		case "realm",
			// Local.
			"path",
			// LDAP
			"search_base_dn", "search_group_filter", "search_user_filter",
			"search_filter", "username", "password":
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single value")
			}
			switch k {
			case "search_filter":
				m["search_user_filter"] = args[0]
			case "username":
				m["bind_username"] = args[0]
			case "password":
				m["bind_password"] = args[0]
			default:
				m[k] = args[0]
			}
		case "trusted_authority":
			// LDAP only.
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single path")
			}
			var values []string
			if v, exists := m["trusted_authorities"]; exists {
				values = v.([]string)
			}
			values = append(values, args[0])
			m["trusted_authorities"] = values
		case "attributes":
			// LDAP only.
			attrMap := make(map[string]interface{})
			for attrNesting := d.Nesting(); d.NextBlock(attrNesting); {
				attrName := d.Val()
				if !d.NextArg() {
					return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "no attribute values found")
				}
				attrMap[attrName] = d.Val()
			}
			m["attributes"] = attrMap
		case "servers":
			// LDAP only.
			serverMaps := []map[string]interface{}{}
			for serverNesting := d.Nesting(); d.NextBlock(serverNesting); {
				serverMap := make(map[string]interface{})
				serverMap["address"] = d.Val()
				serverProps := d.RemainingArgs()
				if len(serverProps) > 0 {
					for _, serverProp := range serverProps {
						switch serverProp {
						case "ignore_cert_errors", "posix_groups":
							serverMap[serverProp] = true
						default:
							return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported prop "+serverProp)
						}
					}
				}
				serverMaps = append(serverMaps, serverMap)
			}
			m[k] = serverMaps
		case "user":
			if len(args) != 1 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain single value")
			}
			userMap := make(map[string]interface{})
			userMap["username"] = args[0]
			for userNesting := d.Nesting(); d.NextBlock(userNesting); {
				userPropName := d.Val()
				userPropValue := d.RemainingArgs()
				switch userPropName {
				case "email":
					if len(userPropValue) != 1 {
						return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, userPropName+" must contain single value")
					}
					userMap["email_address"] = userPropValue[0]
				case "name":
					if len(userPropValue) < 1 {
						return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, userPropName+" must contain one or more values")
					}
					userMap[userPropName] = strings.Join(userPropValue, " ")
				case "password":
					if len(userPropValue) < 1 || len(userPropValue) > 2 {
						return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, userPropName+" must contain one or two values")
					}
					userMap[userPropName] = userPropValue[0]
					if len(userPropValue) > 1 {
						switch userPropValue[1] {
						case "overwrite":
							userMap["password_overwrite_enabled"] = true
						default:
							return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, userPropName+" contains unsupported "+userPropValue[1])
						}
					}
				case "roles":
					if len(userPropValue) < 1 {
						return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, userPropName+" must contain one or more value")
					}
					userMap[userPropName] = userPropValue
				default:
					return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported prop "+userPropName)
				}
			}
			userMaps = append(userMaps, userMap)
		case "groups":
			// LDAP only.
			groupMaps := []map[string]interface{}{}
			for groupNesting := d.Nesting(); d.NextBlock(groupNesting); {
				groupMap := make(map[string]interface{})
				groupDN := d.Val()
				groupMap["dn"] = groupDN
				groupRoles := d.RemainingArgs()
				if len(groupRoles) == 0 {
					return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "no roles found")
				}
				groupMap["roles"] = groupRoles
				groupMaps = append(groupMaps, groupMap)
			}
			m[k] = groupMaps
		case "enable":
			v := strings.Join(args, "_")
			switch v {
			case "username_recovery":
			case "password_recovery":
			case "contact_support":
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported value")
			}
			m[v+"_enabled"] = true
		case "support":
			if len(args) != 2 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "must contain key-value pair")
			}
			switch args[0] {
			case "link":
			case "email":
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported key-value pair")
			}
			m["support_"+args[0]] = args[1]
		case "fallback":
			if len(args) < 2 {
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "too short")
			}
			switch args[0] {
			case "role", "roles":
				m["fallback_roles"] = args[2:]
			default:
				return errors.ErrMalformedDirectiveValue.WithArgs(rd, args, "unsupported argument")
			}
		default:
			return errors.ErrMalformedDirective.WithArgs(rd, args)
		}
	}

	if len(userMaps) > 0 {
		m["users"] = userMaps
	}

	if disabled {
		cfg.AddDisabledIdentityStore(name)
	} else {
		if err := cfg.AddIdentityStore(name, kind, m); err != nil {
			return err
		}
	}

	return nil
}
