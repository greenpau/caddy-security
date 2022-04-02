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
	// "github.com/greenpau/go-authcrunch/pkg/authn"
	// "github.com/greenpau/go-authcrunch/pkg/authn/backends"
	// "strconv"
	// "strings"
)

// parseCaddyfileIdentityStore parses identity store configuration.
//
// Syntax:
//
//   identity store <name> {
//     type <local>
//     file <file_path>
//     realm <name>
//     disabled
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
		default:
			return errors.ErrMalformedDirective.WithArgs(rd, args)
		}
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
