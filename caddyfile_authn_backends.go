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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/backends"
	"strconv"
	"strings"
)

func parseCaddyfileAuthPortalBackends(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string) error {
	for nesting := h.Nesting(); h.NextBlock(nesting); {
		backendName := h.Val()
		cfg := make(map[string]interface{})
		cfg["name"] = backendName
		backendDisabled := false
		var backendAuthMethod string
		for subNesting := h.Nesting(); h.NextBlock(subNesting); {
			backendArg := h.Val()
			switch backendArg {
			case "method", "type":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				backendAuthMethod = h.Val()
				cfg["method"] = backendAuthMethod
			case "trusted_authority":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				var trustedAuthorities []string
				if v, exists := cfg["trusted_authorities"]; exists {
					trustedAuthorities = v.([]string)
				}
				trustedAuthorities = append(trustedAuthorities, h.Val())
				cfg["trusted_authorities"] = trustedAuthorities
			case "disabled":
				backendDisabled = true
				break
			case "username":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg["bind_username"] = util.FindReplace(repl, h.Val())
			case "password":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg["bind_password"] = util.FindReplace(repl, h.Val())
			case "search_base_dn", "search_group_filter", "path", "realm":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg[backendArg] = util.FindReplace(repl, h.Val())
			case "search_filter", "search_user_filter":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg["search_user_filter"] = util.FindReplace(repl, h.Val())

			case "required_token_fields":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg[backendArg] = util.FindReplaceAll(repl, h.RemainingArgs())
			case "attributes":
				attrMap := make(map[string]interface{})
				for attrNesting := h.Nesting(); h.NextBlock(attrNesting); {
					attrName := h.Val()
					if !h.NextArg() {
						return backendPropErr(h, backendName, backendArg, attrName, "has no value")
					}
					attrMap[attrName] = h.Val()
				}
				cfg[backendArg] = attrMap
			case "servers":
				serverMaps := []map[string]interface{}{}
				for serverNesting := h.Nesting(); h.NextBlock(serverNesting); {
					serverMap := make(map[string]interface{})
					serverMap["address"] = h.Val()
					serverProps := h.RemainingArgs()
					if len(serverProps) > 0 {
						for _, serverProp := range serverProps {
							switch serverProp {
							case "ignore_cert_errors", "posix_groups":
								serverMap[serverProp] = true
							default:
								return backendPropErr(h, backendName, backendArg, serverProp, "is unsupported")
							}
						}
					}
					serverMaps = append(serverMaps, serverMap)
				}
				cfg[backendArg] = serverMaps
			case "groups":
				groupMaps := []map[string]interface{}{}
				for groupNesting := h.Nesting(); h.NextBlock(groupNesting); {
					groupMap := make(map[string]interface{})
					groupDN := h.Val()
					groupMap["dn"] = groupDN
					groupRoles := h.RemainingArgs()
					if len(groupRoles) == 0 {
						return backendPropErr(h, backendName, backendArg, groupDN, "has no roles")
					}
					groupMap["roles"] = groupRoles
					groupMaps = append(groupMaps, groupMap)
				}
				cfg[backendArg] = groupMaps
			case "provider":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg[backendArg] = h.Val()
			case "idp_metadata_location", "idp_sign_cert_location", "tenant_id", "idp_login_url",
				"application_id", "application_name", "entity_id", "domain_name",
				"client_id", "client_secret", "server_id", "base_auth_url", "metadata_url",
				"identity_token_name", "authorization_url", "token_url", "callback_url":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				cfg[backendArg] = util.FindReplace(repl, h.Val())
			case "acs_url":
				if !h.NextArg() {
					return backendValueErr(h, backendName, backendArg)
				}
				var acsURLs []string
				if v, exists := cfg["acs_urls"]; exists {
					acsURLs = v.([]string)
				}
				acsURLs = append(acsURLs, h.Val())
				cfg["acs_urls"] = acsURLs
			case "scopes", "user_group_filters", "user_org_filters", "response_type":
				if _, exists := cfg[backendArg]; exists {
					values := cfg[backendArg].([]string)
					values = append(values, h.RemainingArgs()...)
					cfg[backendArg] = values
				} else {
					cfg[backendArg] = h.RemainingArgs()
				}
			case "delay_start", "retry_attempts", "retry_interval":
				backendVal := strings.Join(h.RemainingArgs(), "|")
				i, err := strconv.Atoi(backendVal)
				if err != nil {
					return backendValueConversionErr(h, backendName, backendArg, backendVal, err)
				}
				cfg[backendArg] = i
			case "disable":
				backendVal := strings.Join(h.RemainingArgs(), "_")
				switch backendVal {
				case "metadata_discovery":
				case "key_verification":
				case "pass_grant_type":
				case "response_type":
				case "scope":
				case "nonce":
				default:
					return backendPropErr(h, backendName, backendArg, backendVal, "is unsupported")
				}
				cfg[backendVal+"_disabled"] = true
			case "enable":
				backendVal := strings.Join(h.RemainingArgs(), "_")
				switch backendVal {
				case "accept_header":
				case "js_callback":
				default:
					return backendPropErr(h, backendName, backendArg, backendVal, "is unsupported")
				}
				cfg[backendVal+"_enabled"] = true
			default:
				return backendUnsupportedValueErr(h, backendName, backendArg)
			}
		}
		if !backendDisabled {
			backendConfig, err := backends.NewConfig(cfg)
			if err != nil {
				return h.Errf("auth backend %s directive failed: %v", rootDirective, err.Error())
			}
			portal.BackendConfigs = append(portal.BackendConfigs, *backendConfig)
		}
	}
	return nil
}

func backendValueErr(h *caddyfile.Dispenser, backendName, backendArg string) error {
	return h.Errf("auth backend %s subdirective %s has no value", backendName, backendArg)
}

func backendUnsupportedValueErr(h *caddyfile.Dispenser, backendName, backendArg string) error {
	return h.Errf("auth backend %s subdirective %s is unsupported", backendName, backendArg)
}

func backendPropErr(h *caddyfile.Dispenser, backendName, backendArg, attrName, attrErr string) error {
	return h.Errf("auth backend %q subdirective %q key %q %s", backendName, backendArg, attrName, attrErr)
}

func backendValueConversionErr(h *caddyfile.Dispenser, backendName, k, v string, err error) error {
	return h.Errf("auth backend %s subdirective %s value %q error: %v", backendName, k, v, err)
}
