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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"strings"
)

func parseCaddyfileAuthPortalMisc(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective, k string, args []string) error {
	v := strings.Join(args, " ")
	v = strings.TrimSpace(v)
	switch k {
	case "enable":
		switch {
		case v == "source ip tracking":
			portal.TokenGrantorOptions.EnableSourceAddress = true
		case v == "admin api":
			portal.API.AdminEnabled = true
		case strings.HasPrefix(v, "identity provider"):
			if len(args) < 3 {
				return h.Errf("malformed directive for %s: %s", rootDirective, v)
			}
			for _, providerName := range args[2:] {
				portal.IdentityProviders = append(portal.IdentityProviders, providerName)
			}
			return nil
		case strings.HasPrefix(v, "identity store"):
			if len(args) < 3 {
				return h.Errf("malformed directive for %s: %s", rootDirective, v)
			}
			for _, storeName := range args[2:] {
				portal.IdentityStores = append(portal.IdentityStores, storeName)
			}
			return nil
		case strings.HasPrefix(v, "sso provider"):
			if len(args) < 3 {
				return h.Errf("malformed directive for %s: %s", rootDirective, v)
			}
			for _, providerName := range args[2:] {
				portal.SingleSignOnProviders = append(portal.SingleSignOnProviders, providerName)
			}
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	case "validate":
		switch v {
		case "source address":
			portal.TokenValidatorOptions.ValidateSourceAddress = true
		case "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("%s directive %q is unsupported", rootDirective, v)
		}
	case "trust":
		switch {
		case strings.Contains(v, "logout redirect uri"):
			var domainMatchType, domain, pathMatchType, path string
			argp := 3
			for argp < len(args) {
				switch args[argp] {
				case "domain", "path":
					if hasMatchTypeKeywords(args[argp+1]) {
						if !arrayElementExists(args, argp+2) {
							return h.Errf("%s directive %q is malformed", rootDirective, v)
						}
						if args[argp] == "domain" {
							domainMatchType = args[argp+1]
							domain = args[argp+2]
						} else {
							pathMatchType = args[argp+1]
							path = args[argp+2]
						}
						argp++
					} else {
						if args[argp] == "domain" {
							domain = args[argp+1]
							domainMatchType = "exact"
						} else {
							path = args[argp+1]
							pathMatchType = "exact"
						}
					}
					argp++
				default:
					return h.Errf("%s directive %q has unsupported key %s", rootDirective, v, args[argp])
				}
				argp++
			}

			redirectURIConfig, err := redirects.NewRedirectURIMatchConfig(domainMatchType, domain, pathMatchType, path)
			if err != nil {
				return h.Errf("%s directive %q erred: %v", rootDirective, v, err)
			}
			portal.TrustedLogoutRedirectURIConfigs = append(portal.TrustedLogoutRedirectURIConfigs, redirectURIConfig)
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("%s directive %q is unsupported", rootDirective, v)
		}
	}
	return nil
}
