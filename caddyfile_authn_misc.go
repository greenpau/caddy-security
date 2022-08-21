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
			if portal.API == nil {
				portal.API = &authn.APIConfig{}
				portal.API.Enabled = true
			}
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
	}
	return nil
}
