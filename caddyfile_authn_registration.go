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
	"strings"
)

func parseCaddyfileAuthPortalRegistration(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string) error {
	for nesting := h.Nesting(); h.NextBlock(nesting); {
		subDirective := h.Val()
		switch subDirective {
		case "title":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			portal.UserRegistrationConfig.Title = util.FindReplace(repl, h.Val())
		case "disabled":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			if h.Val() == "yes" || h.Val() == "on" {
				portal.UserRegistrationConfig.Disabled = true
			}
		case "code":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			portal.UserRegistrationConfig.Code = util.FindReplace(repl, h.Val())
		case "dropbox":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			portal.UserRegistrationConfig.Dropbox = util.FindReplace(repl, h.Val())
		case "require":
			args := strings.Join(h.RemainingArgs(), " ")
			args = strings.TrimSpace(args)
			switch args {
			case "accept terms":
				portal.UserRegistrationConfig.RequireAcceptTerms = true
			case "domain mx":
				portal.UserRegistrationConfig.RequireDomainMailRecord = true
			case "":
				return h.Errf("%s directive has no value", rootDirective)
			default:
				return h.Errf("%s directive %q is unsupported", rootDirective, args)
			}
		default:
			return h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
		}
	}

	return nil
}
