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
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strconv"
	"strings"
)

func parseCaddyfileAuthPortalCookie(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string, args []string) error {
	if len(args) != 2 {
		return h.Errf("%s %s directive is invalid", rootDirective, strings.Join(args, " "))
	}
	switch args[0] {
	case "domain":
		portal.CookieConfig.Domain = args[1]
	case "path":
		portal.CookieConfig.Path = args[1]
	case "lifetime":
		lifetime, err := strconv.Atoi(args[1])
		if err != nil {
			return h.Errf("%s %s value %q conversion failed: %v", rootDirective, args[0], args[1], err)
		}
		if lifetime < 1 {
			return h.Errf("%s %s value must be greater than zero", rootDirective, args[0])
		}
		portal.CookieConfig.Lifetime = lifetime
	case "samesite":
		portal.CookieConfig.SameSite = args[1]
	case "insecure":
		enabled, err := cfgutil.ParseBoolArg(args[1])
		if err != nil {
			return h.Errf("%s %s directive value of %q is invalid: %v", rootDirective, args[0], args[1], err)
		}
		portal.CookieConfig.Insecure = enabled
	default:
		return h.Errf("%s %s directive is unsupported", rootDirective, strings.Join(args, " "))
	}
	return nil
}
