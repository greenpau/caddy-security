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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strconv"
	"strings"
)

func parseCaddyfileAuthPortalCookie(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string, args []string) error {
	switch {
	case len(args) == 2:
		if err := updateAuthPortalCookieConfig(portal, "default", args[0], args[1]); err != nil {
			return h.Errf("%s %s directive erred: %v", rootDirective, strings.Join(args, " "), err)
		}

	case len(args) == 3:
		if err := updateAuthPortalCookieConfig(portal, args[0], args[1], args[2]); err != nil {
			return h.Errf("%s %s directive erred: %v", rootDirective, strings.Join(args, " "), err)
		}
	default:
		return h.Errf("%s %s directive is invalid", rootDirective, strings.Join(args, " "))
	}
	return nil
}

func updateAuthPortalCookieConfig(portal *authn.PortalConfig, domain, k, v string) error {
	var defaultDomain bool
	if domain == "default" {
		defaultDomain = true
	}

	if defaultDomain && (k == "domain") {
		domain = v
		defaultDomain = false
	}

	if !defaultDomain {
		if portal.CookieConfig.Domains == nil {
			portal.CookieConfig.Domains = make(map[string]*cookie.DomainConfig)
		}
		if _, exists := portal.CookieConfig.Domains[domain]; !exists {
			portal.CookieConfig.Domains[domain] = &cookie.DomainConfig{
				Domain: domain,
			}
		}
		portal.CookieConfig.Domains[domain].Seq = len(portal.CookieConfig.Domains)
	}

	switch k {
	case "domain":
	case "path":
		if defaultDomain {
			portal.CookieConfig.Path = v
		} else {
			portal.CookieConfig.Domains[domain].Path = v
		}
	case "lifetime":
		lifetime, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("value %q conversion failed: %v", v, err)
		}
		if lifetime < 1 {
			return fmt.Errorf("%s value must be greater than zero", k)
		}
		if defaultDomain {
			portal.CookieConfig.Lifetime = lifetime
		} else {
			portal.CookieConfig.Domains[domain].Lifetime = lifetime
		}
	case "samesite":
		if defaultDomain {
			portal.CookieConfig.SameSite = v
		} else {
			portal.CookieConfig.Domains[domain].SameSite = v
		}
	case "insecure":
		enabled, err := cfgutil.ParseBoolArg(v)
		if err != nil {
			return fmt.Errorf("%s value of %q is invalid: %v", k, v, err)
		}
		for domainkey := range portal.CookieConfig.Domains {
			portal.CookieConfig.Domains[domainkey].Insecure = enabled
		}
		portal.CookieConfig.Insecure = enabled
	case "strip":
		if v != "domain" {
			return fmt.Errorf("stripping of %s is unsupported", v)
		}
		if defaultDomain {
			portal.CookieConfig.StripDomainEnabled = true
		} else {
			portal.CookieConfig.Domains[domain].StripDomainEnabled = true
		}
	default:
		return fmt.Errorf("unsupported %q directive", k)
	}
	return nil
}
