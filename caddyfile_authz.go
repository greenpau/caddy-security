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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const (
	authzPrefix   string = "security.authorization"
	cryptoKeyword string = "crypto"
)

// parseCaddyfileAuthorization parses a policy in security. The caddyfile_authz_*
// helpers document the full grammar and delegated validation of each directive.
//
// Syntax:
//
//	authorization policy <name> {
//		crypto key verify <shared_secret>
//		set auth url <url>
//		allow roles <role> [<role>...]
//		deny <field> <value> [<value>...]
//		acl rule { ... }
//		acl default <allow|deny>
//		bypass uri <exact|partial|prefix|suffix|regex> <path>
//		validate bearer header
//		inject headers with claims
//		use oauth identity provider <name>
//		oauth public origin <https-origin>
//		oauth base path <path>
//		oauth <session|login> cookie name <name>
//		oauth session lifetime <seconds>
//		oauth maximum sessions <count>
//		oauth maximum pending logins <count>
//	}
//
// At least one ACL rule is required. Additional enable, disable, validate, set,
// and with forms are documented at parseCaddyfileAuthorizationMisc.
func parseCaddyfileAuthorization(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	var rootDirective string
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "policy":
		p := &authz.PolicyConfig{Name: args[1]}
		var oauthStatements []string
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			rootDirective = mkcp(authzPrefix, args[0], k)
			switch k {
			case "use", "oauth":
				args := append([]string{k}, d.RemainingArgs()...)
				if d.Next() {
					if d.Val() == "{" {
						return d.Errf("OAuth authorization statements cannot contain blocks")
					}
					d.Prev()
				}
				oauthStatements = append(oauthStatements, cfgutil.EncodeArgs(args))
			case cryptoKeyword:
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationCrypto(d, p, rootDirective, v); err != nil {
					return err
				}
			case "acl":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationACL(d, p, rootDirective, v); err != nil {
					return err
				}
			case "allow", "deny":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationACLShortcuts(d, p, rootDirective, k, v); err != nil {
					return err
				}
			case "bypass":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationBypass(d, p, rootDirective, v); err != nil {
					return err
				}
			case "enable", "disable", "validate", "set", "with":
				if err := parseCaddyfileAuthorizationMisc(d, p, rootDirective, k, d.RemainingArgs()); err != nil {
					return err
				}
			case "inject":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationHeaderInjection(d, p, rootDirective, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, d.RemainingArgs())
			}
		}
		oauth, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(p.Name, oauthStatements)
		if err != nil {
			return d.Errf("%v", err)
		}
		if err := p.ConfigureOAuth(oauth); err != nil {
			return d.Errf("%v", err)
		}
		if err := cfg.AddAuthorizationPolicy(p); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authzPrefix, args)
	}
	return nil
}
