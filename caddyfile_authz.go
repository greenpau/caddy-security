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
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
	"github.com/greenpau/go-authcrunch/pkg/errors"
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
//		acl field <name> { ... }
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
// One block with unquoted structural braces and at least one ACL rule is required.
// Validate the complete policy before publishing it or its deferred settings.
// Each OAuth statement may occur once, without a nested block. The shared parser
// owns defaults and validation. Complete bodies containing runtime references
// survive Caddy JSON and are parsed after replacement, before policy validation.
// OAuth sessions default to 900 absolute seconds and capacities to 10000 sessions
// and 1024 pending logins per policy; expiry requires another provider login.
// Additional enable, disable, validate, set, and with forms are documented at
// parseCaddyfileAuthorizationMisc.
func parseCaddyfileAuthorization(d *caddyfile.Dispenser, app *App) error {
	var rootDirective string
	args := d.RemainingArgs()
	// Caddy treats a quoted opening brace as an argument, not a block token.
	if len(args) == 3 && args[0] == "policy" && args[2] == "{" && d.Token().Quoted() {
		return d.Errf("authorization policy %q requires an unquoted block", args[1])
	}
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "policy":
		p := &authz.PolicyConfig{Name: args[1]}
		if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
			return d.Errf("authorization policy %q requires an unquoted block", p.Name)
		}
		d.Prev()
		var fields []*acl.FieldConfig
		var oauthStatements []string
		nesting := d.Nesting()
		for d.NextBlock(nesting) {
			k := d.Val()
			rootDirective = mkcp(authzPrefix, args[0], k)
			switch k {
			case "}":
				return d.Errf("authorization policy %q requires an unquoted closing brace", p.Name)
			case "use", "oauth":
				args := append([]string{k}, d.RemainingArgs()...)
				if d.Next() {
					if d.Val() == "{" {
						return d.Errf("OAuth authorization statements cannot contain blocks")
					}
					d.Prev()
				}
				if err := validateOAuthDirectiveTokens(args); err != nil {
					return d.Errf("%v", err)
				}
				oauthStatements = append(oauthStatements, encodeOAuthDirective(args))
			case cryptoKeyword:
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationCrypto(d, p, rootDirective, v); err != nil {
					return err
				}
			case "acl":
				v := d.RemainingArgs()
				field, err := parseCaddyfileAuthorizationACL(d, p, rootDirective, v)
				if err != nil {
					return err
				}
				if field != nil {
					fields = append(fields, field)
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
		if d.Nesting() != nesting || d.Val() != "}" || d.Token().Quoted() {
			return d.Errf("authorization policy %q requires an unquoted closing brace", p.Name)
		}
		if err := p.ConfigureAccessListFields(fields); err != nil {
			return d.Errf("authorization policy %q: %v", p.Name, err)
		}
		deferredOAuth := cookieDirectivesNeedResolution(oauthStatements)
		if deferredOAuth {
			if _, exists := app.OAuthAuthorizationDirectives[p.Name]; exists {
				return d.Errf("duplicate OAuth authorization policy %q", p.Name)
			}
		} else {
			oauth, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(p.Name, oauthStatements)
			if err != nil {
				return d.Errf("%v", err)
			}
			if err := p.ConfigureOAuth(oauth); err != nil {
				return d.Errf("%v", err)
			}
		}
		if err := app.Config.AddAuthorizationPolicy(p); err != nil {
			return d.WrapErr(err)
		}
		// Publish deferred settings only after validation accepts the policy.
		// A failed ACL must not leave an orphaned entry or prevent a retry.
		if deferredOAuth {
			if app.OAuthAuthorizationDirectives == nil {
				app.OAuthAuthorizationDirectives = make(map[string][]string)
			}
			app.OAuthAuthorizationDirectives[p.Name] = oauthStatements
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authzPrefix, args)
	}
	return nil
}
