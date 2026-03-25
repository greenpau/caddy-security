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
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	authzPrefix   string = "security.authorization"
	cryptoKeyword string = "crypto"
)

// parseCaddyfileAuthorization parses authorization policy configuration.
//
// Syntax:
//
//		authorization policy <name> {
//	   crypto
//	   acl
//	   <allow|deny>
//	   bypass
//	   enable
//	   disable
//	   validate
//	   set
//	   with
//	   inject
//		}
func parseCaddyfileAuthorization(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	var rootDirective string
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "policy":
		p := &authz.PolicyConfig{Name: args[1]}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			rootDirective = mkcp(authzPrefix, args[0], k)
			switch k {
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
		if err := cfg.AddAuthorizationPolicy(p); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authzPrefix, args)
	}
	return nil
}
