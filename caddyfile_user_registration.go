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
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"strings"
)

// parseCaddyfileIdentityProvider parses identity provider configuration.
//
// Syntax:
//
//   user registration <name> {
//     title <name>
//     code <name>
//     dropbox <path>
//     require accept terms
//     require domain mx
//     email provider <name>
//     admin email <email_address_1> <<email_address_N>
//     identity store <name>
//     link terms <url>
//     link privacy <url>
//   }
//
func parseCaddyfileUserRegistration(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config, name string) error {
	var disabled bool

	r := &registry.UserRegistryConfig{
		Name: name,
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		args := util.FindReplaceAll(repl, d.RemainingArgs())
		rd := mkcp("security.user.registration["+name+"]", k)
		switch k {
		case "disabled":
			disabled = true
		case "title":
			if len(args) != 1 {
				return d.Errf("%s directive %q must contain single value", rd, args)
			}
			r.Title = args[0]
		case "code":
			if len(args) != 1 {
				return d.Errf("%s directive %q must contain single value", rd, args)
			}
			r.Code = args[0]
		case "dropbox":
			if len(args) != 1 {
				return d.Errf("%s directive %q must contain single value", rd, args)
			}
			r.Dropbox = args[0]
		case "require":
			switch strings.Join(args, " ") {
			case "accept terms":
				r.RequireAcceptTerms = true
			case "domain mx":
				r.RequireDomainMailRecord = true
			case "":
				return d.Errf("%s directive has no value", rd)
			default:
				return d.Errf("%s directive %q is unsupported", rd, args)
			}
		case "link":
			if len(args) != 2 {
				return d.Errf("%s directive %q must contain key-value pair", rd, args)
			}
			switch args[0] {
			case "terms":
				r.TermsConditionsLink = args[1]
			case "privacy":
				r.PrivacyPolicyLink = args[1]
			default:
				return d.Errf("%s directive %q contains unsupported value", rd, args)
			}
		case "email":
			if len(args) != 2 {
				return d.Errf("%s directive %q must contain key-value pair", rd, args)
			}
			switch args[0] {
			case "provider":
				r.EmailProvider = args[1]
			default:
				return d.Errf("%s directive %q contains unsupported value", rd, args)
			}
		case "identity":
			if len(args) != 2 {
				return d.Errf("%s directive %q must contain key-value pair", rd, args)
			}
			switch args[0] {
			case "store":
				r.IdentityStore = args[1]
			default:
				return d.Errf("%s directive %q contains unsupported value", rd, args)
			}
		case "admin":
			if len(args) < 2 {
				return d.Errf("%s directive %q must contain key-value pair", rd, args)
			}
			switch args[0] {
			case "email", "emails":
				r.AdminEmails = args[1:]
			default:
				return d.Errf("%s directive %q contains unsupported value", rd, args)
			}
		default:
			return errors.ErrMalformedDirective.WithArgs(rd, args)
		}
	}

	if !disabled {
		if err := cfg.AddUserRegistry(r); err != nil {
			return err
		}
	}

	return nil
}
