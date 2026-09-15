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
)

// parseCaddyfileOAuthRegistrationStore is shared by the security block and local provisioning commands.
// Syntax: oauth registration store { path <absolute-private-directory> }
// The path statement occurs exactly once. The directory is never created here.
func parseCaddyfileOAuthRegistrationStore(d *caddyfile.Dispenser) (*OAuthRegistrationStoreConfig, error) {
	args, err := oauthApplicationArgs(d)
	if err != nil || len(args) != 3 || args[0] != "oauth" || args[1] != "registration" || args[2] != "store" {
		return nil, d.Errf("expected oauth registration store block")
	}
	body, err := readRegistrationBlock(d)
	if err != nil {
		return nil, err
	}
	if len(body) != 1 || len(body[0]) != 2 || body[0][0] != "path" {
		return nil, d.Errf("oauth registration store requires one path statement")
	}
	cfg := &OAuthRegistrationStoreConfig{Path: body[0][1]}
	if err := cfg.validate(); err != nil {
		return nil, d.Errf("%v", err)
	}
	return cfg, nil
}

// readRegistrationBlock keeps structural tokens separate from directive values.
// It also serves the provider block, which uses the same flat statement grammar.
func readRegistrationBlock(d *caddyfile.Dispenser) ([][]string, error) {
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return nil, d.Errf("expected unquoted registration/provider block")
	}
	d.Prev()
	nesting := d.Nesting()
	var body [][]string
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 {
			return nil, d.Errf("nested registration/provider blocks are unsupported")
		}
		args, err := oauthApplicationArgs(d)
		if err != nil {
			return nil, err
		}
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return nil, d.Errf("invalid registration/provider argument")
		}
		body = append(body, args)
		if d.Next() {
			if d.Val() == "{" {
				return nil, d.Errf("nested registration/provider blocks are unsupported")
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return nil, d.Errf("registration/provider closing brace must be unquoted")
				}
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return nil, d.Errf("registration/provider closing brace must end its line")
				}
			}
			d.Prev()
		}
	}
	if d.Nesting() != nesting {
		return nil, d.Errf("unterminated registration/provider block")
	}
	return body, nil
}
