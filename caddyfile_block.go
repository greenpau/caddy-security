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

import "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

// readFlatDirectiveBlock preserves Caddy argument and block boundaries before
// forwarding encoded statements to a shared AuthCrunch parser.
func readFlatDirectiveBlock(d *caddyfile.Dispenser, kind string) ([][]string, error) {
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return nil, d.Errf("expected unquoted %s block", kind)
	}
	d.Prev()
	nesting := d.Nesting()
	var body [][]string
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 {
			return nil, d.Errf("nested %s blocks are unsupported", kind)
		}
		args, err := oauthApplicationArgs(d)
		if err != nil {
			return nil, err
		}
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return nil, d.Errf("invalid %s argument", kind)
		}
		body = append(body, args)
		if d.Next() {
			if d.Val() == "{" {
				return nil, d.Errf("nested %s blocks are unsupported", kind)
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return nil, d.Errf("%s closing brace must be unquoted", kind)
				}
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return nil, d.Errf("%s closing brace must end its line", kind)
				}
			}
			d.Prev()
		}
	}
	if d.Nesting() != nesting {
		return nil, d.Errf("unterminated %s block", kind)
	}
	return body, nil
}
