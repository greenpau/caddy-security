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
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
)

// parseCaddyfileOAuthApplication registers a named client using the upstream
// named-registration parser, which validates without generating credentials.
//
// Syntax (inside security; only redirect_uri may repeat):
//
//	oauth application <nickname> {
//		client_id <id>
//		client_name <display_name>
//		client_secret <secret>
//		token_endpoint_auth_method <client_secret_basic|client_secret_post|none>
//		redirect_uri <uri>
//		scopes <scope> [<scope>...]
//		require_pkce <true|yes|on|1|false|no|off|0>
//		skip_consent <true|yes|on|1|false|no|off|0>
//	}
//
// Each redirect_uri takes one URI and appends it in declaration order. The
// plural redirect_uris directive is unsupported; the native JSON array retains
// that name. Scopes occupy one statement. Nested blocks and spaced field aliases
// are unsupported. Quote multiword display names. Nickname, protocol client_id, and
// client_name are independent; client_name defaults to nickname. Authentication
// defaults to client_secret_basic, PKCE to true, and consent skipping to false.
// Public clients use none, require PKCE, and must omit client_secret. All clients
// require an explicit client_id and confidential clients an explicit secret.
// Block delimiters must be unquoted, and no tokens may follow the closing brace
// on the same line. Otherwise Caddy's NextBlock can read those tokens as body.
// Persisted records may only be supplied by a future private storage integration.
// Adaptation does not enable a provider or change existing provider snapshots.
func parseCaddyfileOAuthApplication(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	header, err := oauthApplicationArgs(d)
	if err != nil {
		return err
	}
	if len(header) != 3 || header[0] != "oauth" || header[1] != "application" {
		// ArgErr includes the current token, which may be a misplaced secret.
		return d.Errf("expected oauth application header with one nickname")
	}
	if err := validateOAuthDirectiveTokens(header); err != nil {
		return d.Errf("invalid oauth application header")
	}
	// Require a block, even for public clients. Peek without consuming it so
	// NextBlock remains responsible for nesting and source locations.
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return d.Errf("oauth application requires a block")
	}
	d.Prev()
	var body []string
	nesting := d.Nesting()
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 {
			return d.Errf("nested oauth application blocks are unsupported")
		}
		args, err := oauthApplicationArgs(d)
		if err != nil {
			return err
		}
		if d.Next() {
			if d.Val() == "{" {
				return d.Errf("nested oauth application blocks are unsupported")
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return d.Errf("oauth application closing brace must be unquoted")
				}
				// NextBlock skips a closing brace when another token follows on
				// the same line, potentially moving that setting into this block.
				// NextLine honors import boundaries as well as source line numbers.
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return d.Errf("oauth application closing brace must end its line")
				}
			}
			d.Prev()
		}
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return d.Errf("empty or invalid oauth application directive argument")
		}
		body = append(body, encodeOAuthDirective(args))
	}
	if d.Nesting() != nesting {
		return d.Errf("unterminated oauth application block")
	}
	// Encode the header separately; never flatten it into body directives or
	// use the credential-generating client constructor during adaptation.
	application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(encodeOAuthDirective(header), body, nil)
	if err != nil {
		return d.Errf("%v", err)
	}
	// AddOAuthApplication rejects duplicate nicknames (even identical clients)
	// before insertion and retains an independent validated client snapshot.
	if err := cfg.AddOAuthApplication(application); err != nil {
		return d.Errf("%v", err)
	}
	return nil
}

// oauthApplicationArgs keeps structural closing braces out of field values.
// RemainingArgs accepts them, which could turn a missing client_id into "}" and
// let NextBlock consume an enclosing security brace to finish the application.
func oauthApplicationArgs(d *caddyfile.Dispenser) ([]string, error) {
	args := []string{d.Val()}
	for d.NextArg() {
		if d.Val() == "}" && !d.Token().Quoted() {
			return nil, d.Errf("unexpected closing brace in oauth application directive")
		}
		args = append(args, d.Val())
	}
	return args, nil
}
