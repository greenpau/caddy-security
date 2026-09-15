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
	//	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"

	// "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch"
	//	"strconv"
	//	"strings"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("security", parseCaddyfile)
}

// parseCaddyfile parses the security app inside Caddy's global options block.
// Syntax below lists block headers; their bodies are documented by each parser.
// Angle brackets denote required values/alternatives, square brackets optional
// arguments, and ... repetition. Syntax catalogues are not runnable configs.
//
// Syntax:
//
//	{
//		security {
//			secrets <module> <id> { ... }
//			credentials <name> { ... }
//			messaging <email|file> provider <name> { ... }
//			<local|ldap> identity store <name> { ... }
//			<oauth|saml> identity provider <name> { ... }
//			oauth application <nickname> { ... }
//			sso provider <name> { ... }
//			user registration <name> { ... }
//			authentication portal <name> { ... }
//			authorization policy <name> { ... }
//		}
//	}
//
// Delegated body syntax and validation remain part of the Caddyfile contract.
// See .codex/skills/configuration/references/syntax-maintenance.md for ownership
// and the audit workflow when local parsers or upstream dependencies change.
func parseCaddyfile(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(App)
	app.Config = authcrunch.NewConfig()

	if !d.Next() {
		return nil, d.ArgErr()
	}

	// Collect registrations before resolving portals/providers, regardless of
	// textual order. Each adaptation owns a fresh Config; previous or persisted
	// registrations are never implicitly carried into this declaration set.
	var declarations []*caddyfile.Dispenser
	for d.NextBlock(0) {
		if d.Val() == "oauth" {
			if !d.NextArg() {
				return nil, d.Errf("expected oauth application or oauth identity provider header")
			}
			kind := d.Val()
			d.Prev()
			switch kind {
			case "application":
				// Parse in place: NextSegment omits empty blocks, which would
				// turn missing credentials into a misleading missing-block error.
				if err := parseCaddyfileOAuthApplication(d, app.Config); err != nil {
					return nil, err
				}
				continue
			case "identity":
				// Resolve identity providers after collecting applications.
			default:
				// A malformed/grouped header may contain a misplaced secret.
				return nil, d.Errf("expected oauth application or oauth identity provider header")
			}
		}
		declaration := d.NewFromNextSegment()
		declaration.Next()
		declarations = append(declarations, declaration)
	}
	// A child parser must not consume this block's closing brace and let EOF
	// masquerade as a completed security block. Quoted brace-valued arguments
	// can otherwise pass Caddy's initial brace counting with the wrong scopes.
	if d.Nesting() != 0 {
		return nil, d.Errf("unterminated security block")
	}

	for _, d := range declarations {
		tld := d.Val()
		switch tld {
		case "credentials":
			if err := parseCaddyfileCredentials(d, app.Config); err != nil {
				return nil, err
			}
		case "messaging":
			if err := parseCaddyfileMessaging(d, app.Config); err != nil {
				return nil, err
			}
		case "local", "ldap", "oauth", "saml":
			if err := parseCaddyfileIdentity(d, app, tld); err != nil {
				return nil, err
			}
		case "user":
			if err := parseCaddyfileUser(d, app.Config); err != nil {
				return nil, err
			}
		case "authentication":
			if err := parseCaddyfileAuthentication(d, app); err != nil {
				return nil, err
			}
		case "authorization":
			if err := parseCaddyfileAuthorization(d, app.Config); err != nil {
				return nil, err
			}
		case "sso":
			if err := parseCaddyfileSingleSignOnProvider(d, app.Config); err != nil {
				return nil, err
			}
		case "secrets":
			if err := parseCaddyfileSecrets(d, app); err != nil {
				return nil, err
			}
		default:
			// Unknown tokens may be grouped headers containing credentials.
			return nil, d.Errf("unsupported security directive")
		}
	}

	return httpcaddyfile.App{
		Name:  appName,
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
