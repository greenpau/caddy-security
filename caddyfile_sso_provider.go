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
	//"github.com/greenpau/go-authcrunch/pkg/errors"
	//"strconv"
	//"strings"
)

// parseCaddyfileSingleSignOnProvider parses single sign-on provider configuration.
//
// Syntax:
//
//   sso provider <name> {
//     disabled
//     entity_id <name>
//     driver [aws]
//     private key <path/to/pem/file>
//     location https://url1/
//     location https://url2/
//   }
//
func parseCaddyfileSingleSignOnProvider(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config) error {
	var locations []string
	var disabled bool

	m := make(map[string]interface{})

	args := util.FindReplaceAll(repl, d.RemainingArgs())

	if len(args) != 2 {
		return d.Errf("malformed sso syntax: %v", args)
	}

	if args[0] != "provider" {
		return d.Errf("malformed sso syntax: %v", args)
	}
	m["name"] = args[1]

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		values := util.FindReplaceAll(repl, d.RemainingArgs())
		switch k {
		case "disabled":
			disabled = true
		case "entity_id", "driver":
			m[k] = values[0]
		case "location":
			locations = append(locations, values[0])
		case "cert":
			m["cert_path"] = values[0]
		case "private":
			if len(values) != 2 {
				return d.Errf("malformed sso provider private key syntax: %s %v", k, values)
			}
			if values[0] != "key" {
				return d.Errf("malformed sso provider syntax: %s %v", k, values)
			}
			m["private_key_path"] = values[1]
		default:
			return d.Errf("malformed sso provider syntax: %s %v", k, values)
		}
	}

	if len(locations) < 1 {
		return d.Errf("malformed sso provider config: locations not found")
	}

	m["locations"] = locations

	if !disabled {
		if err := cfg.AddSingleSignOnProvider(m); err != nil {
			return err
		}
	}

	return nil
}
