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
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	credPrefix = "security.credentials"
)

// parseCaddyfileCredentials parses credentials configuration.
//
// Syntax:
//
//   credentials <label> {
//     username <username>
//     password <password>
//     domain <name>
//   }
//
func parseCaddyfileCredentials(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config) error {
	args := util.FindReplaceAll(repl, d.RemainingArgs())
	if len(args) != 1 {
		return d.ArgErr()
	}
	c := &credentials.Generic{Name: args[0]}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		v := util.FindReplaceAll(repl, d.RemainingArgs())
		switch k {
		case "domain":
			c.Domain = v[0]
		case "username":
			c.Username = v[0]
		case "password":
			c.Password = v[0]
		default:
			return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
		}
	}
	if err := cfg.AddCredential(c); err != nil {
		return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0]}, err)
	}
	return nil
}
