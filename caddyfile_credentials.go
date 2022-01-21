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
	"github.com/greenpau/aaasf"
	"github.com/greenpau/aaasf/pkg/credentials"
	"github.com/greenpau/aaasf/pkg/errors"
	"github.com/greenpau/caddy-security/pkg/util"
)

const (
	credPrefix = "security.credentials"
)

// parseCaddyfileCredentials parses credentials configuration.
//
// Syntax:
//
//   credentials email <label> {
//     address <uri>
//     protocol <smtp|pop3|imap>
//     username <username>
//     password <password>
//   }
//
func parseCaddyfileCredentials(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *aaasf.Config) error {
	args := util.FindReplaceAll(repl, d.RemainingArgs())
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "email":
		c := &credentials.SMTP{Name: args[1]}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := util.FindReplaceAll(repl, d.RemainingArgs())
			switch k {
			case "address":
				c.Address = v[0]
			case "protocol":
				c.Protocol = v[0]
			case "username":
				c.Username = v[0]
			case "password":
				c.Password = v[0]
			default:
				return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
			}
		}
		if err := cfg.AddCredential(c); err != nil {
			return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], args[1]}, err)
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(credPrefix, args)
	}
	return nil
}
