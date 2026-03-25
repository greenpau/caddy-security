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
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const (
	credPrefix = "security.credentials"
)

// parseCaddyfileCredentials parses credentials configuration.
//
// Syntax:
//
//	credentials <label> {
//	  username <username>
//	  password <password>
//	  domain <name>
//	}
func parseCaddyfileCredentials(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return d.ArgErr()
	}
	instructions := []string{}
	instructions = append(instructions, cfgutil.EncodeArgs([]string{"name", args[0]}))

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		k := d.Val()
		v := d.RemainingArgs()
		switch k {
		case "domain":
			if len(v) != 1 {
				return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
			}
			instructions = append(instructions, cfgutil.EncodeArgs([]string{k, v[0]}))
		case "username":
			if len(v) != 1 {
				return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
			}
			instructions = append(instructions, cfgutil.EncodeArgs([]string{k, v[0]}))
		case "password":
			if len(v) != 1 {
				return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
			}
			instructions = append(instructions, cfgutil.EncodeArgs([]string{k, v[0]}))
		default:
			return errors.ErrMalformedDirective.WithArgs([]string{credPrefix, args[0], k}, v)
		}
	}
	cfg.AddCredential(instructions)
	return nil
}
