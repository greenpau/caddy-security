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
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileIdentityProvider parses identity provider configuration.
//
// Syntax:
//
//	user registration <name> {
//	  title <name>
//	  code <name>
//	  dropbox <path>
//	  require accept terms
//	  require domain mx
//	  email provider <name>
//	  admin email <email_address_1> <<email_address_N>
//	  identity store <name>
//	  link terms <url>
//	  link privacy <url>
//	  <allow|deny> [exact|partial|prefix|suffix|regex] domain <string>
//	}
func parseCaddyfileUserRegistration(d *caddyfile.Dispenser, cfg *authcrunch.Config, name, kind string) error {
	instructions := []string{}
	instructions = append(instructions, cfgutil.EncodeArgs([]string{"name", name}))
	instructions = append(instructions, cfgutil.EncodeArgs([]string{"kind", kind}))

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		instruction := append([]string{d.Val()}, d.RemainingArgs()...)
		instructions = append(instructions, cfgutil.EncodeArgs(instruction))
	}
	cfg.AddUserRegistry(instructions)
	return nil
}
