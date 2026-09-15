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

// parseCaddyfileUserRegistration collects a user registry in security.
// Body grammar belongs to go-authcrunch/pkg/registry; name and local kind are
// injected from the header. Deeper validation occurs after runtime resolution.
//
// Syntax:
//
//	user registration <name> {
//		title <title>
//		code <code>
//		dropbox <path>
//		require accept terms
//		require domain mx
//		email provider <name>
//		admin email <email_address>
//		identity store <name> [<realm>]
//		link terms <url>
//		link privacy <url>
//		<allow|deny> [exact|partial|prefix|suffix|regex] domain <pattern>
//	}
//
// admin emails is an alias for admin email; both take one address.
// Repeated lines replace the earlier address.
// Repeat domain rules for multiple patterns. Registration attaches to the named
// store; it is not enabled with a directive inside an authentication portal.
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
