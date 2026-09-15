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

// parseCaddyfileMessaging collects messaging statements in security.
// Body grammar belongs to go-authcrunch/pkg/messaging and its email/file parsers;
// name and kind are injected from the header. Deeper validation is deferred.
//
// Syntax:
//
//	messaging email provider <name> {
//		address <host:port>
//		protocol <smtp|smtps>
//		credentials <credential_name>
//		sender <email_address> [<display_name>]
//		template <password_recovery|registration_confirmation|registration_ready|registration_verdict|mfa_otp> <path>
//		bcc <email_address> [<email_address>...]
//	}
//	messaging file provider <name> {
//		root_dir <path>
//		sender <email_address> [<display_name>]
//		template <template_name> <path>
//		bcc <email_address> [<email_address>...]
//	}
//
// Use passwordless instead of credentials for an unauthenticated SMTP server.
// File providers accept the same template names as email providers. Templates
// are optional; sender is required for both kinds.
func parseCaddyfileMessaging(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	args := d.RemainingArgs()
	if len(args) < 3 {
		return d.ArgErr()
	}
	if args[1] != "provider" {
		return d.ArgErr()
	}

	instructions := []string{}
	instructions = append(instructions, cfgutil.EncodeArgs([]string{"name", args[2]}))
	instructions = append(instructions, cfgutil.EncodeArgs([]string{"kind", args[0]}))

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		instruction := append([]string{d.Val()}, d.RemainingArgs()...)
		instructions = append(instructions, cfgutil.EncodeArgs(instruction))
	}
	cfg.AddMessagingProvider(instructions)
	return nil
}
