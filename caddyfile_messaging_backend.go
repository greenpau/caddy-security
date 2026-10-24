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
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// parseCaddyfileMessagingBackend dispatches a host-owned messaging declaration.
//
//	messaging <driver> provider <name> { ... }
//
// The registered security.messaging.<driver> owns the complete block. Built-in
// email/file declarations retain their existing parser and credential handling.
func parseCaddyfileMessagingBackend(d *caddyfile.Dispenser, app *App) error {
	args := d.RemainingArgs()
	if len(args) != 3 || args[1] != "provider" {
		return d.ArgErr()
	}
	module, err := caddyfile.UnmarshalModule(d, "security.messaging."+args[0])
	if err != nil {
		return err
	}
	app.MessagingProviderConfigs = append(app.MessagingProviderConfigs, caddyconfig.JSONModuleObject(module, "driver", args[0], nil))
	return nil
}
