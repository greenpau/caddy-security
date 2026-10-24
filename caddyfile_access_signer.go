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

// parseCaddyfileAccessSigner owns the exact named backend header:
//
//	access signer <driver> <name> { ... }
//
// The module delegates its complete flat body to the public backend parser.
// Declaration order does not affect selection; factories run only after all
// references, profiles and physical storage namespaces have been checked.
func parseCaddyfileAccessSigner(d *caddyfile.Dispenser, app *App) error {
	args := d.RemainingArgs()
	if len(args) != 3 || args[0] != "signer" {
		return d.Errf("expected access signer driver and name")
	}
	module, err := caddyfile.UnmarshalModule(d, "security.access_signers."+args[1])
	if err != nil {
		return err
	}
	app.AccessSignerConfigs = append(app.AccessSignerConfigs, caddyconfig.JSONModuleObject(module, "driver", args[1], nil))
	return nil
}

// readCaddyfileAccessSignerSelection retains one exact scalar for native runtime
// resolution. A present clause cannot select the implicit empty/KMS default.
func readCaddyfileAccessSignerSelection(d *caddyfile.Dispenser, args []string) (string, error) {
	if len(args) != 2 || args[0] != "signer" || validateOAuthDirectiveTokens(args) != nil {
		return "", d.Errf("expected access signer name")
	}
	if d.Next() {
		block := d.Val() == "{" && !d.Token().Quoted()
		d.Prev()
		if block {
			return "", d.Errf("access signer selection does not accept a block")
		}
	}
	return args[1], nil
}
