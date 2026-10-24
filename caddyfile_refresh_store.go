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

// parseCaddyfileRefreshStore dispatches the exact named backend header:
//
// token refresh store <driver> <name> { ... }
//
// Backend settings delegate as one complete body. Selection and construction
// occur only after declarations and physical storage preflight are complete.
func parseCaddyfileRefreshStore(d *caddyfile.Dispenser, app *App) error {
	args := d.RemainingArgs()
	if len(args) != 4 || args[0] != "refresh" || args[1] != "store" {
		return d.Errf("expected token refresh store driver and name")
	}
	module, err := caddyfile.UnmarshalModule(d, "security.refresh_stores."+args[2])
	if err != nil {
		return err
	}
	app.RefreshStoreConfigs = append(app.RefreshStoreConfigs, caddyconfig.JSONModuleObject(module, "driver", args[2], nil))
	return nil
}
