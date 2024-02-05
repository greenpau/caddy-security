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
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/andrewsonpradeep/caddy-security/pkg/util"
)

const (
	secretsPrefix = "security.secrets"
)

// parseCaddyfileSecrets parses secrets configuration.
//
// Syntax:
//
//	secrets <secrets_plugin_name> <secret_id> {
//	  ...
//	}
func parseCaddyfileSecrets(d *caddyfile.Dispenser, repl *caddy.Replacer, app *App) error {
	args := util.FindReplaceAll(repl, d.RemainingArgs())
	if len(args) != 2 {
		return d.ArgErr()
	}

	modName := args[0]
	modID := secretsPrefix + "." + modName
	mod, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return err
	}

	app.SecretsManagersRaw = append(
		app.SecretsManagersRaw,
		caddyconfig.JSONModuleObject(mod, "driver", modName, nil),
	)

	return nil
}
