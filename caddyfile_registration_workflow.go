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

// parseCaddyfileRegistrationWorkflow dispatches a host-owned enrollment module.
//
//	user registration <driver> <name> { ... }
//
// The registered security.registration_workflows.<driver> owns its entire block.
// The shorter `user registration <name>` header retains legacy local semantics.
// The caller has consumed registration/driver/name, leaving the workflow name
// as the module dispenser's first token, as required by UnmarshalModule.
func parseCaddyfileRegistrationWorkflow(d *caddyfile.Dispenser, app *App, driver string) error {
	module, err := caddyfile.UnmarshalModule(d, "security.registration_workflows."+driver)
	if err != nil {
		return err
	}
	app.RegistrationWorkflowConfigs = append(app.RegistrationWorkflowConfigs, caddyconfig.JSONModuleObject(module, "driver", driver, nil))
	return nil
}
