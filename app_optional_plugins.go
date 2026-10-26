// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"fmt"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// isCompanionModule gates category-specific host capabilities by registered ID.
// Metadata interfaces alone never opt a provider into root-owned attachments or
// enable a SQLite-only worker for an unrelated third-party backend.
func isCompanionModule(value any, id caddy.ModuleID) bool {
	module, ok := value.(caddy.Module)
	return ok && module.CaddyModule().ID == id
}

func validatedSQLiteModulePath(value any) (string, error) {
	metadata, ok := value.(plugin.SQLiteStorage)
	validator, validatable := value.(caddy.Validator)
	if !ok || !validatable || validator.Validate() != nil {
		return "", fmt.Errorf("invalid SQLite storage metadata")
	}
	return filepath.Clean(metadata.SQLiteStoragePath()), nil
}
