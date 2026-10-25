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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

func sqliteIdentityTestConfig(t *testing.T) *identitysqlite.Config {
	t.Helper()
	// The transaction includes bcrypt verification; race instrumentation needs
	// more than the production-speed parser fixtures' subsecond durations.
	return &identitysqlite.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(registrationTestDirectory(t), "identities.db"), Timeout: "5s"}
}

func sqliteIdentityTestProvision(t *testing.T, cfg *identitysqlite.Config) {
	t.Helper()
	store, err := identitysqlite.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Create(t.Context(), &identitysqlite.Account{Username: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}, lifecyclePassword); err != nil {
		t.Fatal(err)
	}
}

func sqliteIdentityTestRaw(t *testing.T, cfg *identitysqlite.Config) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"driver": "sqlite", "name": cfg.Name, "realm": cfg.Realm, "path": cfg.Path, "timeout": cfg.Timeout})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSQLiteIdentityAdaptationIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "identities.db")
	input := fmt.Sprintf("{\nsecurity {\nidentity store sqlite accounts {\nrealm staff\npath %q\n}\nauthentication portal portal {\nenable identity store accounts\ncrypto key sign-verify synthetic-lifecycle-signing-secret\n}\n}\n}\n", path)
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	app := &document.Apps.Security
	if len(app.IdentityStoreConfigs) != 1 || len(app.Config.IdentityStores) != 0 || len(app.Config.ExternalIdentityStores) != 0 {
		t.Fatal("adaptation published a builtin store or runtime descriptor")
	}
	var module SQLiteIdentityStore
	if err := json.Unmarshal(app.IdentityStoreConfigs[0], &module); err != nil || module.Path != path || module.Name != "accounts" || module.Timeout != "1s" {
		t.Fatal("adapted module lost native settings", err)
	}
	if len(app.Config.AuthenticationPortals) != 1 || len(app.Config.AuthenticationPortals[0].IdentityStores) != 1 || app.Config.AuthenticationPortals[0].IdentityStores[0] != "accounts" {
		t.Fatal("portal lost the declared module selection")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("adaptation created storage")
	}
}
