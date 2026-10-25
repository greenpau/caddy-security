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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func sqliteOAuthLoginTestFactory(t *testing.T, module *SQLiteOAuthLoginStore) *sqliteOAuthLoginStoreFactory {
	t.Helper()
	factory, err := module.PrepareOAuthLoginStore()
	if err != nil {
		t.Fatal("cannot prepare SQLite OAuth login storage")
	}
	result, ok := factory.(*sqliteOAuthLoginStoreFactory)
	if !ok || result == nil {
		t.Fatal("prepared factory lost its SQLite storage metadata")
	}
	return result
}

func TestSQLiteOAuthLoginStoreNativeConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "{env.LITERAL_PATH}", "logins.db")
	valid := fmt.Sprintf(`{"driver":"sqlite","name":"shared","path":%q,"timeout":"1000ms","capacity":0}`, path)
	for name, raw := range map[string]string{
		"valid":               valid,
		"missing_name":        strings.Replace(valid, `"name":"shared",`, "", 1),
		"relative_path":       strings.Replace(valid, fmt.Sprintf("%q", path), `"relative.db"`, 1),
		"bad_timeout":         strings.Replace(valid, "1000ms", "31s", 1),
		"capacity_type":       strings.Replace(valid, `"capacity":0`, `"capacity":"1000"`, 1),
		"fractional_capacity": strings.Replace(valid, `"capacity":0`, `"capacity":1.5`, 1),
		"unknown_field":       strings.Replace(valid, `"timeout":`, `"credentials":"private-sentinel","timeout":`, 1),
		"unknown_driver":      strings.Replace(valid, `"driver":"sqlite"`, `"driver":"not_registered"`, 1),
		"null":                "null",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			loader := &App{OAuthLoginStoreConfigs: []json.RawMessage{json.RawMessage(raw)}}
			loaded, err := ctx.LoadModule(loader, "OAuthLoginStoreConfigs")
			if name != "valid" {
				if err == nil {
					t.Fatal("invalid native module loaded")
				}
				return
			}
			if err != nil {
				t.Fatal("valid native module failed loading")
			}
			entries, ok := loaded.([]any)
			if !ok || len(entries) != 1 {
				t.Fatal("native loader did not return one module")
			}
			module, ok := entries[0].(*SQLiteOAuthLoginStore)
			if !ok || module.Name != "shared" || module.Path != path || module.Timeout != "1000ms" || module.Capacity != 0 {
				t.Fatal("native loading mutated literal fields")
			}
			cfg := sqliteOAuthLoginTestFactory(t, module).SQLiteConfig()
			if cfg.Path != path || cfg.Timeout != "1s" || cfg.Capacity != 10000 {
				t.Fatal("native factory omitted defaults or expanded a literal path")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(path))); !os.IsNotExist(err) {
		t.Fatal("native Caddy loading touched storage")
	}
}
