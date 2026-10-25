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
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
	"go.uber.org/zap"
)

func sqliteSecretsTestConfig(t *testing.T) *sqlite.Config {
	t.Helper()
	return &sqlite.Config{Name: "signing", Path: filepath.Join(registrationTestDirectory(t), "secrets.db"), Record: "access", Timeout: "500ms"}
}
func sqliteSecretsTestPut(t *testing.T, cfg *sqlite.Config, values map[string]any) {
	t.Helper()
	c, err := sqlite.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Put(t.Context(), values); err != nil {
		t.Fatal(err)
	}
}
func sqliteSecretsTestModule(t *testing.T, cfg *sqlite.Config) (*SQLiteSecretsManager, context.CancelFunc) {
	t.Helper()
	m := &SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record, Timeout: cfg.Timeout}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = m.Cleanup() })
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	return m, cancel
}

func TestParseCaddyfileSQLiteSecrets(t *testing.T) {
	good := `signing {
 path "/private secrets/secrets.db"
 record access
 timeout 750ms
}`
	m := new(SQLiteSecretsManager)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if m.Name != "signing" || m.Path != "/private secrets/secrets.db" || m.Record != "access" || m.Timeout != "750ms" {
		t.Fatal("incorrect mapping")
	}
	for _, body := range []string{
		strings.Replace(good, "timeout 750ms", "timeout 1s\ntimeout 2s", 1),
		strings.Replace(good, "record access", "name signing\nrecord access", 1),
		strings.Replace(good, "record access", "record access\nrecord second", 1),
		strings.Replace(good, "record access", "record access extra", 1),
		strings.Replace(good, "record access", "unknown private-sentinel", 1),
		strings.Replace(good, "record access", "record {\naccess\n}", 1),
		strings.Replace(good, "signing {", "bad:name {", 1),
		strings.TrimSuffix(good, "}"),
		strings.Replace(good, " {", " \"{\"", 1),
		strings.Replace(good, "timeout 750ms", "timeout 0s", 1),
	} {
		if err := new(SQLiteSecretsManager).UnmarshalCaddyfile(caddyfile.NewTestDispenser(body)); err == nil {
			t.Fatal("invalid block accepted")
		}
	}
	braces := new(SQLiteSecretsManager)
	if err := braces.UnmarshalCaddyfile(caddyfile.NewTestDispenser(strings.Replace(good, "record access", "record \"}\"", 1))); err != nil || braces.Record != "}" {
		t.Fatal("quoted brace must remain literal record data", err)
	}
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\nsecrets sqlite "+good+"\nauthorization policy p {\nallow roles viewer\n}\n}\n}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var c caddy.Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(c.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	if len(app.SecretsManagerConfigs) != 1 {
		t.Fatal("lost native config")
	}
	var restored SQLiteSecretsManager
	if err := json.Unmarshal(app.SecretsManagerConfigs[0], &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Name != m.Name || restored.Path != m.Path || restored.Timeout != m.Timeout {
		t.Fatal("native roundtrip lost fields")
	}
}

func TestAppSQLiteSecrets(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	sqliteSecretsTestPut(t, cfg, map[string]any{"key": authorizationPathKey})
	raw, _ := json.Marshal(map[string]any{"driver": "sqlite", "name": cfg.Name, "path": cfg.Path, "record": cfg.Record})
	for _, duplicate := range []bool{false, true} {
		t.Run(fmt.Sprint(duplicate), func(t *testing.T) {
			app := &App{Config: lifecycleConfig(), SecretsManagerConfigs: []json.RawMessage{raw}}
			app.Config.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = []string{"crypto key verify secrets:signing:key"}
			if duplicate {
				app.SecretsManagerConfigs = append(app.SecretsManagerConfigs, raw)
			}
			before, _ := json.Marshal(app)
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			defer app.Cleanup()
			err := app.Provision(ctx)
			if duplicate {
				if err == nil {
					t.Fatal("duplicate manager accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("provision mutated declarative JSON")
			}
			// The existing resolver consumes one module snapshot, including references
			// encountered in separately resolved fields.
			value, err := substituteString(t.Context(), caddy.NewReplacer(), app.secretsManagers, "key", "secrets:signing:key", zap.NewNop())
			if err != nil || value != authorizationPathKey {
				t.Fatal("runtime resolution failed")
			}
			cancel()
			if _, err := app.secretsManagers[0].GetSecret(t.Context()); err == nil {
				t.Fatal("module cleanup retained snapshot")
			}
			if _, err := app.server.GetGatekeeperByName("policy"); err != nil {
				t.Fatal("snapshot cleanup disposed live consumer")
			}
		})
	}
}

func TestAppSQLiteSecretsPrivateErrors(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	marker := "private-invalid-consumer-value"
	sqliteSecretsTestPut(t, cfg, map[string]any{"key": marker})
	raw, _ := json.Marshal(map[string]any{"driver": "sqlite", "name": cfg.Name, "path": cfg.Path, "record": cfg.Record})
	for _, statement := range []string{"crypto key token lifetime secrets:signing:key", "crypto key verify from file secrets:signing:key"} {
		app := &App{Config: lifecycleConfig(), SecretsManagerConfigs: []json.RawMessage{raw}}
		app.Config.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = []string{statement}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		err := app.Provision(ctx)
		cancel()
		if closeErr := app.Cleanup(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "private secrets") {
			t.Fatal("private consumer failure was not redacted")
		}
	}
}

func TestSQLiteSecretsConsumerTypes(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	sqliteSecretsTestPut(t, cfg, map[string]any{"number": json.Number("9007199254740993"), "null": nil, "object": map[string]any{"key": true}, "empty": ""})
	m, _ := sqliteSecretsTestModule(t, cfg)
	for _, key := range []string{"number", "null", "object", "empty"} {
		if _, _, err := replaceSecretValue(t.Context(), []SecretsManager{m}, "secrets:signing:"+key); err == nil {
			t.Fatal("invalid consumer type accepted", key)
		}
	}
}
