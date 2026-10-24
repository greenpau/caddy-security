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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestSQLiteSecretsSnapshot(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	sqliteSecretsTestPut(t, cfg, map[string]any{"key": "first-private-key", "literal.dot": "a \n b", "number": json.Number("9007199254740993"), "null": nil, "empty": "", "object": map[string]any{"array": []any{true, json.Number("1.00")}}})
	m, _ := sqliteSecretsTestModule(t, cfg)
	data, err := m.GetSecret(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if data["number"] != json.Number("9007199254740993") || data["null"] != nil {
		t.Fatal("changed JSON types")
	}
	data["object"].(map[string]any)["array"].([]any)[0] = false
	delete(data, "key")
	again, _ := m.GetSecret(t.Context())
	if again["key"] != "first-private-key" || !again["object"].(map[string]any)["array"].([]any)[0].(bool) {
		t.Fatal("snapshot aliases caller")
	}
	if v, err := m.GetSecretByKey(t.Context(), "literal.dot"); err != nil || v != "a \n b" {
		t.Fatal("dotted key or whitespace changed")
	}
	if v, err := m.GetSecretByKey(t.Context(), "null"); err != nil || v != nil {
		t.Fatal("null conflated with missing")
	}
	if _, err := m.GetSecretByKey(t.Context(), "missing"); !errors.Is(err, sqlite.ErrNotFound) {
		t.Fatal("missing accepted")
	}
	for _, key := range []string{"number", "null", "object", "empty"} {
		if _, _, err := replaceSecretValue(t.Context(), []SecretsManager{m}, "secrets:signing:"+key); err == nil {
			t.Fatal("invalid consumer type accepted", key)
		}
	}
	sqliteSecretsTestPut(t, cfg, map[string]any{"key": "second-private-key", "other": "same-revision"})
	if v, _ := m.GetSecretByKey(t.Context(), "key"); v != "first-private-key" {
		t.Fatal("existing candidate changed")
	}
	fresh, _ := sqliteSecretsTestModule(t, cfg)
	if v, _ := fresh.GetSecretByKey(t.Context(), "key"); v != "second-private-key" {
		t.Fatal("new candidate did not refresh")
	}
	metadata := m.GetConfig(t.Context())
	metadata["name"] = "mutated"
	if m.GetConfig(t.Context())["name"] != "signing" {
		t.Fatal("metadata aliases caller")
	}
	encoded, _ := json.Marshal(m)
	meta, _ := json.Marshal(m.GetConfig(t.Context()))
	for _, sentinel := range []string{"first-private-key", "second-private-key", "same-revision"} {
		if strings.Contains(string(encoded)+string(meta), sentinel) {
			t.Fatal("payload in metadata/JSON")
		}
	}
	if strings.Contains(string(meta), cfg.Path) {
		t.Fatal("path in metadata")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.GetSecret(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	// Concurrent readers and module cleanup share only the snapshot; the database
	// handle was closed before Provision returned, so disposal needs no database.
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 20 {
				_, _ = m.GetSecret(t.Context())
			}
		})
	}
	_ = m.Cleanup()
	_ = m.Cleanup()
	readers.Wait()
	if _, err := m.GetSecret(t.Context()); !errors.Is(err, sqlite.ErrUnavailable) {
		t.Fatal("closed snapshot usable")
	}
}

func TestSQLiteSecretsConfiguration(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	module := &SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record}
	if err := module.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("validation performed IO")
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := module.Provision(ctx); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("consumer created database")
	}
	for _, kind := range []string{"record_missing", "unsafe_mode", "foreign_schema", "invalid_name", "invalid_timeout"} {
		t.Run(kind, func(t *testing.T) {
			cfg := sqliteSecretsTestConfig(t)
			sqliteSecretsTestPut(t, cfg, map[string]any{"key": "private-sentinel"})
			m := &SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record, Timeout: cfg.Timeout}
			switch kind {
			case "record_missing":
				m.Record = "absent"
			case "unsafe_mode":
				if err := os.Chmod(cfg.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "foreign_schema":
				if err := os.WriteFile(cfg.Path, []byte("private-corrupt-database"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid_name":
				m.Name = "bad:name"
			case "invalid_timeout":
				m.Timeout = "0s"
			}
			err := m.Provision(ctx)
			if err == nil {
				t.Fatal("invalid backend accepted")
			}
			if strings.Contains(err.Error(), cfg.Path) || strings.Contains(err.Error(), "private-") {
				t.Fatal("unredacted failure")
			}
		})
	}
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
