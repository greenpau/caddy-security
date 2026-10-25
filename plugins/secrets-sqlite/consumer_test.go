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

package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/secrets-sqlite"
)

func sqliteSecretsTestConfig(t *testing.T) *sqlite.Config {
	t.Helper()
	return &sqlite.Config{Name: "signing", Path: filepath.Join(privateDirectory(t), "secrets.db"), Record: "access", Timeout: "500ms"}
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

func sqliteSecretsTestModule(t *testing.T, cfg *sqlite.Config) (*companion.SQLiteSecretsManager, context.CancelFunc) {
	t.Helper()
	m := &companion.SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record, Timeout: cfg.Timeout}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = m.Cleanup() })
	if err := m.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	return m, cancel
}

func TestSQLiteSecretsConfiguration(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	module := &companion.SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record}
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
			m := &companion.SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record, Timeout: cfg.Timeout}
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
				values, err := m.GetSecret(t.Context())
				if err != nil && !errors.Is(err, sqlite.ErrUnavailable) {
					t.Errorf("unexpected concurrent snapshot error: %v", err)
				}
				if err == nil && values["key"] != "first-private-key" {
					t.Error("concurrent reader observed an incoherent snapshot")
				}
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

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
