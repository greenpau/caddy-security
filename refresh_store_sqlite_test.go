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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

func refreshStoreTestFactory(t *testing.T, m *SQLiteRefreshStore) *sqliteRefreshStoreFactory {
	t.Helper()
	factory, err := m.PrepareRefreshStore()
	if err != nil {
		t.Fatal("cannot prepare refresh storage fixture")
	}
	value, ok := factory.(*sqliteRefreshStoreFactory)
	if !ok || value == nil {
		t.Fatal("immutable refresh factory missing")
	}
	return value
}
func TestSQLiteRefreshStorePreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "sessions.db")
	module := &SQLiteRefreshStore{Name: "sessions", Path: path}
	before, _ := json.Marshal(module)
	if module.Validate() != nil {
		t.Fatal("valid pure declaration rejected")
	}
	factory := refreshStoreTestFactory(t, module)
	descriptor, err := factory.RefreshStoreConfig()
	if err != nil || descriptor.Validate() != nil || descriptor.Name != "sessions" || descriptor.Kind != "sqlite" || descriptor.MaxSessions != 10000 || descriptor.MaxRotations != 1024 {
		t.Fatal("invalid normalized metadata")
	}
	for _, timeout := range []string{"", "1s", "1000ms", "1000000us"} {
		copy := *module
		copy.Timeout = timeout
		got, _ := refreshStoreTestFactory(t, &copy).RefreshStoreConfig()
		if got != descriptor || copy.Timeout != timeout {
			t.Fatal("equivalent timeout changed digest or input")
		}
	}
	renamed := *module
	renamed.Name = "renamed"
	other, _ := refreshStoreTestFactory(t, &renamed).RefreshStoreConfig()
	if other.Name == descriptor.Name || other.ConfigDigest != descriptor.ConfigDigest {
		t.Fatal("root name changed backend digest")
	}
	for _, edit := range []func(*SQLiteRefreshStore){func(m *SQLiteRefreshStore) { m.Path += "-other" }, func(m *SQLiteRefreshStore) { m.MaxSessions = 2 }, func(m *SQLiteRefreshStore) { m.MaxRotations = 2 }, func(m *SQLiteRefreshStore) { m.Timeout = "2s" }} {
		copy := *module
		edit(&copy)
		got, _ := refreshStoreTestFactory(t, &copy).RefreshStoreConfig()
		if got.ConfigDigest == descriptor.ConfigDigest {
			t.Fatal("material backend setting omitted from digest")
		}
	}
	captured := factory.sqliteConfig()
	captured.Path = "changed"
	descriptor.MaxSessions = 1
	again, _ := factory.RefreshStoreConfig()
	if factory.sqliteConfig().Path != path || again.MaxSessions != 10000 {
		t.Fatal("factory exposed mutable state")
	}
	after, _ := json.Marshal(module)
	if !bytes.Equal(before, after) {
		t.Fatal("pure validation mutated module")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("pure preparation touched storage")
	}
}
func TestSQLiteRefreshStoreInvalidConfiguration(t *testing.T) {
	for name, edit := range map[string]func(*SQLiteRefreshStore){
		"empty_name": func(m *SQLiteRefreshStore) { m.Name = "" }, "padded_name": func(m *SQLiteRefreshStore) { m.Name = " sessions" }, "utf8_name": func(m *SQLiteRefreshStore) { m.Name = "\xff" }, "long_name": func(m *SQLiteRefreshStore) { m.Name = strings.Repeat("a", 129) },
		"relative_path": func(m *SQLiteRefreshStore) { m.Path = "relative.db" }, "root_path": func(m *SQLiteRefreshStore) { m.Path = "/" }, "utf8_path": func(m *SQLiteRefreshStore) { m.Path += "\xff" }, "sessions": func(m *SQLiteRefreshStore) { m.MaxSessions = -1 }, "rotations": func(m *SQLiteRefreshStore) { m.MaxRotations = 100001 }, "timeout": func(m *SQLiteRefreshStore) { m.Timeout = "{env.PRIVATE}" }, "timeout_range": func(m *SQLiteRefreshStore) { m.Timeout = "31s" },
	} {
		t.Run(name, func(t *testing.T) {
			m := &SQLiteRefreshStore{Name: "sessions", Path: "/private/refresh.db"}
			edit(m)
			if m.Validate() == nil {
				t.Fatal("invalid backend declaration accepted")
			}
		})
	}
	if (*SQLiteRefreshStore)(nil).Validate() == nil {
		t.Fatal("nil declaration accepted")
	}
	// Literal braces in a path are owner data, not an unsupported runtime lookup.
	if (&SQLiteRefreshStore{Name: "sessions", Path: "/private/{env.LITERAL}.db"}).Validate() != nil {
		t.Fatal("literal backend path semantics changed")
	}
}
func TestSQLiteRefreshStoreFrozenRuntime(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture setup failed")
	}
	path := filepath.Join(dir, "sessions.db")
	m := &SQLiteRefreshStore{Name: "sessions", Path: path, MaxSessions: 2, MaxRotations: 3}
	raw, _ := json.Marshal(struct {
		Driver string `json:"driver"`
		*SQLiteRefreshStore
	}{"sqlite", m})
	app := &App{RefreshStoreConfigs: []json.RawMessage{raw}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	loaded, err := ctx.LoadModule(app, "RefreshStoreConfigs")
	if err != nil {
		cancel()
		t.Fatal("cannot load refresh module")
	}
	actual := loaded.([]any)[0].(*SQLiteRefreshStore)
	factory := refreshStoreTestFactory(t, actual)
	actual.Path = filepath.Join(dir, "absent", "changed.db")
	actual.MaxSessions = 1
	setup, stop := context.WithCancel(t.Context())
	store, err := factory.NewRefreshStore(setup)
	if err != nil {
		cancel()
		stop()
		t.Fatal("cannot open frozen backend", err)
	}
	defer store.(io.Closer).Close()
	stop()
	cancel()
	metadata, err := store.Metadata()
	descriptor, _ := factory.RefreshStoreConfig()
	if err != nil || metadata.ConfigDigest != descriptor.ConfigDigest || metadata.MaxSessions != 2 || store.CheckReady(t.Context()) != nil {
		t.Fatal("setup/module cleanup changed owned runtime")
	}
	generation := tokenrefresh.Generation{Namespace: strings.Repeat("a", 64), ID: strings.Repeat("1", 64)}
	if view, err := store.ActivateGeneration(t.Context(), generation); err != nil || view.Generation() != generation {
		t.Fatal("core activation unavailable")
	}
	second, err := factory.NewRefreshStore(t.Context())
	if err != nil || second == store {
		t.Fatal("factory reused owned connection")
	}
	defer second.(io.Closer).Close()
	if _, err := os.Stat(actual.Path); !os.IsNotExist(err) {
		t.Fatal("constructor reread mutated module")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if value, err := factory.NewRefreshStore(canceled); err == nil || value != nil {
		t.Fatal("canceled construction published handle")
	}
}
func TestSQLiteRefreshStoreNativeConfiguration(t *testing.T) {
	for _, raw := range []string{`null`, `{"driver":"absent"}`, `{"driver":"sqlite","name":"sessions","path":false}`, `{"driver":"sqlite","private_diagnostic":"sentinel"}`} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		app := &App{RefreshStoreConfigs: []json.RawMessage{json.RawMessage(raw)}}
		_, err := ctx.LoadModule(app, "RefreshStoreConfigs")
		cancel()
		if err == nil {
			t.Fatal("invalid native module accepted")
		}
	}
	var absent *sqliteRefreshStoreFactory
	if _, err := absent.RefreshStoreConfig(); err == nil {
		t.Fatal("nil factory exposed metadata")
	}
	if value, err := absent.NewRefreshStore(t.Context()); err == nil || value != nil {
		t.Fatal("nil factory opened backend")
	}
	m := &SQLiteRefreshStore{Name: "sessions", Path: filepath.Join(t.TempDir(), "absent", "private-sentinel.db")}
	if value, err := refreshStoreTestFactory(t, m).NewRefreshStore(t.Context()); err == nil || value != nil || strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("failed backend construction accepted or disclosed")
	}
}
