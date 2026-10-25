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

	companion "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-sqlite"
)

func refreshStoreTestFactory(t *testing.T, m *companion.SQLiteRefreshStore) *companion.Factory {
	t.Helper()
	factory, err := m.PrepareRefreshStore()
	if err != nil {
		t.Fatal("cannot prepare refresh storage fixture")
	}
	value, ok := factory.(*companion.Factory)
	if !ok || value == nil {
		t.Fatal("immutable refresh factory missing")
	}
	return value
}

func TestSQLiteRefreshStorePreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "sessions.db")
	module := &companion.SQLiteRefreshStore{Name: "sessions", Path: path}
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
	for _, edit := range []func(*companion.SQLiteRefreshStore){func(m *companion.SQLiteRefreshStore) { m.Path += "-other" }, func(m *companion.SQLiteRefreshStore) { m.MaxSessions = 2 }, func(m *companion.SQLiteRefreshStore) { m.MaxRotations = 2 }, func(m *companion.SQLiteRefreshStore) { m.Timeout = "2s" }} {
		copy := *module
		edit(&copy)
		got, _ := refreshStoreTestFactory(t, &copy).RefreshStoreConfig()
		if got.ConfigDigest == descriptor.ConfigDigest {
			t.Fatal("material backend setting omitted from digest")
		}
	}
	captured := factory.SQLiteConfig()
	captured.Path = "changed"
	descriptor.MaxSessions = 1
	again, _ := factory.RefreshStoreConfig()
	if factory.SQLiteConfig().Path != path || factory.SQLiteConfig() == captured || again.MaxSessions != 10000 {
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
	for name, edit := range map[string]func(*companion.SQLiteRefreshStore){
		"empty_name": func(m *companion.SQLiteRefreshStore) { m.Name = "" }, "padded_name": func(m *companion.SQLiteRefreshStore) { m.Name = " sessions" }, "utf8_name": func(m *companion.SQLiteRefreshStore) { m.Name = "\xff" }, "long_name": func(m *companion.SQLiteRefreshStore) { m.Name = strings.Repeat("a", 129) },
		"relative_path": func(m *companion.SQLiteRefreshStore) { m.Path = "relative.db" }, "root_path": func(m *companion.SQLiteRefreshStore) { m.Path = "/" }, "utf8_path": func(m *companion.SQLiteRefreshStore) { m.Path += "\xff" }, "sessions": func(m *companion.SQLiteRefreshStore) { m.MaxSessions = -1 }, "rotations": func(m *companion.SQLiteRefreshStore) { m.MaxRotations = 100001 }, "timeout": func(m *companion.SQLiteRefreshStore) { m.Timeout = "{env.PRIVATE}" }, "timeout_range": func(m *companion.SQLiteRefreshStore) { m.Timeout = "31s" },
	} {
		t.Run(name, func(t *testing.T) {
			m := &companion.SQLiteRefreshStore{Name: "sessions", Path: "/private/refresh.db"}
			edit(m)
			if m.Validate() == nil {
				t.Fatal("invalid backend declaration accepted")
			}
			if factory, err := m.PrepareRefreshStore(); err == nil || factory != nil {
				t.Fatal("invalid declaration published a refresh factory", err)
			}
		})
	}
	if (*companion.SQLiteRefreshStore)(nil).Validate() == nil {
		t.Fatal("nil declaration accepted")
	}
	// Literal braces in a path are owner data, not an unsupported runtime lookup.
	if (&companion.SQLiteRefreshStore{Name: "sessions", Path: "/private/{env.LITERAL}.db"}).Validate() != nil {
		t.Fatal("literal backend path semantics changed")
	}
}

func TestRefreshNilFactory(t *testing.T) {
	var module *companion.SQLiteRefreshStore
	if factory, err := module.PrepareRefreshStore(); err == nil || factory != nil {
		t.Fatal("nil declaration published a factory", err)
	}
	var factory *companion.Factory
	if metadata, err := factory.RefreshStoreConfig(); err == nil || metadata != (tokenrefresh.ExternalStoreConfig{}) {
		t.Fatal("nil factory published metadata", err)
	}
	if store, err := factory.NewRefreshStore(t.Context()); err == nil || store != nil {
		t.Fatal("nil factory published a managed store", err)
	}
}

func TestSQLiteRefreshStoreFrozenRuntime(t *testing.T) {
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private fixture setup failed")
	}
	path := filepath.Join(dir, "sessions.db")
	m := &companion.SQLiteRefreshStore{Name: "sessions", Path: path, MaxSessions: 2, MaxRotations: 3}
	raw, _ := json.Marshal(struct {
		Driver string `json:"driver"`
		*companion.SQLiteRefreshStore
	}{"sqlite", m})
	app := &moduleLoader{RefreshStoreConfigs: []json.RawMessage{raw}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	loaded, err := ctx.LoadModule(app, "RefreshStoreConfigs")
	if err != nil {
		cancel()
		t.Fatal("cannot load refresh module")
	}
	actual := loaded.([]any)[0].(*companion.SQLiteRefreshStore)
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

type moduleLoader struct {
	RefreshStoreConfigs []json.RawMessage `caddy:"namespace=security.refresh_stores inline_key=driver"`
}
