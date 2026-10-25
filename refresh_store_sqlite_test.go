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
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
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
