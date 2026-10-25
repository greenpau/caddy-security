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
	"errors"
	"os"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/identity-stores-sqlite"
)

func TestIdentityFactoryIndependentHandles(t *testing.T) {
	cfg := sqliteIdentityTestConfig(t)
	sqliteIdentityTestProvision(t, cfg)
	module := &companion.SQLiteIdentityStore{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path, Timeout: cfg.Timeout}
	snapshot, err := module.BackendConfig()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Path = "changed"
	metadata, err := module.IdentityStoreConfig()
	if err != nil {
		t.Fatal(err)
	}
	metadata.Realm = "changed"
	if module.Path != cfg.Path || module.Realm != cfg.Realm {
		t.Fatal("snapshot mutated declaration")
	}
	setup, stop := context.WithCancel(t.Context())
	first, err := module.NewIdentityStore(setup)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.(*identitysqlite.Store).Close() })
	second, err := module.NewIdentityStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.(*identitysqlite.Store).Close() })
	if first == second {
		t.Fatal("factory reused an owned handle")
	}
	if _, ok := first.(ids.IdentityRequestStore); ok {
		t.Fatal("password backend falsely advertised local profile support")
	}
	authenticate := func(store ids.IdentityStore) {
		t.Helper()
		request := requests.NewRequest()
		request.Upstream.Realm = cfg.Realm
		request.User.Username, request.User.Password = "alice", lifecyclePassword
		if err := store.Request(operator.Authenticate, request); err != nil || request.User.Email != "alice@example.test" {
			t.Fatal("account unavailable", err)
		}
	}
	authenticate(first)
	if err := first.(*identitysqlite.Store).Close(); err != nil {
		t.Fatal(err)
	}
	authenticate(second)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if value, err := module.NewIdentityStore(canceled); value != nil || !errors.Is(err, identitysqlite.ErrUnavailable) {
		t.Fatal("canceled setup published storage", err)
	}
	authenticate(second)
}

func TestIdentityInvalidDeclarationBeforeConstruction(t *testing.T) {
	cfg := sqliteIdentityTestConfig(t)
	module := &companion.SQLiteIdentityStore{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path}
	module.Realm = ""
	if err := module.Validate(); err == nil {
		t.Fatal("invalid native declaration accepted")
	}
	if value, err := module.IdentityStoreConfig(); value != nil || err == nil {
		t.Fatal("invalid declaration published metadata", err)
	}
	if value, err := module.NewIdentityStore(t.Context()); value != nil || err == nil {
		t.Fatal("invalid declaration published runtime", err)
	}
	if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
		t.Fatal("invalid declaration touched storage")
	}
}
