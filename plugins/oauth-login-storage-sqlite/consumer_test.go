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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	loginsqlite "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"

	"github.com/greenpau/caddy-security/pkg/plugin"
	companion "github.com/greenpau/caddy-security/plugins/oauth-login-storage-sqlite"
)

func sqliteOAuthLoginTestModule(t *testing.T) *companion.SQLiteOAuthLoginStore {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot make OAuth storage fixture private")
	}
	return &companion.SQLiteOAuthLoginStore{Name: "shared", Path: filepath.Join(dir, "logins.db"), Timeout: "5s", Capacity: 2}
}

func sqliteOAuthLoginTestFactory(t *testing.T, module *companion.SQLiteOAuthLoginStore) *companion.Factory {
	t.Helper()
	factory, err := module.PrepareOAuthLoginStore()
	if err != nil {
		t.Fatal("cannot prepare SQLite OAuth login storage")
	}
	result, ok := factory.(*companion.Factory)
	if !ok || result == nil {
		t.Fatal("prepared factory lost its SQLite storage metadata")
	}
	return result
}

func sqliteOAuthLoginTestOpen(t *testing.T, factory plugin.OAuthLoginStoreFactory) plugin.OAuthLoginStore {
	t.Helper()
	store, err := factory.NewOAuthLoginStore(t.Context())
	if err != nil || store == nil {
		t.Fatal("cannot construct SQLite OAuth login storage")
	}
	closer, ok := store.(io.Closer)
	if !ok {
		t.Fatal("SQLite runtime did not transfer its closer")
	}
	t.Cleanup(func() {
		if err := closer.Close(); err != nil {
			t.Error("cannot close SQLite OAuth login storage")
		}
	})
	return store
}

func sqliteOAuthLoginTestTransaction(state string) oauth.LoginTransaction {
	now := time.Now().Unix()
	return oauth.LoginTransaction{State: state, Nonce: "synthetic-nonce", NonceRequired: true, Verifier: "synthetic-private-verifier", Binding: oauth.LoginBinding{Browser: sha256.Sum256([]byte("synthetic-browser")), Callback: "https://portal.example.test/company/auth/oauth2/upstream/authorization-code-callback"}, ReturnURL: "https://portal.example.test/resource?path=a%2Fb&literal=a%26b#section", CreatedAt: now, ExpiresAt: now + 180}
}

func TestSQLiteOAuthLoginStorePreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-created", "logins.db")
	module := &companion.SQLiteOAuthLoginStore{Name: "shared", Path: path}
	before, _ := json.Marshal(module)
	if err := module.Validate(); err != nil {
		t.Fatal("valid module failed pure validation")
	}
	factory := sqliteOAuthLoginTestFactory(t, module)
	metadata, err := factory.OAuthLoginStoreConfig()
	if err != nil || metadata.Validate() != nil || metadata.Name != module.Name || metadata.Driver != "sqlite" {
		t.Fatal("factory has an invalid binding descriptor")
	}
	cfg := loginsqlite.Config{Path: path, Timeout: "1s", Capacity: 10000}
	encoded, _ := json.Marshal(cfg)
	digest := sha256.Sum256(encoded)
	if metadata.ConfigHash != hex.EncodeToString(digest[:]) || factory.SQLiteConfig() != cfg {
		t.Fatal("factory descriptor does not attest normalized backend settings")
	}
	for _, timeout := range []string{"", "1s", "1000ms", "1000000us"} {
		for _, capacity := range []int{0, 10000} {
			copy := *module
			copy.Timeout, copy.Capacity = timeout, capacity
			candidate := sqliteOAuthLoginTestFactory(t, &copy)
			got, err := candidate.OAuthLoginStoreConfig()
			if err != nil || got != metadata || copy.Timeout != timeout || copy.Capacity != capacity {
				t.Fatal("equivalent defaults changed the descriptor or caller input")
			}
		}
	}
	for name, change := range map[string]func(*companion.SQLiteOAuthLoginStore){
		"path":     func(m *companion.SQLiteOAuthLoginStore) { m.Path = path + ".other" },
		"timeout":  func(m *companion.SQLiteOAuthLoginStore) { m.Timeout = "2s" },
		"capacity": func(m *companion.SQLiteOAuthLoginStore) { m.Capacity = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *module
			change(&copy)
			got, err := sqliteOAuthLoginTestFactory(t, &copy).OAuthLoginStoreConfig()
			if err != nil || got.ConfigHash == metadata.ConfigHash {
				t.Fatal("material backend setting did not change its descriptor")
			}
		})
	}
	after, _ := json.Marshal(module)
	if !bytes.Equal(before, after) {
		t.Fatal("preparation mutated the declarative module")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("pure validation or preparation touched storage")
	}
	copy := factory.SQLiteConfig()
	copy.Path, copy.Capacity = "/unreviewed/logins.db", 1
	metadata.Name = "edited"
	if factory.SQLiteConfig() != cfg || factory.SQLiteConfig() == copy {
		t.Fatal("returned storage metadata aliases the prepared factory")
	}
	got, _ := factory.OAuthLoginStoreConfig()
	if got.Name != "shared" {
		t.Fatal("returned descriptor aliases the prepared factory")
	}
}

func TestSQLiteOAuthLoginStoreInvalidConfiguration(t *testing.T) {
	base := &companion.SQLiteOAuthLoginStore{Name: "shared", Path: filepath.Join(t.TempDir(), "missing", "logins.db")}
	cases := map[string]func(*companion.SQLiteOAuthLoginStore){
		"empty_name":        func(m *companion.SQLiteOAuthLoginStore) { m.Name = "" },
		"leading_space":     func(m *companion.SQLiteOAuthLoginStore) { m.Name = " shared" },
		"trailing_space":    func(m *companion.SQLiteOAuthLoginStore) { m.Name = "shared " },
		"control_name":      func(m *companion.SQLiteOAuthLoginStore) { m.Name = "shared\u0085name" },
		"invalid_utf8":      func(m *companion.SQLiteOAuthLoginStore) { m.Name = "shared\xff" },
		"long_name":         func(m *companion.SQLiteOAuthLoginStore) { m.Name = strings.Repeat("n", 129) },
		"missing_path":      func(m *companion.SQLiteOAuthLoginStore) { m.Path = "" },
		"relative_path":     func(m *companion.SQLiteOAuthLoginStore) { m.Path = "logins.db" },
		"root_path":         func(m *companion.SQLiteOAuthLoginStore) { m.Path = "/" },
		"memory_path":       func(m *companion.SQLiteOAuthLoginStore) { m.Path = ":memory:" },
		"zero_timeout":      func(m *companion.SQLiteOAuthLoginStore) { m.Timeout = "0s" },
		"short_timeout":     func(m *companion.SQLiteOAuthLoginStore) { m.Timeout = "999us" },
		"long_timeout":      func(m *companion.SQLiteOAuthLoginStore) { m.Timeout = "31s" },
		"dynamic_timeout":   func(m *companion.SQLiteOAuthLoginStore) { m.Timeout = "{env.LOGIN_TIMEOUT}" },
		"negative_capacity": func(m *companion.SQLiteOAuthLoginStore) { m.Capacity = -1 },
		"large_capacity":    func(m *companion.SQLiteOAuthLoginStore) { m.Capacity = 100001 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copy := *base
			change(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("invalid native module passed validation")
			}
			if factory, err := copy.PrepareOAuthLoginStore(); err == nil || factory != nil {
				t.Fatal("invalid native module published a factory")
			}
		})
	}
	var absent *companion.SQLiteOAuthLoginStore
	if absent.Validate() == nil {
		t.Fatal("nil module passed validation")
	}
	if factory, err := absent.PrepareOAuthLoginStore(); err == nil || factory != nil {
		t.Fatal("nil module published a factory")
	}
	for _, name := range []string{"shared", "shared with spaces,comma", "ログイン", "}", strings.Repeat("n", 128), "{env.LITERAL_NAME}"} {
		copy := *base
		copy.Name = name
		if err := copy.Validate(); err != nil {
			t.Fatal("valid literal name failed validation")
		}
	}
	if _, err := os.Stat(filepath.Dir(base.Path)); !os.IsNotExist(err) {
		t.Fatal("invalid module validation touched storage")
	}
}

func TestSQLiteOAuthLoginStoreFrozenFactoryAndDelegation(t *testing.T) {
	module := sqliteOAuthLoginTestModule(t)
	path := module.Path
	factory := sqliteOAuthLoginTestFactory(t, module)
	metadata, _ := factory.OAuthLoginStoreConfig()
	module.Name, module.Path, module.Timeout, module.Capacity = "edited", filepath.Join(t.TempDir(), "missing", "other.db"), "31s", -1
	first := sqliteOAuthLoginTestOpen(t, factory)
	second := sqliteOAuthLoginTestOpen(t, factory)
	if first == second {
		t.Fatal("factory reused a runtime connection")
	}
	if got, err := first.OAuthLoginStoreConfig(); err != nil || got != metadata {
		t.Fatal("runtime descriptor differs from its prepared factory")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("factory did not open its captured path")
	}
	if _, err := os.Stat(filepath.Dir(module.Path)); !os.IsNotExist(err) {
		t.Fatal("factory reread the edited module path")
	}
	ctx := t.Context()
	const namespace = "private-test-namespace"
	tx := sqliteOAuthLoginTestTransaction("first-state")
	if err := first.Create(ctx, namespace, tx); err != nil {
		t.Fatal("Create did not delegate to the public backend")
	}
	if got, err := second.Get(ctx, namespace, tx.State); err != nil || got != tx {
		t.Fatal("Get lost private transaction fields across independent clients")
	}
	wrong := tx.Binding
	wrong.Browser = sha256.Sum256([]byte("other-browser"))
	if _, err := second.Claim(ctx, namespace, tx.State, wrong, "wrong-claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("Claim changed the public binding error")
	}
	claimed, err := first.Claim(ctx, namespace, tx.State, tx.Binding, "accepted-claim")
	want := tx
	want.Claim = "accepted-claim"
	if err != nil || claimed != want {
		t.Fatal("Claim did not return complete committed evidence")
	}
	if err := second.Complete(ctx, namespace, tx.State, "wrong-claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("Complete changed the public ownership error")
	}
	if err := second.Complete(ctx, namespace, tx.State, claimed.Claim); err != nil {
		t.Fatal("peer Complete did not consume the claim")
	}
	if _, err := first.Get(ctx, namespace, tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("consumed transaction remained available")
	}
	pending := sqliteOAuthLoginTestTransaction("pending-state")
	if err := first.Create(ctx, namespace, pending); err != nil {
		t.Fatal("cannot create cleanup preservation control")
	}
	if ok, err := second.Cancel(ctx, namespace, pending.State, wrong); err != nil || ok {
		t.Fatal("wrong-binding cancellation consumed a transaction")
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatal("cannot close first runtime")
	}
	if _, err := first.OAuthLoginStoreConfig(); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("closed runtime still attested readiness")
	}
	if got, err := second.Get(ctx, namespace, pending.State); err != nil || got != pending {
		t.Fatal("closing a client changed its peer's pending transaction")
	}
	if err := second.(io.Closer).Close(); err != nil {
		t.Fatal("cannot close second runtime")
	}
	reopened := sqliteOAuthLoginTestOpen(t, factory)
	if got, err := reopened.Get(ctx, namespace, pending.State); err != nil || got != pending {
		t.Fatal("Close purged durable pending evidence")
	}
	if ok, err := reopened.Cancel(ctx, namespace, pending.State, pending.Binding); err != nil || !ok {
		t.Fatal("Cancel did not delegate its acknowledged result")
	}
	if _, err := reopened.Get(ctx, namespace, pending.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("canceled transaction remained available")
	}
}

func TestSQLiteOAuthLoginStoreOwnershipAndUnavailable(t *testing.T) {
	module := sqliteOAuthLoginTestModule(t)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	raw, _ := json.Marshal(map[string]any{"driver": "sqlite", "name": module.Name, "path": module.Path, "timeout": module.Timeout})
	loaded, err := ctx.LoadModule(&moduleLoader{OAuthLoginStoreConfigs: []json.RawMessage{raw}}, "OAuthLoginStoreConfigs")
	if err != nil {
		cancel()
		t.Fatal("cannot load ownership control")
	}
	factory := sqliteOAuthLoginTestFactory(t, loaded.([]any)[0].(*companion.SQLiteOAuthLoginStore))
	setup, stopSetup := context.WithCancel(t.Context())
	store, err := factory.NewOAuthLoginStore(setup)
	if err != nil {
		stopSetup()
		cancel()
		t.Fatal("cannot construct ownership control")
	}
	t.Cleanup(func() { _ = store.(io.Closer).Close() })
	stopSetup()
	cancel()
	if err := store.Create(t.Context(), "ownership", sqliteOAuthLoginTestTransaction("after-module-cleanup")); err != nil {
		t.Fatal("module cleanup or setup cancellation closed the app-owned runtime")
	}
	if err := store.(io.Closer).Close(); err != nil {
		t.Fatal("cannot retire ownership control")
	}
	for name, unavailable := range map[string]plugin.OAuthLoginStore{"closed": store} {
		t.Run(name, func(t *testing.T) {
			tx := sqliteOAuthLoginTestTransaction("unavailable")
			if _, err := unavailable.OAuthLoginStoreConfig(); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable runtime published a descriptor")
			}
			if err := unavailable.Create(t.Context(), "n", tx); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Create accepted")
			}
			if _, err := unavailable.Get(t.Context(), "n", tx.State); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Get accepted")
			}
			if _, err := unavailable.Claim(t.Context(), "n", tx.State, tx.Binding, "claim"); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Claim accepted")
			}
			if err := unavailable.Complete(t.Context(), "n", tx.State, "claim"); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Complete accepted")
			}
			if accepted, err := unavailable.Cancel(t.Context(), "n", tx.State, tx.Binding); accepted || !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Cancel accepted")
			}
			if err := unavailable.(io.Closer).Close(); err != nil {
				t.Fatal("unavailable cleanup failed")
			}
		})
	}
}

func TestSQLiteOAuthLoginStoreConstructionFailure(t *testing.T) {
	module := &companion.SQLiteOAuthLoginStore{Name: "shared", Path: filepath.Join(t.TempDir(), "missing", "private-sentinel.db")}
	factory := sqliteOAuthLoginTestFactory(t, module)
	if store, err := factory.NewOAuthLoginStore(t.Context()); !errors.Is(err, oauth.ErrLoginUnavailable) || store != nil || strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("failed construction returned a partial runtime or private diagnostic")
	}
	if _, err := os.Stat(filepath.Dir(module.Path)); !os.IsNotExist(err) {
		t.Fatal("constructor created a missing private parent")
	}
	var missing *companion.Factory
	if _, err := missing.OAuthLoginStoreConfig(); err == nil {
		t.Fatal("nil factory published metadata")
	}
	if store, err := missing.NewOAuthLoginStore(t.Context()); !errors.Is(err, oauth.ErrLoginUnavailable) || store != nil {
		t.Fatal("nil factory constructed a runtime")
	}
}

type moduleLoader struct {
	OAuthLoginStoreConfigs []json.RawMessage `caddy:"namespace=security.oauth_login_stores inline_key=driver"`
}
