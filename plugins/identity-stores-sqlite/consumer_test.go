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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/identity-stores-sqlite"
)

func sqliteIdentityTestConfig(t *testing.T) *identitysqlite.Config {
	t.Helper()
	// The transaction includes bcrypt verification; race instrumentation needs
	// more than the production-speed parser fixtures' subsecond durations.
	return &identitysqlite.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(privateDirectory(t), "identities.db"), Timeout: "5s"}
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

func TestSQLiteIdentityParser(t *testing.T) {
	good := "accounts {\nrealm staff\npath \"/private accounts/identities.db\"\ntimeout 750ms\n}"
	m := new(companion.SQLiteIdentityStore)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if m.Name != "accounts" || m.Realm != "staff" || m.Path != "/private accounts/identities.db" || m.Timeout != "750ms" {
		t.Fatal("parser lost exact configuration")
	}
	for name, input := range map[string]string{
		"empty":             "",
		"extra_name":        strings.Replace(good, "accounts {", "accounts other {", 1),
		"duplicate_name":    strings.Replace(good, "realm staff", "name accounts\nrealm staff", 1),
		"duplicate_path":    strings.Replace(good, "realm staff", "path /private/other.db\nrealm staff", 1),
		"duplicate_realm":   strings.Replace(good, "realm staff", "realm staff\nrealm other", 1),
		"duplicate_timeout": strings.Replace(good, "timeout 750ms", "timeout 1s\ntimeout 2s", 1),
		"missing_realm":     strings.Replace(good, "realm staff\n", "", 1),
		"missing_path":      "accounts {\nrealm staff\n}",
		"empty_realm":       strings.Replace(good, "realm staff", "realm \"\"", 1),
		"relative_path":     strings.Replace(good, "/private accounts/identities.db", "relative.db", 1),
		"root_path":         strings.Replace(good, "/private accounts/identities.db", "/", 1),
		"nested":            strings.Replace(good, "realm staff", "realm {\nstaff\n}", 1),
		"unknown":           strings.Replace(good, "realm staff", "password private-sentinel", 1),
		"unclosed":          strings.TrimSuffix(good, "}"),
		"quoted_open":       strings.Replace(good, " {", " \"{\"", 1),
		"timeout_zero":      strings.Replace(good, "750ms", "0s", 1),
		"timeout_too_short": strings.Replace(good, "750ms", "999us", 1),
		"timeout_too_long":  strings.Replace(good, "750ms", "31s", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := new(companion.SQLiteIdentityStore).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	defaults := strings.Replace(strings.Replace(good, "realm staff", "realm \"}\"", 1), "timeout 750ms\n", "", 1)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(defaults)); err != nil || m.Realm != "}" || m.Timeout != "1s" {
		t.Fatal("quoted brace/default did not survive parsing", err)
	}
}

func TestSQLiteIdentityDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "identities.db")
	m := &companion.SQLiteIdentityStore{Name: "accounts", Realm: "staff", Path: path}
	before, _ := json.Marshal(m)
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	descriptor, err := m.IdentityStoreConfig()
	if err != nil || descriptor.Validate() != nil {
		t.Fatal("descriptor rejected", err)
	}
	wantConfig := &identitysqlite.Config{Name: m.Name, Realm: m.Realm, Path: path, Timeout: "1s"}
	encoded, err := json.Marshal(wantConfig)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if descriptor.Name != "accounts" || descriptor.Kind != "sqlite" || descriptor.Realm != "staff" || descriptor.ConfigDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("descriptor does not bind normalized SQLite configuration")
	}
	after, _ := json.Marshal(m)
	if string(before) != string(after) {
		t.Fatal("descriptor validation mutated native declaration")
	}
	for _, timeout := range []string{"1s", "1000ms", "1000000us"} {
		copy := *m
		copy.Timeout = timeout
		got, err := copy.IdentityStoreConfig()
		if err != nil || *got != *descriptor {
			t.Fatalf("equivalent timeout %q changed persistent binding: %v", timeout, err)
		}
	}
	copy := *m
	copy.Path = filepath.Join(filepath.Dir(path), "other.db")
	changed, err := copy.IdentityStoreConfig()
	if err != nil || changed.ConfigDigest == descriptor.ConfigDigest {
		t.Fatal("different database reused a descriptor")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("pure validation/descriptor hashing touched storage")
	}
}

func TestSQLiteIdentityConsumer(t *testing.T) {
	cfg := sqliteIdentityTestConfig(t)
	m := &companion.SQLiteIdentityStore{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path, Timeout: cfg.Timeout}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if store, err := m.NewIdentityStore(t.Context()); err == nil || store != nil {
		t.Fatal("unprovisioned database accepted")
	}
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("consumer silently initialized an account database")
	}
	sqliteIdentityTestProvision(t, cfg)
	backend, err := m.NewIdentityStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	store := backend.(*identitysqlite.Store)
	t.Cleanup(func() { _ = store.Close() })
	request := requests.NewRequest()
	request.Upstream.Realm = "staff"
	request.User.Username, request.User.Password = "alice", lifecyclePassword
	if err := store.Request(operator.Authenticate, request); err != nil || request.User.Username != "alice" || request.User.Email != "alice@example.test" {
		t.Fatal("factory did not open the provisioned account", err)
	}
	if store.GetName() != "accounts" || store.GetRealm() != "staff" || store.GetKind() != "sqlite" || !store.Configured() {
		t.Fatal("factory changed backend identity or readiness")
	}
	metadata, _ := json.Marshal(store.GetConfig())
	if strings.Contains(string(metadata), cfg.Path) || strings.Contains(string(metadata), lifecyclePassword) {
		t.Fatal("backend diagnostics exposed private storage or credentials")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Request(operator.Authenticate, request); !errors.Is(err, identitysqlite.ErrUnavailable) {
		t.Fatal("closed consumer remained available", err)
	}
	link := filepath.Join(filepath.Dir(cfg.Path), "linked.db")
	if err := os.Symlink(cfg.Path, link); err != nil {
		t.Fatal(err)
	}
	m.Path = link
	if store, err := m.NewIdentityStore(t.Context()); err == nil || store != nil {
		t.Fatal("symlink bypassed the private database boundary")
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

const lifecyclePassword = "synthetic-local-test-password"
