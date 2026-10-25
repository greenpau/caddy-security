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
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	registrationsqlite "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/registration-workflows-sqlite"
)

func sqliteRegistrationTestConfig(t *testing.T) *companion.SQLiteRegistrationWorkflow {
	t.Helper()
	return &companion.SQLiteRegistrationWorkflow{Name: "signup", Path: filepath.Join(privateDirectory(t), "pending.db"), Timeout: "5s", IdentityStore: "accounts", Realm: "staff", EmailProvider: "notifications", PublicOrigin: "https://portal.example.test", BasePath: "/auth"}
}

func sqliteRegistrationTestLoad(t *testing.T, raw json.RawMessage) (any, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	loader := &moduleLoader{RegistrationWorkflowConfigs: []json.RawMessage{raw}}
	loaded, err := ctx.LoadModule(loader, "RegistrationWorkflowConfigs")
	if err != nil {
		return nil, cancel, err
	}
	modules, ok := loaded.([]any)
	if !ok || len(modules) != 1 {
		t.Fatal("Caddy did not load exactly one registration module")
	}
	return modules[0], cancel, nil
}

func sqliteRegistrationTestDependencies(t *testing.T, module *companion.SQLiteRegistrationWorkflow) (*identitysqlite.Store, *messagingsqlite.Outbox) {
	t.Helper()
	dir := filepath.Dir(module.Path)
	store, err := identitysqlite.New(t.Context(), &identitysqlite.Config{Name: module.IdentityStore, Realm: module.Realm, Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	outbox, err := messagingsqlite.New(t.Context(), &messagingsqlite.Config{Name: module.EmailProvider, Path: filepath.Join(dir, "outbox.db"), Timeout: "5s"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return store, outbox
}

func sqliteRegistrationTestEntry(id string) map[string]string {
	data := appMessagingTestNotification()
	data["registration_id"] = id
	data["realm_name"] = "staff"
	data["password"] = lifecyclePassword
	data["return_url"] = "/welcome"
	return data
}

func TestSQLiteRegistrationParser(t *testing.T) {
	good := "signup {\npath \"/private registrations/pending.db\"\nidentity_store accounts\nrealm staff\nemail_provider notifications\npublic_origin https://portal.example.test\n}"
	cases := map[string]string{
		"empty":          "",
		"valid":          good,
		"missing_block":  "signup",
		"extra_header":   strings.Replace(good, "signup {", "signup other {", 1),
		"missing_path":   strings.Replace(good, "path \"/private registrations/pending.db\"\n", "", 1),
		"relative_path":  strings.Replace(good, "/private registrations/pending.db", "pending.db", 1),
		"duplicate":      strings.Replace(good, "realm staff", "realm staff\nrealm staff", 1),
		"extra_value":    strings.Replace(good, "realm staff", "realm staff other", 1),
		"nested":         strings.Replace(good, "realm staff", "realm staff {\n nested value\n}", 1),
		"unknown":        strings.Replace(good, "realm staff", "realm staff\napproval required", 1),
		"missing_origin": strings.Replace(good, "public_origin https://portal.example.test\n", "", 1),
		"origin_http":    strings.Replace(good, "https://portal.example.test", "http://portal.example.test", 1),
		"origin_path":    strings.Replace(good, "https://portal.example.test", "https://portal.example.test/auth", 1),
		"base_reserved":  strings.Replace(good, "realm staff", "realm staff\nbase_path /api", 1),
		"timeout":        strings.Replace(good, "realm staff", "realm staff\ntimeout 31s", 1),
		"unterminated":   strings.TrimSuffix(good, "}"),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var module companion.SQLiteRegistrationWorkflow
			err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if name != "valid" {
				if err == nil {
					t.Fatal("invalid workflow syntax accepted")
				}
				return
			}
			if err != nil || module.Timeout != "1s" || module.BasePath != "/auth" || module.IdentityStore != "accounts" {
				t.Fatal("parser lost defaults or dependency binding", err)
			}
		})
	}
	var module companion.SQLiteRegistrationWorkflow
	literal := strings.Replace(good, "/private registrations/pending.db", "/private/{env.REGISTRATIONS}/pending.db", 1)
	literal = strings.Replace(literal, "realm staff", "realm staff\ntimeout 1000ms\nbase_path /", 1)
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(literal)); err != nil || module.Path != "/private/{env.REGISTRATIONS}/pending.db" || module.BasePath != "/" || module.Timeout != "1s" {
		t.Fatal("literal path or normalized defaults changed", err)
	}
}

func TestSQLiteRegistrationValidationIsReadOnly(t *testing.T) {
	module := sqliteRegistrationTestConfig(t)
	module.Path = filepath.Join(filepath.Dir(module.Path), "missing", "pending.db")
	module.Timeout = ""
	module.BasePath = ""
	before, _ := json.Marshal(module)
	var digest string
	for _, timeout := range []string{"", "1s", "1000ms", "1000000us"} {
		copy := *module
		copy.Timeout = timeout
		descriptor, err := copy.RegistrationWorkflowConfig()
		if err != nil || descriptor.Validate() != nil || descriptor.Name != "signup" || descriptor.IdentityStore != "accounts" || descriptor.EmailProvider != "notifications" || descriptor.Realm != "staff" {
			t.Fatal("normalized descriptor is invalid", err)
		}
		if digest != "" && descriptor.ConfigDigest != digest {
			t.Fatal("equivalent timeout spellings changed persistent configuration digest")
		}
		digest = descriptor.ConfigDigest
		encoded, _ := json.Marshal(descriptor)
		if strings.Contains(string(encoded), module.Path) || strings.Contains(string(encoded), module.PublicOrigin) {
			t.Fatal("descriptor disclosed private backend configuration")
		}
	}
	after, _ := json.Marshal(module)
	if string(before) != string(after) {
		t.Fatal("validation mutated module configuration")
	}
	if _, err := os.Stat(filepath.Dir(module.Path)); !os.IsNotExist(err) {
		t.Fatal("validation created storage")
	}
	copy := *module
	copy.PublicOrigin = "https://other.example.test"
	descriptor, err := copy.RegistrationWorkflowConfig()
	if err != nil || descriptor.ConfigDigest == digest {
		t.Fatal("public origin was omitted from persistent binding")
	}
}

func TestSQLiteRegistrationConsumerAndBorrowedOwnership(t *testing.T) {
	declaration := sqliteRegistrationTestConfig(t)
	store, outbox := sqliteRegistrationTestDependencies(t, declaration)
	entry, cancel, err := sqliteRegistrationTestLoad(t, caddyconfig.JSONModuleObject(declaration, "driver", "sqlite", nil))
	if err != nil {
		t.Fatal(err)
	}
	module := entry.(*companion.SQLiteRegistrationWorkflow)
	setup, cancelSetup := context.WithCancel(t.Context())
	provider, err := module.NewRegistrationWorkflow(setup, store, outbox)
	cancelSetup()
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	workflow := provider.(*registrationsqlite.Workflow)
	t.Cleanup(func() { _ = workflow.Close() })
	info, err := os.Stat(module.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("pending storage is not private", err)
	}
	id := strings.Repeat("a", 64)
	data := sqliteRegistrationTestEntry(id)
	if err := workflow.AddRegistrationEntry(id, data); err != nil {
		t.Fatal(err)
	}
	if err := workflow.Notify(data); err != nil {
		t.Fatal("module cancellation retired the runtime", err)
	}
	message, err := outbox.Claim(t.Context())
	if err != nil || !strings.Contains(message.Body, module.PublicOrigin+"/auth/register") {
		t.Fatal("confirmation did not use configured origin and mount", err)
	}
	if err := outbox.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
		t.Fatal(err)
	}
	if err := workflow.Close(); err != nil {
		t.Fatal(err)
	}
	if err := outbox.CheckReady(t.Context()); err != nil || !store.Configured() {
		t.Fatal("workflow disposed borrowed dependencies", err)
	}
	restored, err := module.NewRegistrationWorkflow(t.Context(), store, outbox)
	if err != nil {
		t.Fatal(err)
	}
	current := restored.(*registrationsqlite.Workflow)
	t.Cleanup(func() { _ = current.Close() })
	metadata, err := current.GetRegistrationEntry(id)
	if err != nil || metadata["username"] != "alice" || metadata["password"] != "" || metadata["registration_code"] != "" {
		t.Fatal("reopened workflow lost safe pending metadata", err)
	}
	if err := current.ConfirmRegistration(t.Context(), id, data["registration_code"]); err != nil {
		t.Fatal(err)
	}
	if err := current.ConfirmRegistration(t.Context(), id, data["registration_code"]); !errors.Is(err, registrationsqlite.ErrDenied) {
		t.Fatal("confirmation replay accepted", err)
	}
	if _, err := store.FetchUserData("alice", "alice@example.test"); err != nil {
		t.Fatal("confirmation did not commit the account", err)
	}
}

func TestSQLiteRegistrationFactoryDependencyFailures(t *testing.T) {
	for _, kind := range []string{"nil_store", "typed_nil_store", "nil_outbox", "typed_nil_outbox", "wrapped_store", "wrapped_outbox", "wrong_store", "wrong_realm", "wrong_outbox", "closed_outbox", "closed_store", "canceled", "missing_parent"} {
		t.Run(kind, func(t *testing.T) {
			module := sqliteRegistrationTestConfig(t)
			store, outbox := sqliteRegistrationTestDependencies(t, module)
			var accounts ids.IdentityStore = store
			var mail messaging.Provider = outbox
			ctx := t.Context()
			switch kind {
			case "nil_store":
				accounts = nil
			case "typed_nil_store":
				accounts = (*identitysqlite.Store)(nil)
			case "nil_outbox":
				mail = nil
			case "typed_nil_outbox":
				mail = (*messagingsqlite.Outbox)(nil)
			case "wrapped_store":
				accounts = &struct{ *identitysqlite.Store }{store}
			case "wrapped_outbox":
				mail = &struct{ *messagingsqlite.Outbox }{outbox}
			case "wrong_store":
				module.IdentityStore = "other"
			case "wrong_realm":
				module.Realm = "other"
			case "wrong_outbox":
				module.EmailProvider = "other"
			case "closed_outbox":
				_ = outbox.Close()
			case "closed_store":
				_ = store.Close()
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing_parent":
				module.Path = filepath.Join(filepath.Dir(module.Path), "missing", "pending.db")
			}
			provider, err := module.NewRegistrationWorkflow(ctx, accounts, mail)
			if provider != nil || !errors.Is(err, registrationsqlite.ErrUnavailable) || strings.Contains(err.Error(), module.Path) {
				t.Fatal("invalid dependency returned a handle or exposed storage details", err)
			}
			if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
				t.Fatal("rejected workflow created pending storage")
			}
		})
	}
}

type moduleLoader struct {
	RegistrationWorkflowConfigs []json.RawMessage `caddy:"namespace=security.registration_workflows inline_key=driver"`
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

func appMessagingTestNotification() map[string]string {
	return map[string]string{
		"template": "registration_confirmation", "session_id": "session-id", "request_id": "request-id", "timestamp": "now",
		"registration_id": "registration-id", "registration_code": "123456", "username": "alice", "email": "alice@example.test",
		"registration_url": "https://portal.example.test/auth/register", "realm_name": "local", "src_ip": "192.0.2.10", "src_conn_ip": "192.0.2.11",
	}
}

const lifecyclePassword = "synthetic-local-test-password"

func TestRegistrationInvalidDeclarationBeforeConstruction(t *testing.T) {
	module := sqliteRegistrationTestConfig(t)
	module.IdentityStore = ""
	if err := module.Validate(); err == nil {
		t.Fatal("invalid native declaration accepted")
	}
	if value, err := module.RegistrationWorkflowConfig(); value != nil || err == nil {
		t.Fatal("invalid declaration published metadata", err)
	}
	if value, err := module.NewRegistrationWorkflow(t.Context(), nil, nil); value != nil || err == nil {
		t.Fatal("invalid declaration published runtime", err)
	}
	if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
		t.Fatal("invalid declaration touched storage")
	}
}

func TestRegistrationNilDeclaration(t *testing.T) {
	var module *companion.SQLiteRegistrationWorkflow
	if config, err := module.BackendConfig(); err == nil || config != nil {
		t.Fatal("nil declaration published backend configuration", err)
	}
	if err := module.Validate(); err == nil {
		t.Fatal("nil declaration passed validation")
	}
	if config, err := module.RegistrationWorkflowConfig(); err == nil || config != nil {
		t.Fatal("nil declaration published workflow metadata", err)
	}
	if provider, err := module.NewRegistrationWorkflow(t.Context(), nil, nil); err == nil || provider != nil {
		t.Fatal("nil declaration published a workflow", err)
	}
}
