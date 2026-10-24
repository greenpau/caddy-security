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
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	registrationsqlite "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
)

func sqliteRegistrationTestConfig(t *testing.T) *SQLiteRegistrationWorkflow {
	t.Helper()
	return &SQLiteRegistrationWorkflow{Name: "signup", Path: filepath.Join(registrationTestDirectory(t), "pending.db"), Timeout: "5s", IdentityStore: "accounts", Realm: "staff", EmailProvider: "notifications", PublicOrigin: "https://portal.example.test", BasePath: "/auth"}
}

func sqliteRegistrationTestLoad(t *testing.T, raw json.RawMessage) (any, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	loader := &App{RegistrationWorkflowConfigs: []json.RawMessage{raw}}
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

func TestSQLiteRegistrationParser(t *testing.T) {
	good := "signup {\npath \"/private registrations/pending.db\"\nidentity_store accounts\nrealm staff\nemail_provider notifications\npublic_origin https://portal.example.test\n}"
	cases := map[string]string{
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
			var module SQLiteRegistrationWorkflow
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
	var module SQLiteRegistrationWorkflow
	literal := strings.Replace(good, "/private registrations/pending.db", "/private/{env.REGISTRATIONS}/pending.db", 1)
	literal = strings.Replace(literal, "realm staff", "realm staff\ntimeout 1000ms\nbase_path /", 1)
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(literal)); err != nil || module.Path != "/private/{env.REGISTRATIONS}/pending.db" || module.BasePath != "/" || module.Timeout != "1s" {
		t.Fatal("literal path or normalized defaults changed", err)
	}
}

func TestSQLiteRegistrationDispatch(t *testing.T) {
	good := "user registration sqlite signup {\npath /private/pending.db\nidentity_store accounts\nrealm staff\nemail_provider notifications\npublic_origin https://portal.example.test\n}"
	for name, input := range map[string]string{"valid": good, "short": "user registration", "extra": strings.Replace(good, "sqlite signup", "sqlite signup extra", 1), "unknown": strings.Replace(good, "sqlite signup", "unknown signup", 1), "wrong_selector": strings.Replace(good, "user registration", "user account", 1)} {
		t.Run(name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(input)
			d.Next()
			app := &App{Config: &authcrunch.Config{}}
			err := parseCaddyfileUser(d, app)
			if name != "valid" {
				if err == nil || len(app.RegistrationWorkflowConfigs) > 0 {
					t.Fatal("invalid declaration published a workflow")
				}
				return
			}
			if err != nil || len(app.RegistrationWorkflowConfigs) != 1 {
				t.Fatal("workflow module dispatch failed", err)
			}
			var result struct {
				SQLiteRegistrationWorkflow
				Driver string `json:"driver"`
			}
			if err := json.Unmarshal(app.RegistrationWorkflowConfigs[0], &result); err != nil || result.Driver != "sqlite" || result.Name != "signup" {
				t.Fatal("module discriminator was lost", err)
			}
		})
	}
	// A legacy registry may itself be named sqlite. Header length disambiguates it.
	d := caddyfile.NewTestDispenser("user registration sqlite {\ndropbox :memory:\nemail provider notifications\nadmin email admin@example.test\nidentity store local\n}")
	d.Next()
	app := &App{Config: &authcrunch.Config{}}
	if err := parseCaddyfileUser(d, app); err != nil || len(app.RegistrationWorkflowConfigs) != 0 || app.Config.UserRegistration == nil || len(app.Config.UserRegistration.RawConfigs) != 1 {
		t.Fatal("legacy registry named sqlite no longer parses", err)
	}
}

func TestSQLiteRegistrationPortalSelection(t *testing.T) {
	for name, input := range map[string]string{"valid": "enable user registration signup second", "missing": "enable user registration", "empty": "enable user registration \"\"", "space": "enable user registration \" signup\"", "control": "enable user registration \"bad\tname\"", "prefix": "enable user registrations signup", "nested": "enable user registration signup {\n value hidden\n}"} {
		t.Run(name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(input)
			d.Next()
			args := d.RemainingArgs()
			portal := new(authn.PortalConfig)
			err := parseCaddyfileAuthPortalMisc(d, portal, "authentication portal", "enable", args)
			if name != "valid" {
				if err == nil || len(portal.UserRegistries) != 0 {
					t.Fatal("invalid portal enrollment selection accepted")
				}
				return
			}
			if err != nil || !slices.Equal(portal.UserRegistries, []string{"signup", "second"}) {
				t.Fatal("explicit workflow selection lost", err)
			}
		})
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

func TestSQLiteRegistrationNativeConfiguration(t *testing.T) {
	config := sqliteRegistrationTestConfig(t)
	config.Timeout = "1000ms"
	config.Path = filepath.Join(filepath.Dir(config.Path), "missing", "pending.db")
	raw := caddyconfig.JSONModuleObject(config, "driver", "sqlite", nil)
	entry, _, err := sqliteRegistrationTestLoad(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	module, ok := entry.(*SQLiteRegistrationWorkflow)
	if !ok || module.Timeout != "1000ms" || module.Path != config.Path {
		t.Fatal("native loading mutated literal fields")
	}
	for name, invalid := range map[string]string{"null": "null", "unknown_field": strings.Replace(string(raw), `"driver":`, `"approval":true,"driver":`, 1), "missing_email": strings.Replace(string(raw), `"email_provider":"notifications",`, "", 1), "origin": strings.Replace(string(raw), "https://portal.example.test", "http://portal.example.test", 1), "driver": strings.Replace(string(raw), `"driver":"sqlite"`, `"driver":"unknown"`, 1)} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sqliteRegistrationTestLoad(t, json.RawMessage(invalid)); err == nil {
				t.Fatal("invalid native declaration accepted")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(config.Path)); !os.IsNotExist(err) {
		t.Fatal("native loading touched storage")
	}
}

func TestSQLiteRegistrationAdaptationIsReadOnly(t *testing.T) {
	config := sqliteRegistrationTestConfig(t)
	config.Path = filepath.Join(filepath.Dir(config.Path), "missing", "{env.REGISTRATIONS}", "pending.db")
	input := fmt.Sprintf("{\nsecurity {\nuser registration sqlite signup {\npath %q\nidentity_store accounts\nrealm staff\nemail_provider notifications\npublic_origin https://portal.example.test\n}\nauthentication portal portal {\nenable identity store accounts\nenable user registration signup\ncrypto key sign-verify synthetic-registration-key\n}\n}\n}\n", config.Path)
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	app := &doc.Apps.Security
	if len(app.RegistrationWorkflowConfigs) != 1 || !slices.Equal(app.Config.AuthenticationPortals[0].UserRegistries, []string{"signup"}) {
		t.Fatal("adaptation lost workflow selection")
	}
	var module SQLiteRegistrationWorkflow
	if err := json.Unmarshal(app.RegistrationWorkflowConfigs[0], &module); err != nil || module.Path != config.Path || module.Timeout != "1s" {
		t.Fatal("adaptation changed literal backend configuration", err)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(config.Path))); !os.IsNotExist(err) {
		t.Fatal("adaptation created pending storage")
	}
}

func sqliteRegistrationTestDependencies(t *testing.T, module *SQLiteRegistrationWorkflow) (*identitysqlite.Store, *messagingsqlite.Outbox) {
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

func TestSQLiteRegistrationConsumerAndBorrowedOwnership(t *testing.T) {
	declaration := sqliteRegistrationTestConfig(t)
	store, outbox := sqliteRegistrationTestDependencies(t, declaration)
	entry, cancel, err := sqliteRegistrationTestLoad(t, caddyconfig.JSONModuleObject(declaration, "driver", "sqlite", nil))
	if err != nil {
		t.Fatal(err)
	}
	module := entry.(*SQLiteRegistrationWorkflow)
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
	for _, kind := range []string{"nil_store", "typed_nil_store", "nil_outbox", "typed_nil_outbox", "wrapped_store", "wrapped_outbox", "wrong_store", "wrong_outbox", "closed_outbox", "closed_store", "canceled", "missing_parent"} {
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
