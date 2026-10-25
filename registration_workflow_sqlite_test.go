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
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
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
