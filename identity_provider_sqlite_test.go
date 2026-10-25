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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func sqliteTicketTestConfig(t *testing.T) *SQLiteTicketIdentityProvider {
	t.Helper()
	return &SQLiteTicketIdentityProvider{Name: "application", Realm: "application", Path: filepath.Join(registrationTestDirectory(t), "tickets.db"), Timeout: "5s", PublicOrigin: "https://portal.example.test", BasePath: "/auth", CookieName: "APP_TICKET_BINDING", IssuerURL: "https://issuer.example.test/login"}
}

func sqliteTicketTestLoad(t *testing.T, raw json.RawMessage) (any, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	loader := &App{IdentityProviderConfigs: []json.RawMessage{raw}}
	loaded, err := ctx.LoadModule(loader, "IdentityProviderConfigs")
	if err != nil {
		return nil, cancel, err
	}
	modules, ok := loaded.([]any)
	if !ok || len(modules) != 1 {
		t.Fatal("Caddy did not load exactly one provider module")
	}
	return modules[0], cancel, nil
}

func TestSQLiteTicketBackendDispatch(t *testing.T) {
	good := "identity provider sqlite application {\nrealm application\npath /private/tickets.db\npublic_origin https://portal.example.test\nissuer_url https://issuer.example.test/login\n}"
	for name, input := range map[string]string{"valid": good, "short": "identity provider sqlite", "extra": strings.Replace(good, "sqlite application {", "sqlite application extra {", 1), "selector": strings.Replace(good, "identity provider", "identity workflow", 1), "driver": strings.Replace(good, "provider sqlite", "provider unknown", 1)} {
		t.Run(name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(input)
			d.Next()
			app := new(App)
			err := parseCaddyfileIdentityBackend(d, app)
			if name != "valid" {
				if err == nil || len(app.IdentityProviderConfigs) != 0 {
					t.Fatal("invalid header published provider")
				}
				return
			}
			if err != nil || len(app.IdentityProviderConfigs) != 1 || len(app.IdentityStoreConfigs) != 0 {
				t.Fatal("provider dispatch selected wrong namespace", err)
			}
			var config struct {
				SQLiteTicketIdentityProvider
				Driver string `json:"driver"`
			}
			if err := json.Unmarshal(app.IdentityProviderConfigs[0], &config); err != nil || config.Driver != "sqlite" || config.Name != "application" {
				t.Fatal("provider module discriminator lost", err)
			}
		})
	}
}

func TestSQLiteTicketNativeConfiguration(t *testing.T) {
	config := sqliteTicketTestConfig(t)
	config.Timeout = "1000ms"
	config.Path = filepath.Join(filepath.Dir(config.Path), "missing", "tickets.db")
	raw := caddyconfig.JSONModuleObject(config, "driver", "sqlite", nil)
	loaded, _, err := sqliteTicketTestLoad(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	module, ok := loaded.(*SQLiteTicketIdentityProvider)
	if !ok || module.Timeout != "1000ms" || module.Path != config.Path || module.CookieName != config.CookieName {
		t.Fatal("native loading changed literals")
	}
	for name, input := range map[string]string{"null": "null", "driver": strings.Replace(string(raw), `"driver":"sqlite"`, `"driver":"unknown"`, 1), "unknown_field": strings.Replace(string(raw), `"driver":`, `"password":"private-sentinel","driver":`, 1), "attachment": strings.Replace(string(raw), `"driver":`, `"attachment":{"local_identity_store":":memory:"},"driver":`, 1), "origin": strings.Replace(string(raw), config.PublicOrigin, "https://portal.example.test:0", 1), "cookie": strings.Replace(string(raw), config.CookieName, "__Host-APP", 1), "missing_issuer": strings.Replace(string(raw), `"issuer_url":"https://issuer.example.test/login",`, "", 1)} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sqliteTicketTestLoad(t, json.RawMessage(input)); err == nil {
				t.Fatal("invalid native ticket configuration accepted")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(config.Path)); !os.IsNotExist(err) {
		t.Fatal("native loading touched storage")
	}
}

func TestSQLiteTicketAdaptationIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "{env.TICKETS}", "tickets.db")
	input := fmt.Sprintf("{\nsecurity {\nidentity provider sqlite application {\nrealm application\npath %q\npublic_origin https://portal.example.test\nissuer_url https://issuer.example.test/login\ncookie_name APP_TICKET_BINDING\n}\nauthentication portal portal {\nenable identity provider application\ncrypto key sign-verify synthetic-ticket-signing-key\n}\n}\n}\n", path)
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
	if len(app.IdentityProviderConfigs) != 1 || len(app.Config.IdentityProviders) != 0 || len(app.Config.ExternalIdentityProviders) != 0 || len(app.Config.AuthenticationPortals[0].IdentityProviders) != 1 || app.Config.AuthenticationPortals[0].IdentityProviders[0] != "application" {
		t.Fatal("adaptation mixed native factory declarations and runtime bindings")
	}
	var module SQLiteTicketIdentityProvider
	if err := json.Unmarshal(app.IdentityProviderConfigs[0], &module); err != nil || module.Path != path || module.CookieName != "APP_TICKET_BINDING" || module.Timeout != "1s" {
		t.Fatal("adaptation changed literal provider fields", err)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(path))); !os.IsNotExist(err) {
		t.Fatal("adaptation created storage")
	}
}
