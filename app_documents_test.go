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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func documentsTestApp(t *testing.T) *App {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("cannot make Documents fixture directory private")
	}
	cfg := lifecycleConfig()
	cfg.UserRegistration = nil
	cfg.AuthenticationPortals[0].API = &authn.APIConfig{DocumentsEnabled: true, ProfileEnabled: true, AdminEnabled: true}
	cfg.AuthenticationPortals[0].Documents = &documents.Config{
		Database:     filepath.Join(directory, "documents.db"),
		PublicOrigin: "https://portal.example.test", BasePath: "/tenant/auth", Realms: []string{"local"},
	}
	return &App{Config: cfg}
}

func provisionDocumentsTestApp(t *testing.T, app *App) error {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	t.Cleanup(func() {
		if err := app.Cleanup(); err != nil {
			t.Error("Documents app cleanup failed")
		}
	})
	return app.Provision(ctx)
}

func TestAppDocumentsSnapshots(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, persistent := range []bool{false, true} {
			t.Run(fmt.Sprintf("native=%t/persistent=%t", native, persistent), func(t *testing.T) {
				app := documentsTestApp(t)
				portal := app.Config.AuthenticationPortals[0]
				database := portal.Documents.Database
				t.Setenv("APP_DOCUMENTS_DATABASE", database)
				if native {
					portal.Documents.Database = "{env.APP_DOCUMENTS_DATABASE}"
					portal.Documents.Realms[0] = "secrets:oauth:realm"
				} else {
					portal.Documents = nil
					portal.API.DocumentsEnabled = false
					app.PortalDocumentsDirectives = map[string][]string{"portal": {
						"enable documents api", "documents api database {env.APP_DOCUMENTS_DATABASE}",
						"documents api public origin https://portal.example.test", "documents api base path /tenant/auth",
						"documents api realms secrets:oauth:realm",
					}}
				}
				app.SecretsManagerConfigs = []json.RawMessage{caddyconfig.JSONModuleObject(&oauthRuntimeSecrets{Values: map[string]string{"realm": "local"}}, "driver", "oauth_test", nil)}
				directory := filepath.Join(t.TempDir(), "state")
				accounts := filepath.Join(t.TempDir(), "accounts.json")
				if persistent {
					app.Config.State = &state.Config{Directory: directory}
					app.Config.IdentityStores[0].Params["path"] = accounts
				}
				before, err := json.Marshal(app)
				if err != nil {
					t.Fatal(err)
				}
				if err := provisionDocumentsTestApp(t, app); err != nil {
					t.Fatal("valid Documents configuration failed", err)
				}
				after, _ := json.Marshal(app)
				if string(before) != string(after) {
					t.Fatal("Documents provisioning changed declarative JSON")
				}
				if err := app.validatePortalMount("portal", "/tenant/auth"); err != nil {
					t.Fatal("normalized Documents mount missing", err)
				}
				if err := app.validatePortalMount("portal", "/other"); err == nil || !strings.Contains(err.Error(), "documents API") {
					t.Fatal("Documents mount mismatch was accepted")
				}
				if persistent {
					if app.server != nil || app.runtimeConfig == nil {
						t.Fatal("Documents bypassed deferred persistent construction")
					}
					for _, path := range []string{database, directory, accounts} {
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatal("persistent provisioning opened storage")
						}
					}
					private := app.runtimeConfig.AuthenticationPortals[0]
					if private.Documents.Database != database || private.Documents.Realms[0] != "local" || !private.API.DocumentsEnabled || !private.API.AdminEnabled || !private.API.ProfileEnabled {
						t.Fatal("private Documents snapshot retained unresolved values or lost API flags")
					}
				}
				if native {
					portal.Documents.Realms[0] = "mutated"
					portal.Documents.BasePath = "/mutated"
					portal.Documents.Database = "invalid"
				} else {
					app.PortalDocumentsDirectives["portal"][1] = "documents api database invalid"
				}
				portal.API.DocumentsEnabled = false
				if err := app.validatePortalMount("portal", "/tenant/auth"); err != nil {
					t.Fatal("mount snapshot retained caller aliases", err)
				}
				beforeStart, _ := json.Marshal(app)
				if err := app.Start(); err != nil || app.server == nil {
					t.Fatal("resolved Documents snapshot was not startable", err)
				}
				afterStart, _ := json.Marshal(app)
				if string(beforeStart) != string(afterStart) {
					t.Fatal("Documents start changed caller declarations")
				}
				if info, err := os.Stat(database); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
					t.Fatal("Documents runtime did not initialize its private database")
				}
			})
		}
	}
}

func TestAppDocumentsDisabledStorage(t *testing.T) {
	for _, api := range []bool{false, true} {
		t.Run(fmt.Sprintf("api=%t", api), func(t *testing.T) {
			app := documentsTestApp(t)
			portal := app.Config.AuthenticationPortals[0]
			path := filepath.Join(t.TempDir(), "missing", "documents.db")
			portal.Documents = &documents.Config{Database: path, BasePath: "unused", MaxFileBytes: -1}
			if api {
				portal.API.DocumentsEnabled = false
			} else {
				portal.API = nil
			}
			before, _ := json.Marshal(app)
			if err := provisionDocumentsTestApp(t, app); err != nil || app.server == nil {
				t.Fatal("disabled Documents validated or opened its storage", err)
			}
			if err := app.validatePortalMount("portal", "/unrelated"); err != nil {
				t.Fatal("disabled Documents constrained mount", err)
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("disabled Documents touched storage")
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("disabled Documents changed declarative API shape")
			}
		})
	}
}

func TestAppDocumentsRejectedCandidates(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*App)
		want string
	}{
		{"missing storage", func(a *App) { a.Config.AuthenticationPortals[0].Documents = nil }, "requires storage configuration"},
		{"unknown realm", func(a *App) { a.Config.AuthenticationPortals[0].Documents.Realms = []string{"missing"} }, "documents realm must identify exactly one supported identity store"},
		{"unselected store", func(a *App) {
			a.Config.IdentityStores = append(a.Config.IdentityStores, &ids.IdentityStoreConfig{Name: "other", Kind: "local", Params: map[string]any{"realm": "other", "path": ":memory:"}})
			a.Config.AuthenticationPortals[0].IdentityStores = []string{"other"}
		}, "documents realm must identify exactly one supported identity store"},
		{"reserved mount", func(a *App) { a.Config.AuthenticationPortals[0].Documents.BasePath = "/api" }, "invalid documents configuration"},
		{"missing parent", func(a *App) { a.Config.AuthenticationPortals[0].Documents.Database += "/missing/documents.db" }, "configure documents"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := documentsTestApp(t)
			database := app.Config.AuthenticationPortals[0].Documents.Database
			tc.edit(app)
			before, _ := json.Marshal(app)
			err := provisionDocumentsTestApp(t, app)
			if err == nil || !strings.Contains(err.Error(), tc.want) || app.server != nil {
				t.Fatalf("Documents candidate did not reach intended validation boundary: %v", err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("rejected Documents candidate changed declarations")
			}
			if _, err := os.Stat(database); !os.IsNotExist(err) {
				t.Fatal("rejected Documents candidate initialized a database")
			}
		})
	}
}

func TestAppDocumentsPrivateFailureSnapshot(t *testing.T) {
	const sentinel = "private-documents-origin-sentinel"
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			app := documentsTestApp(t)
			portal := app.Config.AuthenticationPortals[0]
			database := portal.Documents.Database
			if native {
				portal.Documents.PublicOrigin = "secrets:oauth:origin"
			} else {
				portal.API.DocumentsEnabled, portal.Documents = false, nil
				app.PortalDocumentsDirectives = map[string][]string{"portal": {
					"enable documents api", encodeOAuthDirective([]string{"documents", "api", "database", database}),
					"documents api public origin secrets:oauth:origin", "documents api realms local",
				}}
			}
			app.SecretsManagerConfigs = []json.RawMessage{caddyconfig.JSONModuleObject(&oauthRuntimeSecrets{Values: map[string]string{"origin": sentinel}}, "driver", "oauth_test", nil)}
			before, _ := json.Marshal(app)
			err := provisionDocumentsTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), sentinel) || app.server != nil {
				t.Fatal("invalid resolved Documents origin was accepted or exposed")
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("private Documents failure changed declarative snapshots")
			}
			if _, err := os.Stat(database); !os.IsNotExist(err) {
				t.Fatal("private Documents failure opened storage")
			}
		})
	}
}

func TestAppDocumentsCloseThenReopen(t *testing.T) {
	app := documentsTestApp(t)
	cfg := *app.Config.AuthenticationPortals[0].Documents
	if err := provisionDocumentsTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	store, err := documents.Open(context.Background(), cfg, "portal")
	if err != nil {
		t.Fatal("public Documents consumer could not observe live store")
	}
	id := store.PortalID()
	if err := store.Close(); err != nil {
		t.Fatal("public Documents consumer close failed")
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal("Documents app disposal failed")
	}
	reopened, err := documents.Open(t.Context(), cfg, "portal")
	if err != nil {
		t.Fatal("Documents store could not reopen after app disposal")
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error("reopened Documents store close failed")
		}
	})
	if reopened.PortalID() != id {
		t.Fatal("app disposal changed durable Documents identity")
	}
}
