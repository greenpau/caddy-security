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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/state"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
)

func identityAttachmentTestApp(t *testing.T) (*App, *SQLiteTicketIdentityProvider) {
	t.Helper()
	module := sqliteTicketTestConfig(t)
	module.Attachment = &attachment.Config{LocalIdentityStore: "local"}
	config := identityProviderTestConfig()
	config.IdentityStores = lifecycleConfig().IdentityStores
	// Attachment ownership is independent of enabled password-login realms.
	if len(config.AuthenticationPortals[0].IdentityStores) != 0 {
		t.Fatal("fixture enabled attachment as local login")
	}
	return &App{Config: config, IdentityProviderConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)}}, module
}

func TestAppIdentityProviderAttachmentPreflight(t *testing.T) {
	for _, mode := range []string{"missing", "wrong_kind", "duplicate", "external", "realm_not_name", "literal_reference"} {
		t.Run(mode, func(t *testing.T) {
			app, module := identityAttachmentTestApp(t)
			switch mode {
			case "missing":
				app.Config.IdentityStores = nil
			case "wrong_kind":
				app.Config.IdentityStores[0].Kind = "ldap"
			case "duplicate":
				app.Config.IdentityStores = append(app.Config.IdentityStores, app.Config.IdentityStores[0])
			case "external":
				app.Config.IdentityStores = nil
				app.Config.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "local", Kind: "sqlite", Realm: "local"}}
			case "realm_not_name":
				app.Config.IdentityStores[0].Name = "different"
			case "literal_reference":
				module.Attachment.LocalIdentityStore = "{env.ATTACHMENT_STORE}"
				t.Setenv("ATTACHMENT_STORE", "local")
				app.IdentityProviderConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			}
			before := mustAttachmentJSON(t, app)
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			err := app.prepareIdentityProviders(ctx, app.Config)
			if err == nil || !strings.Contains(err.Error(), "requires one configured local identity store") {
				t.Fatal("invalid target did not reach pure exact-name preflight", err)
			}
			if len(app.identityProviders) != 0 || len(app.Config.ExternalIdentityProviders) != 0 || string(before) != string(mustAttachmentJSON(t, app)) {
				t.Fatal("rejected attachment mutated declarations or published binding")
			}
			if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
				t.Fatal("attachment preflight opened ticket storage")
			}
		})
	}
}

func TestAppIdentityProviderAttachmentSnapshotsAndStart(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory_root"
		if persistent {
			name = "persistent_root"
		}
		t.Run(name, func(t *testing.T) {
			app, module := identityAttachmentTestApp(t)
			accountsPath := filepath.Join(filepath.Dir(module.Path), "accounts.json")
			app.Config.IdentityStores[0].Params["path"] = accountsPath
			if persistent {
				app.Config.State = &state.Config{Directory: filepath.Join(filepath.Dir(module.Path), "state")}
			}
			before := mustAttachmentJSON(t, app)
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			if string(before) != string(mustAttachmentJSON(t, app)) {
				t.Fatal("provisioning rewrote attachment declarations")
			}
			bindings := app.identityProviderAttachmentStores()
			if len(bindings) != 1 || bindings[module.Name] != "local" {
				t.Fatal("bundled ticket opt-in was not prepared")
			}
			bindings[module.Name] = "changed"
			if app.identityProviderAttachmentStores()[module.Name] != "local" {
				t.Fatal("root options share mutable prepared map")
			}
			if persistent {
				if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
					t.Fatal("persistent provision opened tickets")
				}
				if _, err := os.Stat(accountsPath); !os.IsNotExist(err) {
					t.Fatal("persistent provision opened account store")
				}
				// Start must consume the detached prepared configuration, not edited raw JSON.
				raw := strings.Replace(string(app.IdentityProviderConfigs[0]), `"local_identity_store":"local"`, `"local_identity_store":"changed"`, 1)
				app.IdentityProviderConfigs[0] = json.RawMessage(raw)
				app.Config.IdentityStores[0].Name = "changed"
				if err := app.Start(); err != nil {
					t.Fatal("deferred attachment snapshot failed", err)
				}
			}
			portal, err := app.server.GetPortalByName("portal")
			if err != nil || len(portal.GetIdentityStoreNames()) != 0 {
				t.Fatal("attachment unexpectedly enabled local login", err)
			}
			// A separately opened trusted issuer shares pending tickets, never attachment authority.
			issuerRuntime, err := module.NewIdentityProvider(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			issuer := issuerRuntime.(*tickets.Provider)
			defer issuer.Close()
			request, cookie := identityProviderTestBegin(t, app, "portal", issuer)
			callback := identityProviderTestIssue(t, issuer, request)
			response, err := identityProviderTestRequest(app, "portal", callback, cookie)
			if err != nil {
				t.Fatal("attached ticket handler failed", err)
			}
			claims := identityProviderTestClaims(t, response)
			if err := app.Cleanup(); err != nil {
				t.Fatal("attached runtime cleanup failed", err)
			}
			// Reopen only after root disposal: the UUID must have been committed to the
			// selected root store, not an unobservable provider-private fallback.
			database, err := identity.NewDatabase(accountsPath)
			if err != nil {
				t.Fatal("reopen attachment store failed")
			}
			account, err := database.ResolveExternalAccount(t.Context(), identity.ExternalAccount{Provider: module.Name, Kind: "sqlite-ticket", Issuer: module.IssuerURL, Subject: "alice"}, false)
			if err != nil || account.Evidence.UserID != claims["id"] {
				t.Fatal("signed identity was not persisted in selected attachment")
			}
		})
	}
}

func TestAppIdentityProviderAttachmentThirdPartyDefaults(t *testing.T) {
	for _, prebound := range []bool{false, true} {
		label := "unbound_rejected"
		failure := ""
		if prebound {
			label, failure = "caller_bound_preserved", "prebound_attachment"
		}
		t.Run(label, func(t *testing.T) {
			module := sqliteTicketTestConfig(t)
			module.Attachment = &attachment.Config{LocalIdentityStore: "caller-owned"}
			raw, probe := identityProviderTestBinding(t, module, failure)
			app := &App{Config: identityProviderTestConfig(), IdentityProviderConfigs: []json.RawMessage{raw}}
			_, err := credentialTestApp(t, app)
			if prebound {
				if err != nil {
					t.Fatal("caller-prebound provider rejected", err)
				}
				backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
				store, err := backend.IdentityAttachment().Store()
				if err != nil || store != backend.callerStore {
					t.Fatal("root changed third-party attachment")
				}
				if err := app.Cleanup(); err != nil {
					t.Fatal(err)
				}
				if _, err := store.ResolveExternalAccount(t.Context(), identity.ExternalAccount{Provider: module.Name, Kind: "sqlite-ticket", Issuer: module.IssuerURL, Subject: "after-root-close"}, true); err != nil {
					t.Fatal("root disposed caller-owned store")
				}
			} else if err == nil {
				t.Fatal("custom unbound explicit attachment was automatically opted in")
			}
			if app.identityProviderAttachmentStores() != nil || probe.constructed.Load() != 1 || probe.closed.Load() != 1 {
				t.Fatal("third-party binding or cleanup contract changed")
			}
		})
	}
}
