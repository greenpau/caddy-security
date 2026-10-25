// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package plugins_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	secretbackend "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"

	"github.com/greenpau/caddy-security/pkg/plugin"
	claims "github.com/greenpau/caddy-security/plugins/claims-enrichment-static"
	credentials "github.com/greenpau/caddy-security/plugins/credential-authenticators-sqlite"
	signing "github.com/greenpau/caddy-security/plugins/cryptographic-signing-rsapss"
	external "github.com/greenpau/caddy-security/plugins/external-authorization-httpjson"
	providers "github.com/greenpau/caddy-security/plugins/identity-providers-sqlite"
	stores "github.com/greenpau/caddy-security/plugins/identity-stores-sqlite"
	messaging "github.com/greenpau/caddy-security/plugins/messaging-sqlite"
	oauth "github.com/greenpau/caddy-security/plugins/oauth-login-storage-sqlite"
	registration "github.com/greenpau/caddy-security/plugins/registration-workflows-sqlite"
	secrets "github.com/greenpau/caddy-security/plugins/secrets-sqlite"
	refresh "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-sqlite"
)

func implements[T any](value any) bool { _, ok := value.(T); return ok }

// This binary imports the companions without the parent security app. Loading
// them must neither require that app nor link its registration as a side effect.
func TestCompanionModules(t *testing.T) {
	if _, err := caddy.GetModule("security"); err == nil {
		t.Fatal("companion modules unexpectedly imported the security app")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	secretConfig := &secretbackend.Config{Name: "vault", Path: filepath.Join(dir, "secrets.db"), Record: "login"}
	client, err := secretbackend.New(t.Context(), secretConfig)
	if err != nil {
		t.Fatal("cannot provision synthetic secret storage")
	}
	putErr := client.Put(t.Context(), map[string]any{"password": "synthetic-only"})
	closeErr := client.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal("cannot publish synthetic secret record")
	}
	for _, tc := range []struct {
		module   caddy.Module
		contract func(any) bool
	}{
		{&claims.StaticClaimsEnrichment{ClaimsJSON: `{"department":"engineering","quota":9007199254740993}`}, implements[plugin.ClaimsEnrichmentBackendModule]},
		{&credentials.SQLiteCredentialAuthenticator{Name: "api", Realm: "keys", Path: filepath.Join(dir, "keys.db")}, implements[plugin.CredentialAuthenticatorBackendModule]},
		{&signing.RSAPSSAccessSigner{Name: "access", KeyFile: filepath.Join(dir, "key.pem"), KeyID: "primary", Issuer: "https://auth.example.test", Audience: "api"}, implements[plugin.AccessSignerBackendModule]},
		{&external.HTTPJSONExternalAuthorization{Endpoint: "https://policy.example.test/decide"}, implements[plugin.ExternalAuthorizationBackendModule]},
		{&providers.SQLiteTicketIdentityProvider{Name: "tickets", Realm: "tickets", Path: filepath.Join(dir, "tickets.db"), PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/login"}, implements[plugin.IdentityProviderBackendModule]},
		{&stores.SQLiteIdentityStore{Name: "accounts", Realm: "local", Path: filepath.Join(dir, "accounts.db")}, implements[plugin.IdentityStoreBackendModule]},
		{&messaging.SQLiteMessagingProvider{Name: "mail", Path: filepath.Join(dir, "outbox.db")}, implements[plugin.MessagingProviderBackendModule]},
		{&oauth.SQLiteOAuthLoginStore{Name: "pending", Path: filepath.Join(dir, "oauth.db")}, implements[plugin.OAuthLoginStoreBackendModule]},
		{&registration.SQLiteRegistrationWorkflow{Name: "signup", Path: filepath.Join(dir, "signup.db"), IdentityStore: "accounts", Realm: "local", EmailProvider: "mail", PublicOrigin: "https://auth.example.test"}, implements[plugin.RegistrationWorkflowBackendModule]},
		{&secrets.SQLiteSecretsManager{Name: secretConfig.Name, Path: secretConfig.Path, Record: secretConfig.Record}, implements[plugin.SecretsManager]},
		{&refresh.SQLiteRefreshStore{Name: "sessions", Path: filepath.Join(dir, "sessions.db")}, implements[plugin.RefreshStoreBackendModule]},
	} {
		t.Run(string(tc.module.CaddyModule().ID), func(t *testing.T) {
			before, err := json.Marshal(tc.module)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			id := string(tc.module.CaddyModule().ID)
			loaded, err := ctx.LoadModuleByID(id, before)
			if err != nil {
				t.Fatalf("cannot load companion %s: %v", id, err)
			}
			if !tc.contract(loaded) {
				t.Fatal("loaded companion lost its typed app contract")
			}
			after, err := json.Marshal(loaded)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("module loading changed declarative configuration")
			}
			if manager, ok := loaded.(plugin.SecretsManager); ok {
				value, err := manager.GetSecretByKey(t.Context(), "password")
				if err != nil || value != "synthetic-only" {
					t.Fatal("standalone companion could not resolve its secret")
				}
			}
			var invalid map[string]json.RawMessage
			if err := json.Unmarshal(before, &invalid); err != nil {
				t.Fatal(err)
			}
			invalid["unknown_setting"] = json.RawMessage(`true`)
			raw, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ctx.LoadModuleByID(id, raw); err == nil {
				t.Fatal("module accepted an unknown native setting")
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "secrets.db" {
			t.Fatalf("module loading unexpectedly acquired runtime storage: %s", entry.Name())
		}
	}
}
