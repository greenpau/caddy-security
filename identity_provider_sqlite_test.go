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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
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

func TestSQLiteTicketParser(t *testing.T) {
	good := "application {\nrealm application\npath \"/private tickets/tickets.db\"\npublic_origin https://portal.example.test\nissuer_url https://issuer.example.test/login\n}"
	for name, input := range map[string]string{
		"valid": good, "missing_block": "application", "extra_header": strings.Replace(good, "application {", "application other {", 1),
		"missing_path": strings.Replace(good, "path \"/private tickets/tickets.db\"\n", "", 1), "relative_path": strings.Replace(good, "/private tickets/tickets.db", "tickets.db", 1),
		"duplicate": strings.Replace(good, "realm application", "realm application\nrealm application", 1), "extra_value": strings.Replace(good, "realm application", "realm application other", 1),
		"nested": strings.Replace(good, "realm application", "realm application {\nunknown value\n}", 1), "unknown": strings.Replace(good, "realm application", "realm application\napproval required", 1),
		"attachment":  strings.Replace(good, "realm application", "realm application\nattach to local identity store accounts", 1),
		"origin_http": strings.Replace(good, "https://portal.example.test", "http://portal.example.test", 1), "origin_path": strings.Replace(good, "https://portal.example.test", "https://portal.example.test/auth", 1),
		"origin_empty_port": strings.Replace(good, "https://portal.example.test", "https://portal.example.test:", 1), "issuer_bad_port": strings.Replace(good, "https://issuer.example.test/login", "https://issuer.example.test:65536/login", 1),
		"issuer_missing_path": strings.Replace(good, "https://issuer.example.test/login", "https://issuer.example.test", 1), "issuer_query": strings.Replace(good, "https://issuer.example.test/login", "https://issuer.example.test/login?query=value", 1),
		"callback_issuer": strings.Replace(good, "https://issuer.example.test/login", "https://portal.example.test/auth/provider/application", 1),
		"base_reserved":   strings.Replace(good, "realm application", "realm application\nbase_path /connected-accounts", 1), "host_cookie": strings.Replace(good, "realm application", "realm application\ncookie_name __Host-APP", 1),
		"timeout": strings.Replace(good, "realm application", "realm application\ntimeout 31s", 1), "unterminated": strings.TrimSuffix(good, "}"),
	} {
		t.Run(name, func(t *testing.T) {
			var module SQLiteTicketIdentityProvider
			err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			if name != "valid" {
				if err == nil {
					t.Fatal("invalid ticket provider syntax accepted")
				}
				return
			}
			if err != nil || module.BasePath != "/auth" || module.Timeout != "1s" || module.CookieName != "AUTHP_PROVIDER_SESSION_ID" {
				t.Fatal("parser lost defaults", err)
			}
		})
	}
	literal := strings.Replace(good, "/private tickets/tickets.db", "/private/{env.TICKETS}/tickets.db", 1)
	literal = strings.Replace(literal, "realm application", "realm application\nbase_path /\ntimeout 1000ms\ncookie_name __Secure-APP", 1)
	var module SQLiteTicketIdentityProvider
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(literal)); err != nil || module.Path != "/private/{env.TICKETS}/tickets.db" || module.Timeout != "1s" || module.BasePath != "/" || module.CookieName != "__Secure-APP" {
		t.Fatal("literal path or explicit protocol defaults changed", err)
	}
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

func TestSQLiteTicketDescriptorIsReadOnly(t *testing.T) {
	module := sqliteTicketTestConfig(t)
	module.Timeout = ""
	module.BasePath = ""
	module.CookieName = ""
	module.Path = filepath.Join(filepath.Dir(module.Path), "missing", "tickets.db")
	before, _ := json.Marshal(module)
	descriptor, err := module.IdentityProviderConfig()
	if err != nil || descriptor.Validate() != nil {
		t.Fatal(err)
	}
	cfg := &tickets.Config{Name: module.Name, Realm: module.Realm, Path: module.Path, Timeout: "1s", PublicOrigin: module.PublicOrigin, BasePath: "/auth", CookieName: "AUTHP_PROVIDER_SESSION_ID", IssuerURL: module.IssuerURL}
	encoded, _ := json.Marshal(cfg)
	digest := sha256.Sum256(encoded)
	if descriptor.Name != module.Name || descriptor.Realm != module.Realm || descriptor.Kind != "sqlite-ticket" || descriptor.Driver != "ticket" || descriptor.ConfigDigest != hex.EncodeToString(digest[:]) {
		t.Fatal("descriptor failed to bind normalized configuration")
	}
	for _, timeout := range []string{"1s", "1000ms", "1000000us"} {
		copy := *module
		copy.Timeout = timeout
		copy.BasePath = "/auth"
		copy.CookieName = "AUTHP_PROVIDER_SESSION_ID"
		got, err := copy.IdentityProviderConfig()
		if err != nil || *got != *descriptor {
			t.Fatal("equivalent defaults changed persistent binding", err)
		}
	}
	for name, change := range map[string]func(*SQLiteTicketIdentityProvider){"origin": func(m *SQLiteTicketIdentityProvider) { m.PublicOrigin = "https://other.example.test" }, "issuer": func(m *SQLiteTicketIdentityProvider) { m.IssuerURL = "https://other.example.test/login" }, "mount": func(m *SQLiteTicketIdentityProvider) { m.BasePath = "/tenant/auth" }, "cookie": func(m *SQLiteTicketIdentityProvider) { m.CookieName = "OTHER_BINDING" }, "path": func(m *SQLiteTicketIdentityProvider) { m.Path = filepath.Join(filepath.Dir(m.Path), "other.db") }} {
		t.Run(name, func(t *testing.T) {
			copy := *module
			change(&copy)
			got, err := copy.IdentityProviderConfig()
			if err != nil || got.ConfigDigest == descriptor.ConfigDigest {
				t.Fatal("trust/storage change kept prior root binding", err)
			}
		})
	}
	encoded, _ = json.Marshal(descriptor)
	if strings.Contains(string(encoded), module.Path) || strings.Contains(string(encoded), module.IssuerURL) {
		t.Fatal("descriptor disclosed backend details")
	}
	after, _ := json.Marshal(module)
	if string(before) != string(after) {
		t.Fatal("validation mutated native declaration")
	}
	if _, err := os.Stat(filepath.Dir(module.Path)); !os.IsNotExist(err) {
		t.Fatal("validation created storage")
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
	for name, input := range map[string]string{"null": "null", "driver": strings.Replace(string(raw), `"driver":"sqlite"`, `"driver":"unknown"`, 1), "unknown_field": strings.Replace(string(raw), `"driver":`, `"password":"private-sentinel","driver":`, 1), "attachment": strings.Replace(string(raw), `"driver":`, `"attachment":{"local_identity_store":"accounts"},"driver":`, 1), "origin": strings.Replace(string(raw), config.PublicOrigin, "https://portal.example.test:0", 1), "cookie": strings.Replace(string(raw), config.CookieName, "__Host-APP", 1), "missing_issuer": strings.Replace(string(raw), `"issuer_url":"https://issuer.example.test/login",`, "", 1)} {
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

func sqliteTicketBegin(t *testing.T, provider *tickets.Provider) (string, *http.Cookie) {
	t.Helper()
	result, err := provider.Login(t.Context(), httptest.NewRequest(http.MethodGet, provider.CallbackURL(), nil))
	if err != nil || result == nil || result.Cookie == nil || result.Identity != nil {
		t.Fatal("provider begin failed", err)
	}
	target, err := url.Parse(result.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if target.Query().Get("callback") != provider.CallbackURL() || target.Query().Get("request") == "" {
		t.Fatal("issuer redirect lost pinned request binding")
	}
	return target.Query().Get("request"), result.Cookie
}

func sqliteTicketRedeem(t *testing.T, provider *tickets.Provider, request, ticket string, cookie *http.Cookie) (*idp.HTTPLoginResult, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, provider.CallbackURL()+"?"+url.Values{"state": {request}, "ticket": {ticket}}.Encode(), nil)
	r.AddCookie(cookie)
	return provider.Login(t.Context(), r)
}

func TestSQLiteTicketConsumerPreservesCapabilitiesAndPendingState(t *testing.T) {
	declaration := sqliteTicketTestConfig(t)
	entry, cancel, err := sqliteTicketTestLoad(t, caddyconfig.JSONModuleObject(declaration, "driver", "sqlite", nil))
	if err != nil {
		t.Fatal(err)
	}
	module := entry.(*SQLiteTicketIdentityProvider)
	setup, cancelSetup := context.WithCancel(t.Context())
	runtime, err := module.NewIdentityProvider(setup)
	cancelSetup()
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := runtime.(*tickets.Provider)
	if !ok {
		t.Fatal("factory narrowed the dynamic provider")
	}
	t.Cleanup(func() { _ = provider.Close() })
	consumer, ok := runtime.(attachment.Consumer)
	if !ok || consumer.IdentityAttachment() != provider.IdentityAttachment() || consumer.IdentityAttachment().StoreName() != "" {
		t.Fatal("factory lost the provider-owned implicit attachment")
	}
	if _, ok := runtime.(idp.HTTPLoginProvider); !ok || !runtime.Configured() {
		t.Fatal("factory/context cleanup lost HTTP login readiness")
	}
	info, err := os.Stat(module.Path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("ticket storage is not private", err)
	}
	cfg, err := module.config()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tickets.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	identity := &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}
	var firstID string
	for range 2 {
		request, cookie := sqliteTicketBegin(t, provider)
		ticket, err := issuer.Issue(t.Context(), request, identity)
		if err != nil {
			t.Fatal(err)
		}
		result, err := sqliteTicketRedeem(t, provider, request, ticket, cookie)
		if err != nil || result == nil || result.Identity == nil || result.Identity.Subject != "alice" || result.ExternalIdentity.Issuer != module.IssuerURL || result.ExternalIdentity.Evidence.UserID == "" {
			t.Fatal("real consumer lost verified identity or private attachment", err)
		}
		if firstID != "" && result.ExternalIdentity.Evidence.UserID != firstID {
			t.Fatal("same provider changed its implicit identity")
		}
		firstID = result.ExternalIdentity.Evidence.UserID
		if result.Cookie == nil || result.Cookie.Name != cookie.Name || result.Cookie.Path != cookie.Path || result.Cookie.Domain != "" || !result.Cookie.Secure || !result.Cookie.HttpOnly || result.Cookie.SameSite != http.SameSiteLaxMode || result.Cookie.MaxAge != -1 {
			t.Fatal("binding cookie deletion changed scope")
		}
		encoded, _ := json.Marshal(result)
		if string(encoded) != "{}" {
			t.Fatal("runtime identity result became serializable")
		}
	}
	request, cookie := sqliteTicketBegin(t, provider)
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	ticket, err := issuer.Issue(t.Context(), request, identity)
	if err != nil {
		t.Fatal("retiring consumer closed the independent issuer", err)
	}
	replacement, err := module.NewIdentityProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	restored := replacement.(*tickets.Provider)
	t.Cleanup(func() { _ = restored.Close() })
	result, err := sqliteTicketRedeem(t, restored, request, ticket, cookie)
	if err != nil || result.ExternalIdentity.Evidence.UserID == firstID || result.ExternalIdentity.Evidence.UserID == "" {
		t.Fatal("reopening lost pending state or incorrectly persisted implicit identity", err)
	}
	if result, err := sqliteTicketRedeem(t, restored, request, ticket, cookie); !errors.Is(err, tickets.ErrDenied) || result != nil {
		t.Fatal("restored binding cookie replay was accepted", err)
	}
}

func TestSQLiteTicketFactoryFailures(t *testing.T) {
	for _, kind := range []string{"missing_parent", "public_parent", "directory", "symlink", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			module := sqliteTicketTestConfig(t)
			ctx := t.Context()
			switch kind {
			case "missing_parent":
				module.Path = filepath.Join(filepath.Dir(module.Path), "missing", "tickets.db")
			case "public_parent":
				if err := os.Chmod(filepath.Dir(module.Path), 0755); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(module.Path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(filepath.Dir(module.Path), "target.db"), module.Path); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			provider, err := module.NewIdentityProvider(ctx)
			if provider != nil || !errors.Is(err, tickets.ErrUnavailable) || strings.Contains(err.Error(), module.Path) {
				t.Fatal("factory did not return a real nil and sanitized failure", err)
			}
			if kind == "missing_parent" || kind == "public_parent" || kind == "canceled" {
				if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
					t.Fatal("rejected factory created storage")
				}
			}
		})
	}
}
