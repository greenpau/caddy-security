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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"go.uber.org/zap"
)

const lifecyclePassword = "SyntheticPassword42!"
const lifecycleJWKS = `{"keys":[{"kid":"test","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`

func lifecycleConfig() *authcrunch.Config {
	key := []string{"crypto key sign-verify synthetic-lifecycle-signing-secret"}
	return &authcrunch.Config{
		UserRegistration: &registry.Config{RawConfigs: [][]string{{"name registry", "kind local", "dropbox :memory:", "email provider unused", "admin email admin@example.test", "identity store local"}}},
		IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{
			"realm": "local", "path": ":memory:", "users": []any{map[string]any{
				"username": "alice", "email_address": "alice@example.test", "password": lifecyclePassword,
				"roles": []string{"authp/admin", "authp/user"},
			}},
		}}},
		AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: key, UI: &ui.Parameters{}, CookieConfig: cookie.NewConfig()}},
		AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", RawCryptoKeyStoreConfig: key, ValidateBearerHeader: true,
			AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}},
		}},
	}
}

func provisionLifecycleApp(t *testing.T, config *authcrunch.Config) *App {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	app := &App{Config: config}
	t.Cleanup(func() {
		if err := app.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	if err := app.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	return app
}

func awaitLifecycle(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitDisposing(t *testing.T, app *App) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		app.mu.Lock()
		disposing := app.disposing
		app.mu.Unlock()
		if disposing {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("cleanup did not close admission")
		}
	}
}

func assertServerClosed(t *testing.T, app *App) {
	t.Helper()
	if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
		t.Fatalf("portal lookup after cleanup: %v", err)
	}
	if _, err := app.server.GetGatekeeperByName("policy"); !errors.Is(err, authcrunch.ErrServerClosed) {
		t.Fatalf("gatekeeper lookup after cleanup: %v", err)
	}
}

func TestAppLifecycleOptionalPortalConfig(t *testing.T) {
	for _, omitted := range []string{"ui", "cookie_config", "both"} {
		t.Run(omitted, func(t *testing.T) {
			cfg := lifecycleConfig()
			if omitted != "cookie_config" {
				cfg.AuthenticationPortals[0].UI = nil
			}
			if omitted != "ui" {
				cfg.AuthenticationPortals[0].CookieConfig = nil
			}
			app := provisionLifecycleApp(t, cfg)
			portal, err := app.getPortal("portal")
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "https://portal.example.test/auth/login", nil)
			if err := (&AuthnMiddleware{app: app, portal: portal}).ServeHTTP(w, r, nil); err != nil || w.Code != http.StatusOK {
				t.Fatalf("portal with defaults: status=%d error=%v", w.Code, err)
			}
		})
	}
}

// Exercise JSON inputs independently of Caddyfile constructors, which normally
// allocate these optional settings and never emit null collection entries.
var lifecycleInvalidConfigs = []struct{ name, patch, want string }{
	{"store", `{"identity_stores":[null]}`, "identity_stores[0]"},
	{"provider", `{"identity_providers":[null]}`, "identity_providers[0]"},
	{"sso", `{"sso_providers":[null]}`, "sso_providers[0]"},
	{"portal", `{"authentication_portals":[null]}`, "authentication_portals[0]"},
	{"policy", `{"authorization_policies":[null]}`, "authorization_policies[0]"},
	{"transform", `{"authentication_portals":[{"user_transformer_configs":[null]}]}`, "user_transformer_configs[0]"},
	{"link", `{"authentication_portals":[{"ui":{"private_links":[null]}}]}`, "ui.private_links[0]"},
	{"asset", `{"authentication_portals":[{"ui":{"static_assets":[null]}}]}`, "ui.static_assets[0]"},
	{"domain", `{"authentication_portals":[{"cookie_config":{"domains":{"example.test":null}}}]}`, `cookie_config.domains["example.test"]`},
	{"ui_realm", `{"authentication_portals":[{"ui":{"realms":[null]}}]}`, "ui.realms[0]"},
	{"oidc_client", `{"authentication_portals":[{"oidc_provider":{"clients":[null]}}]}`, "oidc_provider.clients[0]"},
	{"oauth_application", `{"oauth_applications":[null]}`, "oauth_applications[0]"},
	{"policy_acl", `{"authorization_policies":[{"access_list_rules":[null]}]}`, "access_list_rules[0]"},
	{"bypass", `{"authorization_policies":[{"bypass_configs":[null]}]}`, "bypass_configs[0]"},
	{"header", `{"authorization_policies":[{"header_injection_configs":[null]}]}`, "header_injection_configs[0]"},
	{"proxy_realm", `{"authorization_policies":[{"auth_proxy_config":{"realms":{"local":null}}}]}`, `auth_proxy_config.realms["local"]`},
	{"portal_acl", `{"authentication_portals":[{"access_list_configs":[null]}]}`, "access_list_configs[0]"},
	{"login_redirect", `{"authentication_portals":[{"trusted_login_redirect_uri_configs":[null]}]}`, "trusted_login_redirect_uri_configs[0]"},
	{"logout_redirect", `{"authentication_portals":[{"trusted_logout_redirect_uri_configs":[null]}]}`, "trusted_logout_redirect_uri_configs[0]"},
	{"credential", `{"credentials":{"generic":[null]}}`, "credentials.generic[0]"},
	{"registry", `{"user_registration":{"raw_configs":null,"local_providers":[null]}}`, "user_registration.local_providers[0]"},
	{"email", `{"messaging":{"email_providers":[null]}}`, "messaging.email_providers[0]"},
	{"file_message", `{"messaging":{"file_providers":[null]}}`, "messaging.file_providers[0]"},
	{"user", `{"identity_stores":[{"params":{"users":[{"username":"alice"},null]}}]}`, "users[1]"},
	{"user_scalar", `{"identity_stores":[{"params":{"users":[true]}}]}`, "users"},
	{"users_object", `{"identity_stores":[{"params":{"users":{"username":"alice"}}}]}`, "users"},
	{"ldap_server", `{"identity_stores":[{"kind":"ldap","params":{"servers":[{"address":"ldap.example.test"},null]}}]}`, "servers[1]"},
	{"saml_url", `{"identity_providers":[{"name":"saml","kind":"saml","params":{"idp_login_url":["https://idp.example.test"]}}]}`, "idp_login_url"},
	{"portal_crypto_short", `{"authentication_portals":[{"raw_crypto_key_store_config":["crypto"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"policy_crypto_short", `{"authorization_policies":[{"raw_crypto_key_store_config":["crypto"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"portal_crypto_empty_literal", `{"authentication_portals":[{"raw_crypto_key_store_config":["crypto \"\""]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"policy_crypto_empty_literal", `{"authorization_policies":[{"raw_crypto_key_store_config":["crypto \"\""]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"portal_crypto_empty", `{"authentication_portals":[{"raw_crypto_key_store_config":["crypto {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"policy_crypto_empty", `{"authorization_policies":[{"raw_crypto_key_store_config":["crypto {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"portal_crypto_empty_key", `{"authentication_portals":[{"raw_crypto_key_store_config":["crypto key sign-verify {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"policy_crypto_empty_key", `{"authorization_policies":[{"raw_crypto_key_store_config":["crypto key sign-verify {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]}]}`, "RawCryptoKeyStoreConfigs[0]"},
	{"messaging_kind_short", `{"messaging":{"raw_configs":[["kind"]]}}`, "RawMessagingConfigs[0]"},
	{"registration_kind_short", `{"user_registration":{"raw_configs":[["kind"]]}}`, "RawUserRegistrationConfigs[0]"},
	{"messaging_kind_empty", `{"messaging":{"raw_configs":[["kind {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]]}}`, "RawMessagingConfigs[0]"},
	{"registration_kind_empty", `{"user_registration":{"raw_configs":[["kind {env.CADDY_SECURITY_LIFECYCLE_EMPTY}"]]}}`, "RawUserRegistrationConfigs[0]"},
}

func TestResolveRuntimeAppConfigRejectsMalformedUsers(t *testing.T) {
	cfg := lifecycleConfig()
	cfg.IdentityStores[0].Params["users"] = []any{true}
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, cfg, zap.NewNop()); err == nil {
		t.Fatal("a boolean user passed runtime configuration validation")
	}
}

func lifecycleParsedConfig(t *testing.T) *authcrunch.Config {
	t.Helper()
	cfg := lifecycleConfig()
	cfg.AddCredential([]string{"name mail", "username alice", "password synthetic-mail-password"})
	cfg.AddMessagingProvider([]string{"name mail", "kind email", "address 127.0.0.1:1", "protocol smtp", "credentials mail", "sender alice@example.test"})
	if err := cfg.Credentials.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Messaging.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.UserRegistration.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.UserRegistration.LocalProviders[0].EmailProviderName = "mail"
	cfg.Credentials.RawCredentialConfigs = nil
	cfg.Messaging.RawConfigs = nil
	cfg.UserRegistration.RawConfigs = nil
	return cfg
}

func TestAppLifecycleParsedConfig(t *testing.T) {
	cfg := lifecycleParsedConfig(t)
	app := provisionLifecycleApp(t, cfg)
	data, err := json.Marshal(app.server.GetConfig())
	if err != nil {
		t.Fatal(err)
	}
	var actual authcrunch.Config
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual.Credentials.Generic) != 1 || len(actual.Messaging.EmailProviders) != 1 || len(actual.UserRegistration.LocalProviders) != 1 {
		t.Fatal("runtime discarded parsed configuration")
	}
	if actual.Credentials.Generic[0].Password != cfg.Credentials.Generic[0].Password || actual.UserRegistration.LocalProviders[0].Dropbox != ":memory:" {
		t.Fatal("runtime changed parsed configuration values")
	}
}

func TestAppLifecycleEmptyOptionalSections(t *testing.T) {
	cfg := lifecycleConfig()
	cfg.UserRegistration = nil
	if err := json.Unmarshal([]byte(`{"credentials":{},"messaging":{},"user_registration":{}}`), cfg); err != nil {
		t.Fatal(err)
	}
	app := provisionLifecycleApp(t, cfg)
	if _, err := app.getPortal("portal"); err != nil {
		t.Fatal(err)
	}
}

func TestAppLifecycleInvalidConfig(t *testing.T) {
	t.Setenv("CADDY_SECURITY_LIFECYCLE_EMPTY", "")
	for _, tc := range lifecycleInvalidConfigs {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lifecycleConfig()
			if err := json.Unmarshal([]byte(tc.patch), cfg); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			app := &App{Config: cfg}
			defer app.Cleanup()
			if err := app.Provision(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid config: %v; want path %s", err, tc.want)
			}
		})
	}
}

func TestAppLifecycleFreshConfig(t *testing.T) {
	config := lifecycleConfig()
	before, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	first := provisionLifecycleApp(t, config)
	second := provisionLifecycleApp(t, config)
	after, _ := json.Marshal(config)
	if !bytes.Equal(before, after) {
		t.Fatal("provisioning mutated the caller's configuration")
	}
	if first.server == second.server {
		t.Fatal("runtime reused")
	}
	p1, _ := first.getPortal("portal")
	p2, _ := second.getPortal("portal")
	if p1 == p2 {
		t.Fatal("portal reused")
	}
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertServerClosed(t, first)
	if _, err := second.getPortal("portal"); err != nil {
		t.Fatal("cleanup affected another runtime", err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := second.Provision(ctx); err == nil {
		t.Fatal("serving instance was reprovisioned")
	}
}

func TestAppLifecycleConcurrentCleanupDrains(t *testing.T) {
	app := provisionLifecycleApp(t, lifecycleConfig())
	portal, _ := app.getPortal("portal")
	gate, _ := app.getGatekeeper("policy")
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("request refused")
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	if err := app.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := app.getPortal("portal"); err != nil {
		t.Fatal("Stop disposed the runtime before HTTP shutdown", err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := app.Cleanup(); err != nil {
				t.Error(err)
			}
		})
	}
	go func() { wg.Wait(); close(done) }()
	waitDisposing(t, app)
	select {
	case <-done:
		t.Fatal("cleanup returned before drain")
	default:
	}
	if _, err := app.server.GetPortalByName("portal"); err != nil {
		t.Fatal("runtime closed with an admitted request", err)
	}
	if release, ok := app.acquireRequest(); ok {
		release()
		t.Fatal("new request entered a retiring runtime")
	}
	an := &AuthnMiddleware{app: app, portal: portal}
	az := &AuthzMiddleware{app: app, gatekeeper: gate}
	req := httptest.NewRequest(http.MethodGet, "https://example.test/auth/login", nil)
	denial := httptest.NewRecorder()
	if err := an.ServeHTTP(denial, req, nil); err == nil || denial.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("retired authenticator admitted work")
	}
	denial = httptest.NewRecorder()
	if _, ok, err := az.Authenticate(denial, req); ok || err == nil || denial.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("retired authorizer admitted work")
	}
	// Referencing handlers must not independently dispose their shared app.
	if _, ok := any(an).(caddy.CleanerUpper); ok {
		t.Fatal("authenticator owns cleanup")
	}
	if _, ok := any(az).(caddy.CleanerUpper); ok {
		t.Fatal("authorizer owns cleanup")
	}
	releaseOnce.Do(release)
	awaitLifecycle(t, done, "all concurrent cleanup calls")
	assertServerClosed(t, app)
}

func TestAppLifecyclePartialProvision(t *testing.T) {
	for _, config := range []*authcrunch.Config{nil, {}, lifecycleConfig()} {
		if config != nil && len(config.AuthenticationPortals) > 0 {
			// Unsupported JSON values must produce an error, not share a graph.
			config.IdentityStores[0].Params["bad"] = make(chan struct{})
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		app := &App{Config: config}
		if err := app.Provision(ctx); err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if err := app.Cleanup(); err != nil {
			t.Fatal(err)
		}
		if err := app.Cleanup(); err != nil {
			t.Fatal(err)
		}
		cancel()
	}
}

func lifecycleOAuth(url, name string, delay int) *idp.IdentityProviderConfig {
	return &idp.IdentityProviderConfig{Name: name, Kind: "oauth", Params: map[string]any{
		"realm": name, "driver": "generic", "client_id": "client", "client_secret": "synthetic",
		"base_auth_url": url, "metadata_url": url + "/metadata", "delay_start": delay,
		"tls_insecure_skip_verify": true,
	}}
}

func TestAppLifecycleCancelsDiscovery(t *testing.T) {
	for _, stage := range []string{"metadata", "keys"} {
		t.Run(stage, func(t *testing.T) {
			entered, canceled := make(chan struct{}), make(chan struct{})
			abort := make(chan struct{})
			var attempts atomic.Int32
			var upstream *httptest.Server
			upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if stage == "keys" && r.URL.Path == "/metadata" {
					_ = json.NewEncoder(w).Encode(map[string]any{"authorization_endpoint": upstream.URL + "/authorize", "token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys"})
					return
				}
				close(entered)
				select {
				case <-r.Context().Done():
				case <-abort:
				}
				// Even a late successful reply must not restart the disposed provider.
				if stage == "metadata" {
					_ = json.NewEncoder(w).Encode(map[string]any{"authorization_endpoint": upstream.URL + "/authorize", "token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys"})
				} else {
					_, _ = w.Write([]byte(lifecycleJWKS))
				}
				close(canceled)
			}))
			defer upstream.Close()
			defer close(abort)
			config := lifecycleConfig()
			config.IdentityProviders = []*idp.IdentityProviderConfig{lifecycleOAuth(upstream.URL, "slow", 1)}
			config.AuthenticationPortals[0].IdentityProviders = []string{"slow"}
			// Both portals refer to the same constructed provider and local store.
			config.AuthenticationPortals = append(config.AuthenticationPortals, &authn.PortalConfig{
				Name: "other", IdentityStores: []string{"local"}, IdentityProviders: []string{"slow"},
				UI: &ui.Parameters{}, CookieConfig: cookie.NewConfig(),
				RawCryptoKeyStoreConfig: []string{"crypto key sign-verify synthetic-lifecycle-signing-secret"},
			})
			app := provisionLifecycleApp(t, config)
			awaitLifecycle(t, entered, "upstream "+stage)
			done := make(chan struct{})
			go func() { _ = app.Cleanup(); close(done) }()
			awaitLifecycle(t, done, "provider cleanup")
			awaitLifecycle(t, canceled, "network cancellation")
			assertServerClosed(t, app)
			count := attempts.Load()
			time.Sleep(100 * time.Millisecond)
			if attempts.Load() != count {
				t.Fatal("provider made requests after cleanup")
			}
		})
	}
}

func TestAppLifecycleSharedProviders(t *testing.T) {
	var discoveries atomic.Int32
	var upstream *httptest.Server
	upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata" {
			discoveries.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"authorization_endpoint": upstream.URL + "/authorize", "token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys"})
			return
		}
		_, _ = w.Write([]byte(lifecycleJWKS))
	}))
	defer upstream.Close()
	config := lifecycleConfig()
	config.IdentityProviders = []*idp.IdentityProviderConfig{lifecycleOAuth(upstream.URL, "shared", 0)}
	config.AuthenticationPortals[0].IdentityProviders = []string{"shared"}
	other := lifecycleConfig().AuthenticationPortals[0]
	other.Name = "other"
	other.IdentityProviders = []string{"shared"}
	config.AuthenticationPortals = append(config.AuthenticationPortals, other)
	app := provisionLifecycleApp(t, config)
	if discoveries.Load() != 1 {
		t.Fatalf("shared provider constructed %d times", discoveries.Load())
	}
	for _, name := range []string{"portal", "other"} {
		portal, err := app.getPortal(name)
		if err != nil {
			t.Fatal(err)
		}
		m := &AuthnMiddleware{app: app, portal: portal}
		r := httptest.NewRequest(http.MethodGet, "https://portal.example.test/auth/oauth2/shared", nil)
		w := httptest.NewRecorder()
		if err := m.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), upstream.URL+"/authorize?") {
			t.Fatalf("portal %s could not use shared provider: %d", name, w.Code)
		}
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertServerClosed(t, app)
}

func TestAppIdentityFileOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	config := lifecycleConfig()
	config.IdentityStores[0].Params["path"] = path
	first := provisionLifecycleApp(t, config)
	before := lifecycleReadFile(t, path)
	parentAlias := lifecycleParentAlias(t, dir)
	for _, alias := range []string{path, filepath.Join(dir, "symlink.json"), filepath.Join(dir, "hardlink.json"), parentAlias + "/users.json"} {
		if strings.Contains(alias, "symlink") {
			if err := os.Symlink(path, alias); err != nil {
				t.Fatal(err)
			}
		}
		if strings.Contains(alias, "hardlink") {
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
		}
		candidate := lifecycleConfig()
		candidate.IdentityStores[0].Params["path"] = alias
		user := candidate.IdentityStores[0].Params["users"].([]any)[0].(map[string]any)
		user["password_overwrite_enabled"] = true
		user["password"] = "CandidateMustNotOverwrite42!"
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		t.Cleanup(cancel)
		app := &App{Config: candidate}
		t.Cleanup(func() { _ = app.Cleanup() })
		if err := app.Provision(ctx); err == nil || !strings.Contains(err.Error(), "already belongs") {
			t.Fatalf("overlapping identity writer accepted: %v", err)
		}
		_ = app.Cleanup()
		cancel()
	}
	after := lifecycleReadFile(t, path)
	if !bytes.Equal(before, after) {
		t.Fatal("abandoned candidate modified the active identity file")
	}
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	second := provisionLifecycleApp(t, config)
	// Replaying an old owner's cleanup must not release a newer owner's file.
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	third := &App{Config: config}
	defer third.Cleanup()
	if err := third.Provision(ctx); err == nil || !strings.Contains(err.Error(), "already belongs") {
		t.Fatalf("old cleanup released the new owner's reservation: %v", err)
	}
	if err := second.Cleanup(); err != nil {
		t.Fatal(err)
	}
	after = lifecycleReadFile(t, path)
	if !bytes.Equal(before, after) {
		t.Fatal("identity file changed after sequential replacement")
	}
}

// Do not use filepath.Join on the returned path: lexical cleaning changes the
// meaning of '..' after a symlink, before the filesystem can resolve the link.
func lifecycleParentAlias(t *testing.T, target string) string {
	t.Helper()
	child := filepath.Join(target, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	return link + "/.."
}

func TestAppIdentityFileReservations(t *testing.T) {
	dir := t.TempDir()
	config := func(path string) *authcrunch.Config {
		return &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"path": path}}}}
	}
	// Keep redundant separators in a missing parent; filepath.Join would clean
	// them before exercising the same path supplied to the runtime constructor.
	path := dir + "/new//users.json"
	// Reservations protect missing files before constructors create them.
	owner, err := reserveIdentityFiles(config(path))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseIdentityFiles(owner)
	// Until a file exists, SameFile cannot detect aliases on a case-insensitive
	// filesystem. Reserve case variants together before either writer starts.
	if got, err := reserveIdentityFiles(config(dir + "/new/USERS.JSON")); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("case variant bypassed missing-file reservation")
	}
	dangling := filepath.Join(dir, "dangling.json")
	if err := os.Symlink(path, dangling); err != nil {
		t.Fatal(err)
	}
	if got, err := reserveIdentityFiles(config(dangling)); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("dangling symlink bypassed missing-file reservation")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if got, err := reserveIdentityFiles(config(filepath.Join(alias, "new", "users.json"))); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("missing file through symlink ancestor bypassed reservation")
	}
	registryConfig := &authcrunch.Config{UserRegistration: &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Name: "registry", Dropbox: path}}}}
	if got, err := reserveIdentityFiles(registryConfig); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("registration writer bypassed identity reservation")
	}
	unused := filepath.Join(dir, "unused.json")
	conflict := config(unused)
	conflict.IdentityStores = append(conflict.IdentityStores, config(path).IdentityStores...)
	if got, err := reserveIdentityFiles(conflict); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("multi-file conflict accepted")
	}
	got, err := reserveIdentityFiles(config(unused))
	if err != nil {
		t.Fatal("failed multi-file reservation left partial ownership", err)
	}
	releaseIdentityFiles(got)

	var wg sync.WaitGroup
	var winners atomic.Int32
	winnersRelease := make(chan struct{})
	allAttempted := make(chan struct{}, 16)
	for range 16 {
		wg.Go(func() {
			got, err := reserveIdentityFiles(config(unused))
			if err == nil {
				winners.Add(1)
			}
			allAttempted <- struct{}{}
			if err == nil {
				<-winnersRelease
				releaseIdentityFiles(got)
			}
		})
	}
	for range 16 {
		<-allAttempted
	}
	close(winnersRelease)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent identity owners: %d", winners.Load())
	}
}

func TestAppIdentityFileUnicodeAliases(t *testing.T) {
	dir := t.TempDir()
	config := func(name string) *authcrunch.Config {
		return &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"path": filepath.Join(dir, name)}}}}
	}
	owner, err := reserveIdentityFiles(config("caf\u00e9.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseIdentityFiles(owner)
	if got, err := reserveIdentityFiles(config("cafe\u0301.json")); err == nil {
		releaseIdentityFiles(got)
		t.Fatal("Unicode normalization alias bypassed missing-file reservation")
	}
}

func TestAppIdentityFileExistingNames(t *testing.T) {
	for _, tc := range []struct{ name, first, second string }{
		{"case", "Users.json", "users.json"},
		{"unicode", "caf\u00e9.json", "cafe\u0301.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			first, second := filepath.Join(dir, tc.first), filepath.Join(dir, tc.second)
			if err := os.WriteFile(first, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			// Ask the filesystem whether these names can identify distinct files.
			// Existing distinct files must remain usable on case/normalization-
			// sensitive filesystems despite conservative missing-file reservations.
			file, err := os.OpenFile(second, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			aliases := os.IsExist(err)
			if err != nil && !aliases {
				t.Fatal(err)
			}
			if file != nil {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			cfg := &authcrunch.Config{IdentityStores: []*ids.IdentityStoreConfig{
				{Name: "first", Kind: "local", Params: map[string]any{"path": first}},
				{Name: "second", Kind: "local", Params: map[string]any{"path": second}},
			}}
			owners, err := reserveIdentityFiles(cfg)
			defer releaseIdentityFiles(owners)
			if aliases && err == nil {
				t.Fatal("filesystem aliases admitted two identity writers")
			}
			if !aliases && err != nil {
				t.Fatal("distinct existing files were rejected", err)
			}
		})
	}
}
