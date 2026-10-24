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
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

// Static verification keys and explicit endpoints make construction independent
// of discovery, network availability or disabled signature checks. The same
// baseline must construct before each selection error can be meaningful.
func providerRefreshAppConfig() *authcrunch.Config {
	config := lifecycleConfig()
	config.UserRegistration = nil
	config.IdentityProviders = []*idp.IdentityProviderConfig{{Name: "upstream", Kind: "oauth", Params: map[string]any{
		"realm": "upstream", "driver": "generic", "client_id": "snapshot-client", "client_secret": "synthetic-snapshot-client-secret",
		"base_auth_url": "https://issuer.example.test", "authorization_url": "https://issuer.example.test/authorize", "token_url": "https://issuer.example.test/token",
		"jwks_keys": map[string]any{"fixture": "testdata/oauth/87329db33bf_pub.pem"},
	}}}
	portal := config.AuthenticationPortals[0]
	portal.IdentityProviders = []string{"upstream"}
	portal.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local", "upstream"}, PublicOrigin: "https://portal.example.test", BasePath: "/auth",
		ProviderRevalidation: []authn.TokenRefreshProviderConfig{{Realm: "upstream", Mode: "snapshot"}}}
	return config
}

func provisionProviderRefreshApp(t *testing.T, app *App) error {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	t.Cleanup(func() {
		if err := app.Cleanup(); err != nil {
			t.Error("provider refresh app cleanup failed")
		}
	})
	return app.Provision(ctx)
}

func TestAppTokenRefreshProviderSourceSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*authcrunch.Config)
		want string
	}{
		{"valid offline provider", func(*authcrunch.Config) {}, ""},
		{"unselected provider is access only", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens.Realms = []string{"local"}
			c.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation = nil
		}, ""},
		{"unknown realm", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens.Realms = []string{"missing"}
			c.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation = []authn.TokenRefreshProviderConfig{{Realm: "missing", Mode: "snapshot"}}
		}, `refresh realm "missing" must identify exactly one renewal source`},
		{"provider not attached to portal", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].IdentityProviders = nil
		}, `refresh realm "upstream" must identify exactly one renewal source`},
		{"ambiguous store and provider realm", func(c *authcrunch.Config) {
			c.IdentityStores[0].Params["realm"] = "upstream"
			c.AuthenticationPortals[0].RefreshTokens.Realms = []string{"upstream"}
			// Global realm uniqueness rejects this ambiguity before refresh
			// selects a source; keep that earlier root invariant observable.
		}, `identity provider "upstream" has the same "upstream" realm as "local"`},
		{"local source cannot use provider mode", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation = append(c.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation, authn.TokenRefreshProviderConfig{Realm: "local", Mode: "snapshot"})
		}, "refresh provider mode requires a provider realm"},
		{"OAuth requires opt in", func(c *authcrunch.Config) {
			c.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation = nil
		}, `refresh provider realm "upstream" requires explicit OAuth snapshot mode`},
		{"identity token cookie conflicts", func(c *authcrunch.Config) {
			c.IdentityProviders[0].Params["identity_token_cookie_enabled"] = true
		}, "refresh provider snapshot mode requires identity token cookies disabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := providerRefreshAppConfig()
			tc.edit(config)
			before, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			app := &App{Config: config}
			err = provisionProviderRefreshApp(t, app)
			if tc.want == "" {
				if err != nil || app.server == nil {
					t.Fatal("valid static provider refresh configuration failed", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || app.server != nil {
				t.Fatalf("provider selection did not reach the intended validator: %v", err)
			}
			after, _ := json.Marshal(config)
			if string(before) != string(after) {
				t.Fatal("provider selection mutated the declarative configuration")
			}
		})
	}
}

func TestAppTokenRefreshProviderRejectsNonOAuth(t *testing.T) {
	// A real configured HTTP-login provider reaches refresh eligibility. Reusing
	// an invalid SAML metadata fixture would fail before this boundary.
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("refresh=%t", enabled), func(t *testing.T) {
			module := sqliteTicketTestConfig(t)
			config := identityProviderTestConfig()
			config.AuthenticationPortals[0].IdentityProviders = []string{module.Name}
			config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: enabled, Realms: []string{module.Realm}, PublicOrigin: module.PublicOrigin, BasePath: module.BasePath,
				ProviderRevalidation: []authn.TokenRefreshProviderConfig{{Realm: module.Realm, Mode: "snapshot"}}}
			app := &App{Config: config, IdentityProviderConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)}}
			err := provisionProviderRefreshApp(t, app)
			if !enabled {
				if err != nil || app.server == nil {
					t.Fatal("non-OAuth positive construction control failed", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "requires explicit OAuth snapshot mode") || app.server != nil {
				t.Fatal("non-OAuth provider did not reach refresh eligibility", err)
			}
		})
	}
}

func TestAppTokenRefreshProviderSnapshots(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, native := range []bool{false, true} {
			t.Run(fmt.Sprintf("persistent=%t/native=%t", persistent, native), func(t *testing.T) {
				t.Setenv("APP_PROVIDER_REFRESH_REALM", "upstream")
				app := &App{Config: providerRefreshAppConfig()}
				portal := app.Config.AuthenticationPortals[0]
				if native {
					portal.RefreshTokens.Realms[1] = "{env.APP_PROVIDER_REFRESH_REALM}"
					portal.RefreshTokens.ProviderRevalidation[0] = authn.TokenRefreshProviderConfig{Realm: "{env.APP_PROVIDER_REFRESH_REALM}", Mode: "secrets:oauth:mode"}
				} else {
					portal.RefreshTokens = nil
					app.PortalTokenRefreshDirectives = map[string][]string{"portal": {"realms local {env.APP_PROVIDER_REFRESH_REALM}", "provider revalidation {env.APP_PROVIDER_REFRESH_REALM} secrets:oauth:mode", "public origin https://portal.example.test", "base path /auth"}}
				}
				app.SecretsManagerConfigs = []json.RawMessage{caddyconfig.JSONModuleObject(&oauthRuntimeSecrets{Values: map[string]string{"mode": "snapshot"}}, "driver", "oauth_test", nil)}
				directory := filepath.Join(t.TempDir(), "state")
				if persistent {
					app.Config.State = &state.Config{Directory: directory}
					app.Config.IdentityStores[0].Params["path"] = filepath.Join(t.TempDir(), "accounts.json")
				}
				before, err := json.Marshal(app)
				if err != nil {
					t.Fatal(err)
				}
				if err := provisionProviderRefreshApp(t, app); err != nil {
					t.Fatal(err)
				}
				after, _ := json.Marshal(app)
				if string(before) != string(after) {
					t.Fatal("provisioning rewrote provider, secret or deferred declarations")
				}
				if persistent {
					if app.server != nil || app.runtimeConfig == nil {
						t.Fatal("persistent provider configuration bypassed deferred construction")
					}
					cfg := app.runtimeConfig.AuthenticationPortals[0].RefreshTokens
					if cfg.Realms[1] != "upstream" || cfg.ProviderRevalidation[0] != (authn.TokenRefreshProviderConfig{Realm: "upstream", Mode: "snapshot"}) {
						t.Fatal("persistent snapshot retained unresolved provider settings")
					}
					for _, path := range []string{directory, app.Config.IdentityStores[0].Params["path"].(string)} {
						if _, err := os.Stat(path); !os.IsNotExist(err) {
							t.Fatal("persistent preparation opened identity or state storage")
						}
					}
					// Start must use its own resolved graph even if the caller later
					// mutates a nested entry or a saved source statement.
					if native {
						portal.RefreshTokens.ProviderRevalidation[0].Mode = "invalid"
					} else {
						app.PortalTokenRefreshDirectives["portal"][1] = "provider revalidation missing invalid"
					}
					if err := app.Start(); err != nil || app.server == nil {
						t.Fatal("persistent provider snapshot was not independently startable", err)
					}
				} else if app.server == nil {
					t.Fatal("volatile provider configuration omitted runtime construction")
				}
			})
		}
	}
}

func TestAppTokenRefreshProviderPrivateFailureSnapshot(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			app := &App{Config: providerRefreshAppConfig()}
			if native {
				app.Config.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation[0].Mode = "secrets:oauth:mode"
			} else {
				app.Config.AuthenticationPortals[0].RefreshTokens = nil
				app.PortalTokenRefreshDirectives = map[string][]string{"portal": {"realms upstream", "provider revalidation upstream secrets:oauth:mode", "public origin https://portal.example.test", "base path /auth"}}
			}
			const sentinel = "private-provider-mode-sentinel"
			app.SecretsManagerConfigs = []json.RawMessage{caddyconfig.JSONModuleObject(&oauthRuntimeSecrets{Values: map[string]string{"mode": sentinel}}, "driver", "oauth_test", nil)}
			before, _ := json.Marshal(app)
			err := provisionProviderRefreshApp(t, app)
			if err == nil || strings.Contains(err.Error(), sentinel) || app.server != nil {
				t.Fatal("invalid private provider mode was admitted or exposed")
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("failed provider resolution changed declarative snapshots")
			}
		})
	}
}
