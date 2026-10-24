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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestPortalMountNativeRefreshCookieOverride(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "immediate"
		if persistent {
			name = "deferred"
		}
		t.Run(name, func(t *testing.T) {
			config := lifecycleConfig()
			config.UserRegistration = nil
			portal := config.AuthenticationPortals[0]
			portal.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://issuer.example.test", BasePath: "/tenant/auth", CookieName: "MOUNT_REFRESH"}
			// Native configuration may retain a stale shared name. The enabled
			// refresh override replaces it before factory collision validation.
			portal.CookieConfig.RefreshTokenCookieName = portal.CookieConfig.AccessTokenCookieName
			directory := filepath.Join(t.TempDir(), "state")
			if persistent {
				config.State = &state.Config{Directory: directory}
			}
			before, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			app := provisionLifecycleApp(t, config)
			if len(app.PortalCookieDirectives) != 0 || (app.server == nil) != persistent {
				t.Fatal("native override relied on deferred cookie statements or changed construction timing")
			}
			factory := app.portalMounts[portal.Name].cookies
			if factory == nil || factory.RefreshTokenCookieName != "MOUNT_REFRESH" || factory.AccessTokenCookieName != "AUTHP_ACCESS_TOKEN" {
				t.Fatal("native mount snapshot lost the effective refresh override")
			}
			if err := app.validatePortalMount(portal.Name, "/tenant/auth"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("native cookie preflight initialized persistent state")
			}
			after, err := json.Marshal(config)
			if err != nil || string(after) != string(before) {
				t.Fatal("native override mutated declarative configuration")
			}
			portal.RefreshTokens.CookieName = "CHANGED_REFRESH"
			portal.CookieConfig.RefreshTokenCookieName = "CHANGED_SHARED_REFRESH"
			if factory.RefreshTokenCookieName != "MOUNT_REFRESH" {
				t.Fatal("effective cookie snapshot retained caller aliases")
			}
		})
	}
}

func TestPortalMountNativeCookieControls(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*authn.PortalConfig)
		refresh   string
		access    string
		reject    bool
	}{
		{"disabled override cannot repair collision", func(p *authn.PortalConfig) {
			p.RefreshTokens.Enabled = false
			p.CookieConfig.RefreshTokenCookieName = p.CookieConfig.AccessTokenCookieName
		}, "", "", true},
		{"empty override cannot repair collision", func(p *authn.PortalConfig) {
			p.RefreshTokens.CookieName = ""
			p.CookieConfig.RefreshTokenCookieName = p.CookieConfig.AccessTokenCookieName
		}, "", "", true},
		{"override cannot introduce collision", func(p *authn.PortalConfig) {
			p.RefreshTokens.CookieName = p.CookieConfig.AccessTokenCookieName
		}, "", "", true},
		{"disabled override preserves shared name", func(p *authn.PortalConfig) {
			p.RefreshTokens.Enabled = false
			p.CookieConfig.RefreshTokenCookieName = "SHARED_REFRESH"
		}, "SHARED_REFRESH", "AUTHP_ACCESS_TOKEN", false},
		{"nil cookie config", func(p *authn.PortalConfig) {
			p.CookieConfig = nil
		}, "MOUNT_REFRESH", "AUTHP_ACCESS_TOKEN", false},
		{"prefix fills omitted names", func(p *authn.PortalConfig) {
			p.CookieConfig = &cookie.Config{CookieNamePrefix: "MOUNT"}
		}, "MOUNT_REFRESH", "MOUNT_ACCESS_TOKEN", false},
		{"prefix preserves explicit names", func(p *authn.PortalConfig) {
			p.CookieConfig.CookieNamePrefix = "MOUNT"
		}, "MOUNT_REFRESH", "AUTHP_ACCESS_TOKEN", false},
		{"empty override inherits prefix", func(p *authn.PortalConfig) {
			p.CookieConfig = &cookie.Config{CookieNamePrefix: "MOUNT"}
			p.RefreshTokens.CookieName = ""
		}, "MOUNT_REFRESH_TOKEN", "MOUNT_ACCESS_TOKEN", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := lifecycleConfig()
			config.UserRegistration = nil
			portal := config.AuthenticationPortals[0]
			portal.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://issuer.example.test", BasePath: "/tenant/auth", CookieName: "MOUNT_REFRESH"}
			tc.configure(portal)
			directory := filepath.Join(t.TempDir(), "state")
			config.State = &state.Config{Directory: directory}
			before, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			t.Cleanup(cancel)
			app := &App{Config: config}
			t.Cleanup(func() {
				if err := app.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			err = app.Provision(ctx)
			if tc.reject {
				if err == nil || !strings.Contains(err.Error(), "cookie mount configuration is invalid") || app.runtimeConfig != nil {
					t.Fatal("ineffective or conflicting refresh override bypassed cookie preflight")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				factory := app.portalMounts[portal.Name].cookies
				if factory == nil || factory.RefreshTokenCookieName != tc.refresh || factory.AccessTokenCookieName != tc.access {
					t.Fatal("effective cookie defaults or explicit names changed")
				}
			}
			if app.server != nil {
				t.Fatal("cookie preflight constructed the persistent runtime")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("cookie preflight initialized persistent storage")
			}
			after, err := json.Marshal(config)
			if err != nil || string(after) != string(before) {
				t.Fatal("cookie preflight mutated declared configuration")
			}
		})
	}
}

func TestPortalMountResolvedSnapshot(t *testing.T) {
	t.Setenv("PORTAL_MOUNT_TEST", "/tenant/auth")
	for _, persistent := range []bool{false, true} {
		name := "immediate"
		if persistent {
			name = "deferred"
		}
		t.Run(name, func(t *testing.T) {
			config := lifecycleConfig()
			config.UserRegistration = nil
			portal := config.AuthenticationPortals[0]
			portal.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://issuer.example.test", BasePath: "{env.PORTAL_MOUNT_TEST}"}
			portal.CookieConfig.SandboxIDCookieName = "MOUNT_SANDBOX"
			portal.CookieConfig.Path = "{env.PORTAL_MOUNT_TEST}"
			directory := filepath.Join(t.TempDir(), "state")
			if persistent {
				config.State = &state.Config{Directory: directory}
			}
			before, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			app := provisionLifecycleApp(t, config)
			if (app.server == nil) != persistent {
				t.Fatal("mount snapshot changed root construction timing")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("mount preflight initialized persistent storage")
			}
			if err := app.validatePortalMount(portal.Name, "/tenant/auth"); err != nil {
				t.Fatal(err)
			}
			if err := app.validatePortalMount(portal.Name, "/other"); err == nil || !strings.Contains(err.Error(), "token refresh") {
				t.Fatal("resolved refresh mount was not enforced", err)
			}
			if err := app.validatePortalMount("missing", "/tenant/auth"); err == nil {
				t.Fatal("undeclared portal gained a mount snapshot")
			}
			after, err := json.Marshal(config)
			if err != nil || string(after) != string(before) {
				t.Fatal("mount preparation mutated declared configuration", err)
			}
			// The snapshot must not depend on the declarative object after provisioning.
			portal.RefreshTokens.BasePath = "/other"
			portal.CookieConfig.SandboxIDCookieName = "__Host-CHANGED"
			if err := app.validatePortalMount(portal.Name, "/tenant/auth"); err != nil {
				t.Fatal("resolved mount snapshot retained caller aliases", err)
			}
		})
	}
}

func TestPortalMountFeatureBindings(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		configure            func(*authn.PortalConfig)
		want, other, feature string
	}{
		{"unrestricted", func(*authn.PortalConfig) {}, "/team/auth", "/other", ""},
		{"refresh", func(p *authn.PortalConfig) {
			p.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, BasePath: "/team/auth"}
		}, "/team/auth", "/other", "token refresh"},
		{"disabled refresh", func(p *authn.PortalConfig) { p.RefreshTokens = &authn.TokenRefreshConfig{BasePath: "ignored"} }, "/team/auth", "/other", ""},
		{"oidc nested", func(p *authn.PortalConfig) {
			p.OIDCProvider = &authn.OIDCProviderConfig{Enabled: true, Issuer: "https://issuer.example.test/team/auth"}
		}, "/team/auth", "/other", "oidc provider"},
		{"oidc root", func(p *authn.PortalConfig) {
			p.OIDCProvider = &authn.OIDCProviderConfig{Enabled: true, Issuer: "https://issuer.example.test"}
		}, "/", "/other", "oidc provider"},
		{"disabled oidc", func(p *authn.PortalConfig) { p.OIDCProvider = &authn.OIDCProviderConfig{Issuer: "ignored"} }, "/team/auth", "/other", ""},
		{"host cookie", func(p *authn.PortalConfig) { p.CookieConfig = &cookie.Config{SandboxIDCookieName: "__Host-FLOW"} }, "/", "/team/auth", "cookie scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portal := &authn.PortalConfig{Name: "myportal"}
			tc.configure(portal)
			app := &App{}
			if err := app.preparePortalMounts(&authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}}); err != nil {
				t.Fatal(err)
			}
			if err := app.validatePortalMount("myportal", tc.want); err != nil {
				t.Fatal(err)
			}
			err := app.validatePortalMount("myportal", tc.other)
			if tc.feature == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "portal mount conflicts with "+tc.feature) {
				t.Fatal("feature mount mismatch was not rejected", err)
			}
		})
	}
}

func TestPortalMountBundledProviderBindings(t *testing.T) {
	for _, feature := range []string{"ticket provider", "registration workflow"} {
		t.Run(feature, func(t *testing.T) {
			portal := &authn.PortalConfig{Name: "myportal"}
			app := &App{}
			var storage string
			var mutate func()
			var selectFeature func()
			if feature == "ticket provider" {
				module := sqliteTicketTestConfig(t)
				storage = module.Path
				module.BasePath = "" // Public defaults must be used without mutating the module.
				app.identityProviders = []preparedIdentityProvider{{config: idp.ExternalIdentityProviderConfig{Name: module.Name}, module: module}}
				selectFeature = func() { portal.IdentityProviders = []string{module.Name} }
				mutate = func() { module.BasePath = "/changed" }
			} else {
				module := sqliteRegistrationTestConfig(t)
				storage = module.Path
				module.BasePath = ""
				app.registrationWorkflows = []preparedRegistrationWorkflow{{config: registry.ExternalUserRegistryConfig{Name: module.Name}, module: module}}
				selectFeature = func() { portal.UserRegistries = []string{module.Name} }
				mutate = func() { module.BasePath = "/changed" }
			}
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}}
			if err := app.preparePortalMounts(config); err != nil {
				t.Fatal(err)
			}
			if err := app.validatePortalMount("myportal", "/unrelated"); err != nil {
				t.Fatal("unused backend constrained portal", err)
			}
			selectFeature()
			if err := app.preparePortalMounts(config); err != nil {
				t.Fatal(err)
			}
			if err := app.validatePortalMount("myportal", "/auth"); err != nil {
				t.Fatal("normalized backend default lost", err)
			}
			if err := app.validatePortalMount("myportal", "/unrelated"); err == nil || !strings.Contains(err.Error(), feature) {
				t.Fatal("selected backend mount was not enforced", err)
			}
			mutate()
			if err := app.validatePortalMount("myportal", "/auth"); err != nil {
				t.Fatal("snapshot retained module alias", err)
			}
			if _, err := os.Stat(storage); !os.IsNotExist(err) {
				t.Fatal("mount snapshot opened storage")
			}
		})
	}
}

func TestPortalMountDocumentsBindings(t *testing.T) {
	for _, tc := range []struct {
		name, base, mount string
		enabled, storage  bool
	}{
		{"default root", "", "/", true, true},
		{"nested", "/tenant/auth", "/tenant/auth", true, true},
		{"disabled invalid", "invalid", "/unrelated", false, true},
		{"omitted", "", "/unrelated", false, false},
		{"enabled missing", "", "/", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "absent", "documents.db")
			portal := &authn.PortalConfig{Name: "portal", API: &authn.APIConfig{DocumentsEnabled: tc.enabled}}
			if tc.storage {
				portal.Documents = &documents.Config{Database: path, PublicOrigin: "https://portal.example.test", BasePath: tc.base, Realms: []string{"local"}}
				if tc.enabled {
					if err := portal.Documents.Validate(); err != nil {
						t.Fatal(err)
					}
				}
			}
			app := &App{}
			err := app.preparePortalMounts(&authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}})
			if tc.enabled && !tc.storage {
				if err == nil {
					t.Fatal("enabled Documents without storage lost its mount constraint")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := app.validatePortalMount("portal", tc.mount); err != nil {
				t.Fatal(err)
			}
			err = app.validatePortalMount("portal", "/different")
			if tc.enabled && (err == nil || !strings.Contains(err.Error(), "documents API")) || !tc.enabled && err != nil {
				t.Fatal("Documents enabled state did not control mount agreement", err)
			}
			portal.API.DocumentsEnabled = !tc.enabled
			if portal.Documents != nil {
				portal.Documents.BasePath = "/mutated"
			}
			if err := app.validatePortalMount("portal", tc.mount); err != nil {
				t.Fatal("Documents mount snapshot retained a caller alias", err)
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("Documents mount preparation touched storage")
			}
		})
	}
}
