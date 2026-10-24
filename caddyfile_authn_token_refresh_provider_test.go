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
	"fmt"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"go.uber.org/zap"
)

const providerRefreshTestRequired = "realms local upstream second\npublic origin https://auth.example.test\nbase path /auth\n"

func TestPortalTokenRefreshProviderParsing(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []authn.TokenRefreshProviderConfig
	}{
		{"unselected", providerRefreshTestRequired, nil},
		{"two providers", providerRefreshTestRequired + "provider revalidation upstream snapshot\nprovider revalidation second snapshot", []authn.TokenRefreshProviderConfig{{Realm: "upstream", Mode: "snapshot"}, {Realm: "second", Mode: "snapshot"}}},
		{"quoted single realm", "realms \"corp, west\"\npublic origin https://auth.example.test\nbase path /auth\nprovider revalidation \"corp, west\" snapshot", []authn.TokenRefreshProviderConfig{{Realm: "corp, west", Mode: "snapshot"}}},
		{"disabled selection", "disabled\nprovider revalidation upstream snapshot", []authn.TokenRefreshProviderConfig{{Realm: "upstream", Mode: "snapshot"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := tokenRefreshTestApp(t, tokenRefreshTestBlock(tc.body))
			data, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			var restored App
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, restored.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, restored.Config.AuthenticationPortals[0].RefreshTokens.ProviderRevalidation); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortalTokenRefreshProviderParsingRejects(t *testing.T) {
	for name, line := range map[string]string{
		"missing realm and mode": "provider revalidation",
		"missing mode":           "provider revalidation upstream",
		"extra argument":         "provider revalidation upstream snapshot extra",
		"empty realm":            `provider revalidation "" snapshot`,
		"empty mode":             `provider revalidation upstream ""`,
		"userinfo mode":          "provider revalidation upstream userinfo",
		"refresh-token mode":     "provider revalidation upstream refresh_token",
		"unselected realm":       "provider revalidation other snapshot",
		"duplicate":              "provider revalidation upstream snapshot\nprovider revalidation upstream snapshot",
		"nested empty":           "provider revalidation upstream snapshot {\n}",
		"nested populated":       "provider revalidation upstream snapshot {\nmode snapshot\n}",
	} {
		t.Run(name, func(t *testing.T) {
			if app, err := parseCookieApp(cookiePortalInput(tokenRefreshTestBlock(providerRefreshTestRequired + line))); err == nil || app != nil {
				t.Fatal("invalid provider renewal declaration accepted")
			}
		})
	}
	// Disabled configuration ignores semantics, but never malformed grammar.
	if _, err := parseCookieApp(cookiePortalInput(tokenRefreshTestBlock("disabled\nprovider revalidation upstream"))); err == nil {
		t.Fatal("disabled block accepted malformed provider statement")
	}
}

func TestPortalTokenRefreshProviderBlockBoundaries(t *testing.T) {
	for _, suffix := range []string{"{}", "{\n}"} {
		input := cookiePortalInput(tokenRefreshTestBlock(providerRefreshTestRequired + "provider revalidation upstream snapshot " + suffix))
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+input+"\n}"), nil)
		if err == nil || len(data) != 0 {
			t.Fatal("Caddy adapter accepted a provider statement with an empty block")
		}
	}

	// The low-level dispenser does not run Caddy's front parser, which rejects
	// an unquoted compact {} token at end of line. As an ordinary argument that
	// contains a brace, it deliberately defers shared grammar validation. It
	// must still fail before becoming usable runtime configuration.
	input := cookiePortalInput(tokenRefreshTestBlock(providerRefreshTestRequired + "provider revalidation upstream snapshot {}"))
	app, err := parseCookieApp(input)
	if err != nil || app.Config.AuthenticationPortals[0].RefreshTokens != nil || len(app.PortalTokenRefreshDirectives["portal"]) == 0 {
		t.Fatal("compact brace argument was not retained as deferred configuration")
	}
	if err := resolveProviderRefreshTestApp(t, app, nil); err == nil {
		t.Fatal("runtime resolution accepted an extra provider argument")
	}
}

func providerRefreshResolutionApp(t *testing.T, native bool, realm, mode string) *App {
	t.Helper()
	if native {
		app := tokenRefreshTestApp(t, "")
		app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{
			Enabled: true, Realms: []string{"local", realm}, PublicOrigin: "https://auth.example.test", BasePath: "/auth",
			ProviderRevalidation: []authn.TokenRefreshProviderConfig{{Realm: realm, Mode: mode}},
		}
		return app
	}
	body := "realms local " + fmt.Sprintf("%q", realm) + "\npublic origin https://auth.example.test\nbase path /auth\nprovider revalidation " + fmt.Sprintf("%q %q", realm, mode)
	return tokenRefreshTestApp(t, "cookie prefix PROVIDER\n"+tokenRefreshTestBlock(body))
}

func resolveProviderRefreshTestApp(t *testing.T, app *App, values map[string]string) error {
	t.Helper()
	managers := []SecretsManager{&oauthRuntimeSecrets{Values: values}}
	if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), managers, app.Config, nil, app.PortalTokenRefreshDirectives, nil, zap.NewNop()); err != nil {
		return err
	}
	return resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), managers, app.Config, app.PortalCookieDirectives, zap.NewNop())
}

func TestPortalTokenRefreshProviderResolution(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, source := range []string{"environment", "secrets"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, source), func(t *testing.T) {
				t.Setenv("PROVIDER_REFRESH_REALM", "upstream")
				t.Setenv("PROVIDER_REFRESH_MODE", "snapshot")
				realm, mode := "secrets:oauth:realm", "secrets:oauth:mode"
				if source == "environment" {
					realm, mode = "{env.PROVIDER_REFRESH_REALM}", "{env.PROVIDER_REFRESH_MODE}"
				}
				app := providerRefreshResolutionApp(t, native, realm, mode)
				before, err := json.Marshal(app)
				if err != nil {
					t.Fatal(err)
				}
				var restored App
				if err := json.Unmarshal(before, &restored); err != nil {
					t.Fatal(err)
				}
				statements, _ := json.Marshal(restored.PortalTokenRefreshDirectives)
				cookies, _ := json.Marshal(restored.PortalCookieDirectives)
				if err := resolveProviderRefreshTestApp(t, &restored, map[string]string{"realm": "upstream", "mode": "snapshot"}); err != nil {
					t.Fatal(err)
				}
				cfg := restored.Config.AuthenticationPortals[0].RefreshTokens
				if diff := cmp.Diff([]authn.TokenRefreshProviderConfig{{Realm: "upstream", Mode: "snapshot"}}, cfg.ProviderRevalidation); diff != "" {
					t.Fatal(diff)
				}
				if diff := cmp.Diff([]string{"local", "upstream"}, cfg.Realms); diff != "" {
					t.Fatal(diff)
				}
				afterStatements, _ := json.Marshal(restored.PortalTokenRefreshDirectives)
				afterCookies, _ := json.Marshal(restored.PortalCookieDirectives)
				if string(statements) != string(afterStatements) || string(cookies) != string(afterCookies) {
					t.Fatal("provider resolution mutated saved directive snapshots")
				}
				if !native && restored.Config.AuthenticationPortals[0].CookieConfig.RefreshTokenCookieName != "PROVIDER_REFRESH_TOKEN" {
					t.Fatal("provider resolution lost deferred cookie coordination")
				}
			})
		}
	}
}

func TestPortalTokenRefreshProviderExactReplacement(t *testing.T) {
	t.Setenv("PROVIDER_REFRESH_SECOND_PASS", "unexpected")
	for _, native := range []bool{false, true} {
		for _, realm := range []string{"corp, west", "literal-{env.PROVIDER_REFRESH_SECOND_PASS}"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, realm), func(t *testing.T) {
				app := providerRefreshResolutionApp(t, native, "secrets:oauth:realm", "secrets:oauth:mode")
				if err := resolveProviderRefreshTestApp(t, app, map[string]string{"realm": realm, "mode": "snapshot"}); err != nil {
					t.Fatal(err)
				}
				cfg := app.Config.AuthenticationPortals[0].RefreshTokens
				if len(cfg.Realms) != 2 || cfg.Realms[1] != realm || cfg.ProviderRevalidation[0].Realm != realm {
					t.Fatal("replacement was split, normalized or expanded twice")
				}
			})
		}
		for _, mode := range []string{"", "snapshot extra", "snapshot\nrealms local", "snapshot\x00", "snapshot\t", "snapshot\u00a0", "{env.PROVIDER_REFRESH_SECOND_PASS}", "userinfo"} {
			t.Run(fmt.Sprintf("native=%t/invalid-mode-%x", native, mode), func(t *testing.T) {
				app := providerRefreshResolutionApp(t, native, "secrets:oauth:realm", "secrets:oauth:mode")
				if err := resolveProviderRefreshTestApp(t, app, map[string]string{"realm": "upstream", "mode": mode}); err == nil {
					t.Fatal("invalid provider mode replacement accepted")
				}
			})
		}
	}
}

func TestPortalTokenRefreshProviderResolvedRejections(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, failure := range []string{"duplicate provider", "unselected provider", "missing secret", "empty realm"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, failure), func(t *testing.T) {
				app := providerRefreshResolutionApp(t, native, "secrets:oauth:realm", "secrets:oauth:mode")
				values := map[string]string{"realm": "upstream", "mode": "snapshot", "second": "upstream"}
				switch failure {
				case "duplicate provider":
					if native {
						cfg := app.Config.AuthenticationPortals[0].RefreshTokens
						cfg.ProviderRevalidation = append(cfg.ProviderRevalidation, authn.TokenRefreshProviderConfig{Realm: "secrets:oauth:second", Mode: "snapshot"})
					} else {
						app.PortalTokenRefreshDirectives["portal"] = append(app.PortalTokenRefreshDirectives["portal"], "provider revalidation secrets:oauth:second snapshot")
					}
				case "unselected provider":
					if native {
						app.Config.AuthenticationPortals[0].RefreshTokens.Realms = []string{"local"}
					} else {
						for i, line := range app.PortalTokenRefreshDirectives["portal"] {
							if strings.HasPrefix(line, "realms ") {
								app.PortalTokenRefreshDirectives["portal"][i] = "realms local"
							}
						}
					}
				case "missing secret":
					delete(values, "mode")
				case "empty realm":
					values["realm"] = ""
				}
				if err := resolveProviderRefreshTestApp(t, app, values); err == nil {
					t.Fatal("invalid resolved provider selection accepted")
				}
			})
		}
	}
}

func TestPortalTokenRefreshProviderDisabledResolution(t *testing.T) {
	t.Setenv("DISABLED_PROVIDER_SECOND_PASS", "snapshot")
	app := providerRefreshResolutionApp(t, true, "secrets:oauth:realm", "secrets:oauth:mode")
	cfg := app.Config.AuthenticationPortals[0].RefreshTokens
	cfg.Enabled = false
	cfg.Realms = nil
	const realm = "not-selected-{env.DISABLED_PROVIDER_SECOND_PASS}"
	const mode = "{env.DISABLED_PROVIDER_SECOND_PASS}"
	if err := resolveProviderRefreshTestApp(t, app, map[string]string{"realm": realm, "mode": mode}); err != nil {
		t.Fatal("disabled native provider settings lost opt-out semantics", err)
	}
	if cfg.Enabled || cfg.ProviderRevalidation[0] != (authn.TokenRefreshProviderConfig{Realm: realm, Mode: mode}) {
		t.Fatal("disabled native provider references were skipped or expanded twice")
	}
	// Disabled native settings retain ignored values; deferred statements still
	// obey the shared grammar after replacement, including the supported mode.
	deferred := tokenRefreshTestApp(t, tokenRefreshTestBlock("disabled\nprovider revalidation upstream secrets:oauth:mode"))
	if err := resolveProviderRefreshTestApp(t, deferred, map[string]string{"mode": "userinfo"}); err == nil {
		t.Fatal("disabled deferred provider bypassed shared mode grammar")
	}
}
