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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"go.uber.org/zap"
)

const refreshStoreTestRequired = "realms local\npublic origin https://auth.example.test\nbase path /auth\n"

func refreshStoreTestAdapt(body string) (*App, error) {
	return parseCookieApp("security {\n" + body + "\n}")
}
func TestSQLiteRefreshStoreParser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "sessions, {env.LITERAL}.db")
	backend := fmt.Sprintf("token refresh store sqlite sessions {\npath %q\nmax sessions 2\nmax rotations 3\ntimeout 1000ms\n}", path)
	portal := "authentication portal portal {\n" + tokenRefreshTestBlock(refreshStoreTestRequired+"store sessions\nmax sessions 2\nmax rotations 3") + "\n}"
	for _, input := range []string{backend + "\n" + portal, portal + "\n" + backend} {
		app, err := refreshStoreTestAdapt(input)
		if err != nil {
			t.Fatal("named refresh storage adaptation failed", err)
		}
		var module SQLiteRefreshStore
		if len(app.RefreshStoreConfigs) != 1 || json.Unmarshal(app.RefreshStoreConfigs[0], &module) != nil || module.Path != path || module.Timeout != "1s" || module.MaxSessions != 2 || module.MaxRotations != 3 {
			t.Fatal("backend parser changed literal fields or normalization")
		}
		if app.Config.AuthenticationPortals[0].RefreshTokens.Store != "sessions" {
			t.Fatal("portal selection lost")
		}
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("adaptation accessed storage")
	}
	defaults, err := refreshStoreTestAdapt("token refresh store sqlite defaults {\npath /private/refresh.db\n}")
	if err != nil {
		t.Fatal(err)
	}
	var module SQLiteRefreshStore
	_ = json.Unmarshal(defaults.RefreshStoreConfigs[0], &module)
	if module.MaxSessions != 10000 || module.MaxRotations != 1024 || module.Timeout != "1s" {
		t.Fatal("public backend defaults lost")
	}
}
func TestSQLiteRefreshStoreParserRejects(t *testing.T) {
	base := "path /private/refresh.db\n"
	for i, body := range []string{"", base + "path /private/other.db", base + "timeout 1s\ntimeout 1000ms", base + "max sessions 2\nmax sessions 3", base + "max rotations 2\nmax rotations 3", base + "max sessions 0", base + "max rotations -1", base + "timeout {env.TIMEOUT}", base + "mystery sentinel", base + "path nested {\n}", "path \"\"", base + "max sessions", base + "max rotations 2 extra"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := refreshStoreTestAdapt("token refresh store sqlite sessions {\n" + body + "\n}"); err == nil {
				t.Fatal("invalid shared backend body accepted")
			}
		})
	}
	for _, input := range []string{"token refresh store sqlite", "token refresh store sqlite sessions extra {\n" + base + "}", "token refresh store absent sessions {\n" + base + "}", "token refresh sqlite sessions {\n" + base + "}", "token refresh store sqlite sessions"} {
		if _, err := refreshStoreTestAdapt(input); err == nil {
			t.Fatal("invalid backend header accepted")
		}
	}
	for _, selection := range []string{"store", "store \"\"", "store one two", "store one\nstore one", "store one {\n}", "disabled\nstore one"} {
		if _, err := parseCookieApp(cookiePortalInput(tokenRefreshTestBlock(refreshStoreTestRequired + selection))); err == nil {
			t.Fatal("invalid portal storage selection accepted")
		}
	}
	m := &SQLiteRefreshStore{Name: "unchanged", Path: "/private/unchanged.db"}
	before, _ := json.Marshal(m)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("sessions {\n" + base)); err == nil {
		t.Fatal("truncated backend accepted")
	}
	after, _ := json.Marshal(m)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected parse mutated module")
	}
}
func TestRefreshStoreResolutionParity(t *testing.T) {
	const exact = "sessions, {env.REFRESH_SECOND}"
	t.Setenv("REFRESH_SECOND", "must-not-expand")
	secrets := &oauthRuntimeSecrets{Values: map[string]string{"selection": exact}}
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprint(native), func(t *testing.T) {
			app := tokenRefreshTestApp(t, "")
			if native {
				app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Store: "secrets:oauth:selection", Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth"}
			} else {
				app = tokenRefreshTestApp(t, tokenRefreshTestBlock(refreshStoreTestRequired+"store secrets:oauth:selection"))
			}
			before, _ := json.Marshal(app)
			copied, _ := json.Marshal(app.Config)
			var resolved authcrunch.Config
			if json.Unmarshal(copied, &resolved) != nil {
				t.Fatal("cannot copy config")
			}
			if err := resolvePortalTokenRefresh(t.Context(), caddy.NewReplacer(), []SecretsManager{secrets}, &resolved, app.PortalTokenRefreshDirectives, zap.NewNop()); err != nil {
				t.Fatal("refresh selection resolution failed", err)
			}
			if resolved.AuthenticationPortals[0].RefreshTokens.Store != exact {
				t.Fatal("selection split or expanded more than once")
			}
			after, _ := json.Marshal(app)
			if !bytes.Equal(before, after) {
				t.Fatal("resolver test mutated declarative snapshot")
			}
		})
	}
	for _, value := range []string{"", " padded", "bad\nvalue", "bad\xff", strings.Repeat("a", 129)} {
		for _, native := range []bool{false, true} {
			t.Run(fmt.Sprintf("rejected/%d/%v", len(value), native), func(t *testing.T) {
				secrets := &oauthRuntimeSecrets{Values: map[string]string{"selection": value}}
				app := tokenRefreshTestApp(t, tokenRefreshTestBlock(refreshStoreTestRequired+"store secrets:oauth:selection"))
				if native {
					app.PortalTokenRefreshDirectives = nil
					app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Store: "secrets:oauth:selection", Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth"}
				}
				if err := resolvePortalTokenRefresh(t.Context(), caddy.NewReplacer(), []SecretsManager{secrets}, app.Config, app.PortalTokenRefreshDirectives, zap.NewNop()); err == nil {
					t.Fatal("invalid resolved storage reference fell back to memory")
				}
			})
		}
	}
	// Keywords are literal; resolution cannot manufacture a new setting.
	app := tokenRefreshTestApp(t, tokenRefreshTestBlock(refreshStoreTestRequired+"{env.REFRESH_KEYWORD} sessions"))
	t.Setenv("REFRESH_KEYWORD", "store")
	if err := resolvePortalTokenRefresh(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalTokenRefreshDirectives, zap.NewNop()); err == nil {
		t.Fatal("runtime keyword injection accepted")
	}
}
func TestRefreshStoreInputTextBeforeSnapshot(t *testing.T) {
	config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{Store: "bad\xff"}}}}
	if validateRefreshStoreInputText(config) == nil {
		t.Fatal("malformed native selector accepted")
	}
	app := &App{Config: config}
	err := app.Provision(caddy.Context{})
	if err == nil || !strings.Contains(err.Error(), "refresh storage selection text") {
		t.Fatal("app repaired invalid selector bytes before checking")
	}
	if config.AuthenticationPortals[0].RefreshTokens.Store != "bad\xff" {
		t.Fatal("pre-copy guard mutated input")
	}
}
func TestRefreshStoreDisabledResolution(t *testing.T) {
	for _, selected := range []bool{false, true} {
		config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", RefreshTokens: &authn.TokenRefreshConfig{PublicOrigin: "unused", BasePath: "unused"}}}}
		if selected {
			config.AuthenticationPortals[0].RefreshTokens.Store = "sessions"
		}
		err := resolvePortalTokenRefresh(t.Context(), caddy.NewReplacer(), nil, config, nil, zap.NewNop())
		if selected && err == nil || !selected && err != nil {
			t.Fatal("disabled selection semantics changed", err)
		}
	}
}
