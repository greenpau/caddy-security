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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"go.uber.org/zap"
)

const tokenRefreshTestRequired = "realms employees contractors\npublic origin https://auth.example.test\nbase path /auth\n"

func tokenRefreshTestBlock(body string) string { return "token refresh {\n" + body + "\n}\n" }
func tokenRefreshTestApp(t *testing.T, body string) *App {
	t.Helper()
	app, err := parseCookieApp(cookiePortalInput(body))
	if err != nil {
		t.Fatal(err)
	}
	return app
}

func TestPortalTokenRefresh(t *testing.T) {
	defaults := &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"employees", "contractors"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth", AccessLifetimeSeconds: 300, IdleTimeoutSeconds: 1800, AbsoluteTimeoutSeconds: 28800, MaxSessions: 10000, MaxRotations: 1024}
	all := *defaults
	all.CookieName = "CUSTOM_REFRESH"
	all.AccessLifetimeSeconds, all.IdleTimeoutSeconds, all.AbsoluteTimeoutSeconds = 45, 90, 240
	all.MaxSessions, all.MaxRotations, all.BodyTransportEnabled = 2, 3, true
	for _, tc := range []struct {
		name, body string
		want       *authn.TokenRefreshConfig
	}{
		{"absent", "", nil},
		{"defaults", tokenRefreshTestBlock(tokenRefreshTestRequired), defaults},
		{"zero defaults", tokenRefreshTestBlock(tokenRefreshTestRequired + "enabled\naccess lifetime 0\nidle timeout 0\nabsolute timeout 0\nmax sessions 0\nmax rotations 0\nbody transport disabled"), defaults},
		{"all fields", tokenRefreshTestBlock(tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH\naccess lifetime 45\nidle timeout 90\nabsolute timeout 240\nmax sessions 2\nmax rotations 3\nbody transport enabled"), &all},
		{"disabled", tokenRefreshTestBlock("disabled"), &authn.TokenRefreshConfig{}},
		{"disabled semantics", tokenRefreshTestBlock("disabled\ncookie name IGNORED\npublic origin http://unused\nbase path not-a-mount\nbody transport enabled\naccess lifetime -1"), &authn.TokenRefreshConfig{CookieName: "IGNORED", PublicOrigin: "http://unused", BasePath: "not-a-mount", BodyTransportEnabled: true, AccessLifetimeSeconds: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := tokenRefreshTestApp(t, tc.body)
			if diff := cmp.Diff(tc.want, app.Config.AuthenticationPortals[0].RefreshTokens); diff != "" {
				t.Fatal(diff)
			}
			// Parsing above already round-trips Caddy's app JSON. Restore and validate
			// once more to cover native typed JSON as well as a freshly parsed portal.
			b, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			var restored App
			if err := json.Unmarshal(b, &restored); err != nil {
				t.Fatal(err)
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, restored.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, restored.Config.AuthenticationPortals[0].RefreshTokens); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortalTokenRefreshRejects(t *testing.T) {
	cases := []string{
		tokenRefreshTestBlock(""), tokenRefreshTestBlock("disabled") + tokenRefreshTestBlock("disabled"),
		tokenRefreshTestBlock("") + tokenRefreshTestBlock("disabled"),
		"token refresh extra {\ndisabled\n}", "token other {\ndisabled\n}", "token refresh", "token refresh \"{\"\ndisabled\n}",
		tokenRefreshTestBlock("disabled {\nrealms ignored\n}"), "token refresh {\ndisabled\n} realms ignored",
		"token refresh {\nrealms }\n", "token refresh {\ndisabled\ncookie name \"}\"\n",
	}
	for _, line := range []string{
		"mystery value", "enabled true", "disabled false", "enabled\ndisabled", "base_path /auth", "max_sessions 1", "store distributed",
		"body transport true", "body transport false", "body transport 0", "body transport 1", "body transport on",
		"access lifetime 1m", "max sessions 999999999999999999999999", "max rotations -1", "idle timeout -1",
		"realms", `realms ""`, `cookie name ""`, `cookie name " "`, "cookie name", "cookie name one two", `"body transport" enabled`,
		`cookie name "bad name"`, `cookie name "NAME;"`, "cookie name __Host-REFRESH", "absolute timeout 2592001",
	} {
		cases = append(cases, tokenRefreshTestBlock(tokenRefreshTestRequired+line))
	}
	for _, line := range []string{"realms employees", "public origin https://auth.example.test", "base path /auth", "cookie name REFRESH", "access lifetime 30", "idle timeout 90", "absolute timeout 240", "body transport enabled", "max sessions 1", "max rotations 2", "enabled", "disabled"} {
		cases = append(cases, tokenRefreshTestBlock(tokenRefreshTestRequired+line+"\n"+line))
	}
	for _, field := range []string{"realms", "public origin", "base path", "cookie name", "access lifetime", "idle timeout", "absolute timeout", "body transport", "max sessions", "max rotations"} {
		// Keep every unrelated required field valid so optional argument tests
		// cannot pass merely because the origin, mount or realms were omitted.
		base := ""
		for _, line := range strings.Split(strings.TrimSpace(tokenRefreshTestRequired), "\n") {
			if !strings.HasPrefix(line, field+" ") {
				base += line + "\n"
			}
		}
		for _, args := range []string{"", ` ""`, ` value ""`} {
			cases = append(cases, tokenRefreshTestBlock(base+field+args))
		}
		if field != "realms" {
			cases = append(cases, tokenRefreshTestBlock(base+field+" one two"))
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(tokenRefreshTestRequired), "\n") {
		cases = append(cases, tokenRefreshTestBlock(strings.Replace(tokenRefreshTestRequired, line+"\n", "", 1)))
	}
	for _, origin := range []string{"http://auth.example.test", "https://AUTH.example.test", "https://auth.example.test/path", "https://user@auth.example.test", "https://auth.example.test?x"} {
		cases = append(cases, tokenRefreshTestBlock(strings.Replace(tokenRefreshTestRequired, "https://auth.example.test", origin, 1)))
	}
	for _, mount := range []string{"auth", "/auth/", "/a/../auth", "/auth%2fpath", "/auth?x", "/auth;path"} {
		cases = append(cases, tokenRefreshTestBlock(strings.Replace(tokenRefreshTestRequired, "/auth\n", mount+"\n", 1)))
	}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			input := "{\n" + cookiePortalInput(body) + "\n}\n"
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if err == nil || len(data) != 0 {
				t.Fatalf("accepted malformed refresh: %s", body)
			}
		})
	}
}

func TestPortalTokenRefreshImports(t *testing.T) {
	block := tokenRefreshTestBlock(tokenRefreshTestRequired)
	file := filepath.Join(t.TempDir(), "refresh.Caddyfile")
	if err := os.WriteFile(file, []byte(block), 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{fmt.Sprintf("import %q", file), "import refresh_block"} {
		prefix := "(refresh_block) {\n" + block + "}\n"
		for _, duplicate := range []string{"", block} {
			input := prefix + "{\n" + cookiePortalInput(body+"\n"+duplicate) + "\n}\n"
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if duplicate == "" && err != nil {
				t.Fatal(err)
			}
			if duplicate != "" && (err == nil || !strings.Contains(err.Error(), "already configured")) {
				t.Fatalf("import duplicate: %v", err)
			}
		}
	}
	// Settings imported into one block retain duplicate detection too.
	if err := os.WriteFile(file, []byte("max rotations 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	body := tokenRefreshTestBlock(tokenRefreshTestRequired + fmt.Sprintf("import %q\nmax rotations 3", file))
	_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput(body)+"\n}"), nil)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("imported setting duplicate: %v", err)
	}
}

func TestPortalTokenRefreshPlaceholders(t *testing.T) {
	for _, mode := range []string{"environment", "runtime", "secrets"} {
		t.Run(mode, func(t *testing.T) {
			values := map[string]string{"REALM": "employees", "ORIGIN": "https://auth.example.test", "MOUNT": "/auth", "COOKIE": "CUSTOM_REFRESH", "ACCESS": "45", "IDLE": "90", "ABSOLUTE": "240", "BODY": "enabled", "SESSIONS": "2", "ROTATIONS": "3", "STATE": "enabled"}
			ref := func(key string) string {
				switch mode {
				case "environment":
					return "{$TOKEN_REFRESH_TEST_" + key + "}"
				case "runtime":
					return "{env.TOKEN_REFRESH_TEST_" + key + "}"
				default:
					return "secrets:oauth:" + key
				}
			}
			for k, v := range values {
				t.Setenv("TOKEN_REFRESH_TEST_"+k, v)
			}
			body := ref("STATE") + "\n"
			for _, entry := range []struct{ key, field string }{{"REALM", "realms"}, {"ORIGIN", "public origin"}, {"MOUNT", "base path"}, {"COOKIE", "cookie name"}, {"ACCESS", "access lifetime"}, {"IDLE", "idle timeout"}, {"ABSOLUTE", "absolute timeout"}, {"BODY", "body transport"}, {"SESSIONS", "max sessions"}, {"ROTATIONS", "max rotations"}} {
				body += entry.field + " " + ref(entry.key) + "\n"
			}
			input := "{\n" + cookiePortalInput(tokenRefreshTestBlock(body)) + "\n}"
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Apps struct {
					Security App `json:"security"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			app := &doc.Apps.Security
			original, _ := json.Marshal(app.PortalTokenRefreshDirectives)
			if mode != "environment" && app.Config.AuthenticationPortals[0].RefreshTokens != nil {
				t.Fatal("unresolved config attached")
			}
			if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: values}}, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			want := &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"employees"}, PublicOrigin: values["ORIGIN"], BasePath: "/auth", CookieName: "CUSTOM_REFRESH", AccessLifetimeSeconds: 45, IdleTimeoutSeconds: 90, AbsoluteTimeoutSeconds: 240, BodyTransportEnabled: true, MaxSessions: 2, MaxRotations: 3}
			if diff := cmp.Diff(want, app.Config.AuthenticationPortals[0].RefreshTokens); diff != "" {
				t.Fatal(diff)
			}
			after, _ := json.Marshal(app.PortalTokenRefreshDirectives)
			if string(original) != string(after) {
				t.Fatal("mutated declarative snapshot")
			}
		})
	}
}

func TestPortalTokenRefreshRuntimeRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*App)
	}{
		{"unknown portal", func(a *App) { a.PortalTokenRefreshDirectives["missing"] = []string{"disabled"} }},
		{"duplicate portal", func(a *App) {
			a.Config.AuthenticationPortals = append(a.Config.AuthenticationPortals, a.Config.AuthenticationPortals[0])
		}},
		{"typed and directives", func(a *App) { a.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{} }},
		{"empty block", func(a *App) { a.PortalTokenRefreshDirectives["portal"] = nil }},
		{"empty statement", func(a *App) { a.PortalTokenRefreshDirectives["portal"] = []string{""} }},
		{"multiline", func(a *App) { a.PortalTokenRefreshDirectives["portal"] = []string{"disabled\nunknown value"} }},
		{"missing placeholder", func(a *App) {
			a.PortalTokenRefreshDirectives["portal"] = []string{"disabled", "cookie name {env.TOKEN_REFRESH_UNSET}"}
		}},
		{"duplicate placeholder", func(a *App) {
			a.PortalTokenRefreshDirectives["portal"] = []string{"disabled", "cookie name A", "cookie name secrets:oauth:name"}
		}},
		{"numeric overflow", func(a *App) {
			a.PortalTokenRefreshDirectives["portal"] = []string{"disabled", "max sessions secrets:oauth:overflow"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TOKEN_REFRESH_UNSET", "")
			app := tokenRefreshTestApp(t, tokenRefreshTestBlock("disabled\ncookie name secrets:oauth:name"))
			tc.change(app)
			err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": "A", "overflow": "999999999999999999999999"}}}, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop())
			if err == nil {
				t.Fatal("accepted invalid runtime refresh")
			}
		})
	}
	// A secret remains exactly one value, including record-edge whitespace, and
	// cannot turn into settings. Semantic validation must see the original value.
	for _, value := range []string{"", "NAME\nbody transport enabled", "NAME\r", "NAME\x00", "NAME\t", "NAME\u00a0", "NAME extra"} {
		t.Run(fmt.Sprintf("value %q", value), func(t *testing.T) {
			app := tokenRefreshTestApp(t, tokenRefreshTestBlock(tokenRefreshTestRequired+"cookie name secrets:oauth:name"))
			err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": value}}}, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop())
			if err == nil {
				t.Fatal("invalid replacement was accepted or normalized")
			}
		})
	}
}

func TestPortalTokenRefreshNativeJSONPlaceholders(t *testing.T) {
	app := tokenRefreshTestApp(t, "")
	app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"{env.TOKEN_REFRESH_REALM}"}, PublicOrigin: "{env.TOKEN_REFRESH_ORIGIN}", BasePath: "{env.TOKEN_REFRESH_MOUNT}", CookieName: "secrets:oauth:name"}
	t.Setenv("TOKEN_REFRESH_REALM", "employees")
	t.Setenv("TOKEN_REFRESH_ORIGIN", "https://auth.example.test")
	t.Setenv("TOKEN_REFRESH_MOUNT", "/auth")
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": "JSON_REFRESH"}}}, app.Config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	cfg := app.Config.AuthenticationPortals[0].RefreshTokens
	if cfg.Realms[0] != "employees" || cfg.PublicOrigin != "https://auth.example.test" || cfg.BasePath != "/auth" || cfg.CookieName != "JSON_REFRESH" || cfg.AccessLifetimeSeconds != 300 {
		t.Fatalf("typed config not resolved: %+v", cfg)
	}
}

func TestPortalTokenRefreshReplacementIsNotExpandedTwice(t *testing.T) {
	app := tokenRefreshTestApp(t, tokenRefreshTestBlock("disabled\ncookie name secrets:oauth:name"))
	const literal = "{env.TOKEN_REFRESH_LITERAL}"
	t.Setenv("TOKEN_REFRESH_LITERAL", "EXPANDED")
	if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": literal}}}, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if app.Config.AuthenticationPortals[0].RefreshTokens.CookieName != literal {
		t.Fatal("substituted refresh value expanded twice")
	}
}

func TestPortalTokenRefreshCookieOverrideBeforeValidation(t *testing.T) {
	t.Setenv("TOKEN_REFRESH_COOKIE_OVERRIDE", "CUSTOM_REFRESH")
	t.Setenv("TOKEN_REFRESH_COOKIE_SHARED", "SHARED_REFRESH")
	for _, tc := range []struct{ name, cookies, override, access string }{
		{"default name reused", "cookie access token name AUTHP_REFRESH_TOKEN", "CUSTOM_REFRESH", "AUTHP_REFRESH_TOKEN"},
		{"shared name reused", "cookie refresh token name SHARED_REFRESH\ncookie access token name SHARED_REFRESH", "CUSTOM_REFRESH", "SHARED_REFRESH"},
		{"legacy shared name reused", "set refresh_token cookie name SHARED_REFRESH\nset access_token cookie name SHARED_REFRESH", "CUSTOM_REFRESH", "SHARED_REFRESH"},
		{"deferred override", "cookie access token name AUTHP_REFRESH_TOKEN", "{env.TOKEN_REFRESH_COOKIE_OVERRIDE}", "AUTHP_REFRESH_TOKEN"},
		{"both deferred", "cookie refresh token name {env.TOKEN_REFRESH_COOKIE_SHARED}\ncookie access token name {env.TOKEN_REFRESH_COOKIE_SHARED}", "{env.TOKEN_REFRESH_COOKIE_OVERRIDE}", "SHARED_REFRESH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			block := tokenRefreshTestBlock(tokenRefreshTestRequired + "cookie name " + tc.override)
			for _, body := range []string{tc.cookies + "\n" + block, block + tc.cookies} {
				// parseCookieApp restores the adapted app JSON, including deferred bodies.
				app := tokenRefreshTestApp(t, body)
				before, err := json.Marshal(app.PortalCookieDirectives)
				if err != nil {
					t.Fatal(err)
				}
				if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop()); err != nil {
					t.Fatal(err)
				}
				if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err != nil {
					t.Fatal(err)
				}
				cfg := app.Config.AuthenticationPortals[0].CookieConfig
				if cfg.RefreshTokenCookieName != "CUSTOM_REFRESH" || cfg.AccessTokenCookieName != tc.access {
					t.Fatalf("wrong effective cookie names: %+v", cfg)
				}
				after, err := json.Marshal(app.PortalCookieDirectives)
				if err != nil || string(before) != string(after) {
					t.Fatal("mutated cookie directive snapshot")
				}
			}
		})
	}
}

func TestPortalTokenRefreshCookieOverrideRejects(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		for _, tc := range []struct{ name, cookies, refresh string }{
			{"disabled cannot resolve collision", "cookie access token name AUTHP_REFRESH_TOKEN", "disabled\ncookie name CUSTOM_REFRESH"},
			{"inherited collision", "cookie access token name AUTHP_REFRESH_TOKEN", tokenRefreshTestRequired},
			{"effective collision", "cookie access token name CUSTOM_REFRESH", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"unrelated collision", "cookie access token name SAME\ncookie session id name SAME", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"duplicate name", "cookie refresh token name FIRST\ncookie refresh token name SECOND", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"legacy duplicate name", "set refresh_token cookie name FIRST\ncookie refresh token name SECOND", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"duplicate prefix", "cookie prefix FIRST\ncookie prefix SECOND", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"invalid name", `cookie refresh token name "bad name"`, tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"missing name", "cookie refresh token name", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"empty name", `cookie refresh token name ""`, tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"extra name", "cookie refresh token name FIRST SECOND", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"quoted keywords", `cookie "refresh token" name FIRST`, tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
			{"unknown role", "cookie refresh name FIRST", tokenRefreshTestRequired + "cookie name CUSTOM_REFRESH"},
		} {
			t.Run(fmt.Sprintf("%s/deferred=%t", tc.name, deferred), func(t *testing.T) {
				body := tc.refresh
				if deferred {
					// Defer the entire refresh/cookie snapshot without changing semantics.
					t.Setenv("TOKEN_REFRESH_COOKIE_BODY", "disabled")
					body += "\nbody transport {env.TOKEN_REFRESH_COOKIE_BODY}"
				}
				app, err := parseCookieApp(cookiePortalInput(tc.cookies + "\n" + tokenRefreshTestBlock(body)))
				if err == nil {
					err = resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, nil, app.PortalTokenRefreshDirectives, zap.NewNop())
				}
				if err == nil {
					err = resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop())
				}
				if err == nil {
					t.Fatal("refresh override concealed invalid cookie configuration")
				}
			})
		}
	}
}

func TestPortalTokenRefreshSharedCookieArgumentsRemainExact(t *testing.T) {
	for _, mode := range []string{"literal", "environment", "secret"} {
		for _, value := range []string{"SHARED_REFRESH\t", "SHARED_REFRESH\u00a0", "SHARED_REFRESH\r"} {
			t.Run(fmt.Sprintf("%s/%q", mode, value), func(t *testing.T) {
				name := `"` + value + `"`
				switch mode {
				case "environment":
					t.Setenv("TOKEN_REFRESH_SHARED_NAME", value)
					name = "{env.TOKEN_REFRESH_SHARED_NAME}"
				case "secret":
					name = "secrets:oauth:name"
				}
				input := "cookie refresh token name " + name + "\n" + tokenRefreshTestBlock(tokenRefreshTestRequired+"cookie name CUSTOM_REFRESH")
				app, err := parseCookieApp(cookiePortalInput(input))
				if err == nil {
					err = resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": value}}}, app.Config, app.PortalCookieDirectives, zap.NewNop())
				}
				if err == nil {
					t.Fatal("invalid shared cookie name was normalized before applying refresh override")
				}
			})
		}
	}
	for _, statement := range []string{
		"cookie refresh token name SHARED_REFRESH\ncookie access token name HIDDEN",
		"cookie refresh token name SHARED_REFRESH\r\ncookie access token name HIDDEN",
		"cookie refresh token name SHARED_REFRESH\r",
	} {
		t.Run(fmt.Sprintf("snapshot/%q", statement), func(t *testing.T) {
			app := tokenRefreshTestApp(t, tokenRefreshTestBlock(tokenRefreshTestRequired+"cookie name CUSTOM_REFRESH"))
			app.PortalCookieDirectives = map[string][]string{"portal": {statement}}
			if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err == nil {
				t.Fatal("saved cookie statement hid a record or carriage return")
			}
		})
	}
}
