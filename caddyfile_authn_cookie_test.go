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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"go.uber.org/zap"
)

func parseCookieApp(input string) (*App, error) {
	parsed, err := parseCaddyfile(caddyfile.NewTestDispenser(input), nil)
	if err != nil {
		return nil, err
	}
	var app App
	err = json.Unmarshal(parsed.(httpcaddyfile.App).Value, &app)
	return &app, err
}

func cookiePortalInput(lines string) string {
	return "security {\n authentication portal portal {\n" + lines + "\n }\n}"
}

func TestPortalCookieDirectives(t *testing.T) {
	names := `cookie session id name AUTHP_SESSION_ID
 cookie redirect url name NEXT
 cookie sandbox id name CHALLENGE
 cookie id token name IDENTITY
 cookie access token name LOGIN_ACCESS
 cookie refresh token name LOGIN_REFRESH
 cookie oidc session id name LOGIN_SESSION
 cookie oidc request id name LOGIN_REQUEST`
	for _, lines := range []string{names + "\ncookie prefix PORTAL", "cookie prefix PORTAL\n" + names} {
		app, err := parseCookieApp(cookiePortalInput(lines))
		if err != nil {
			t.Fatal(err)
		}
		want := &cookie.Config{CookieNamePrefix: "PORTAL", SessionIDCookieName: "AUTHP_SESSION_ID", RefererCookieName: "NEXT", SandboxIDCookieName: "CHALLENGE", IdentityTokenCookieName: "IDENTITY", AccessTokenCookieName: "LOGIN_ACCESS", RefreshTokenCookieName: "LOGIN_REFRESH", OIDCSessionIDCookieName: "LOGIN_SESSION", OIDCRequestIDCookieName: "LOGIN_REQUEST"}
		if diff := cmp.Diff(want, app.Config.AuthenticationPortals[0].CookieConfig); diff != "" {
			t.Fatal(diff)
		}
		// Validate the typed JSON roundtrip through the public snapshot API.
		portal := app.Config.AuthenticationPortals[0]
		if err := portal.ConfigureCookies(portal.CookieConfig); err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(want, portal.CookieConfig); diff != "" {
			t.Fatal(diff)
		}
	}
	for _, prefix := range []string{"", "Portal", "__Host-PORTAL", "__Secure-PORTAL"} {
		t.Run("prefix_"+prefix, func(t *testing.T) {
			lines := ""
			if prefix != "" {
				lines = "cookie prefix " + prefix
			}
			if prefix == "__Host-PORTAL" {
				// Identity cookies always use a whoami subpath, even at root.
				lines += "\ncookie identity token name __Secure-PORTAL_ID_TOKEN"
			}
			app, err := parseCookieApp(cookiePortalInput(lines))
			if err != nil {
				t.Fatal(err)
			}
			want := cookie.NewConfig()
			if err := want.SetCookieNamePrefix(prefix); err != nil {
				t.Fatal(err)
			}
			if prefix == "__Host-PORTAL" {
				want.IdentityTokenCookieName = "__Secure-PORTAL_ID_TOKEN"
			}
			if diff := cmp.Diff(want, app.Config.AuthenticationPortals[0].CookieConfig); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortalCookieLegacyAndDomains(t *testing.T) {
	modern := `cookie prefix PORTAL
 cookie session id name FIXED
 cookie referer name NEXT
 cookie sandbox id name SANDBOX
 cookie identity token name ID
 cookie access token name ACCESS
 cookie refresh token name REFRESH
 cookie path "/app with spaces"
 cookie lifetime 3600
 cookie same site lax
 cookie insecure enabled
 cookie guess domain enabled
 cookie strip domain enabled
 cookie domain .EXAMPLE.COM
 cookie domain example.com path /domain
 cookie domain example.com lifetime 120
 cookie domain example.com samesite strict
 cookie domain example.com insecure disabled
 cookie domain example.com strip domain enabled
 cookie domain sub.example.com path /sub`
	legacy := `set session_id cookie name FIXED
 set redirect_url cookie name NEXT
 set sandbox_id cookie name SANDBOX
 set id_token cookie name ID
 set access_token cookie name ACCESS
 set refresh_token cookie name REFRESH
 set cookie name prefix portal
 cookie path "/app with spaces"
 cookie lifetime 3600
 cookie samesite lax
 cookie insecure on
 cookie guess domain
 cookie strip domain
 cookie domain .EXAMPLE.COM
 cookie example.com path /domain
 cookie example.com lifetime 120
 cookie example.com samesite strict
 cookie example.com insecure off
 cookie example.com strip domain
 cookie sub.example.com path /sub`
	a, err := parseCookieApp(cookiePortalInput(modern))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseCookieApp(cookiePortalInput(legacy))
	if err != nil {
		t.Fatal(err)
	}
	config := a.Config.AuthenticationPortals[0].CookieConfig
	if diff := cmp.Diff(config, b.Config.AuthenticationPortals[0].CookieConfig); diff != "" {
		t.Fatal(diff)
	}
	if config.Path != "/app with spaces" || config.SameSite != "Lax" || !config.Insecure || !config.GuessDomainEnabled || !config.StripDomainEnabled {
		t.Fatalf("global attributes: %+v", config)
	}
	want := map[string]*cookie.DomainConfig{
		"example.com":     {Domain: "example.com", Path: "/domain", Lifetime: 120, SameSite: "Strict", StripDomainEnabled: true},
		"sub.example.com": {Domain: "sub.example.com", Seq: 1, Path: "/sub"},
	}
	if diff := cmp.Diff(want, config.Domains); diff != "" {
		t.Fatal(diff)
	}
	// Revisiting a domain must not change its declaration priority.
	c, err := parseCookieApp(cookiePortalInput("cookie domain a.example.com\ncookie domain example.com\ncookie domain a.example.com path /a"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.AuthenticationPortals[0].CookieConfig.Domains["a.example.com"].Seq != 0 {
		t.Fatal("domain priority changed")
	}
}

func TestPortalCookieMalformedDirectives(t *testing.T) {
	cases := []string{
		`cookie`, `cookie prefix`, `cookie prefix ""`, `cookie prefix " "`,
		`cookie "session id" name SESSION`, `cookie "same site" lax`, `cookie path /a extra`,
		`cookie access token name "bad name"`, `cookie path "/bad;path"`, `cookie domain bad/domain`,
		`cookie prefix path /app`, `cookie session path /app`, `cookie lifetime many`, `cookie same site unsupported`, `cookie insecure maybe`, `cookie guess domain on`,
		`cookie domain example.com guess domain enabled`, `cookie strip path`,
		"cookie prefix A\ncookie prefix B", "set cookie name prefix a\ncookie prefix B",
		"cookie referer name A\ncookie redirect url name B", "cookie identity token name A\ncookie id token name B",
		"set access_token cookie name A\ncookie access token name B",
		"cookie session id name SAME\ncookie oidc request id name SAME",
		"cookie prefix PORTAL\ncookie access token name PORTAL_SESSION_ID",
		"cookie same site lax\ncookie samesite strict", "cookie path /a\ncookie path /a",
		"cookie domain EXAMPLE.com\ncookie domain .example.com",
		"cookie example.com samesite lax\ncookie domain .EXAMPLE.COM same site strict",
		"cookie guess domain\ncookie guess domain disabled",
		"cookie prefix __Host-PORTAL",
		"cookie access token name __Host-ACCESS\ncookie path /app",
		"cookie session id name __Host-SESSION\ncookie domain example.com",
		"cookie access token name __Secure-ACCESS\ncookie insecure enabled",
		"cookie access token name __sEcUrE-ACCESS\ncookie insecure enabled",
		"cookie example.com insecure on\ncookie domain example.com insecure disabled",
		`set session_id arbitrary cookie name`, `set set name prefix PORTAL`, `set cookie name prefix`, `set unknown cookie name UNKNOWN`,
		`cookie path "/line
break"`, "cookie domain example.com {\n path /app\n}",
		"cookie path /app {\n cookie prefix PORTAL\n}", "cookie path /app {\n}",
	}
	for _, lines := range cases {
		t.Run(lines, func(t *testing.T) {
			if _, err := parseCookieApp(cookiePortalInput(lines)); err == nil {
				t.Fatal("invalid directive accepted")
			}
		})
	}
}

func TestPortalCookieRuntimeDirectives(t *testing.T) {
	t.Setenv("COOKIE_PREFIX", "portal")
	t.Setenv("COOKIE_ACCESS", "AUTHP_ACCESS_TOKEN")
	t.Setenv("COOKIE_DOMAIN", "example.com")
	t.Setenv("COOKIE_PATH", `/a "quoted" path`)
	input := cookiePortalInput(`set access_token cookie name {env.COOKIE_ACCESS}
 set cookie name prefix {env.COOKIE_PREFIX}
 cookie domain {env.COOKIE_DOMAIN}
 cookie domain {env.COOKIE_DOMAIN} path {env.COOKIE_PATH}`)
	app, err := parseCookieApp(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.PortalCookieDirectives["portal"]) != 4 {
		t.Fatal("partial snapshot")
	}
	if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	config := app.Config.AuthenticationPortals[0].CookieConfig
	if config.CookieNamePrefix != "PORTAL" || config.OIDCRequestIDCookieName != "PORTAL_OIDC_REQUEST_ID" || config.AccessTokenCookieName != "AUTHP_ACCESS_TOKEN" || config.Domains["example.com"].Path != `/a "quoted" path` {
		t.Fatalf("resolved config: %+v", config)
	}
	// Replacement is repeatable and must not mutate declarative statements.
	if !strings.Contains(app.PortalCookieDirectives["portal"][0], "{env.COOKIE_ACCESS}") {
		t.Fatal("raw input mutated")
	}
	for _, value := range []string{"", "   ", "bad name", "a\nb", "PORTAL_SESSION_ID"} {
		t.Setenv("COOKIE_ACCESS", value)
		app, err := parseCookieApp(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err == nil {
			t.Fatal("bad resolved cookie accepted")
		}
	}
	t.Setenv("COOKIE_ACCESS", "ACCESS")
	for _, value := range []string{"", " ", "bad/domain"} {
		t.Setenv("COOKIE_DOMAIN", value)
		app, err := parseCookieApp(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err == nil {
			t.Fatal("bad resolved domain accepted")
		}
	}
	t.Setenv("COOKIE_EMPTY", "")
	for _, line := range []string{`cookie prefix "{$COOKIE_EMPTY}"`, `cookie access token name "{$COOKIE_EMPTY}"`, `cookie domain "{$COOKIE_EMPTY}"`, `cookie path "{$COOKIE_EMPTY}"`} {
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput(line)+"\n}\n:8443 {\n respond ok\n}"), nil)
		if err == nil {
			t.Fatalf("empty placeholder accepted: %s", line)
		}
	}
}

func TestPortalCookieLegacyPrefixAllRoles(t *testing.T) {
	app, err := parseCookieApp(cookiePortalInput("set cookie name prefix portal"))
	if err != nil {
		t.Fatal(err)
	}
	want := &cookie.Config{
		CookieNamePrefix:        "PORTAL",
		SessionIDCookieName:     "PORTAL_SESSION_ID",
		RefererCookieName:       "PORTAL_REDIRECT_URL",
		SandboxIDCookieName:     "PORTAL_SANDBOX_ID",
		IdentityTokenCookieName: "PORTAL_ID_TOKEN",
		AccessTokenCookieName:   "PORTAL_ACCESS_TOKEN",
		RefreshTokenCookieName:  "PORTAL_REFRESH_TOKEN",
		OIDCSessionIDCookieName: "PORTAL_OIDC_SESSION_ID",
		OIDCRequestIDCookieName: "PORTAL_OIDC_REQUEST_ID",
	}
	if diff := cmp.Diff(want, app.Config.AuthenticationPortals[0].CookieConfig); diff != "" {
		t.Fatal(diff)
	}
}

func TestPortalCookieDeferredErrors(t *testing.T) {
	t.Setenv("COOKIE_DOMAIN_ONE", "example.com")
	t.Setenv("COOKIE_DOMAIN_TWO", ".EXAMPLE.COM")
	for _, input := range []string{
		"cookie domain {env.COOKIE_DOMAIN_ONE}\ncookie domain {env.COOKIE_DOMAIN_TWO}",
		"cookie {env.COOKIE_DOMAIN_ONE} path /a\ncookie domain {env.COOKIE_DOMAIN_TWO} path /b",
	} {
		app, err := parseCookieApp(cookiePortalInput(input))
		if err != nil {
			t.Fatal(err)
		}
		if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err == nil {
			t.Fatal("duplicate resolved domain accepted")
		}
	}
	for _, directives := range []map[string][]string{
		{"missing": {"cookie prefix PORTAL"}},
		{"portal": {""}},
		{"portal": {"unrelated prefix PORTAL"}},
		{"portal": {"cookie path \"unterminated"}},
		{"portal": {"cookie path \"\""}},
	} {
		app, err := parseCookieApp(cookiePortalInput(""))
		if err != nil {
			t.Fatal(err)
		}
		if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, directives, zap.NewNop()); err == nil {
			t.Fatal("malformed deferred snapshot accepted")
		}
	}
}

func TestPortalCookieResolvedLegacyPath(t *testing.T) {
	t.Setenv("COOKIE_LITERAL_PATH", "/app {literal}")
	for _, line := range []string{
		"cookie path {env.COOKIE_LITERAL_PATH}",
		"cookie default path {env.COOKIE_LITERAL_PATH}",
		"cookie example.com path {env.COOKIE_LITERAL_PATH}",
	} {
		t.Run(line, func(t *testing.T) {
			app, err := parseCookieApp(cookiePortalInput(line))
			if err != nil {
				t.Fatal(err)
			}
			if err := resolvePortalCookieDirectives(t.Context(), caddy.NewReplacer(), nil, app.Config, app.PortalCookieDirectives, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			config := app.Config.AuthenticationPortals[0].CookieConfig
			path := config.Path
			if strings.Contains(line, "example.com") {
				path = config.Domains["example.com"].Path
			}
			if path != "/app {literal}" {
				t.Fatalf("replacement was expanded again: %q", path)
			}
		})
	}
}

func TestPortalCookieTypedDomainResolution(t *testing.T) {
	t.Setenv("COOKIE_DOMAIN_ONE", "example.com")
	t.Setenv("COOKIE_DOMAIN_TWO", "example.com")
	for _, second := range []string{"example.com", "{env.COOKIE_DOMAIN_TWO}"} {
		t.Run(second, func(t *testing.T) {
			cfg := lifecycleConfig()
			cfg.AuthenticationPortals[0].CookieConfig.Domains = map[string]*cookie.DomainConfig{
				"{env.COOKIE_DOMAIN_ONE}": {Domain: "{env.COOKIE_DOMAIN_ONE}", Path: "/private"},
				second:                    {Domain: second, Path: "/", Seq: 1},
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, cfg, zap.NewNop()); err == nil {
				t.Fatal("resolved domain collision silently overwrote an entry")
			}
		})
	}
	t.Run("distinct domains", func(t *testing.T) {
		t.Setenv("COOKIE_DOMAIN_TWO", "sub.example.com")
		t.Setenv("COOKIE_DOMAIN_PATH", "/app {literal}")
		cfg := lifecycleConfig()
		original := map[string]*cookie.DomainConfig{
			"{env.COOKIE_DOMAIN_ONE}": {Domain: "{env.COOKIE_DOMAIN_ONE}", Path: "{env.COOKIE_DOMAIN_PATH}", Lifetime: 600},
			"{env.COOKIE_DOMAIN_TWO}": {Domain: "{env.COOKIE_DOMAIN_TWO}", Path: "/sub", Seq: 1, StripDomainEnabled: true},
		}
		cfg.AuthenticationPortals[0].CookieConfig.Domains = original
		if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, cfg, zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		want := map[string]*cookie.DomainConfig{
			"example.com":     {Domain: "example.com", Path: "/app {literal}", Lifetime: 600},
			"sub.example.com": {Domain: "sub.example.com", Path: "/sub", Seq: 1, StripDomainEnabled: true},
		}
		if diff := cmp.Diff(want, cfg.AuthenticationPortals[0].CookieConfig.Domains); diff != "" {
			t.Fatal(diff)
		}
		if len(original) != 2 || original["{env.COOKIE_DOMAIN_ONE}"].Path != "{env.COOKIE_DOMAIN_PATH}" {
			t.Fatal("domain resolution modified the source map")
		}
	})
}
