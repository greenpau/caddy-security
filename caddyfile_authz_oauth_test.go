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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"go.uber.org/zap"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
)

func TestParseAuthorizationOAuth(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		invalid    bool
	}{
		{"minimal", "use oauth identity provider upstream", false},
		{"all", `use oauth identity provider upstream
oauth public origin https://app.example.test
oauth base path /private/oauth
oauth session cookie name __Host-SESSION
oauth login cookie name __Host-LOGIN
oauth session lifetime 600
oauth maximum sessions 200
oauth maximum pending logins 20
validate method path`, false},
		{"duplicate", "use oauth identity provider upstream\nuse oauth identity provider other", true},
		{"missing provider", "oauth session lifetime 600", true},
		{"extra", "use oauth identity provider upstream sentinel-secret", true},
		{"invalid origin", "use oauth identity provider upstream\noauth public origin sentinel-secret", true},
		{"unknown", "use oauth identity provider upstream\noauth sentinel-secret value", true},
		{"nested empty", "use oauth identity provider upstream {\n}", true},
		{"jwt incompatible", "use oauth identity provider upstream\ncrypto key verify sentinel-secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser("authorization policy direct {\n" + tc.body + "\nallow roles authp/user\n}")
			d.Next()
			cfg := authcrunch.NewConfig()
			err := parseCaddyfileAuthorization(d, &App{Config: cfg})
			if tc.invalid {
				if err == nil || strings.Contains(err.Error(), "sentinel-secret") {
					t.Fatalf("expected redacted error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.AuthorizationPolicies[0]
			if p.OAuth == nil || p.OAuth.IdentityProvider != "upstream" || p.SessionIDCookieName != "" || len(p.AccessTokenCookieNames) != 0 {
				t.Fatal("incorrect direct policy mapping")
			}
			if tc.name == "all" && (!p.ValidateMethodPath || p.ValidateAccessListPathClaim || p.OAuth.SessionLifetime != 600 || p.OAuth.MaxSessions != 200) {
				t.Fatal("lost independent OAuth/ACL settings")
			}
		})
	}
}

func directOAuthTestApp(t *testing.T, body string) *App {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n security {\n"+body+"\n}\n}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Apps struct{ Security *App } }
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Apps.Security
}

func directOAuthPolicy(body string) string {
	return "authorization policy direct {\n" + body + "\nallow roles authp/user\n}"
}

func TestAuthorizationOAuthStatementBoundaries(t *testing.T) {
	for _, body := range []string{
		`use oauth identity provider upstream ""`,
		`use oauth identity provider ""`,
		`use "oauth identity" provider upstream`,
		"use oauth identity provider upstream\noauth session lifetime 0",
		"use oauth identity provider upstream\noauth session lifetime 86401",
		"use oauth identity provider upstream\noauth maximum sessions 65537",
		"use oauth identity provider upstream\noauth maximum pending logins -1",
		"use oauth identity provider upstream\noauth maximum sessions 99999999999999999999",
		"use oauth identity provider upstream\noauth base path \"/app with spaces\"",
		"use oauth identity provider upstream\noauth session cookie name \"SESSION\t\"",
		"use oauth identity provider upstream\noauth session cookie name S\noauth login cookie name S",
		"use oauth identity provider upstream\noauth public origin https://app.example/path",
		"use oauth identity provider upstream\noauth base path /app {\n ignored value\n}",
		"use oauth identity provider upstream\nvalidate bearer header",
	} {
		t.Run(body, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(directOAuthPolicy(body))
			d.Next()
			if err := parseCaddyfileAuthorization(d, &App{Config: authcrunch.NewConfig()}); err == nil {
				t.Fatal("invalid statement accepted")
			}
		})
	}
	fields := []string{"use oauth identity provider upstream", "oauth public origin https://app.example", "oauth base path /app", "oauth session cookie name SESSION", "oauth login cookie name LOGIN", "oauth session lifetime 30", "oauth maximum sessions 2", "oauth maximum pending logins 2"}
	for _, field := range fields {
		t.Run("duplicate/"+field, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(directOAuthPolicy(strings.Join(fields, "\n") + "\n" + field))
			d.Next()
			if err := parseCaddyfileAuthorization(d, &App{Config: authcrunch.NewConfig()}); err == nil {
				t.Fatal("duplicate accepted")
			}
		})
	}
	app := directOAuthTestApp(t, directOAuthPolicy(""))
	if app.Config.AuthorizationPolicies[0].OAuth != nil || len(app.OAuthAuthorizationDirectives) != 0 {
		t.Fatal("omitted OAuth enabled")
	}
}

func TestAuthorizationOAuthRuntime(t *testing.T) {
	values := map[string]string{"provider": "upstream", "origin": "https://app.example.test", "base": "/private/oauth", "session": "__Host-SESSION", "login": "__Host-LOGIN", "lifetime": "600", "sessions": "200", "pending": "20"}
	body := `use oauth identity provider PROVIDER
oauth public origin ORIGIN
oauth base path BASE
oauth session cookie name SESSION
oauth login cookie name LOGIN
oauth session lifetime LIFETIME
oauth maximum sessions SESSIONS
oauth maximum pending logins PENDING`
	for _, mode := range []string{"environment", "placeholder", "secret"} {
		t.Run(mode, func(t *testing.T) {
			replacements := []string{}
			// Replace longer markers first (SESSION is a prefix of SESSIONS).
			for _, key := range []string{"provider", "origin", "base", "sessions", "session", "login", "lifetime", "pending"} {
				t.Setenv("DIRECT_OAUTH_"+strings.ToUpper(key), values[key])
				token := "secrets:oauth:" + key
				if mode == "placeholder" {
					token = "{env.DIRECT_OAUTH_" + strings.ToUpper(key) + "}"
				}
				if mode == "environment" {
					token = "{$DIRECT_OAUTH_" + strings.ToUpper(key) + "}"
				}
				replacements = append(replacements, strings.ToUpper(key), token)
			}
			app := directOAuthTestApp(t, directOAuthPolicy(strings.NewReplacer(replacements...).Replace(body)))
			before, _ := json.Marshal(app.OAuthAuthorizationDirectives)
			if mode != "environment" && (app.Config.AuthorizationPolicies[0].OAuth != nil || len(app.OAuthAuthorizationDirectives["direct"]) != 8) {
				t.Fatal("lost complete deferred body")
			}
			err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: values}}, app.Config, nil, nil, app.OAuthAuthorizationDirectives, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			want := &authz.OAuthAuthorizationConfig{IdentityProvider: "upstream", PublicOrigin: values["origin"], BasePath: values["base"], SessionCookieName: values["session"], LoginCookieName: values["login"], SessionLifetime: 600, MaxSessions: 200, MaxPendingLogins: 20}
			if diff := cmp.Diff(want, app.Config.AuthorizationPolicies[0].OAuth); diff != "" {
				t.Fatal(diff)
			}
			after, _ := json.Marshal(app.OAuthAuthorizationDirectives)
			if string(before) != string(after) {
				t.Fatal("mutated declarative statements")
			}
		})
	}
}

func TestAuthorizationOAuthRuntimeRejects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*App)
	}{
		{"unknown target", func(a *App) {
			a.OAuthAuthorizationDirectives["missing"] = []string{"use oauth identity provider upstream"}
		}},
		{"duplicate target", func(a *App) {
			a.Config.AuthorizationPolicies = append(a.Config.AuthorizationPolicies, a.Config.AuthorizationPolicies[0])
		}},
		{"typed conflict", func(a *App) {
			a.Config.AuthorizationPolicies[0].OAuth = &authz.OAuthAuthorizationConfig{IdentityProvider: "upstream"}
		}},
		{"empty", func(a *App) { a.OAuthAuthorizationDirectives["direct"] = nil }},
		{"multiline", func(a *App) {
			a.OAuthAuthorizationDirectives["direct"] = []string{"use oauth identity provider upstream\noauth unknown value"}
		}},
		{"nul", func(a *App) {
			a.OAuthAuthorizationDirectives["direct"] = []string{"use oauth identity provider upstream\x00"}
		}},
		{"duplicate", func(a *App) {
			a.OAuthAuthorizationDirectives["direct"] = append(a.OAuthAuthorizationDirectives["direct"], "oauth session cookie name SECOND")
		}},
		{"unknown", func(a *App) {
			a.OAuthAuthorizationDirectives["direct"] = append(a.OAuthAuthorizationDirectives["direct"], "oauth unknown setting")
		}},
		{"empty token", func(a *App) {
			a.OAuthAuthorizationDirectives["direct"] = append(a.OAuthAuthorizationDirectives["direct"], `oauth session lifetime ""`)
		}},
		{"typed key conflict", func(a *App) {
			a.Config.AuthorizationPolicies[0].CryptoKeyStoreConfig = &kms.CryptoKeyStoreConfig{TokenName: "custom"}
		}},
		{"bearer conflict", func(a *App) { a.Config.AuthorizationPolicies[0].ValidateBearerHeader = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := directOAuthTestApp(t, directOAuthPolicy("use oauth identity provider upstream\noauth session cookie name secrets:oauth:name"))
			tc.mutate(app)
			err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": "SESSION"}}}, app.Config, nil, nil, app.OAuthAuthorizationDirectives, zap.NewNop())
			if err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
	for i, value := range []string{"", "S\nuse oauth identity provider evil", "S\x00", "S\t", "S\u00a0", "S extra"} {
		t.Run(fmt.Sprint("value/", i), func(t *testing.T) {
			app := directOAuthTestApp(t, directOAuthPolicy("use oauth identity provider upstream\noauth session cookie name secrets:oauth:name"))
			err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"name": value}}}, app.Config, nil, nil, app.OAuthAuthorizationDirectives, zap.NewNop())
			if err == nil {
				t.Fatal("invalid replacement normalized or accepted")
			}
		})
	}
}

func TestAuthorizationOAuthRootValidation(t *testing.T) {
	provider := `oauth identity provider upstream {
 realm upstream
 driver linkedin
 client_id synthetic-client
 client_secret synthetic-secret
}`
	for _, reverse := range []bool{false, true} {
		input := directOAuthPolicy("use oauth identity provider upstream") + "\n" + provider
		if reverse {
			input = provider + "\n" + directOAuthPolicy("use oauth identity provider upstream")
		}
		if err := directOAuthTestApp(t, input).Config.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*App)
	}{
		{"missing", func(a *App) { a.Config.IdentityProviders = nil }},
		{"disabled", func(a *App) { a.Config.AddDisabledIdentityProvider("upstream") }},
		{"wrong kind", func(a *App) {
			a.Config.IdentityProviders = []*idp.IdentityProviderConfig{{Name: "upstream", Kind: "saml"}}
		}},
		{"duplicate", func(a *App) {
			a.Config.IdentityProviders = append(a.Config.IdentityProviders, a.Config.IdentityProviders[0])
		}},
		{"cookie collision", func(a *App) {
			q := *a.Config.AuthorizationPolicies[0]
			o := *q.OAuth
			q.Name = "second"
			q.OAuth = &o
			o.BasePath = "/second"
			a.Config.AuthorizationPolicies = append(a.Config.AuthorizationPolicies, &q)
		}},
		{"callback collision", func(a *App) {
			q := *a.Config.AuthorizationPolicies[0]
			o := *q.OAuth
			q.Name = "second"
			q.OAuth = &o
			o.SessionCookieName = "S"
			o.LoginCookieName = "L"
			a.Config.AuthorizationPolicies = append(a.Config.AuthorizationPolicies, &q)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := directOAuthTestApp(t, provider+"\n"+directOAuthPolicy("use oauth identity provider upstream"))
			tc.mutate(a)
			if err := a.Config.Validate(); err == nil {
				t.Fatal("invalid policy reference/collision accepted")
			}
		})
	}
}

func TestAuthorizationOAuthNativeJSON(t *testing.T) {
	t.Setenv("DIRECT_JSON_PROVIDER", "upstream")
	t.Setenv("DIRECT_JSON_ORIGIN", "https://app.example.test")
	app := directOAuthTestApp(t, directOAuthPolicy(""))
	app.Config.AuthorizationPolicies[0].OAuth = &authz.OAuthAuthorizationConfig{IdentityProvider: "{env.DIRECT_JSON_PROVIDER}", PublicOrigin: "{env.DIRECT_JSON_ORIGIN}", BasePath: "secrets:oauth:base", SessionCookieName: "secrets:oauth:session", LoginCookieName: "secrets:oauth:login", SessionLifetime: 30, MaxSessions: 2, MaxPendingLogins: 3}
	values := map[string]string{"base": "/app/oauth", "session": "APP_SESSION", "login": "APP_LOGIN"}
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: values}}, app.Config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	want := &authz.OAuthAuthorizationConfig{IdentityProvider: "upstream", PublicOrigin: "https://app.example.test", BasePath: "/app/oauth", SessionCookieName: "APP_SESSION", LoginCookieName: "APP_LOGIN", SessionLifetime: 30, MaxSessions: 2, MaxPendingLogins: 3}
	if diff := cmp.Diff(want, app.Config.AuthorizationPolicies[0].OAuth); diff != "" {
		t.Fatal(diff)
	}
}
