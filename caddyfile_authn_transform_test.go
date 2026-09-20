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
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"go.uber.org/zap"
)

func TestPortalTransformSharedParser(t *testing.T) {
	for _, header := range []string{"user", "users"} {
		t.Run(header, func(t *testing.T) {
			app, err := parseCookieApp(cookiePortalInput("transform " + header + ` {
    match realm local
    field email exists
    action add role match
    add label "match value" as string
    add teams "one team" two as string list
    add nested metadata label with "literal value" as string
    add nested empty as map
    action delete org
    add obsolete cleanup as string
    action delete obsolete
    require auth challenges u2f
    require auth challenges totp if u2f not available
    require auth challenges password if u2f and totp not available
   }`))
			if err != nil {
				t.Fatal(err)
			}
			cfg := app.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
			if diff := cmp.Diff([]string{"exact match realm local", "field email exists"}, cfg.Matchers); diff != "" {
				t.Fatal(diff)
			}
			encoded, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var restored transformer.Config
			if err := json.Unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			factory, err := transformer.NewFactory([]*transformer.Config{&restored})
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct{ inventory, want []string }{
				{[]string{"password", "totp", "u2f"}, []string{"u2f"}},
				{[]string{"password", "totp"}, []string{"totp"}},
				{[]string{"password"}, []string{"password"}},
			} {
				claims := map[string]any{"realm": "local", "email": "alice@example.test", "org": []string{"old"}}
				selected, err := factory.TransformWithAuthMethods(claims, tc.inventory)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tc.want, selected); diff != "" {
					t.Fatal(diff)
				}
				want := map[string]any{"realm": "local", "email": "alice@example.test", "roles": []string{"match"}, "label": "match value", "teams": []string{"one team", "two"}, "metadata": map[string]any{"label": "literal value"}, "empty": map[string]any{}}
				if diff := cmp.Diff(want, claims); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
	for _, matcher := range []string{"match any", "field email not exists", "no exact match realm excluded"} {
		app, err := parseCookieApp(cookiePortalInput("transform user {\n" + matcher + "\nadd role member\n}"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := app.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
		if diff := cmp.Diff([]string{matcher}, cfg.Matchers); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestPortalTransformChallengeCombinations(t *testing.T) {
	for _, tc := range []struct {
		rule      string
		inventory []string
		want      []string
	}{
		{"password totp", []string{"password", "totp"}, []string{"password", "totp"}},
		{"u2f or totp or password", []string{"password", "totp"}, []string{"totp"}},
		{"u2f or totp or password", []string{"password"}, []string{"password"}},
	} {
		app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch realm local\nrequire auth challenges " + tc.rule + "\n}"))
		if err != nil {
			t.Fatal(err)
		}
		factory, err := transformer.NewFactory(app.Config.AuthenticationPortals[0].UserTransformerConfigs)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := factory.TransformWithAuthMethods(map[string]any{"realm": "local"}, tc.inventory)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(tc.want, selected); diff != "" {
			t.Fatal(diff)
		}
	}
}

func TestPortalTransformRejects(t *testing.T) {
	bodies := []string{"", "match any", "add role member", "match any\nrequire auth challenges email", "match any\nrequire auth challenges password if email not available"}
	for _, line := range []string{
		"require auth challenges", "require auth challenges password or totp u2f", "require auth challenges u2f if totp available",
		"require auth challenges sms", "require auth challenges password\nrequire auth challenges password",
		`add label "" as string`, `add role ""`, "add label one two as string", "add nested with one as string", "add label one as invented",
		"overwrite custom value", "require invented", "deny extra", "action require mfa", "unknown private-sentinel",
		"regex match email [", "field email sometimes exists",
	} {
		bodies = append(bodies, "match any\n"+line)
	}
	inputs := []string{"transform user", "transform unknown {\nmatch any\ndeny\n}", "transform user {\nmatch any {\ndeny\n}\n}", "transform user {\nmatch any\ndeny\n} deny"}
	for _, body := range bodies {
		inputs = append(inputs, "transform user {\n"+body+"\n}")
	}
	for i, input := range inputs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput(input)+"\n}"), nil)
			if err == nil || len(data) != 0 {
				t.Fatalf("accepted malformed transform %d", i)
			}
			if strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("error exposed directive value")
			}
		})
	}
}

func TestPortalTransformRuntimeValues(t *testing.T) {
	t.Setenv("TRANSFORM_TEST_ROLE", "one role")
	t.Setenv("TRANSFORM_TEST_LABEL", "literal {claims.sub}")
	app, err := parseCookieApp(cookiePortalInput(`transform user {
  match realm local
  action add role {env.TRANSFORM_TEST_ROLE}
  add label "{env.TRANSFORM_TEST_LABEL} {claims.sub}" as string
 }`))
	if err != nil {
		t.Fatal(err)
	}
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory(app.Config.AuthenticationPortals[0].UserTransformerConfigs)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"realm": "local", "sub": "alice"}
	if err := factory.Transform(claims); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(map[string]any{"realm": "local", "sub": "alice", "roles": []string{"one role"}, "label": "literal alice alice"}, claims); diff != "" {
		t.Fatal(diff)
	}
}

func TestPortalTransformRuntimeBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"empty", ""}, {"unknown placeholder", "{not.a.known.placeholder}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TRANSFORM_TEST_VALUE", tc.value)
			value := "{env.TRANSFORM_TEST_VALUE}"
			if tc.name == "unknown placeholder" {
				value = tc.value
			}
			app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch any\nadd label " + value + " as string\n}"))
			if err != nil {
				t.Fatal(err)
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err == nil {
				t.Fatal("accepted invalid transform replacement")
			}
		})
	}
	app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch any\nadd label secrets:oauth:label as string\n}"))
	if err != nil {
		t.Fatal(err)
	}
	repl := caddy.NewReplacer()
	secrets := []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"label": `one "quoted" {claims.sub}`}}}
	if err := ResolveRuntimeAppConfig(t.Context(), repl, secrets, app.Config, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory(app.Config.AuthenticationPortals[0].UserTransformerConfigs)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"sub": "alice", "exp": 1}
	if err := factory.Transform(claims); err != nil || claims["label"] != `one "quoted" alice` {
		t.Fatal("secret argument or claim template changed meaning")
	}
	if _, ok := repl.Get("claims.sub"); ok {
		t.Fatal("transform resolver changed the shared replacer")
	}
	app.Config.AuthenticationPortals[0].UI.LogoURL = "{claims.sub}"
	if err := ResolveRuntimeAppConfig(t.Context(), repl, nil, app.Config, zap.NewNop()); err == nil {
		t.Fatal("claim templates escaped the transform scope")
	}
	app.Config.AuthenticationPortals[0].UI.LogoURL = ""
	app.Config.AuthenticationPortals[0].UserTransformerConfigs[0].Actions = []string{"require auth challenges email"}
	if err := ResolveRuntimeAppConfig(t.Context(), repl, nil, app.Config, zap.NewNop()); err == nil {
		t.Fatal("native JSON bypassed transform validation")
	}
}

func TestPortalTransformMatchAnyIdentityContext(t *testing.T) {
	// Record the selected library's limitation independently of Caddy's guard.
	// Remove the restriction only after upstream and actual Caddy refresh/OP
	// flows apply the same policy with and without token timestamps present.
	app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch any\nadd label matched as string\n}"))
	if err != nil {
		t.Fatal(err)
	}
	factory, err := transformer.NewFactory(app.Config.AuthenticationPortals[0].UserTransformerConfigs)
	if err != nil {
		t.Fatal(err)
	}
	for _, timed := range []bool{false, true} {
		claims := map[string]any{"sub": "alice", "origin": "local"}
		if timed {
			claims["exp"] = 1
		}
		if err := factory.Transform(claims); err != nil {
			t.Fatal(err)
		}
		if (claims["label"] == "matched") != timed {
			t.Fatal("upstream match-any contract changed; requalify and remove the compatibility guard")
		}
	}
	for _, mode := range []string{"absent", "disabled", "refresh", "oidc", "both", "system", "resolved system", "signing", "defaults"} {
		t.Run(mode, func(t *testing.T) {
			app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch any\nadd label matched as string\n}"))
			if err != nil {
				t.Fatal(err)
			}
			p := app.Config.AuthenticationPortals[0]
			switch mode {
			case "system":
				p.AddRawCryptoKeyStoreConfig("crypto key internal system " + strings.Repeat("a", 64))
			case "resolved system":
				t.Setenv("TRANSFORM_TEST_KEY_USAGE", "system")
				p.AddRawCryptoKeyStoreConfig("crypto key internal {env.TRANSFORM_TEST_KEY_USAGE} " + strings.Repeat("a", 64))
			case "signing":
				p.AddRawCryptoKeyStoreConfig(`crypto key internal sign-verify "synthetic system key"`)
			case "defaults":
				p.AddRawCryptoKeyStoreConfig("crypto default autogenerate algorithm EdDSA")
			}
			if mode != "absent" {
				p.RefreshTokens = &authn.TokenRefreshConfig{Enabled: mode == "refresh" || mode == "both", Realms: []string{"local"}, PublicOrigin: "https://example.test", BasePath: "/auth"}
				p.OIDCProvider = &authn.OIDCProviderConfig{Enabled: mode == "oidc" || mode == "both"}
			}
			// Exercise the same exported resolution entry point used by native JSON.
			err = ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop())
			if mode == "absent" || mode == "disabled" || mode == "signing" || mode == "defaults" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported") {
				t.Fatalf("unsupported combination escaped the guard: %v", err)
			}
		})
	}
}

func TestPortalTransformMatchAnyEncoding(t *testing.T) {
	t.Setenv("TRANSFORM_TEST_MATCHER", "match any")
	for _, matcher := range []string{"match any", `"match" "any"`, `"match any"`, "{env.TRANSFORM_TEST_MATCHER}"} {
		for _, mode := range []string{"access", "refresh", "oidc", "system"} {
			t.Run(mode+"/"+matcher, func(t *testing.T) {
				app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch any\nadd label matched as string\n}"))
				if err != nil {
					t.Fatal(err)
				}
				p := app.Config.AuthenticationPortals[0]
				// Native JSON can encode a condition as one quoted argument. The
				// upstream ACL joins decoded arguments before recognizing match any.
				p.UserTransformerConfigs[0].Matchers = []string{matcher}
				switch mode {
				case "refresh":
					p.RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://example.test", BasePath: "/auth"}
				case "oidc":
					p.OIDCProvider = &authn.OIDCProviderConfig{Enabled: true}
				case "system":
					p.AddRawCryptoKeyStoreConfig("crypto key internal system " + strings.Repeat("a", 64))
				}
				err = ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop())
				if mode != "access" {
					if err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported") {
						t.Fatalf("encoded unconditional matcher escaped %s guard: %v", mode, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				factory, err := transformer.NewFactory(p.UserTransformerConfigs)
				if err != nil {
					t.Fatal(err)
				}
				for _, timed := range []bool{false, true} {
					claims := map[string]any{"sub": "alice"}
					if timed {
						claims["exp"] = 1
					}
					if err := factory.Transform(claims); err != nil {
						t.Fatal(err)
					}
					if (claims["label"] == "matched") != timed {
						t.Fatal("encoded matcher no longer has the upstream timestamp limitation")
					}
				}
			})
		}
	}
}

func TestPortalTransformRuntimeRejectsMultilineInstructions(t *testing.T) {
	for _, field := range []string{"action", "matcher"} {
		for _, newline := range []string{"\n", "\r", "\r\n"} {
			t.Run(fmt.Sprintf("%s/%q", field, newline), func(t *testing.T) {
				app, err := parseCookieApp(cookiePortalInput("transform user {\nmatch realm local\nadd role member\n}"))
				if err != nil {
					t.Fatal(err)
				}
				cfg := app.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
				if field == "action" {
					cfg.Actions[0] += newline + "require auth challenges totp"
				} else {
					cfg.Matchers[0] += newline + "match email private-sentinel"
				}
				if _, err := transformparser.CompileUserTransformerConfig(cfg); err == nil {
					t.Fatal("test did not violate the shared single-line instruction contract")
				}
				err = ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop())
				if err == nil || !strings.Contains(err.Error(), "instructions must be single-line") {
					t.Fatalf("multiline %s did not fail before CSV normalization: %v", field, err)
				}
				if strings.Contains(err.Error(), "private-sentinel") {
					t.Fatal("invalid instruction leaked its value")
				}
			})
		}
	}
}
