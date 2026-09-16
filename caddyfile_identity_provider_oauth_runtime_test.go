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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
)

// This module exposes synthetic fixture values only; GetConfig never returns them.
type oauthRuntimeSecrets struct {
	Values map[string]string `json:"values"`
}

func (*oauthRuntimeSecrets) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.secrets.oauth_test", New: func() caddy.Module { return new(oauthRuntimeSecrets) }}
}
func (*oauthRuntimeSecrets) GetConfig(context.Context) map[string]any {
	return map[string]any{"id": "oauth"}
}
func (*oauthRuntimeSecrets) GetSecret(context.Context) (map[string]any, error) { return nil, nil }
func (s *oauthRuntimeSecrets) GetSecretByKey(_ context.Context, key string) (any, error) {
	if value, ok := s.Values[key]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("unknown synthetic OAuth secret")
}
func init() { caddy.RegisterModule(&oauthRuntimeSecrets{}) }

func oauthRuntimeTestApp(t *testing.T, body string) *App {
	t.Helper()
	input := "{\n security {\n oauth identity provider upstream {\n" + body + "\n}\n}\n}"
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps struct {
			Security *App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document.Apps.Security
}

func TestOAuthRuntimeDriverDefaults(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		values     map[string]string
		want       map[string]any
	}{
		{"google secret client ID", "driver google\nclient_id secrets:oauth:client", map[string]string{"client": "complete.apps.googleusercontent.com"}, map[string]any{"client_id": "complete.apps.googleusercontent.com"}},
		{"google short secret client ID", "driver google\nclient_id secrets:oauth:client", map[string]string{"client": "short"}, map[string]any{"client_id": "short.apps.googleusercontent.com"}},
		{"nextcloud secret base URL", "driver nextcloud\nclient_id client\nbase_auth_url secrets:oauth:base", map[string]string{"base": "https://nextcloud.example"}, map[string]any{"authorization_url": "https://nextcloud.example/apps/oauth2/authorize", "token_url": "https://nextcloud.example/apps/oauth2/api/v1/token"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := oauthRuntimeTestApp(t, "realm upstream\nclient_secret secret\n"+tc.body)
			original, err := json.Marshal(app.OAuthProviderDirectives)
			if err != nil {
				t.Fatal(err)
			}
			if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: tc.values}}, app.Config, app.OAuthProviderDirectives, nil, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(app.OAuthProviderDirectives)
			if err != nil {
				t.Fatal(err)
			}
			if string(original) != string(after) {
				t.Fatal("runtime resolution mutated declarative statements")
			}
			for key, want := range tc.want {
				if diff := cmp.Diff(want, app.Config.IdentityProviders[0].Params[key]); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
}

func TestOAuthRuntimeSnapshotValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*App)
	}{
		{"unknown provider", func(app *App) { app.OAuthProviderDirectives["missing"] = app.OAuthProviderDirectives["upstream"] }},
		{"duplicate provider", func(app *App) {
			app.Config.IdentityProviders = append(app.Config.IdentityProviders, app.Config.IdentityProviders[0])
		}},
		{"wrong kind", func(app *App) { app.Config.IdentityProviders[0].Kind = "saml" }},
		{"unsupported target parameter", func(app *App) { app.Config.IdentityProviders[0].Params["logout_url"] = "https://example.test/logout" }},
		{"empty snapshot", func(app *App) { app.OAuthProviderDirectives["upstream"] = nil }},
		{"empty statement", func(app *App) {
			app.OAuthProviderDirectives["upstream"] = append(app.OAuthProviderDirectives["upstream"], "")
		}},
		{"multiline statement", func(app *App) {
			app.OAuthProviderDirectives["upstream"] = append(app.OAuthProviderDirectives["upstream"], "issuer exact\nnonce disabled")
		}},
		{"duplicate alias", func(app *App) {
			app.OAuthProviderDirectives["upstream"] = append(app.OAuthProviderDirectives["upstream"], "client id duplicate")
		}},
		{"typed-only logout URL", func(app *App) {
			app.OAuthProviderDirectives["upstream"] = append(app.OAuthProviderDirectives["upstream"], "logout_url https://example.test/logout")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := oauthRuntimeTestApp(t, strings.Replace(oauthParserBase, "client_secret synthetic-secret", "client_secret secrets:oauth:secret", 1))
			tc.change(app)
			before, err := json.Marshal(app.Config.IdentityProviders)
			if err != nil {
				t.Fatal(err)
			}
			if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"secret": "synthetic-secret"}}}, app.Config, app.OAuthProviderDirectives, nil, zap.NewNop()); err == nil {
				t.Fatal("invalid OAuth snapshot accepted")
			}
			after, err := json.Marshal(app.Config.IdentityProviders)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("invalid OAuth snapshot partially replaced provider")
			}
		})
	}
}

func TestOAuthRuntimeExactValues(t *testing.T) {
	for _, value := range []string{"  exact value\t", `literal-{env.DO_NOT_EXPAND}`, `quote " and comma,`, "issuer\u2003"} {
		app := oauthRuntimeTestApp(t, oauthParserBase+"issuer secrets:oauth:issuer")
		if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"issuer": value}}}, app.Config, app.OAuthProviderDirectives, nil, zap.NewNop()); err != nil {
			t.Fatal(err)
		}
		if app.Config.IdentityProviders[0].Params["issuer"] != value {
			t.Fatal("resolved issuer changed or expanded twice")
		}
	}
	for _, value := range []string{"", " ", "bad\nvalue", "bad\x00value", "bad\xffvalue"} {
		app := oauthRuntimeTestApp(t, oauthParserBase+"issuer secrets:oauth:issuer")
		if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"issuer": value}}}, app.Config, app.OAuthProviderDirectives, nil, zap.NewNop()); err == nil {
			t.Fatal("invalid replacement accepted")
		}
	}
}
