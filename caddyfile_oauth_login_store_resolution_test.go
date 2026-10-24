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
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"go.uber.org/zap"
)

func oauthLoginStoreResolutionClone(t *testing.T, source *App) *App {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal("cannot snapshot OAuth configuration")
	}
	var copy App
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("cannot copy OAuth configuration")
	}
	return &copy
}

func oauthLoginStoreResolvedSelection(t *testing.T, app *App) *oauth.LoginStoreConfig {
	t.Helper()
	if app.Config == nil || len(app.Config.IdentityProviders) != 1 {
		t.Fatal("resolution lost the selected OAuth provider")
	}
	raw, err := json.Marshal(app.Config.IdentityProviders[0].Params)
	var provider oauth.Config
	if err != nil || json.Unmarshal(raw, &provider) != nil || provider.LoginStore == nil || provider.LoginStore.Validate() != nil {
		t.Fatal("resolution did not produce a valid typed storage selection")
	}
	return provider.LoginStore
}

func TestCaddyfileOAuthLoginStoreRuntimeResolution(t *testing.T) {
	const name = "shared, {env.OAUTH_LOGIN_SECOND_PASS}"
	const namespace = "deployment, {env.OAUTH_NAMESPACE_SECOND_PASS}"
	t.Setenv("OAUTH_LOGIN_SECOND_PASS", "must-not-expand")
	t.Setenv("OAUTH_NAMESPACE_SECOND_PASS", "must-not-expand")
	t.Setenv("OAUTH_LOGIN_NAMESPACE", namespace)
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			app := oauthRuntimeTestApp(t, oauthParserBase+"login store secrets:oauth:store namespace {env.OAUTH_LOGIN_NAMESPACE}")
			if native {
				app.OAuthProviderDirectives = nil
			}
			path := filepath.Join(t.TempDir(), "missing", "{env.OAUTH_LOGIN_SECOND_PASS}", "logins.db")
			module, _ := json.Marshal(map[string]any{"driver": "sqlite", "name": name, "path": path})
			app.OAuthLoginStoreConfigs = []json.RawMessage{module}
			before, _ := json.Marshal(app)
			runtime := oauthLoginStoreResolutionClone(t, app)
			if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"store": name}}}, runtime.Config, app.OAuthProviderDirectives, nil, nil, nil, zap.NewNop()); err != nil {
				t.Fatal("valid provider storage selection did not resolve")
			}
			selection := oauthLoginStoreResolvedSelection(t, runtime)
			if selection.Name != name || selection.Namespace != namespace {
				t.Fatal("provider selection was split, trimmed or expanded more than once")
			}
			after, _ := json.Marshal(app)
			if !bytes.Equal(before, after) || !bytes.Equal(runtime.OAuthLoginStoreConfigs[0], app.OAuthLoginStoreConfigs[0]) {
				t.Fatal("runtime resolution changed source declarations or literal backend fields")
			}
			if _, err := os.Stat(filepath.Dir(filepath.Dir(path))); !os.IsNotExist(err) {
				t.Fatal("provider resolution opened backend storage")
			}
		})
	}
}

func TestCaddyfileOAuthLoginStoreRejectsResolvedSelection(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, field := range []string{"name", "namespace"} {
			for label, value := range map[string]string{
				"empty": "", "leading_space": " shared", "control": "private-sentinel\nvalue", "unicode_control": "shared\u0085value", "invalid_utf8": "shared\xff",
			} {
				t.Run(fmt.Sprintf("native=%t/%s/%s", native, field, label), func(t *testing.T) {
					statement := "login store secrets:oauth:selection namespace deployment"
					if field == "namespace" {
						statement = "login store shared namespace secrets:oauth:selection"
					}
					app := oauthRuntimeTestApp(t, oauthParserBase+statement)
					if native {
						app.OAuthProviderDirectives = nil
					}
					before, _ := json.Marshal(app)
					runtime := oauthLoginStoreResolutionClone(t, app)
					err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"selection": value}}}, runtime.Config, app.OAuthProviderDirectives, nil, nil, nil, zap.NewNop())
					if err == nil {
						t.Fatal("invalid resolved selector silently selected private memory or a different backend")
					}
					after, _ := json.Marshal(app)
					if !bytes.Equal(before, after) {
						t.Fatal("rejected resolution changed declarative state")
					}
				})
			}
		}
	}
}

func TestCaddyfileOAuthLoginStoreResolvedFixture(t *testing.T) {
	const prefix = "testdata/caddyfile_adapt/testcase_oauth_login_storage"
	for _, entry := range parseTestEnvVars(prefix + ".env") {
		t.Setenv(entry.key, entry.value)
	}
	raw, err := os.ReadFile(prefix + ".json")
	if err != nil {
		t.Fatal("cannot read OAuth storage adaptation fixture")
	}
	var document struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("cannot decode OAuth storage adaptation fixture")
	}
	app := &document.Apps.Security
	before, _ := json.Marshal(app)
	runtime := oauthLoginStoreResolutionClone(t, app)
	if err := resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, runtime.Config, app.OAuthProviderDirectives, nil, nil, nil, zap.NewNop()); err != nil {
		t.Fatal("cannot resolve OAuth storage fixture")
	}
	want, err := os.ReadFile(prefix + "_resolved.json")
	if err != nil {
		t.Fatal("cannot read resolved OAuth storage fixture")
	}
	var expected map[string]any
	if json.Unmarshal(want, &expected) != nil {
		t.Fatal("invalid resolved OAuth storage fixture")
	}
	gotJSON, _ := json.Marshal(runtime.Config)
	var actual map[string]any
	if json.Unmarshal(gotJSON, &actual) != nil {
		t.Fatal("cannot decode resolved OAuth storage config")
	}
	wantJSON, _ := json.Marshal(expected)
	gotJSON, _ = json.Marshal(actual)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatal("resolved OAuth storage configuration differs from its fixture")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("fixture resolution changed declarations")
	}
}

func TestCaddyfileOAuthLoginStoreNativeSelectionShape(t *testing.T) {
	for label, selection := range map[string]any{
		"null":              nil,
		"empty":             map[string]any{},
		"missing_name":      map[string]any{"namespace": "deployment"},
		"missing_namespace": map[string]any{"name": "shared"},
		"empty_name":        map[string]any{"name": "", "namespace": "deployment"},
		"empty_namespace":   map[string]any{"name": "shared", "namespace": ""},
		"name_type":         map[string]any{"name": true, "namespace": "deployment"},
		"namespace_type":    map[string]any{"name": "shared", "namespace": 1},
		"string":            "shared",
		"array":             []string{"shared", "deployment"},
	} {
		t.Run(label, func(t *testing.T) {
			app := oauthRuntimeTestApp(t, oauthParserBase)
			app.Config.IdentityProviders[0].Params["login_store"] = selection
			before, _ := json.Marshal(app)
			runtime := oauthLoginStoreResolutionClone(t, app)
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, runtime.Config, zap.NewNop()); err == nil {
				t.Fatal("present invalid native selection silently fell back to private memory")
			}
			after, _ := json.Marshal(app)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid native selection changed declarative inputs")
			}
		})
	}
	app := oauthRuntimeTestApp(t, oauthParserBase)
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
		t.Fatal("omission no longer retains private memory")
	}
	if _, exists := app.Config.IdentityProviders[0].Params["login_store"]; exists {
		t.Fatal("resolution converted omission into an explicit selection")
	}
}
