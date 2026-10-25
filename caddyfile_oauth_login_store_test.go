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

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCaddyfileOAuthLoginStoreDispatch(t *testing.T) {
	good := "oauth login store sqlite shared {\npath /private/logins.db\n}"
	for name, input := range map[string]string{
		"valid":          good,
		"short":          "oauth login store sqlite",
		"extra":          strings.Replace(good, "shared {", "shared extra {", 1),
		"wrong_kind":     strings.Replace(good, "login store", "identity store", 1),
		"wrong_selector": strings.Replace(good, "login store", "login provider", 1),
		"unknown_driver": strings.Replace(good, "sqlite shared", "not_registered shared", 1),
	} {
		t.Run(name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(input)
			if !d.Next() {
				t.Fatal("missing dispatcher input")
			}
			app := new(App)
			err := parseCaddyfileOAuthLoginStore(d, app)
			if name != "valid" {
				if err == nil || len(app.OAuthLoginStoreConfigs) != 0 {
					t.Fatal("invalid header published a module")
				}
				return
			}
			if err != nil || len(app.OAuthLoginStoreConfigs) != 1 {
				t.Fatal("valid backend dispatcher failed")
			}
			var got struct {
				SQLiteOAuthLoginStore
				Driver string `json:"driver"`
			}
			if json.Unmarshal(app.OAuthLoginStoreConfigs[0], &got) != nil || got.Driver != "sqlite" || got.Name != "shared" || got.Path != "/private/logins.db" || got.Timeout != "1s" || got.Capacity != 10000 {
				t.Fatal("dispatcher did not preserve the module's complete output")
			}
		})
	}
}

func TestCaddyfileOAuthLoginStoreAdapter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "{env.LITERAL_PATH}", "logins.db")
	t.Setenv("SHARED_OAUTH_LEXICAL_PATH", path)
	backend := "oauth login store sqlite shared {\npath {$SHARED_OAUTH_LEXICAL_PATH}\n}\n"
	provider := "oauth identity provider upstream {\n" + oauthParserBase + "login store shared namespace deployment\n}\n"
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprintf("backend_after_provider=%t", after), func(t *testing.T) {
			declarations := backend + provider
			if after {
				declarations = provider + backend
			}
			app := adaptApplicationTestConfig(t, declarations)
			if len(app.OAuthLoginStoreConfigs) != 1 || len(app.Config.IdentityProviders) != 1 {
				t.Fatal("declaration order lost a provider or backend")
			}
			var cfg SQLiteOAuthLoginStore
			if json.Unmarshal(app.OAuthLoginStoreConfigs[0], &cfg) != nil || cfg.Path != path {
				t.Fatal("lexical expansion or literal runtime marker changed")
			}
			if cfg.Validate() != nil {
				t.Fatal("adapted module failed pure validation")
			}
		})
	}
	for name, declaration := range map[string]string{
		"empty_block":    "oauth login store sqlite shared {\n}\n",
		"missing_block":  "oauth login store sqlite shared\n",
		"empty_nested":   "oauth login store sqlite shared {\npath /private/logins.db {\n}\n}\n",
		"literal_braces": "oauth login store sqlite shared {\npath /private/logins.db {}\n}\n",
		"extra_header":   "oauth login store sqlite shared extra {\npath /private/logins.db\n}\n",
		"wrong_header":   "oauth login provider sqlite shared {\npath /private/logins.db\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := "{\nsecurity {\n" + declaration + "}\n}\n"
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err == nil {
				t.Fatal("actual Caddy adapter accepted malformed backend syntax")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(path))); !os.IsNotExist(err) {
		t.Fatal("adaptation or validation touched backend storage")
	}
}

func TestCaddyfileOAuthLoginStoreProviderSelection(t *testing.T) {
	params := oauthTestParams(t, oauthParserBase+`login store "shared name,comma" namespace "deployment name,comma"`)
	selection, ok := params["login_store"].(map[string]any)
	if !ok || selection["name"] != "shared name,comma" || selection["namespace"] != "deployment name,comma" {
		t.Fatal("shared provider parser changed encoded binding values")
	}
	if _, present := oauthTestParams(t, oauthParserBase)["login_store"]; present {
		t.Fatal("omission became an explicit shared backend")
	}
	for name, line := range map[string]string{
		"missing_name":            "login store",
		"missing_namespace":       "login store shared",
		"missing_namespace_value": "login store shared namespace",
		"wrong_keyword":           "login store shared scope deployment",
		"empty_name":              `login store "" namespace deployment`,
		"empty_namespace":         `login store shared namespace ""`,
		"extra":                   "login store shared namespace deployment extra",
		"duplicate":               "login store shared namespace deployment\nlogin store shared namespace deployment",
		"nested":                  "login store shared namespace deployment {\n}",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseOAuthTest(oauthParserBase + line)
			if err == nil || len(cfg.IdentityProviders) != 0 {
				t.Fatal("malformed provider selection was accepted or partially published")
			}
		})
	}
}
