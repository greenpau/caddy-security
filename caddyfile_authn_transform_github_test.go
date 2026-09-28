// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestPortalTransformGithubMatchers(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		matchers   []string
	}{
		{"exact ID", "match github id exact 12345678", []string{"match github id exact 12345678"}},
		{"regex ID", "match github id regex ^(12345678|87654321)$", []string{"match github id regex ^(12345678|87654321)$"}},
		{"exact organization", "match github org exact acme", []string{"match github org exact acme"}},
		{"regex organization", "match github org regex ^(acme|acme-labs)$", []string{"match github org regex ^(acme|acme-labs)$"}},
		{"quoted regex", `match github org regex "(?i)^(acme|acme labs){1,2}$"`, []string{cfgutil.EncodeArgs([]string{"match", "github", "org", "regex", "(?i)^(acme|acme labs){1,2}$"})}},
		{"AND with realm", "match github id exact 12345678\nmatch github org exact acme\nmatch realm github", []string{"match github id exact 12345678", "match github org exact acme", "exact match realm github"}},
		{"bare realm", "match realm github", []string{"exact match realm github"}},
		{"explicit ACL", "exact match github_id 12345678\nregex match github_orgs ^acme$", []string{"exact match github_id 12345678", "regex match github_orgs ^acme$"}},
		{"match any", "match any", []string{"match any"}},
	} {
		for _, header := range []string{"user", "users"} {
			t.Run(tc.name+"/"+header, func(t *testing.T) {
				data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput("transform "+header+" {\n"+tc.body+"\naction add role authp/admin\n}")+"\n}"), nil)
				if err != nil {
					t.Fatal(err)
				}
				var document struct {
					Apps struct {
						Security App `json:"security"`
					} `json:"apps"`
				}
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				cfg := document.Apps.Security.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
				if diff := cmp.Diff(tc.matchers, cfg.Matchers); diff != "" {
					t.Fatal(diff)
				}
				if diff := cmp.Diff([]string{"action add role authp/admin"}, cfg.Actions); diff != "" {
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
				if diff := cmp.Diff(cfg, &restored); diff != "" {
					t.Fatal(diff)
				}
				if _, err := transformer.NewFactory([]*transformer.Config{&restored}); err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(tc.matchers, restored.Matchers); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	}
}

func TestPortalTransformGithubRejects(t *testing.T) {
	for i, statement := range []string{
		"match github", "match github id", "match github org", "match github id exact", "match github org regex",
		"match github id exact 123 456", "match github org exact acme other",
		"match github id partial private-sentinel", "match github org prefix private-sentinel", "match github login exact private-sentinel",
		"match github id regex [private-sentinel", "match github org regex [private-sentinel",
		"match github id exact 0", "match github id exact -1", "match github id exact +1", "match github id exact 01",
		"match github id exact 1.0", "match github id exact 1e2", "match github id exact 18446744073709551616",
		"match github id exact private-sentinel",
		"match github id exact 123\nmatch github id regex ^123$",
		"match github org exact acme\nmatch github org regex ^acme$",
		"match github id exact 123\nexact match github_id 123",
		"match github org exact acme\nregex match github_orgs ^acme$",
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) { assertGithubTransformRejected(t, statement+"\naction add role authp/admin") })
	}
	for _, field := range []string{"github_id", "github_orgs"} {
		for _, action := range []string{
			"add " + field + " private-sentinel as string", "overwrite " + field + " private-sentinel", "delete " + field,
			"add nested " + field + " label with private-sentinel as string", "add nested " + field + " as map",
		} {
			for _, prefix := range []string{"", "action "} {
				t.Run(prefix+action, func(t *testing.T) { assertGithubTransformRejected(t, "match realm github\n"+prefix+action) })
			}
		}
	}
	// Empty Caddy tokens are rejected by the existing block reader, before encoding.
	for _, line := range []string{`match github id exact ""`, `match github org regex ""`} {
		if _, err := parseCookieApp(cookiePortalInput("transform user {\n" + line + "\naction add role member\n}")); err == nil {
			t.Fatal("accepted empty operand")
		}
	}
}

func assertGithubTransformRejected(t *testing.T, body string) {
	t.Helper()
	// Compare with the shared constructor, including malformed provider syntax:
	// Caddy must not prepend an ACL operator or invent its own GitHub validation.
	statements := strings.Split(body, "\n")
	for i, line := range statements {
		if line == "match realm github" {
			statements[i] = "exact " + line
		}
	}
	_, sharedErr := transformparser.NewUserTransformerConfigFromDirectives(statements)
	if sharedErr == nil {
		t.Fatal("shared constructor accepted malformed transform")
	}
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput("transform user {\n"+body+"\n}")+"\n}"), nil)
	if err == nil || len(data) != 0 {
		t.Fatal("adapter accepted malformed transform")
	}
	if !strings.Contains(err.Error(), sharedErr.Error()) {
		t.Fatalf("adapter did not retain shared validation error: %v; want %v", err, sharedErr)
	}
	if strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("diagnostic exposed matcher/action value")
	}
}
