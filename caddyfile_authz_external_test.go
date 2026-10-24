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
	"github.com/google/go-cmp/cmp"
)

const externalAuthorizationBlock = `external authorization httpjson {
 endpoint https://policy.example.test/decide
 policy reports
 version revision-1
 issuer test-issuer
 realm local
}`

func externalAdaptTest(t *testing.T, body string) (*App, error) {
	t.Helper()
	input := "{\nsecurity {\nauthorization policy app_policy {\nallow roles viewer\n" + body + "\n}\n}\n}"
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		return nil, err
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	return &app, nil
}

func TestParseCaddyfileExternalAuthorization(t *testing.T) {
	for _, additions := range []string{"", `subject claim directory_id
 tenant claim tenant
 attribute roles
 attribute department
 timeout 500ms
 tls ca file "/private roots/ca.pem"
 tls client certificate "/private certs/client.pem" "/private certs/key.pem"`} {
		t.Run(additions, func(t *testing.T) {
			app, err := externalAdaptTest(t, strings.Replace(externalAuthorizationBlock, "realm local", "realm local\n"+additions, 1))
			if err != nil {
				t.Fatal(err)
			}
			if len(app.ExternalAuthorization) != 1 {
				t.Fatal("lost binding")
			}
			binding := app.ExternalAuthorization[0]
			if binding.Policy != "app_policy" || binding.Config.Policy != "reports" {
				t.Fatal("conflated local and remote policy names")
			}
			var module HTTPJSONExternalAuthorization
			if err := json.Unmarshal(binding.BackendRaw, &module); err != nil {
				t.Fatal(err)
			}
			if module.Endpoint != "https://policy.example.test/decide" {
				t.Fatal("lost endpoint")
			}
			if additions == "" {
				if binding.Config.SubjectClaim != "sub" || binding.Config.Timeout != "1s" || module.Timeout != "1s" || module.TLS != nil {
					t.Fatal("defaults changed")
				}
			} else {
				if binding.Config.SubjectClaim != "directory_id" || binding.Config.TenantClaim != "tenant" || len(binding.Config.Attributes) != 2 || binding.Config.Timeout != "500ms" || module.Timeout != "500ms" || module.TLS.RootCAFile != "/private roots/ca.pem" {
					t.Fatal("lost explicit configuration")
				}
			}
			// Parsing and validation must not read nonexistent TLS paths.
			if err := module.Validate(); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			var restored App
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(app.ExternalAuthorization, restored.ExternalAuthorization); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestParseCaddyfileExternalAuthorizationRejects(t *testing.T) {
	t.Run("missing_owned_closing_brace", func(t *testing.T) {
		d := caddyfile.NewTestDispenser(strings.TrimSuffix(externalAuthorizationBlock, "}"))
		d.Next()
		if _, err := parseCaddyfileExternalAuthorization(d, "app_policy"); err == nil {
			t.Fatal("unclosed external authorization block accepted")
		}
	})
	for _, tc := range []struct{ name, body string }{
		{"missing_block", "external authorization httpjson"},
		{"quoted_open", strings.Replace(externalAuthorizationBlock, "httpjson {", `httpjson "{"`, 1)},
		{"quoted_close", strings.TrimSuffix(externalAuthorizationBlock, "}") + `"}"`},
		{"wrong_driver", strings.Replace(externalAuthorizationBlock, "httpjson", "private-sentinel", 1)},
		{"extra_header", strings.Replace(externalAuthorizationBlock, "httpjson {", "httpjson private-sentinel {", 1)},
		{"duplicate_block", externalAuthorizationBlock + "\n" + externalAuthorizationBlock},
		{"nested", strings.Replace(externalAuthorizationBlock, "realm local", "realm local {\nprivate-sentinel\n}", 1)},
		{"duplicate_endpoint", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\nendpoint https://private-sentinel.example", 1)},
		{"duplicate_policy", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\npolicy private-sentinel", 1)},
		{"duplicate_timeout", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\ntimeout 1s\ntimeout 2s", 1)},
		{"duplicate_attribute", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\nattribute roles\nattribute roles", 1)},
		{"duplicate_tls", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\ntls ca file one\ntls ca file private-sentinel", 1)},
		{"tls_arity", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\ntls client certificate private-sentinel", 1)},
		{"tls_empty", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\ntls ca file \"\"", 1)},
		{"unknown", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\nunknown private-sentinel", 1)},
		{"HTTP_remote", strings.Replace(externalAuthorizationBlock, "https://policy.example.test/decide", "http://private-sentinel.example/decide", 1)},
		{"endpoint_credentials", strings.Replace(externalAuthorizationBlock, "https://policy.example.test/decide", "https://private-sentinel@policy.example.test/decide", 1)},
		{"endpoint_query", strings.Replace(externalAuthorizationBlock, "/decide", "/decide?private-sentinel", 1)},
		{"missing_binding", strings.Replace(externalAuthorizationBlock, "policy reports\n", "", 1)},
		{"invalid_timeout", strings.Replace(externalAuthorizationBlock, "realm local", "realm local\ntimeout 31s", 1)},
		{"TLS_over_HTTP", strings.Replace(strings.Replace(externalAuthorizationBlock, "https://policy.example.test/decide", "http://127.0.0.1/decide", 1), "realm local", "realm local\ntls ca file private-sentinel", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := externalAdaptTest(t, tc.body)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("missing or unredacted error", err)
			}
		})
	}
}
