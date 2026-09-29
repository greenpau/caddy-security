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
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"go.uber.org/zap"
)

func aclFieldBlock(name, claim, kind string) string {
	// Caddy double-quoted tokens escape quotes, but keep other backslashes literal.
	quoted := strings.ReplaceAll(claim, `"`, `\"`)
	return fmt.Sprintf("acl field %s {\n claim \"%s\"\n type %s\n}\n", name, quoted, kind)
}

func TestAuthorizationACLFields(t *testing.T) {
	const literal = "https://example.org/profile.department|value, literal"
	body := `authorization policy first {
 crypto key verify synthetic-acl-test-key
 disable auth redirect
 allow roles viewer
 allow external_roles admin
 deny department blocked
 acl rule {
  match external_roles admin
  match department engineering
  allow stop
 }
 acl default deny
 ` + aclFieldBlock("external_roles", "https://example.org/roles", "string list") + `
 acl field department {
  type string
  claim "` + literal + `"
 }
}
authorization policy second {
 allow external_roles admin
 ` + aclFieldBlock("external_roles", "https://other.example/roles", "string") + `
}
`
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n security {\n"+body+"\n}\n}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Apps struct{ Security *App } }
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	policies := doc.Apps.Security.Config.AuthorizationPolicies
	want := []*acl.FieldConfig{
		{Name: "external_roles", Claim: "https://example.org/roles", Type: acl.FieldTypeStringList},
		{Name: "department", Claim: literal, Type: acl.FieldTypeString},
	}
	if diff := cmp.Diff(want, policies[0].AccessListFields); diff != "" {
		t.Fatal(diff)
	}
	if policies[1].AccessListFields[0].Claim != "https://other.example/roles" || policies[1].AccessListFields[0].Type != acl.FieldTypeString {
		t.Fatal("fields crossed policy boundaries")
	}
	wantRules := []*acl.RuleConfiguration{
		{Conditions: []string{"match roles viewer"}, Action: "allow log debug"},
		{Conditions: []string{"match external_roles admin"}, Action: "allow log debug"},
		{Conditions: []string{"match department blocked"}, Action: "deny stop log warn"},
		{Conditions: []string{"match external_roles admin", "match department engineering"}, Action: "allow stop"},
		{Conditions: []string{"match any"}, Action: "deny"},
	}
	if diff := cmp.Diff(wantRules, policies[0].AccessListRules); diff != "" {
		t.Fatal(diff)
	}
	if !policies[0].AuthRedirectDisabled || len(policies[0].RawCryptoKeyStoreConfig) != 1 {
		t.Fatal("lost unrelated settings")
	}
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	roundtrip, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var restored struct{ Apps struct{ Security *App } }
	if err := json.Unmarshal(roundtrip, &restored); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(policies[0].AccessListFields, restored.Apps.Security.Config.AuthorizationPolicies[0].AccessListFields); diff != "" {
		t.Fatal(diff)
	}
}

func TestAuthorizationACLFieldRejects(t *testing.T) {
	const sentinel = "sensitive-claim-sentinel"
	good := aclFieldBlock("external_roles", sentinel, "string list")
	cases := []struct{ name, body string }{
		{"missing block", "acl field external_roles"},
		{"missing name", "acl field {\nclaim " + sentinel + "\ntype string\n}"},
		{"empty name", aclFieldBlock(`""`, sentinel, "string")},
		{"extra header", aclFieldBlock("external_roles "+sentinel, sentinel, "string")},
		{"duplicate alias", good + good},
		{"empty block", "acl field external_roles {\n}"},
		{"missing claim", "acl field external_roles {\ntype string\n}"},
		{"missing type", "acl field external_roles {\nclaim " + sentinel + "\n}"},
		{"duplicate claim", strings.Replace(good, "type string list", "claim "+sentinel+"\ntype string list", 1)},
		{"duplicate type", strings.Replace(good, "type string list", "type string\ntype string list", 1)},
		{"trailing tab claim", aclFieldBlock("external_roles", sentinel+"\t", "string")},
		{"trailing Unicode space claim", aclFieldBlock("external_roles", sentinel+"\u00a0", "string")},
		{"trailing Unicode space type", aclFieldBlock("external_roles", sentinel, "\"string\u00a0\"")},
		{"leading space claim", aclFieldBlock("external_roles", " "+sentinel, "string")},
		{"empty claim", aclFieldBlock("external_roles", "", "string")},
		{"blank claim", aclFieldBlock("external_roles", " ", "string")},
		{"empty trailing type", aclFieldBlock("external_roles", sentinel, `string ""`)},
		{"empty trailing claim", strings.Replace(good, `claim "`+sentinel+`"`, `claim "`+sentinel+`" ""`, 1)},
		{"extra claim", strings.Replace(good, `claim "`+sentinel+`"`, `claim "`+sentinel+`" extra`, 1)},
		{"extra type", aclFieldBlock("external_roles", sentinel, "string list extra")},
		{"list spelling", aclFieldBlock("external_roles", sentinel, "string_list")},
		{"number", aclFieldBlock("external_roles", sentinel, "number")},
		{"object", aclFieldBlock("external_roles", sentinel, "object")},
		{"bool", aclFieldBlock("external_roles", sentinel, "bool")},
		{"unknown setting", strings.Replace(good, "type string list", sentinel+" value", 1)},
		{"nested block", strings.Replace(good, "type string list", "type string {\n}", 1)},
		{"second block", good + "{\nclaim " + sentinel + "\n}"},
		{"quoted opening", `acl field external_roles "{"` + "\nclaim " + sentinel + "\ntype string\n}"},
		{"quoted closing", strings.TrimSuffix(good, "}\n") + `"}"`},
		{"closing brace argument", "acl field external_roles {\nclaim }\ntype string\n}"},
		{"closing brace same line", strings.TrimSuffix(good, "}\n") + "} " + sentinel + " value"},
		{"unterminated", strings.TrimSuffix(good, "}\n")},
		{"undefined value match", "allow unregistered value"},
		{"case sensitive", good + "allow External_roles admin"},
		{"deferred OAuth invalid ACL", good + "use oauth identity provider {env.ACL_TEST_PROVIDER}\nallow unregistered admin"},
	}
	for _, name := range []string{"roles", "role", "groups", "group", "method", "http_method", "path", "http_path", "addr", "ip", "exp", "acl", "allow", "match", "with", "any", "0bad", "bad.name", "résumé", strings.Repeat("a", 129)} {
		cases = append(cases, struct{ name, body string }{"reserved or invalid/" + name, aclFieldBlock(name, sentinel, "string")})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Direct parsing must not publish a partial policy or alter a previous one.
			existing := &authz.PolicyConfig{Name: "existing", AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}}}
			app := &App{Config: &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{existing}}}
			before, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			input := "authorization policy candidate {\n" + tc.body + "\nallow roles viewer\n}"
			d := caddyfile.NewTestDispenser(input)
			d.Next()
			err = parseCaddyfileAuthorization(d, app)
			if err == nil {
				t.Fatal("accepted malformed field/policy")
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatalf("error leaked claim/directive: %v", err)
			}
			if !strings.Contains(err.Error(), "candidate") || !strings.Contains(err.Error(), "Testfile:") {
				t.Fatalf("error lacks policy/source context: %v", err)
			}
			if tc.name == "undefined value match" && !errors.Is(err, autherrors.ErrInvalidConfiguration) {
				t.Fatalf("lost policy validation error identity: %v", err)
			}
			after, marshalErr := json.Marshal(app)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if string(before) != string(after) {
				t.Fatal("failed policy modified app config")
			}
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+input+"\n}\n}"), nil); err == nil || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("public adapter failed to reject/redact malformed configuration: %v", err)
			}
		})
	}
}

func TestAuthorizationACLFieldLiteralResolution(t *testing.T) {
	t.Setenv("ACL_FIELD_CLAIM", "substituted")
	for _, claim := range []string{"{env.ACL_FIELD_CLAIM}", "secrets:manager:key", "https://example.org/a.b|c, d", `https://example.org/a"b\c`, "https://example.org/département", "roles"} {
		t.Run(claim, func(t *testing.T) {
			app := directOAuthTestApp(t, "authorization policy literal {\n"+aclFieldBlock("custom", claim, "string")+"allow custom viewer\n}")
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			if got := app.Config.AuthorizationPolicies[0].AccessListFields[0].Claim; got != claim {
				t.Fatalf("claim changed: %q", got)
			}
		})
	}
}

func TestAuthorizationACLFieldNames(t *testing.T) {
	// Exercise the boundary through Caddy tokenization and policy compilation;
	// the shared parser still owns the identifier rules.
	for _, name := range []string{"_", "a", "External-roles_2", strings.Repeat("a", 128)} {
		t.Run(name, func(t *testing.T) {
			app := directOAuthTestApp(t, "authorization policy names {\nallow "+name+" viewer\n"+aclFieldBlock(name, "https://example.org/roles", "string list")+"}")
			if got := app.Config.AuthorizationPolicies[0].AccessListFields[0].Name; got != name {
				t.Fatalf("field name changed: %q, want %q", got, name)
			}
		})
	}
}

func TestAuthorizationACLFieldPolicyBoundaries(t *testing.T) {
	good := "authorization policy candidate {\nallow custom viewer\n" + aclFieldBlock("custom", "https://example.org/roles", "string list") + "}"
	for _, tc := range []struct{ name, input string }{
		{"quoted opening", strings.Replace(good, "candidate {", `candidate "{"`, 1)},
		{"quoted closing", strings.TrimSuffix(good, "}") + `"}"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{Config: authcrunch.NewConfig()}
			d := caddyfile.NewTestDispenser(tc.input)
			d.Next()
			if err := parseCaddyfileAuthorization(d, app); err == nil {
				t.Error("policy parser accepted quoted structural brace")
			}
			if len(app.Config.AuthorizationPolicies) != 0 || len(app.OAuthAuthorizationDirectives) != 0 {
				t.Error("malformed boundary published a policy")
			}
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+tc.input+"\n}\n}"), nil)
			if err == nil || len(data) != 0 {
				t.Error("public adapter accepted quoted structural brace")
			}
		})
	}
	for _, input := range []string{"authorization policy candidate", strings.TrimSuffix(good, "}")} {
		app := &App{Config: authcrunch.NewConfig()}
		d := caddyfile.NewTestDispenser(input)
		d.Next()
		if err := parseCaddyfileAuthorization(d, app); err == nil || len(app.Config.AuthorizationPolicies) != 0 {
			t.Fatalf("incomplete policy was not rejected atomically: %v", err)
		}
	}
}

func TestAuthorizationACLFieldImports(t *testing.T) {
	const literal = "https://example.org/roles|team, external"
	prefix := `(typed_fields) {
 acl field custom {
  claim "{args[0]}"
  type string list
 }
}
{
 security {
  authorization policy first {
   allow custom admin
   import typed_fields "` + literal + `"
  }
  authorization policy second {
   allow custom viewer
`
	for _, tc := range []struct {
		name, statements, wantError string
	}{
		{"policy local bindings", "import typed_fields https://other.example/roles", ""},
		{"duplicate imported fields", "import typed_fields source_a\nimport typed_fields source_b", "duplicate name"},
		{"no inherited alias", "", "second: configuration error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(prefix+tc.statements+"\n}\n}\n}"), nil)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || len(data) != 0 {
					t.Fatalf("expected %q rejection without partial JSON: %v", tc.wantError, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var doc struct{ Apps struct{ Security *App } }
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			policies := doc.Apps.Security.Config.AuthorizationPolicies
			if policies[0].AccessListFields[0].Claim != literal || policies[1].AccessListFields[0].Claim != "https://other.example/roles" {
				t.Fatal("import changed literal bindings or crossed policy boundaries")
			}
		})
	}
}
