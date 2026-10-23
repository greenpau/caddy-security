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
	"github.com/greenpau/go-authcrunch"
)

const staticClaimsBlock = `claims enrichment static {
 source static
 version v1
 issuer test-issuer
 realm local
 subject claim directory_id
 tenant claim tenant
 audience api
 attribute department string
 claim department engineering
}`

func TestParseCaddyfileStaticClaims(t *testing.T) {
	body := strings.Replace(staticClaimsBlock, "claim department engineering", `claim department engineering
 attribute quota json
 claim quota json 9007199254740993
 attribute settings json
 claim settings json `+"`"+`{"array":[true,null,1.2300e+10],"text":" a|b, c ","empty":""}`+"`"+`
 attribute literal json
 claim literal "{env.STATIC_CLAIMS_SECRET}"
 attribute brace string
 claim brace "}"
 attribute tags string list
 claim tags json `+"`"+`["reader","writer"]`+"`"+`
 attribute optional json
 claim optional json null`, 1)
	input := "{\nsecurity {\nauthorization policy first {\n" + body + "\nallow roles viewer\n}\nauthorization policy second {\n" + staticClaimsBlock + "\nallow roles viewer\n}\n}\n}"
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc caddy.Config
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(doc.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	if len(app.ClaimsEnrichment) != 2 || app.ClaimsEnrichment[0].Policy != "first" || app.ClaimsEnrichment[1].Policy != "second" {
		t.Fatal("lost policy bindings")
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	for _, binding := range app.ClaimsEnrichment {
		loaded, err := loadStaticClaimsTestModule(ctx, binding.BackendRaw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := loaded.(ClaimsEnrichmentBackendModule).NewClaimsEnrichmentBackend(t.Context(), *binding.Config); err != nil {
			t.Fatal(err)
		}
	}
	var raw struct {
		ClaimsJSON string `json:"claims_json"`
	}
	if err := json.Unmarshal(app.ClaimsEnrichment[0].BackendRaw, &raw); err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw.ClaimsJSON), &claims); err != nil {
		t.Fatal(err)
	}
	if string(claims["quota"]) != "9007199254740993" || !strings.Contains(string(claims["settings"]), "1.2300e+10") {
		t.Fatalf("adaptation rounded JSON: %s", app.ClaimsEnrichment[0].BackendRaw)
	}
	if string(claims["literal"]) != `"{env.STATIC_CLAIMS_SECRET}"` || string(claims["brace"]) != `"}"` {
		t.Fatal("literal claims changed")
	}
	if app.ClaimsEnrichment[0].Config.Timeout != "1s" || app.ClaimsEnrichment[0].Config.MaxAge != "1m" {
		t.Fatal("missing shared defaults")
	}
	before, err := json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(app.ClaimsEnrichment, restored.ClaimsEnrichment); diff != "" {
		t.Fatal(diff)
	}
}

func TestParseCaddyfileStaticClaimsRejects(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"missing block", "claims enrichment static"},
		{"wrong backend", strings.Replace(staticClaimsBlock, "enrichment static", "enrichment private-sentinel", 1)},
		{"header arguments", strings.Replace(staticClaimsBlock, "static {", "static private-sentinel {", 1)},
		{"quoted open", strings.Replace(staticClaimsBlock, "static {", `static "{"`, 1)},
		{"quoted close", strings.TrimSuffix(staticClaimsBlock, "}") + `"}"`},
		{"missing close", strings.TrimSuffix(staticClaimsBlock, "}")},
		{"duplicate block", staticClaimsBlock + "\n" + staticClaimsBlock},
		{"nested block", strings.Replace(staticClaimsBlock, "claim department engineering", "claim department {\nclaim nested private-sentinel\n}", 1)},
		{"duplicate scalar", strings.Replace(staticClaimsBlock, "source static", "source static\nsource static", 1)},
		{"duplicate claim", strings.Replace(staticClaimsBlock, "claim department engineering", "claim department engineering\nclaim department private-sentinel", 1)},
		{"duplicate attribute", strings.Replace(staticClaimsBlock, "attribute department string", "attribute department string\nattribute department json", 1)},
		{"missing claim", strings.Replace(staticClaimsBlock, "claim department engineering", "claim other private-sentinel", 1)},
		{"wrong type", strings.Replace(staticClaimsBlock, "claim department engineering", "claim department json true", 1)},
		{"reserved claim", strings.ReplaceAll(staticClaimsBlock, "department", "roles")},
		{"binding source", strings.Replace(staticClaimsBlock, "source static", "source other", 1)},
		{"binding version", strings.Replace(staticClaimsBlock, "version v1", "version other", 1)},
		{"short age", strings.Replace(staticClaimsBlock, "source static", "source static\nmax age 1s", 1)},
		{"missing issuer", strings.Replace(staticClaimsBlock, "issuer test-issuer", "", 1)},
		{"unknown statement", strings.Replace(staticClaimsBlock, "source static", "unknown private-sentinel", 1)},
		{"invalid json", strings.Replace(staticClaimsBlock, "claim department engineering", `claim department json "private-sentinel"`, 1)},
		{"trailing json", strings.Replace(staticClaimsBlock, "claim department engineering", `claim department json "true false"`, 1)},
		{"empty literal", strings.Replace(staticClaimsBlock, "claim department engineering", `claim department ""`, 1)},
		{"newline", strings.Replace(staticClaimsBlock, "claim department engineering", "claim department \"private-sentinel\nvalue\"", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser("authorization policy test {\n" + tc.body + "\nallow roles viewer\n}\n")
			d.Next()
			app := &App{Config: &authcrunch.Config{}}
			err := parseCaddyfileAuthorization(d, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatalf("expected redacted parse error: %v", err)
			}
			if len(app.ClaimsEnrichment) != 0 || len(app.Config.AuthorizationPolicies) != 0 {
				t.Fatal("failed parser published partial settings")
			}
		})
	}
	// A valid enrichment block must not escape a later policy validation error.
	d := caddyfile.NewTestDispenser("authorization policy test {\n" + staticClaimsBlock + "\nallow unregistered value\n}\n")
	d.Next()
	app := &App{Config: &authcrunch.Config{}}
	if err := parseCaddyfileAuthorization(d, app); err == nil || len(app.ClaimsEnrichment) != 0 {
		t.Fatal("invalid policy retained enrichment")
	}
}
