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

package static_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	staticbackend "github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"

	companion "github.com/greenpau/caddy-security/plugins/claims-enrichment-static"
)

func staticClaimsBinding() *enrichment.Config {
	return &enrichment.Config{Source: "static", Version: "v1", Issuer: "test-issuer", Realm: "local", SubjectClaim: "directory_id", TenantClaim: "tenant", Audience: "api", Attributes: []enrichment.AttributeConfig{{Name: "department", Type: "string"}}}
}

func TestStaticClaimsBindingRejectsInvalidBackendConfig(t *testing.T) {
	// Public binding validation must reject backend output even when the caller
	// did not obtain it through the module's validated JSON decoder.
	config := &staticbackend.Config{Claims: map[string]any{"roles": []string{"admin"}}}
	if err := companion.ValidateBinding(staticClaimsBinding(), config); err == nil {
		t.Fatal("protected backend claim accepted by direct binding validation")
	}
}

func staticClaimsModuleJSON(t *testing.T, claims string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"driver": "static", "claims_json": claims})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func loadStaticClaimsTestModule(ctx caddy.Context, raw json.RawMessage) (any, error) {
	binding := &moduleLoader{BackendRaw: raw}
	return ctx.LoadModule(binding, "BackendRaw")
}

func TestStaticClaimsNative(t *testing.T) {
	claims := `{"department":"engineering","quota":9007199254740993,"exponent":1.2300e+10,"settings":{"list":[null,true," ",{}]},"optional":null,"literal":"{env.STATIC_CLAIMS_SECRET}"}`
	raw := staticClaimsModuleJSON(t, claims)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	loaded, err := loadStaticClaimsTestModule(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	module := loaded.(*companion.StaticClaimsEnrichment)
	config, err := module.BackendConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Claims["quota"] != json.Number("9007199254740993") || config.Claims["exponent"] != json.Number("1.2300e+10") {
		t.Fatalf("module loader rounded numbers: %#v", config.Claims)
	}
	encoded, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	var restored companion.StaticClaimsEnrichment
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	original, err := restored.BackendConfig()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(config.Claims, original.Claims); diff != "" {
		t.Fatal(diff)
	}
	binding := staticClaimsBinding()
	for _, name := range []string{"quota", "exponent", "settings", "optional", "literal"} {
		binding.Attributes = append(binding.Attributes, enrichment.AttributeConfig{Name: name, Type: "json"})
	}
	backend, err := module.NewClaimsEnrichmentBackend(t.Context(), *binding)
	if err != nil {
		t.Fatal(err)
	}
	// Neither later config mutation nor mutation of a returned nested snapshot
	// can affect another request. Runtime placeholders remain literal.
	module.ClaimsJSON = `{"department":"changed"}`
	config.Claims["quota"] = json.Number("2")
	config.Claims["settings"].(map[string]any)["list"].([]any)[0] = "mutated"
	req := enrichment.Request{Identity: enrichment.Identity{Issuer: "test-issuer", Realm: "local", Subject: "immutable", Tenant: "north"}, Audience: "api", Purpose: "authorization"}
	for _, attr := range binding.Attributes {
		req.Attributes = append(req.Attributes, attr.Name)
	}
	first, err := backend.Lookup(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	first.Attributes["settings"].(map[string]any)["list"].([]any)[1] = false
	second, err := backend.Lookup(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(original.Claims, second.Attributes); diff != "" {
		t.Fatal(diff)
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := module.NewClaimsEnrichmentBackend(canceled, *binding); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled construction accepted")
	}
	if _, err := backend.Lookup(canceled, req); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request accepted")
	}
}

func TestStaticClaimsRejects(t *testing.T) {
	for _, raw := range []string{
		`null`, `[]`, `{}`, `{"roles":["admin"]}`, `{"github_id":"private-sentinel"}`,
		`{"authcrunch_test":true}`, `{"department":"` + strings.Repeat("x", 4097) + `"}`,
		"{\"department\":\"" + string([]byte{0xff}) + "\"}", `{"department":true} {}`, `bad-json-private-sentinel`,
	} {
		t.Run(raw[:min(len(raw), 70)], func(t *testing.T) {
			module := &companion.StaticClaimsEnrichment{ClaimsJSON: raw}
			err := module.Validate()
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatalf("expected redacted invalid config: %v", err)
			}
			if _, err := module.NewClaimsEnrichmentBackend(t.Context(), *staticClaimsBinding()); err == nil {
				t.Fatal("invalid JSON accepted at construction")
			}
		})
	}

	for _, tc := range []struct {
		name   string
		change func(*enrichment.Config)
	}{
		{"source", func(c *enrichment.Config) { c.Source = "other" }},
		{"version", func(c *enrichment.Config) { c.Version = "other" }},
		{"max age", func(c *enrichment.Config) { c.MaxAge = "59s" }},
		{"duration", func(c *enrichment.Config) { c.Timeout = "31s" }},
		{"binding", func(c *enrichment.Config) { c.Issuer = "" }},
		{"absent", func(c *enrichment.Config) { c.Attributes[0].Name = "missing" }},
		{"type", func(c *enrichment.Config) { c.Attributes[0].Type = "string_list" }},
		{"identity collision", func(c *enrichment.Config) { c.SubjectClaim = "department" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := staticClaimsBinding()
			tc.change(config)
			module := &companion.StaticClaimsEnrichment{ClaimsJSON: `{"department":"engineering"}`}
			if _, err := module.NewClaimsEnrichmentBackend(t.Context(), *config); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	for _, raw := range []string{`[]`, `null`, `{}`, `{"driver":null}`, `{"driver":true}`, `{"driver":""}`, `{"driver":"missing"}`, `{"driver":"static","claims":{"quota":9007199254740993}}`, `{"driver":"static","unknown":"private-sentinel"}`} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		_, err := loadStaticClaimsTestModule(ctx, json.RawMessage(raw))
		cancel()
		if err == nil {
			t.Fatalf("invalid selector accepted: %s", raw)
		}
	}
}

type moduleLoader struct {
	BackendRaw json.RawMessage `caddy:"namespace=security.claims_enrichment inline_key=driver"`
}
