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

package consul

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
)

func TestConsulSecretsConfiguration(t *testing.T) {
	var m ConsulSecretsManager
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser("signing {\nrecord tokens\n}")); err != nil || m.Timeout != "3s" || m.Prefix != "security/secrets" {
		t.Fatal("defaults changed", err)
	}
	for name, input := range map[string]string{"missing": "signing", "colon": "signing:bad {\nrecord tokens\n}", "duplicate": "signing {\nrecord tokens\nrecord other\n}", "unknown": "signing {\nrecord tokens\nvalue private-input\n}", "timeout": "signing {\nrecord tokens\ntimeout 0s\n}", "prefix": "signing {\nrecord tokens\nprefix /absolute\n}"} {
		t.Run(name, func(t *testing.T) {
			if new(ConsulSecretsManager).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
}
func TestConsulSecretsSnapshots(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "secrets-unit")
	openClient := func(name, record string) *Client {
		c, err := (Config{Name: name, Record: record}).normalized()
		if err != nil {
			t.Fatal(err)
		}
		client, err := open(t.Context(), c, binding)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}
	a, b := openClient("signing", "tokens"), openClient("alias", "tokens")
	if _, err := a.GetSecrets(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing record returned fallback", err)
	}
	missing := &ConsulSecretsManager{Name: "missing", Record: "missing"}
	if err := missing.provision(t.Context(), binding); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing snapshot provisioned", err)
	}
	values := map[string]any{"key": "  exact private key\t\u00a0", "number": json.Number("9007199254740993"), "nil": nil, "empty": "", "nested": map[string]any{"roles": []any{"viewer", true}}, "dotted.key": "literal"}
	if err := a.Put(t.Context(), values); err != nil {
		t.Fatal(err)
	}
	m := &ConsulSecretsManager{Name: "signing", Record: "tokens"}
	if err := m.provision(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	snapshot, err := m.GetSecret(t.Context())
	if err != nil || snapshot["number"].(json.Number).String() != "9007199254740993" || snapshot["key"] != values["key"] {
		t.Fatal("snapshot changed exact values", err)
	}
	snapshot["nested"].(map[string]any)["roles"].([]any)[0] = "changed"
	again, _ := m.GetSecret(t.Context())
	if again["nested"].(map[string]any)["roles"].([]any)[0] != "viewer" {
		t.Fatal("snapshot exposed mutable nested values")
	}
	if value, err := m.GetSecretByKey(t.Context(), "nil"); err != nil || value != nil {
		t.Fatal("present null lost", err)
	}
	if _, err := m.GetSecretByKey(t.Context(), "empty"); !errors.Is(err, consulstate.ErrInvalid) {
		t.Fatal("empty credential accepted")
	}
	if _, err := m.GetSecretByKey(t.Context(), "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing key confused with null")
	}
	if value, err := m.GetSecretByKey(t.Context(), "dotted.key"); err != nil || value != "literal" {
		t.Fatal("key traversal changed literal key", err)
	}
	if err := b.Put(t.Context(), map[string]any{"key": "rotated"}); err != nil {
		t.Fatal(err)
	}
	if value, err := m.GetSecretByKey(t.Context(), "key"); err != nil || value != values["key"] {
		t.Fatal("write changed serving snapshot", err)
	}
	fresh := &ConsulSecretsManager{Name: "alias", Record: "tokens"}
	if err := fresh.provision(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	if value, err := fresh.GetSecretByKey(t.Context(), "key"); err != nil || value != "rotated" {
		t.Fatal("new candidate missed rotation", err)
	}
	if err := m.provision(t.Context(), binding); err == nil {
		t.Fatal("reprovisioning mutated serving snapshot")
	}
	for name, value := range map[string]any{"utf8": string([]byte{0xff}), "raw": json.RawMessage(`"private"`), "number": json.Number("null"), "empty_number": json.Number(""), "infinity": math.Inf(1), "oversized": strings.Repeat("x", maxSecretBytes), "typed_slice": []string{"coerced"}} {
		t.Run(name, func(t *testing.T) {
			if err := a.Put(t.Context(), map[string]any{"key": value}); !errors.Is(err, consulstate.ErrInvalid) {
				t.Fatal("invalid JSON graph accepted", err)
			}
		})
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if err := a.Put(t.Context(), cycle); !errors.Is(err, consulstate.ErrInvalid) {
		t.Fatal("cyclic JSON accepted", err)
	}
	if value, err := b.GetSecret(t.Context(), "key"); err != nil || value != "rotated" {
		t.Fatal("failed write replaced valid secret", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := fresh.GetSecret(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("snapshot ignored cancellation", err)
	}
	if err := m.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetSecret(t.Context()); err == nil {
		t.Fatal("retired snapshot readable")
	}
	if err := m.provision(t.Context(), binding); err == nil {
		t.Fatal("retired snapshot reprovisioned")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete(t.Context()); err != nil {
		t.Fatal("delete not idempotent", err)
	}
	if _, err := b.GetSecrets(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted record remained readable")
	}
	if value, err := fresh.GetSecretByKey(t.Context(), "key"); err != nil || value != "rotated" {
		t.Fatal("delete changed active snapshot", err)
	}
}
