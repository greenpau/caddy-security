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

package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	backend "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/secrets-sqlite"
)

func TestSecretsCaddyfile(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	good := fmt.Sprintf("signing {\npath %q\nrecord \"}\"\n}", cfg.Path)
	module := new(companion.SQLiteSecretsManager)
	meta := module.GetConfig(t.Context())
	if len(meta) != 4 || meta["kind"] != "sqlite" {
		t.Fatal("unprovisioned metadata disclosed configuration")
	}
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if module.Record != "}" || module.Timeout != "1s" || module.Path != cfg.Path {
		t.Fatal("quoted brace or defaults lost")
	}
	for name, input := range map[string]string{
		"empty": "", "extra header": strings.Replace(good, "signing {", "signing extra {", 1),
		"duplicate": strings.Replace(good, "record \"}\"", "record access\nrecord other", 1),
		"unknown":   strings.Replace(good, "record \"}\"", "credentials private-canary", 1),
		"nested":    strings.Replace(good, "record \"}\"", "record {\naccess\n}", 1),
		"unclosed":  strings.TrimSuffix(good, "}"),
		"colon":     strings.Replace(good, "signing {", "bad:name {", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := new(companion.SQLiteSecretsManager).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("invalid parser input accepted or disclosed", err)
			}
		})
	}
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("parser created database")
	}
}

func TestSecretsSnapshotOwnsNoDatabase(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	sqliteSecretsTestPut(t, cfg, map[string]any{"literal.dot": map[string]any{"array": []any{json.Number("1.00")}}, "empty": ""})
	module, _ := sqliteSecretsTestModule(t, cfg)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := module.Provision(ctx); err == nil {
		t.Fatal("live snapshot reprovisioned")
	}
	if err := os.Remove(cfg.Path); err != nil {
		t.Fatal(err)
	}
	// Removing storage after provisioning cannot affect snapshot-only lookups.
	value, err := module.GetSecretByKey(t.Context(), "literal.dot")
	if err != nil {
		t.Fatal(err)
	}
	value.(map[string]any)["array"].([]any)[0] = "mutated"
	again, err := module.GetSecretByKey(t.Context(), "literal.dot")
	if err != nil || again.(map[string]any)["array"].([]any)[0] != json.Number("1.00") {
		t.Fatal("key lookup leaked mutable snapshot", err)
	}
	if _, err := module.GetSecretByKey(t.Context(), "empty"); !errors.Is(err, backend.ErrInvalid) {
		t.Fatal("empty credential accepted", err)
	}
	metadata := module.GetConfig(t.Context())
	if len(metadata) != 4 || metadata["id"] != cfg.Name || metadata["name"] != cfg.Name || metadata["kind"] != "sqlite" || metadata["record"] != cfg.Record {
		t.Fatal("metadata is not allowlisted")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := module.GetSecretByKey(canceled, "literal.dot"); !errors.Is(err, context.Canceled) {
		t.Fatal("key lookup ignored cancellation", err)
	}
	if err := module.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := module.Provision(ctx); err == nil {
		t.Fatal("retired module reprovisioned")
	}
	if _, err := module.GetSecretByKey(t.Context(), "literal.dot"); !errors.Is(err, backend.ErrUnavailable) {
		t.Fatal("retired key snapshot available", err)
	}
}
