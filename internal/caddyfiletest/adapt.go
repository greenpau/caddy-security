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

// Package caddyfiletest runs companion-owned Caddyfile adaptation fixtures.
// Callers register the security app explicitly in their integration tests.
package caddyfiletest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
)

// Run adapts every .Caddyfile in dir through Caddy's registered adapter. Each
// input has exactly one .json or .error expectation and an optional .env file.
// JSON is compared semantically, preserving number precision and array order.
func Run(t *testing.T, dir string) {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("Caddyfile adapter is not registered")
	}
	inputs, err := filepath.Glob(filepath.Join(dir, "*.Caddyfile"))
	if err != nil || len(inputs) == 0 {
		t.Fatalf("discover adaptation fixtures in %s: %v (found %d)", dir, err, len(inputs))
	}
	for _, input := range inputs {
		prefix := strings.TrimSuffix(input, ".Caddyfile")
		t.Run(filepath.Base(prefix), func(t *testing.T) {
			setEnvironment(t, prefix+".env")
			source, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, jsonErr := os.ReadFile(prefix + ".json")
			wantError, errorErr := os.ReadFile(prefix + ".error")
			if jsonErr != nil && !os.IsNotExist(jsonErr) {
				t.Fatal(jsonErr)
			}
			if errorErr != nil && !os.IsNotExist(errorErr) {
				t.Fatal(errorErr)
			}
			if (jsonErr == nil) == (errorErr == nil) {
				t.Fatal("fixture requires exactly one .json or .error expectation")
			}
			got, warnings, err := adapter.Adapt(source, map[string]any{"filename": "Caddyfile"})
			if errorErr == nil {
				if err == nil {
					t.Fatal("invalid Caddyfile unexpectedly adapted")
				}
				if diff := cmp.Diff(strings.TrimSpace(string(wantError)), err.Error()); diff != "" {
					t.Fatalf("adapt error mismatch (-want +got):\n%s", diff)
				}
				return
			}
			if err != nil {
				t.Fatalf("adapt Caddyfile: %v", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("unexpected adaptation warnings: %+v", warnings)
			}
			if diff := cmp.Diff(decodeJSON(t, wantJSON), decodeJSON(t, got)); diff != "" {
				t.Fatalf("adapted JSON mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func decodeJSON(t *testing.T, data []byte) any {
	t.Helper()
	if !json.Valid(data) {
		t.Fatal("fixture or adapter produced invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func setEnvironment(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for line, entry := range strings.Split(string(data), "\n") {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			t.Fatalf("invalid environment entry at %s:%d", path, line+1)
		}
		t.Setenv(key, value)
	}
}
