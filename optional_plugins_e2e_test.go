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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func assertOptionalCompanionModules(t *testing.T, binary string, expected ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "list-modules")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("list executable modules: %v\n%s", err, output)
	}
	var found []string
	core := false
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		core = core || fields[0] == "security"
		if strings.HasPrefix(fields[0], "security.") {
			found = append(found, fields[0])
		}
		if len(expected) == 0 && fields[0] == "caddy.storage.consul" {
			t.Fatal("default build linked Consul storage")
		}
	}
	slices.Sort(found)
	want := slices.Clone(expected)
	slices.Sort(want)
	if !core || !slices.Equal(found, want) {
		t.Fatalf("executable companion modules = %v (security app=%v); want %v", found, core, want)
	}
}

// This child has its own module registry: the parent test binary explicitly
// imports companions for integration tests and cannot establish default linkage.
func TestCaddyOptionalPluginsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "caddy")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build default Caddy: %v\n%s", err, output)
	}
	assertOptionalCompanionModules(t, binary)
	deps := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-deps", "./cmd/authcrunch")
	deps.WaitDelay = 5 * time.Second
	output, err := deps.CombinedOutput()
	if err != nil {
		t.Fatalf("list production imports: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if strings.HasPrefix(dependency, "github.com/greenpau/caddy-security/plugins/") {
			t.Fatalf("default build imports optional companion %s", dependency)
		}
	}
	core := filepath.Join(dir, "core.Caddyfile")
	if err := os.WriteFile(core, []byte(`{
 admin off
 security {
  authorization policy core {
   crypto key verify optional-plugin-fixture-signing-secret
   allow roles authp/user
  }
 }
}
`), 0600); err != nil {
		t.Fatal(err)
	}
	validate := exec.CommandContext(ctx, binary, "validate", "--config", core, "--adapter", "caddyfile")
	validate.Env = append(os.Environ(), "XDG_CONFIG_HOME="+dir, "XDG_DATA_HOME="+dir)
	validate.WaitDelay = 5 * time.Second
	if output, err := validate.CombinedOutput(); err != nil {
		t.Fatalf("core security configuration rejected: %v\n%s", err, output)
	}
	missing := filepath.Join(dir, "missing.Caddyfile")
	if err := os.WriteFile(missing, []byte("{\n security {\n oauth login store consul shared\n }\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, module string }{
		{missing, "security.oauth_login_stores.consul"},
		{"plugins/claims-enrichment-static/testdata/configured.Caddyfile", "security.claims_enrichment.static"},
		{"plugins/external-authorization-httpjson/testdata/configured.Caddyfile", "security.external_authorization.httpjson"},
	} {
		adapt := exec.CommandContext(ctx, binary, "adapt", "--config", tc.path, "--adapter", "caddyfile")
		adapt.WaitDelay = 5 * time.Second
		output, err := adapt.CombinedOutput()
		if err == nil || !strings.Contains(string(output), tc.module) || !strings.Contains(string(output), "not registered") {
			t.Fatalf("missing companion %s did not fail adaptation: %v\n%s", tc.module, err, output)
		}
	}
}
