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

package rsapss_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	companion "github.com/greenpau/caddy-security/plugins/cryptographic-signing-rsapss"
)

func TestSignerCaddyfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "key, {env.LITERAL}.pem")
	good := fmt.Sprintf("primary {\nkey file %q\nkey id current\nissuer https://auth.example.test/auth\naudience service-a\nmax lifetime 900s\n}", path)
	var module companion.RSAPSSAccessSigner
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if module.Name != "primary" || module.KeyFile != path || module.Algorithm != "PS256" || module.MaxLifetime != "15m0s" {
		t.Fatal("literal transport or defaults changed")
	}
	for name, input := range map[string]string{
		"bad name": strings.Replace(good, "primary {", "\" primary\" {", 1),
		"empty":    "", "extra header": strings.Replace(good, "primary {", "primary extra {", 1),
		"duplicate": strings.Replace(good, "key id current", "key id current\nkey id second", 1),
		"unknown":   strings.Replace(good, "key id current", "unknown private-canary", 1),
		"nested":    strings.Replace(good, "key id current", "key id current {\n}", 1),
		"unclosed":  strings.TrimSuffix(good, "}"),
		"algorithm": strings.Replace(good, "key id current", "key id current\nalgorithm RS256", 1),
	} {
		t.Run(name, func(t *testing.T) {
			before := module
			if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("invalid input accepted or disclosed", err)
			}
			if module != before {
				t.Fatal("failed parse changed declaration")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("parsing performed key I/O")
	}
}

func TestSignerRejectsMalformedKeys(t *testing.T) {
	for _, content := range []string{"private-key-canary", "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n", strings.Repeat("x", 16385)} {
		path := filepath.Join(t.TempDir(), "key.pem")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		factory := accessSignerTestFactory(t, accessSignerTestModuleConfig(path))
		if signer, err := factory.NewAccessSigner(t.Context()); signer != nil || err == nil || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), path) {
			t.Fatal("invalid private key accepted or disclosed", err)
		}
	}
}
