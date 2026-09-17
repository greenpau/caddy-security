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

//go:build identity_profile_regression

package security

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// This deliberately failing qualification test records a go-authcrunch v1.2.5
// gap. It is separate from the supported-contract suite, never inverted into an
// assertion that cross-user access is correct. Run the documented build tag
// after an upstream fix, then remove the tag to make this a default regression.
func TestCaddyProfileCanonicalIdentityRegression(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", transform: true}, cert, key, roots)
	f.input = strings.Replace(f.input, "overwrite email alias@example.test", "overwrite email bob@example.test", 1)
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	f.load(t)
	f.formLogin(t, "alice", lifecyclePassword, false)
	response := f.profile(t, map[string]any{"kind": "fetch_user_info"}, 200)
	var result struct {
		Entry struct{ Metadata struct{ Username string } }
	}
	if json.Unmarshal(response.body, &result) != nil {
		t.Fatal("invalid profile metadata")
	}
	if result.Entry.Metadata.Username != "alice" {
		t.Errorf("canonical Alice login selected profile identity %q", result.Entry.Metadata.Username)
	}
	keyData, err := os.ReadFile("testdata/identity/legacy_pgp_public.pem")
	if err != nil {
		t.Fatal(err)
	}
	f.profile(t, map[string]any{"kind": "add_user_gpg_key", "content": string(keyData), "title": "Fixture key", "description": "Compatibility fixture"}, 200)
	alice, bob := localIdentityRecord(t, f.database, "alice"), localIdentityRecord(t, f.database, "bob")
	if len(alice.PublicKeys) != 1 || len(bob.PublicKeys) != 0 {
		t.Errorf("Alice's profile upload persisted keys for Alice=%d, Bob=%d", len(alice.PublicKeys), len(bob.PublicKeys))
	}
}
