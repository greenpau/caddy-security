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
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestRegistrationProviderKeyPathIdentity(t *testing.T) {
	dir := registrationTestDirectory(t)
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte("host validation fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := registrationTestDirectory(t)
	child := filepath.Join(outside, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "key.pem"), []byte("different upstream file"), 0644); err != nil {
		t.Fatal(err)
	}
	// This rejection fixture must be nonprivate even under a restrictive umask.
	if err := os.Chmod(filepath.Join(outside, "key.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "alias.pem")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		valid      bool
	}{
		{"canonical", path, true},
		{"symlink parent traversal", dir + "/link/../key.pem", false},
		{"dot", dir + "/./key.pem", false},
		{"double separator", dir + "//key.pem", false},
		{"trailing separator", path + "/", false},
		{"nonprivate file", filepath.Join(outside, "key.pem"), false},
		{"symlink file", filepath.Join(dir, "alias.pem"), false},
		{"relative", "key.pem", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, source := range []string{"directives", "native JSON"} {
				t.Run(source, func(t *testing.T) {
					cfg := authcrunch.NewConfig()
					cfg.AuthenticationPortals = []*authn.PortalConfig{{Name: "myportal"}}
					if err := cfg.AddOAuthApplication(&oidc.OAuthApplicationConfig{Name: "website", Client: &oidc.ClientConfig{
						ClientID: "test-client", ClientSecret: registrationTestSecret, RedirectURIs: []string{"https://rp.example.test/callback"},
					}}); err != nil {
						t.Fatal(err)
					}
					app := &App{OIDCProviderDirectives: map[string][]string{"myportal": {
						"issuer https://auth.example.test/auth", "realms local", "applications website",
						encodeOAuthDirective([]string{"signing", "key", "files", tc.path}),
					}}}
					if source == "native JSON" {
						if err := cfg.ConfigureOIDCProvider(cfg.AuthenticationPortals[0], app.OIDCProviderDirectives["myportal"]); err != nil {
							t.Fatal(err)
						}
						app.OIDCProviderDirectives = nil
					}
					err := app.resolveOAuthRegistrationConfig(t.Context(), cfg)
					if (err == nil) != tc.valid {
						t.Fatalf("key path acceptance = %v, want %v", err == nil, tc.valid)
					}
				})
			}
		})
	}
}
