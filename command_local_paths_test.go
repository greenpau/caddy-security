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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func TestSecurityLocalPathResolution(t *testing.T) {
	testSecurityLocalPathResolution(t, executeLocalCommand)
}

func TestSecurityLocalPathResolutionE2E(t *testing.T) {
	testSecurityLocalPathResolution(t, func(t *testing.T, args ...string) ([]byte, error) {
		return securityCommand(t, append([]string{"security", "local"}, args...)...)
	})
}

func testSecurityLocalPathResolution(t *testing.T, run func(*testing.T, ...string) ([]byte, error)) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix symlink traversal fixture")
	}
	for _, scenario := range []string{"config_collision", "config_default_cache", "config_relative_cache", "flag_traversal", "yaml_traversal", "hard_link_collision", "token_symlink", "dangling_token_symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			physical := filepath.Join(root, "physical")
			if err := os.MkdirAll(filepath.Join(physical, "child"), 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "link")
			if err := os.Symlink(filepath.Join(physical, "child"), link); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				fmt.Fprint(w, `{"authenticated":true,"access_token":"synthetic-path-token"}`)
			}))
			defer server.Close()
			config := filepath.Join(physical, "client.yaml")
			configArg := config
			tokenFlag, tokenYAML := "", ""
			wantDir := physical
			wantErr := false
			// Concatenation is intentional: filepath.Join would erase link/..
			// before the filesystem follows the symlink.
			throughLink := link + string(filepath.Separator) + ".." + string(filepath.Separator)
			switch scenario {
			case "config_collision":
				configArg, tokenFlag, wantErr = throughLink+"client.yaml", config, true
			case "config_default_cache":
				configArg, wantDir = throughLink+"client.yaml", filepath.Join(physical, ".security-tokens")
			case "config_relative_cache":
				configArg, tokenYAML, wantDir = throughLink+"client.yaml", "cache/token.json", filepath.Join(physical, "cache")
			case "flag_traversal":
				tokenFlag = throughLink + "token.json"
			case "yaml_traversal":
				config = filepath.Join(root, "client.yaml")
				configArg, tokenYAML = config, "link/../token.json"
			case "hard_link_collision", "token_symlink", "dangling_token_symlink":
				tokenFlag, wantErr = filepath.Join(root, "alias"), true
			}
			data := []byte(fmt.Sprintf("base_url: %q\nusername: admin\nrealm: local\npassword: %q\ntoken_path: %q\n", server.URL, registrationTestSecret, tokenYAML))
			if err := os.WriteFile(config, data, 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "hard_link_collision":
				err = os.Link(config, tokenFlag)
			case "token_symlink":
				target := filepath.Join(physical, "token.json")
				if err := os.WriteFile(target, []byte(`{"access_token":"synthetic-existing-token"}`), 0600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(target, tokenFlag)
			case "dangling_token_symlink":
				err = os.Symlink(filepath.Join(root, "missing.json"), tokenFlag)
			}
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"connect", "--config", configArg}
			if tokenFlag != "" {
				args = append(args, "--token-path", tokenFlag)
			}
			output, err := run(t, args...)
			if wantErr {
				if err == nil || calls.Load() != 0 {
					t.Error("unsafe token target was accepted or reached the portal")
				}
			} else {
				if err != nil || calls.Load() != 1 {
					t.Fatal("path-based login failed", err)
				}
				var result struct {
					TokenPath string `json:"token_path"`
				}
				if json.Unmarshal(output, &result) != nil || filepath.Dir(result.TokenPath) != wantDir {
					t.Error("token cache was redirected by lexical path cleaning")
				} else {
					store, err := authclient.NewFileTokenStore(result.TokenPath)
					if err != nil {
						t.Fatal(err)
					}
					if credentials, err := store.Load(); err != nil || credentials.AccessToken != "synthetic-path-token" {
						t.Error("credentials were not saved at the intended path")
					}
				}
			}
			if current, err := os.ReadFile(config); err != nil || !bytes.Equal(current, data) {
				t.Error("login overwrote its client configuration")
			}
		})
	}
}
