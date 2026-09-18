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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const securityTerminalMFASecret = "0123456789abcdef0123456789abcdef"

func securityTerminalCommand(t *testing.T, mode string, args ...string) []byte {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix PTY test")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python 3 is required for the terminal test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, append([]string{"testdata/security_cli/terminal.py", os.Args[0], mode}, args...)...)
	cmd.Env = append(os.Environ(), "SECURITY_LOCAL_TEST_TOTP_SECRET="+securityTerminalMFASecret)
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 2 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("terminal %s: %v\n%s", mode, err, output)
	}
	var response struct {
		Output string `json:"output"`
	}
	if json.Unmarshal(output, &response) != nil {
		t.Fatal("invalid terminal broker response")
	}
	return []byte(response.Output)
}

func TestSecurityTerminalE2E(t *testing.T) {
	for _, mode := range []string{"success", "unicode", "crlf", "paste", "invalid-utf8", "replacement", "keyboard-interrupt", "keyboard-eof", "interrupt", "terminate", "hash-interrupt", "timeout", "login-terminate", "login-invalid-utf8", "login-replacement", "login-mfa-terminate", "login-totp-timeout"} {
		t.Run(mode, func(t *testing.T) {
			var loginCalls atomic.Int32
			var tokenPath string
			const cachedToken = `{"access_token":"synthetic-preserved-token"}`
			args := []string{"security", "local", "generate", "password", "hash", "--cost", "8"}
			if mode == "hash-interrupt" {
				args[len(args)-1] = "31"
			}
			if mode == "timeout" || strings.HasPrefix(mode, "login-") {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					loginCalls.Add(1)
					if r.URL.Path != "/login" {
						t.Error("unexpected request during password prompt")
					}
					if loginCalls.Load() == 2 {
						var request struct {
							Response string `json:"challenge_response"`
						}
						if json.NewDecoder(r.Body).Decode(&request) != nil || request.Response != "Terminal-secret-123" {
							t.Error("interactive password was changed")
						}
						fmt.Fprint(w, `{"sandbox_id":"test","sandbox_secret":"test-secret","next_challenge":"mfa"}`)
						return
					}
					fmt.Fprint(w, `{"sandbox_id":"test","sandbox_secret":"test-secret","next_challenge":"password"}`)
				}))
				defer server.Close()
				config := filepath.Join(t.TempDir(), "client.yaml")
				if err := os.WriteFile(config, []byte(fmt.Sprintf("base_url: %q\nusername: alice\nrealm: local\n", server.URL)), 0600); err != nil {
					t.Fatal(err)
				}
				tokenPath = filepath.Join(filepath.Dir(config), "token.json")
				if err := os.WriteFile(tokenPath, []byte(cachedToken), 0600); err != nil {
					t.Fatal(err)
				}
				timeout := "5s"
				if mode == "timeout" {
					timeout = "1s"
				}
				args = []string{"security", "local", "connect", "--config", config, "--token-path", tokenPath, "--timeout", timeout}
			}
			output := securityTerminalCommand(t, mode, args...)
			if mode == "timeout" || strings.HasPrefix(mode, "login-") {
				wantCalls := int32(1)
				if mode == "login-mfa-terminate" || mode == "login-totp-timeout" {
					wantCalls = 2
				}
				if loginCalls.Load() != wantCalls {
					t.Error("interrupted or malformed challenge reached the portal")
				}
				if data, err := os.ReadFile(tokenPath); err != nil || string(data) != cachedToken {
					t.Error("unsuccessful interactive login replaced cached credentials")
				}
			}
			switch mode {
			case "success", "crlf", "paste":
				passwordDirective(t, output, "Terminal-secret-123")
			case "unicode":
				passwordDirective(t, output, "Terminal-秘密-é-123")
			case "replacement":
				if len(output) != 0 {
					passwordDirective(t, output, "Terminal-\ufffd-secret-123")
				}
			}
		})
	}
}
