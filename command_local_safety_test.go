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
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func TestSecurityLocalConfigUTF8(t *testing.T) {
	invalid := "decoded-secret-\xff"
	for _, field := range []string{"base_url", "username", "realm", "password", "api_key", "totp_secret", "access_token_name", "refresh_transport", "token_path", "cookie_name"} {
		t.Run(field, func(t *testing.T) {
			settings := map[string]string{"base_url": "https://example.test", "username": "alice", "realm": "local"}
			delete(settings, field)
			if field == "api_key" {
				delete(settings, "username")
			}
			var input strings.Builder
			for name, value := range settings {
				fmt.Fprintf(&input, "%s: %q\n", name, value)
			}
			fmt.Fprintf(&input, "%s: !!binary %s\n", field, base64.StdEncoding.EncodeToString([]byte(invalid)))
			_, err := parseSecurityLocalConfig([]byte(input.String()))
			if err == nil || strings.Contains(err.Error(), "decoded-secret") {
				t.Error("invalid decoded UTF-8 accepted or disclosed")
			}
		})
	}
	// A Unicode password must survive YAML decoding without normalization.
	password := "Test-秘密-é-\ufffd-123"
	input := fmt.Sprintf("base_url: https://example.test\nusername: alice\nrealm: local\npassword: !!binary %s\n", base64.StdEncoding.EncodeToString([]byte(password)))
	cfg, err := parseSecurityLocalConfig([]byte(input))
	if err != nil || cfg.Password != password {
		t.Fatal("valid Unicode password changed", err)
	}
}

func TestSecurityLocalStrictTLS(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); fmt.Fprint(w, `{"version":"test"}`) }))
	defer server.Close()
	config, _ := localCommandConfig(t, server.URL, true)
	// Simulate another module changing the process-wide transport. CLI trust
	// must remain explicit even inside a custom Caddy executable.
	original := http.DefaultTransport
	transport := original.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	output, err := executeLocalCommand(t, "metadata", "--config", config)
	if err == nil || len(output) != 0 || calls.Load() != 0 {
		t.Fatal("inherited transport disabled CLI certificate verification")
	}
}

func TestSecurityLocalConfiguredTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(11 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			fmt.Fprint(w, `{"version":"slow-test"}`)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	config, _ := localCommandConfig(t, server.URL, true)
	output, err := executeLocalCommand(t, "metadata", "--config", config, "--timeout", "20s")
	if err != nil || !bytes.Contains(output, []byte("slow-test")) {
		t.Fatal("request was cut off before the configured deadline", err)
	}
}

// Run Caddy with the transport customization a third-party module could make.
func TestSecurityLocalTransportProcess(t *testing.T) {
	if os.Getenv("SECURITY_LOCAL_TRANSPORT_PROCESS") != "1" {
		t.Skip("subprocess helper")
	}
	if os.Getenv("SECURITY_LOCAL_INSECURE_DEFAULT") == "1" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		http.DefaultTransport = transport
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			caddycmd.Main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

func TestSecurityLocalClientSafetyE2E(t *testing.T) {
	run := func(insecure bool, args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestSecurityLocalTransportProcess$", "--", "security", "local"}, args...)...)
		insecureValue := "0"
		if insecure {
			insecureValue = "1"
		}
		cmd.Env = append(os.Environ(), "SECURITY_LOCAL_TRANSPORT_PROCESS=1", "SECURITY_LOCAL_INSECURE_DEFAULT="+insecureValue)
		collectSubprocessCoverage(t, cmd)
		cmd.WaitDelay = 2 * time.Second
		return cmd.CombinedOutput()
	}
	t.Run("strict_tls", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); fmt.Fprint(w, `{"version":"test"}`) }))
		defer server.Close()
		config, _ := localCommandConfig(t, server.URL, true)
		if _, err := run(true, "metadata", "--config", config); err == nil || calls.Load() != 0 {
			t.Fatal("Caddy inherited insecure certificate verification")
		}
	})
	t.Run("invalid_utf8", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			fmt.Fprint(w, `{"authenticated":true,"access_token":"synthetic-token"}`)
		}))
		defer server.Close()
		config := filepath.Join(t.TempDir(), "client.yaml")
		input := fmt.Sprintf("base_url: %q\nusername: alice\nrealm: local\npassword: !!binary //8=\n", server.URL)
		if err := os.WriteFile(config, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := run(false, "connect", "--config", config); err == nil || calls.Load() != 0 {
			t.Fatal("Caddy sent an invalid UTF-8 credential to the portal")
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(config), ".security-tokens")); !os.IsNotExist(err) {
			t.Fatal("invalid config created a credential cache")
		}
	})
	t.Run("configured_timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := time.NewTimer(11 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				fmt.Fprint(w, `{"authenticated":true,"access_token":"synthetic-token"}`)
			case <-r.Context().Done():
			}
		}))
		defer server.Close()
		config, _ := localCommandConfig(t, server.URL, false)
		if _, err := run(false, "connect", "--config", config, "--timeout", "20s"); err != nil {
			t.Fatal("Caddy login was cut off before configured deadline", err)
		}
	})
}

func TestSecurityLocalMutationFailureAfterCommit(t *testing.T) {
	for _, process := range []bool{false, true} {
		for _, status := range []int{http.StatusOK, http.StatusBadGateway} {
			t.Run(fmt.Sprintf("process=%v/status=%d", process, status), func(t *testing.T) {
				var commits atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/api/server/user" || r.Method != http.MethodPost {
						t.Error("unexpected mutation request")
					}
					// A backend or proxy can fail after applying the requested change.
					commits.Add(1)
					w.WriteHeader(status)
					fmt.Fprintf(w, `{"status":"failure","error":%q}`, registrationTestSecret)
				}))
				defer server.Close()
				config, _ := localCommandConfig(t, server.URL, true)
				args := []string{"delete", "user", "--config", config, "--realm", "local", "--username", "alice", "--email", "alice@example.test"}
				var output []byte
				var err error
				if process {
					output, err = securityCommand(t, append([]string{"security", "local"}, args...)...)
				} else {
					output, err = executeLocalCommand(t, args...)
				}
				if err == nil || commits.Load() != 1 {
					t.Fatal("post-commit failure was accepted or retried")
				}
				diagnostic := string(output) + err.Error()
				if !strings.Contains(diagnostic, "outcome may be unknown") || !strings.Contains(diagnostic, "inspect") {
					t.Error("post-commit failure did not explain how to avoid repeating a mutation")
				}
				if strings.Contains(diagnostic, registrationTestSecret) {
					t.Error("server error exposed a secret")
				}
				if status == http.StatusBadGateway && strings.Contains(diagnostic, "credentials") {
					t.Error("gateway failure incorrectly suggested renewing credentials")
				}
			})
		}
	}
}

func TestSecurityLocalResponseEncoding(t *testing.T) {
	for _, process := range []bool{false, true} {
		for _, tc := range []struct {
			name, body, password string
		}{
			{"invalid_utf8", "{\"status\":\"success\",\"password\":\"Test-\xff-secret\"}", ""},
			{"high_surrogate", `{"status":"success","password":"Test-\ud800-secret"}`, ""},
			{"low_surrogate", `{"status":"success","password":"Test-\udc00-secret"}`, ""},
			{"surrogate_pair", `{"status":"success","password":"Test-\ud83d\udd11-secret"}`, "Test-🔑-secret"},
			{"replacement_character", `{"status":"success","password":"Test-\ufffd-secret"}`, "Test-\ufffd-secret"},
		} {
			t.Run(fmt.Sprintf("process=%v/%s", process, tc.name), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					fmt.Fprint(w, tc.body)
				}))
				defer server.Close()
				config, _ := localCommandConfig(t, server.URL, true)
				args := []string{"update", "user", "--reset-password", "--config", config, "--realm", "local", "--username", "alice", "--email", "alice@example.test"}
				var output []byte
				var err error
				if process {
					output, err = securityCommand(t, append([]string{"security", "local"}, args...)...)
				} else {
					output, err = executeLocalCommand(t, args...)
				}
				if calls.Load() != 1 {
					t.Fatal("response handling repeated a password reset")
				}
				if tc.password == "" {
					if err == nil {
						t.Error("corrupt password response was accepted")
					} else if !strings.Contains(string(output)+err.Error(), "outcome may be unknown") {
						t.Error("corrupt mutation response omitted recovery guidance")
					}
					if bytes.Contains(output, []byte("Test-")) {
						t.Error("corrupt password response was disclosed")
					}
					return
				}
				var result struct{ Password string }
				if err != nil || json.Unmarshal(output, &result) != nil || result.Password != tc.password {
					t.Error("valid response password changed")
				}
			})
		}
	}
}
