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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func localCommandConfig(t *testing.T, base string, cached bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	config, token := filepath.Join(dir, "client.yaml"), filepath.Join(dir, "token.json")
	data := fmt.Sprintf("base_url: %q\nusername: admin\nrealm: local\npassword: %q\ntoken_path: %q\n", base, registrationTestSecret, token)
	if err := os.WriteFile(config, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if cached {
		store, err := authclient.NewFileTokenStore(token)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Save(&authclient.Credentials{AccessToken: registrationTestSecret, AccessTokenName: "custom_token"}); err != nil {
			t.Fatal(err)
		}
	}
	return config, token
}

func executeLocalCommand(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	cmd, output := securityTestCommand(t)
	cmd.SetArgs(append([]string{"local"}, args...))
	err := cmd.Execute()
	return output.Bytes(), err
}

func TestSecurityLocalRequests(t *testing.T) {
	for _, tc := range []struct{ path, flags, endpoint, want string }{
		{"metadata", "", "metadata", ""},
		{"list realms", "", "realms", `{"query":"all"}`},
		{"list users", "--realm local", "users", `{"realm":"local","query":"all"}`},
		{"info realm", "--realm local", "info", `{"realm":"local"}`},
		{"reload", "--realm local", "reload", `{"realm":"local"}`},
		{"info user", "", "user", `{"realm":"local","operation":"info","user":{"username":"alice","email":"alice@example.test"}}`},
		{"delete user", "", "user", `{"realm":"local","operation":"delete","user":{"username":"alice","email":"alice@example.test"}}`},
		{"add user", "--name Alice --roles authp/user,reader --roles editor", "user", `{"realm":"local","operation":"add","user":{"username":"alice","email":"alice@example.test","name":"Alice","roles":["authp/user","reader","editor"]}}`},
		{"update user", "--disable", "user", `{"realm":"local","operation":"disable","user":{"username":"alice","email":"alice@example.test"}}`},
		{"update user", "--enable", "user", `{"realm":"local","operation":"enable","user":{"username":"alice","email":"alice@example.test"}}`},
		{"update user", "--reset-password", "user", `{"realm":"local","operation":"reset_password","user":{"username":"alice","email":"alice@example.test"}}`},
		{"update user", "--overwrite-roles authp/user,reader", "user", `{"realm":"local","operation":"overwrite_roles","user":{"username":"alice","email":"alice@example.test","roles":["authp/user","reader"]}}`},
		{"update user", "--add-roles reader", "user", `{"realm":"local","operation":"add_roles","user":{"username":"alice","email":"alice@example.test","roles":["reader"]}}`},
		{"update user", "--overwrite-auth-challenges password,totp", "user", `{"realm":"local","operation":"overwrite_auth_challenges","user":{"username":"alice","email":"alice@example.test","challenges":["password","totp"]}}`},
	} {
		t.Run(tc.path+"/"+tc.flags, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/auth/api/server/"+tc.endpoint || r.Header.Get("Authorization") != "custom_token="+registrationTestSecret || r.Header.Get("Accept") != "application/json" {
					t.Error("incorrect request target or credentials")
				}
				method := http.MethodPost
				if tc.endpoint == "metadata" {
					method = http.MethodGet
				}
				if r.Method != method {
					t.Error("incorrect HTTP method")
				}
				body, _ := io.ReadAll(r.Body)
				if tc.want == "" {
					if len(body) != 0 {
						t.Error("unexpected metadata body")
					}
				} else {
					var got, want map[string]any
					if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(tc.want), &want) != nil {
						t.Error("invalid payload")
					}
					if diff := cmp.Diff(want, got); diff != "" {
						t.Error(diff)
					}
				}
				fmt.Fprint(w, `{"status":"success","version":"test","realms":[],"users":[],"policy":{},"username":"alice","password":"synthetic-generated-password"}`)
			}))
			defer server.Close()
			config, _ := localCommandConfig(t, server.URL+"/auth", true)
			args := append(strings.Fields(tc.path), "--config", config)
			if strings.HasSuffix(tc.path, " user") {
				args = append(args, "--realm", "local", "--username", "alice", "--email", "alice@example.test")
			}
			args = append(args, strings.Fields(tc.flags)...)
			output, err := executeLocalCommand(t, args...)
			if err != nil || !json.Valid(output) || calls.Load() != 1 {
				t.Fatal("command did not send one successful request", err)
			}
		})
	}
}

func TestSecurityLocalValidation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	config, token := localCommandConfig(t, server.URL, false)
	for _, args := range [][]string{
		{"update", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test"},
		{"update", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--enable", "--disable"},
		{"update", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--disable=false"},
		{"update", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--add-roles", ""},
		{"update", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--overwrite-auth-challenges", "password,"},
		{"add", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--name", "Alice", "--roles", ""},
		{"info", "user", "--realm", "local", "--username", "alice"},
		{"reload", "--realm", " "},
		{"list", "users", "--realm", "local", "--format", registrationTestSecret},
		{"metadata", "--timeout", "0"},
		{"metadata", "--timeout", registrationTestSecret},
		{"metadata", registrationTestSecret},
		{"metadata", "--" + registrationTestSecret},
		{"metadata", "--token-path", ""},
		{"metadata", "--token-path", "invalid-utf8-\xff"},
		{"connect", "--token-path", config},
	} {
		output, err := executeLocalCommand(t, append(args, "--config", config)...)
		if err == nil || bytes.Contains(output, []byte(registrationTestSecret)) || strings.Contains(err.Error(), registrationTestSecret) {
			t.Error("invalid command accepted or disclosed a secret")
		}
	}
	if calls.Load() != 0 {
		t.Error("invalid commands contacted server")
	}
	if _, err := os.Stat(token); !errors.Is(err, os.ErrNotExist) {
		t.Error("invalid command saved credentials")
	}
}

func TestSecurityLocalConfig(t *testing.T) {
	valid := "base_url: https://example.test/auth/\nusername: alice\nrealm: local\n"
	for _, data := range []string{"", "null", "[]", valid + "password: [" + registrationTestSecret + "]\n", valid + "unknown: " + registrationTestSecret, valid + "realm: duplicate", valid + "---\n" + valid, strings.Replace(valid, "https://example.test/auth/", "https://"+registrationTestSecret+"@example.test", 1)} {
		_, err := parseSecurityLocalConfig([]byte(data))
		if err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatal("invalid config accepted or secret disclosed")
		}
	}
	cfg, err := parseSecurityLocalConfig([]byte(valid + "cookie_name: legacy\ntoken_path: token.json\n"))
	if err != nil || cfg.BaseURL != "https://example.test/auth" || cfg.AccessTokenName != authclient.DefaultAccessTokenName {
		t.Fatal("config defaults or compatibility failed", err)
	}
	paths := map[string]bool{}
	config := filepath.Join(t.TempDir(), "client.yaml")
	for _, data := range []string{valid, strings.Replace(valid, "example.test", "other.test", 1), strings.Replace(valid, "alice", "bob", 1)} {
		if err := os.WriteFile(config, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		root, _ := securityTestCommand(t)
		cmd, _, err := root.Find([]string{"local", "connect"})
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Flags().Parse([]string{"--config", config}); err != nil {
			t.Fatal(err)
		}
		client, err := newSecurityLocalClient(t.Context(), cmd)
		if err != nil {
			t.Fatal(err)
		}
		if paths[client.tokenPath] {
			t.Error("default token path shared across portals or identities")
		}
		paths[client.tokenPath] = true
		client.http.CloseIdleConnections()
	}
}

func TestSecurityLocalResponseFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"http", 403, registrationTestSecret},
		{"server", 500, registrationTestSecret},
		{"failure", 200, `{"status":"failure","error":"` + registrationTestSecret + `"}`},
		{"null", 200, "null"},
		{"array", 200, "[]"},
		{"missing-status", 200, `{"timestamp":"now"}`},
		{"bad-status", 200, `{"status":123}`},
		{"trailing", 200, `{"status":"success"}{}`},
		{"oversized", 200, strings.Repeat(" ", securityLocalMaxResponse+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()
			config, _ := localCommandConfig(t, server.URL, true)
			output, err := executeLocalCommand(t, "delete", "user", "--realm", "local", "--username", "alice", "--email", "alice@example.test", "--config", config)
			if err == nil || calls.Load() != 1 || len(output) != 0 || strings.Contains(err.Error(), registrationTestSecret) {
				t.Error("failure was exposed, retried, or treated as success")
			}
		})
	}
	for _, endpoint := range []string{"metadata", "realms", "users", "info", "user"} {
		if err := validateSecurityLocalResponse(endpoint, false, []byte(`{"timestamp":"now"}`)); err == nil {
			t.Error("accepted incomplete query response", endpoint)
		}
	}
	for endpoint, body := range map[string]string{
		"metadata": `{"version":[]}`, "realms": `{"realms":[null]}`,
		"users": `{"users":true}`, "info": `{"policy":[]}`, "user": `{"username":42}`,
	} {
		if err := validateSecurityLocalResponse(endpoint, false, []byte(body)); err == nil {
			t.Error("invalid query response accepted", endpoint)
		}
	}
}

func TestSecurityLocalTransport(t *testing.T) {
	var forwarded atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); fmt.Fprint(w, `{"status":"success"}`) }))
	defer destination.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, code) }))
		config, _ := localCommandConfig(t, server.URL, true)
		_, err := executeLocalCommand(t, "reload", "--realm", "local", "--config", config)
		server.Close()
		if err == nil {
			t.Error("accepted redirect")
		}
	}
	if forwarded.Load() != 0 {
		t.Error("redirect forwarded admin credentials")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	config, _ := localCommandConfig(t, server.URL, true)
	start := time.Now()
	_, err := executeLocalCommand(t, "metadata", "--config", config, "--timeout", "40ms")
	if err == nil || time.Since(start) > time.Second {
		t.Error("command ignored timeout")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readSecuritySecret(ctx, strings.NewReader(""), io.Discard, "Password: "); !errors.Is(err, context.Canceled) {
		t.Error("prompt ignored cancellation")
	}
}

type securityFailedWriter struct{}

func (securityFailedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSecurityLocalOutput(t *testing.T) {
	data := []byte(`{"users":[{"username":"alice","name":"Alice, Example","email":"alice@example.test","roles":["authp/user","reader"],"disabled":true}]}`)
	for _, format := range []string{"json", "table", "csv"} {
		var output bytes.Buffer
		if err := writeSecurityLocalResponse(&output, "users", format, data); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "alice") || !strings.Contains(output.String(), "true") {
			t.Error("user fields missing from output")
		}
		if err := writeSecurityLocalResponse(securityFailedWriter{}, "users", format, data); err == nil {
			t.Error("output failure ignored")
		}
	}
	var table bytes.Buffer
	if err := writeSecurityLocalResponse(&table, "realms", "table", []byte(`{"realms":[{"realm":"local","kind":"local","name":"unsafe\u001b[2J\nname"}]}`)); err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsRune(table.Bytes(), '\x1b') {
		t.Error("table emitted terminal control sequence")
	}
}

func TestSecurityLocalLoginAndCache(t *testing.T) {
	var logins, requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xauth/login" {
			logins.Add(1)
			var request map[string]string
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				t.Error("bad login body")
			}
			if request["challenge_response"] == "" {
				fmt.Fprint(w, `{"sandbox_id":"test","sandbox_secret":"test-secret","next_challenge":"password"}`)
			} else {
				if request["challenge_response"] != registrationTestSecret {
					t.Error("password not forwarded to authclient")
				}
				fmt.Fprint(w, `{"authenticated":true,"access_token":"`+registrationTestSecret+`","access_token_name":"custom_token"}`)
			}
			return
		}
		requests.Add(1)
		if r.URL.Path != "/xauth/api/server/metadata" {
			t.Error("admin request lost the configured portal mount")
		}
		if r.Header.Get("Authorization") != "custom_token="+registrationTestSecret {
			t.Error("cached credentials not used")
		}
		fmt.Fprint(w, `{"version":"test"}`)
	}))
	defer server.Close()
	config, token := localCommandConfig(t, server.URL+"/xauth/", false)
	for range 2 {
		if _, err := executeLocalCommand(t, "metadata", "--config", config); err != nil {
			t.Fatal(err)
		}
	}
	if logins.Load() != 2 || requests.Load() != 2 {
		t.Error("cache did not avoid duplicate logins")
	}
	if info, err := os.Stat(token); err != nil || info.Mode().Perm() != 0600 {
		t.Error("credentials not saved privately")
	}
	if err := os.WriteFile(token, []byte("invalid-token-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := executeLocalCommand(t, "metadata", "--config", config); err == nil {
		t.Error("invalid cache silently replaced")
	}
	output, err := executeLocalCommand(t, "connect", "--config", config)
	if err != nil || !json.Valid(output) || bytes.Contains(output, []byte(registrationTestSecret)) {
		t.Error("explicit connect did not repair cache privately", err)
	}
}

func TestSecurityLocalTLSAndInputFiles(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"version":"test"}`)
	}))
	defer server.Close()
	config, _ := localCommandConfig(t, server.URL, true)
	if _, err := executeLocalCommand(t, "metadata", "--config", config); err == nil || calls.Load() != 0 {
		t.Error("untrusted TLS certificate accepted")
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := executeLocalCommand(t, "metadata", "--config", config, "--ca-file", caFile); err != nil || calls.Load() != 1 {
		t.Error("trusted CA file failed", err)
	}
	if _, err := executeLocalCommand(t, "connect", "--config", config, "--ca-file", caFile, "--token-path", caFile); err == nil {
		t.Error("token output accepted CA input path")
	}
	if _, err := readSecurityLocalFile(t.Context(), filepath.Dir(config), 1024, true); err == nil {
		t.Error("directory accepted as credential file")
	}
	if _, err := readSecurityLocalFile(t.Context(), config, 1, true); err == nil {
		t.Error("input size limit ignored")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "link.yaml")
		if err := os.Symlink(config, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readSecurityLocalFile(t.Context(), link, 1<<20, true); err == nil {
			t.Error("credential symlink accepted")
		}
		if err := os.Chmod(config, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := executeLocalCommand(t, "metadata", "--config", config, "--ca-file", caFile); err == nil {
			t.Error("publicly readable credential config accepted")
		}
	}
}

func TestSecurityLocalUncertainMutation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close() // A mutation may already have committed before the connection drops.
	}))
	defer server.Close()
	config, _ := localCommandConfig(t, server.URL, true)
	output, err := executeLocalCommand(t, "reload", "--realm", "local", "--config", config)
	if err == nil || !strings.Contains(err.Error(), "unknown") || len(output) != 0 || calls.Load() != 1 {
		t.Error("uncertain mutation was retried or reported as successful")
	}
}
