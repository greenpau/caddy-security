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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Use the production command and a verified TLS connection, with no portal.
// The actual CLI issues/revokes credentials while Caddy keeps serving traffic.
func TestCaddySQLiteCredentialsE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	buildCtx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CGO-free Caddy: %v\n%s", err, output)
	}
	cert, tlsKey, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, tlsKey, roots)
	cfg := sqliteCredentialsConfig(t)
	input := filepath.Join(filepath.Dir(cfg.Path), "provision.json")
	markers := []string{"malformed-private-key", "private-basic-password", base64.StdEncoding.EncodeToString([]byte("alice:private-basic-password"))}
	cli := func(action string, fields map[string]any, output string, success bool) []byte {
		t.Helper()
		if err := os.WriteFile(input, sqliteAPIKeyDocument(t, cfg, fields), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
		defer cancel()
		args := []string{"security", "api-key", action, "--config", input}
		if action == "issue" {
			args = append(args, "--output", output)
		}
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.WaitDelay = 5 * time.Second
		data, err := cmd.CombinedOutput()
		assertAdminRedacted(t, data, markers)
		if (err == nil) != success {
			t.Fatalf("api-key %s success=%v: %v\n%s", action, success, err, data)
		}
		return data
	}
	issue := func(name string, roles []string) (string, string) {
		t.Helper()
		output := filepath.Join(filepath.Dir(cfg.Path), name+".key")
		fields := sqliteAPIKeyIssueFields()
		fields["roles"] = roles
		commandOutput := cli("issue", fields, output, true)
		data, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		key := strings.TrimSuffix(string(data), "\n")
		markers = append(markers, key)
		assertAdminRedacted(t, commandOutput, markers)
		return key, output
	}
	key, keyFile := issue("alice", []string{"authp/user"})
	denied, _ := issue("denied", []string{"unprivileged"})
	source := fmt.Sprintf(`{
 admin %s
 auto_https off
 log {
  level DEBUG
  format filter {
   wrap json
   fields {
    request>headers>X-Api-Key delete
    request>headers>X-Private-Key delete
   }
  }
 }
 security {
  credential authenticator sqlite keys {
   path %q
   realm staff
   timeout 500ms
  }
  authorization policy policy {
   crypto key verify synthetic-api-key-signing-secret
   with api key auth portal keys realm staff
   allow roles authp/user
   disable auth redirect
   enable strip token
  }
  authorization policy custom {
   crypto key verify synthetic-api-key-signing-secret
   with api key auth portal keys realm staff
   with api key header name X-Private-Key
   with auth realm header name X-Private-Realm
   allow roles authp/user
   disable auth redirect
   enable strip token
  }
 }
}
%s {
 tls %q %q
 log {
  format filter {
   wrap json
   fields {
    request>headers>X-Api-Key delete
    request>headers>X-Private-Key delete
   }
  }
 }
 route /ready {
  respond "ready"
 }
 route /protected {
  authorize with policy
  respond "email={http.request.header.X-Token-User-Email};key={http.request.header.X-Api-Key}"
 }
 route /custom {
  authorize with custom
  respond "key={http.request.header.X-Private-Key}"
 }
}`, f.admin, cfg.Path, f.base, cert, tlsKey)
	baseline := f.write(t, source)
	assertAdminRedacted(t, baseline, markers)
	f.start(t)
	headers := func(key, realm string) http.Header { return http.Header{"X-Api-Key": {key}, "X-Auth-Realm": {realm}} }
	request := func(key, realm string, status int) oidcRPResponse {
		t.Helper()
		return persistentRequest(t, f.client, "GET", f.base+"/protected", nil, headers(key, realm), status)
	}
	for range 3 {
		response := request(key, "staff", 200)
		if strings.Contains(string(response.body), key) || !strings.Contains(string(response.body), "key=") {
			t.Fatal("credential not stripped")
		}
	}
	custom := persistentRequest(t, f.client, "GET", f.base+"/custom", nil, http.Header{"X-Private-Key": {key}, "X-Private-Realm": {"staff"}}, 200)
	if string(custom.body) != "key=" {
		t.Fatal("custom credential not stripped")
	}
	request(key, "guests", 401)
	request(key, "", 401)
	request("malformed-private-key", "staff", 401)
	request(denied, "staff", 403)
	persistentRequest(t, f.client, "GET", f.base+"/protected", nil, http.Header{"Authorization": {"Basic " + markers[2]}, "X-Auth-Realm": {"staff"}}, 401)
	reload := func(data []byte, success bool) {
		t.Helper()
		if err := os.WriteFile(f.config, data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "reload", "--force", "--config", f.config, "--address", f.admin)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		assertAdminRedacted(t, output, markers)
		if (err == nil) != success {
			t.Fatalf("reload success=%v: %v\n%s", success, err, output)
		}
	}
	// An invalid candidate must not close the current app's backend.
	var candidate map[string]any
	if err := json.Unmarshal(baseline, &candidate); err != nil {
		t.Fatal(err)
	}
	security := candidate["apps"].(map[string]any)["security"].(map[string]any)
	security["credential_authenticators"].([]any)[0].(map[string]any)["realm"] = "guests"
	bad, _ := json.Marshal(candidate)
	reload(bad, false)
	request(key, "staff", 200)
	// File safety is checked on each read. A previously successful key cannot
	// fall back to a credential cache while storage is unavailable.
	if err := os.Chmod(cfg.Path, 0644); err != nil {
		t.Fatal(err)
	}
	request(key, "staff", 401)
	reload(baseline, false)
	if err := os.Chmod(cfg.Path, 0600); err != nil {
		t.Fatal(err)
	}
	request(key, "staff", 200)
	cfg.Realm = "guests"
	cli("revoke", map[string]any{"key_file": keyFile}, "", true)
	request(key, "staff", 200)
	cfg.Realm = "staff"
	cli("revoke", map[string]any{"key_file": keyFile}, "", true)
	request(key, "staff", 401)
	persistentRequest(t, f.client, "GET", f.base+"/custom", nil, http.Header{"X-Private-Key": {key}, "X-Private-Realm": {"staff"}}, 401)
	replacement, _ := issue("replacement", []string{"authp/user"})
	request(replacement, "staff", 200)
	reload(baseline, true)
	request(replacement, "staff", 200)
	request(key, "staff", 401)
	f.restart(t)
	request(replacement, "staff", 200)
	request(key, "staff", 401)
	// Ordinary admin/config surfaces contain only declarations, never key bytes.
	adminCtx, cancelAdmin := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelAdmin()
	adminRequest, err := http.NewRequestWithContext(adminCtx, "GET", "http://"+f.admin+"/config/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(adminRequest)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("admin introspection", err)
	}
	assertAdminRedacted(t, body, markers)
	f.kill(t)
	log, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep failures useful without reproducing the leaked credential in reports.
	for _, line := range strings.Split(string(log), "\n") {
		redacted := line
		for _, marker := range markers {
			redacted = strings.ReplaceAll(redacted, marker, "[credential redacted]")
		}
		if redacted != line {
			t.Errorf("credential in diagnostic log: %s", redacted)
		}
	}
	if err := filepath.WalkDir(f.workspace, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (d.Name() == "autosave.json" || d.Name() == "config.json") {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			assertAdminRedacted(t, data, markers)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
