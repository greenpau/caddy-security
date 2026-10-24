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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Build the actual production command without CGO. The journey uses trusted TLS,
// private CLI input, browser password login, and independent JWT verification.
func TestCaddySQLiteSecretsE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CGO-free Caddy: %v\n%s", err, output)
	}
	cert, key, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	cfg := sqliteSecretsTestConfig(t)
	input := filepath.Join(filepath.Dir(cfg.Path), "provision.json")
	keyA := "sqlite-private-signing-key-A-0123456789\t\u00a0"
	keyB := "sqlite-private-signing-key-B-0123456789"
	markers := []string{strings.TrimSpace(keyA), keyB, "private-invalid-lifetime"}
	cli := func(action string, data []byte, success bool) {
		t.Helper()
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}
		commandCtx, stop := context.WithTimeout(t.Context(), 40*time.Second)
		defer stop()
		cmd := exec.CommandContext(commandCtx, binary, "security", "secrets", action, "--config", input)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		assertAdminRedacted(t, output, markers)
		if (err == nil) != success {
			t.Fatalf("secret %s success=%v: %v\n%s", action, success, err, output)
		}
	}
	put := func(values map[string]any) { t.Helper(); cli("put", sqliteSecretsInput(t, cfg, values), true) }
	put(map[string]any{"key": keyA, "bad": "private-invalid-lifetime", "number": json.Number("9007199254740993")})
	source := fmt.Sprintf(`{
 admin %s
 auto_https off
 log {
  level DEBUG
 }
 security {
  secrets sqlite signing {
   path %q
   record access
  }
  local identity store localdb {
   realm local
   path :memory:
   user keyadmin {
    email keyadmin@example.test
    password %q
    roles authp/admin authp/user
   }
  }
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify secrets:signing:key
  }
  authorization policy policy {
   crypto key verify secrets:signing:key
   allow roles authp/user
   validate bearer header
   disable auth redirect
  }
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /protected {
  authorize with policy
  respond "allowed"
 }
 route /auth* {
  authenticate with myportal
 }
}`, f.admin, cfg.Path, lifecyclePassword, f.base, cert, key)
	baseline := f.write(t, source)
	assertAdminRedacted(t, baseline, markers)
	f.start(t)
	admin := &caddyAdminFixture{base: f.base, mount: "/auth", client: f.client}
	login := func(secret string) string {
		t.Helper()
		token := admin.login(t, "keyadmin")
		parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS512"}))
		if err != nil || !parsed.Valid {
			t.Fatal("issued JWT did not verify with the exact secret")
		}
		return token
	}
	authorize := func(token string, status int) {
		t.Helper()
		persistentRequest(t, f.client, "GET", f.base+"/protected", nil, http.Header{"Authorization": {"Bearer " + token}}, status)
	}
	reload := func(data []byte, success bool) {
		t.Helper()
		if err := os.WriteFile(f.config, data, 0600); err != nil {
			t.Fatal(err)
		}
		reloadCtx, stop := context.WithTimeout(t.Context(), 15*time.Second)
		defer stop()
		cmd := exec.CommandContext(reloadCtx, binary, "reload", "--force", "--config", f.config, "--address", f.admin)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		assertAdminRedacted(t, output, markers)
		if (err == nil) != success {
			t.Fatalf("reload success=%v: %v\n%s", success, err, output)
		}
	}
	tokenA := login(keyA)
	authorize(tokenA, 200)
	put(map[string]any{"key": keyB, "bad": "private-invalid-lifetime"})
	authorize(tokenA, 200)
	// Neither an external Put nor a new login implicitly rotates the serving root.
	authorize(login(keyA), 200)
	reload(baseline, true)
	tokenB := login(keyB)
	authorize(tokenB, 200)
	authorize(tokenA, 401)

	// Rejected trusted writes preserve the record even for a freshly built consumer.
	cli("put", sqliteSecretsInput(t, cfg, map[string]any{"key": strings.Repeat("x", 65<<10)}), false)
	reload(baseline, true)
	authorize(login(keyB), 200)
	for _, bad := range []any{nil, "", json.Number("9007199254740993"), map[string]any{"nested": "value"}} {
		put(map[string]any{"key": bad})
		reload(baseline, false)
		authorize(tokenB, 200)
	}
	put(map[string]any{"key": keyB, "bad": "private-invalid-lifetime"})
	// Upstream validation and constructor errors can contain resolved instructions.
	// Neither the admin response nor the Caddy debug log may expose their values.
	for _, statement := range []string{"crypto key token lifetime secrets:signing:bad", "crypto key verify from file secrets:signing:key"} {
		var candidate map[string]json.RawMessage
		if err := json.Unmarshal(baseline, &candidate); err != nil {
			t.Fatal(err)
		}
		var apps map[string]json.RawMessage
		if err := json.Unmarshal(candidate["apps"], &apps); err != nil {
			t.Fatal(err)
		}
		var app App
		if err := json.Unmarshal(apps["security"], &app); err != nil {
			t.Fatal(err)
		}
		app.Config.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = []string{statement}
		apps["security"], _ = json.Marshal(app)
		candidate["apps"], _ = json.Marshal(apps)
		data, _ := json.Marshal(candidate)
		reload(data, false)
		authorize(tokenB, 200)
	}
	cli("delete", sqliteSecretsInput(t, cfg, nil), true)
	reload(baseline, false)
	authorize(tokenB, 200)
	put(map[string]any{"key": keyB})
	for _, failure := range []string{"permissions", "missing", "foreign"} {
		switch failure {
		case "permissions":
			if err := os.Chmod(cfg.Path, 0644); err != nil {
				t.Fatal(err)
			}
		default:
			if err := os.Rename(cfg.Path, cfg.Path+".saved"); err != nil {
				t.Fatal(err)
			}
			if failure == "foreign" {
				if err := os.WriteFile(cfg.Path, []byte("foreign database"), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		reload(baseline, false)
		authorize(tokenB, 200)
		if failure == "permissions" {
			if err := os.Chmod(cfg.Path, 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			if failure == "foreign" {
				if err := os.Remove(cfg.Path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(cfg.Path+".saved", cfg.Path); err != nil {
				t.Fatal(err)
			}
		}
	}
	reload(baseline, true)
	authorize(login(keyB), 200)
	f.restart(t)
	authorize(login(keyB), 200)
	authorize(tokenB, 200)
	// Caddy introspection and its autosave retain declarative secret references.
	req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+f.admin+"/config/", nil)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("admin config read failed")
	}
	assertAdminRedacted(t, data, markers)
	if !bytes.Contains(data, []byte("secrets:signing:key")) {
		t.Fatal("declarative references disappeared")
	}
	saved, err := os.ReadFile(filepath.Join(f.workspace, "caddy", "autosave.json"))
	if err != nil {
		t.Fatal(err)
	}
	assertAdminRedacted(t, saved, markers)
	f.kill(t)
	log, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	assertAdminRedacted(t, log, markers)
}
