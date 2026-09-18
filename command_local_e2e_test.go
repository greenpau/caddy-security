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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestCaddySecurityLocalE2E(t *testing.T) {
	// Include a real unused TOTP step after each automatic metadata login,
	// plus bounded time for the three portal mounts and process cleanup.
	ctx, cancel := context.WithTimeout(t.Context(), 330*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSecurityLocalPortalProcess$", "-test.v", "-test.timeout=320s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_LOCAL_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("local administration through TLS Caddy: %v\n%s", err, output)
	}
}

func TestSecurityLocalPortalProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_LOCAL_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, certKey, roots := cookieTLSCertificate(t)
	for _, mount := range []string{"", "/auth", "/xauth"} {
		t.Run("mount="+mount, func(t *testing.T) {
			f := newCaddyAdminFixture(t, mount, "enable admin api", false, certFile, certKey, roots)
			dir := t.TempDir()
			database := filepath.Join(dir, "users.json")
			// Seed an enrolled administrator before Caddy owns this database.
			// Its MFA rules exercise both configured and prompted CLI logins.
			const mfaSecret = securityTerminalMFASecret
			db, err := identity.NewDatabase(database)
			if err != nil {
				t.Fatal("cannot create MFA fixture database")
			}
			// Each successful login journey owns an identity; TOTP replay
			// protection stays enabled across aliases and Caddy reloads.
			for _, username := range []string{"mfaadmin", "mfaadmin-prompt", "mfaadmin-interactive", "mfaadmin-reload"} {
				enrollment := &requests.Request{
					User:     requests.User{Username: username, Email: username + "@example.test", Password: "Terminal-secret-123", Roles: []string{"authp/admin"}, Challenges: []string{"password mfa"}},
					MfaToken: requests.MfaToken{Type: "totp", Secret: mfaSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true},
				}
				if err := db.AddUser(enrollment); err != nil {
					t.Fatal("cannot add MFA administrator")
				}
				if err := db.AddMfaToken(enrollment); err != nil {
					t.Fatal("cannot enroll MFA administrator")
				}
				if err := db.OverwriteUserAuthChallengeRules(enrollment); err != nil {
					t.Fatal("cannot require administrator MFA")
				}
			}
			f.secrets = append(f.secrets, mfaSecret, "Terminal-secret-123")
			f.input = strings.Replace(f.input, "path :memory:", "path "+database, 1)
			keyOutput, err := securityCommand(t, "security", "local", "generate", "api", "key", "--cost", "8")
			if err != nil {
				t.Fatal("API key generation failed")
			}
			apiKey, hash := apiKeyDirective(t, keyOutput)
			f.input = strings.Replace(f.input, "roles authp/admin", fmt.Sprintf("roles authp/admin\napi key %s %q", apiKey[:24], hash), 1)
			passwordOutput, err := securityCommandInput(t, lifecyclePassword+"\n", "security", "local", "generate", "password", "hash", "--password-file", "-", "--cost", "8")
			if err != nil {
				t.Fatal("password hash generation failed")
			}
			passwordDirective(t, passwordOutput, lifecyclePassword)
			// Exercise generated password directives through Caddy adaptation,
			// local-store provisioning, and the real logins below.
			f.input = strings.ReplaceAll(f.input, "password "+lifecyclePassword, strings.TrimSpace(string(passwordOutput)))
			if err := f.reload("enable admin api"); err != nil {
				t.Fatal("cannot provision persistent local store", err)
			}
			f.secrets = append(f.secrets, apiKey)
			config := filepath.Join(dir, "client.yaml")
			writeConfig := func(username, password, key string) {
				t.Helper()
				data := fmt.Sprintf("base_url: %q\nrealm: local\n", f.base+mount)
				if key != "" {
					data += fmt.Sprintf("api_key: %q\n", key)
				} else {
					data += fmt.Sprintf("username: %q\npassword: %q\n", username, password)
				}
				if err := os.WriteFile(config, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeConfig("keyadmin", lifecyclePassword, "")
			call := func(path string, flags ...string) ([]byte, error) {
				t.Helper()
				args := append([]string{"security", "local"}, strings.Fields(path)...)
				args = append(args, "--config", config, "--ca-file", certFile)
				return securityCommand(t, append(args, flags...)...)
			}
			jsonCall := func(path string, flags ...string) map[string]json.RawMessage {
				t.Helper()
				output, err := call(path, flags...)
				if err != nil {
					t.Fatalf("local %s failed: %v; %s", path, err, output)
				}
				var result map[string]json.RawMessage
				if json.Unmarshal(output, &result) != nil || result == nil {
					t.Fatal("CLI did not return a JSON object")
				}
				return result
			}
			failure := func(path string, flags ...string) {
				t.Helper()
				output, err := call(path, flags...)
				if err == nil {
					t.Fatalf("local %s unexpectedly succeeded", path)
				}
				assertAdminRedacted(t, output, f.secrets)
			}
			login := func(password string, success bool) {
				t.Helper()
				client, err := authclient.NewClient(&authclient.Config{BaseURL: f.base + mount, Realm: "local", Username: "alice", Password: password}, authclient.Options{HTTPClient: f.client})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
				defer cancel()
				_, err = client.Authenticate(ctx)
				if (err == nil) != success {
					t.Fatalf("login acceptance mismatch, wanted success=%v", success)
				}
			}
			connected := jsonCall("connect")
			var tokenPath string
			if json.Unmarshal(connected["token_path"], &tokenPath) != nil {
				t.Fatal("connect omitted token path")
			}
			if info, err := os.Stat(tokenPath); err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("connect did not save private credentials")
			}
			jsonCall("metadata")
			realms := jsonCall("list realms")
			if !bytes.Contains(realms["realms"], []byte(`"local"`)) {
				t.Fatal("local realm missing")
			}
			info := jsonCall("info realm", "--realm", "local")
			var storedPath string
			if json.Unmarshal(info["path"], &storedPath) != nil || storedPath != database {
				t.Fatal("wrong local database inspected")
			}
			userFlags := []string{"--realm", "local", "--username", "alice", "--email", "alice@example.test"}
			created := jsonCall("add user", append(slices.Clone(userFlags), "--name", "Alice Example", "--roles", "authp/user")...)
			var originalPassword string
			if json.Unmarshal(created["password"], &originalPassword) != nil || originalPassword == "" {
				t.Fatal("add user did not return password")
			}
			f.secrets = append(f.secrets, originalPassword)
			login(originalPassword, true)
			jsonCall("info user", userFlags...)
			failure("add user", append(slices.Clone(userFlags), "--name", "Alice Example", "--roles", "authp/user")...)
			jsonCall("update user", append(slices.Clone(userFlags), "--disable")...)
			login(originalPassword, false)
			jsonCall("update user", append(slices.Clone(userFlags), "--enable")...)
			login(originalPassword, true)
			reset := jsonCall("update user", append(slices.Clone(userFlags), "--reset-password")...)
			var newPassword string
			if json.Unmarshal(reset["password"], &newPassword) != nil || newPassword == "" || newPassword == originalPassword {
				t.Fatal("reset did not return a replacement password")
			}
			f.secrets = append(f.secrets, newPassword)
			login(originalPassword, false)
			login(newPassword, true)
			jsonCall("update user", append(slices.Clone(userFlags), "--overwrite-roles", "authp/user,reader")...)
			jsonCall("update user", append(slices.Clone(userFlags), "--add-roles", "editor")...)
			jsonCall("update user", append(slices.Clone(userFlags), "--overwrite-auth-challenges", "password,totp")...)
			user := jsonCall("info user", userFlags...)
			if !bytes.Contains(user["auth_challenge_rules"], []byte("totp")) {
				t.Fatal("challenge update not persisted")
			}
			jsonCall("update user", append(slices.Clone(userFlags), "--overwrite-auth-challenges", "password")...)
			jsonCall("reload", "--realm", "local")
			login(newPassword, true)
			users := jsonCall("list users", "--realm", "local")
			var records []struct {
				Username string
				Roles    []string
			}
			if json.Unmarshal(users["users"], &records) != nil {
				t.Fatal("invalid user list")
			}
			var found bool
			for _, record := range records {
				if record.Username == "alice" {
					found = slices.Contains(record.Roles, "reader") && slices.Contains(record.Roles, "editor")
				}
			}
			if !found {
				t.Fatal("role updates not persisted across realm reload")
			}
			for _, format := range []string{"csv", "table"} {
				output, err := call("list users", "--realm", "local", "--format", format)
				if err != nil || !bytes.Contains(output, []byte("alice")) {
					t.Fatal("formatted user listing failed")
				}
			}
			failure("reload", "--realm", "missing")
			failure("info user", "--realm", "missing", "--username", "alice", "--email", "alice@example.test")
			failure("delete user", "--realm", "local", "--username", "alice", "--email", "wrong@example.test")
			login(newPassword, true)
			jsonCall("delete user", userFlags...)
			login(newPassword, false)
			failure("info user", userFlags...)
			failure("delete user", userFlags...)
			// Default cache isolation must not reuse the admin token after changing
			// the login identity in the same config file.
			writeConfig("keymember", lifecyclePassword, "")
			jsonCall("connect")
			failure("metadata")
			writeConfig("", "", apiKey)
			jsonCall("connect")
			jsonCall("list users", "--realm", "local")
			// Verify the CLI's conditional prompt wiring against real TOTP MFA.
			writeMFAConfig := func(username, password string, digits int) {
				t.Helper()
				writeConfig(username, password, "")
				data, err := os.ReadFile(config)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, []byte(fmt.Sprintf("totp_secret: %q\ntotp_code_length: %d\n", mfaSecret, digits))...)
				if err := os.WriteFile(config, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeMFAConfig("mfaadmin", "Terminal-secret-123", 6)
			mfaConnected := jsonCall("connect")
			jsonCall("metadata")
			var mfaTokenPath string
			if json.Unmarshal(mfaConnected["token_path"], &mfaTokenPath) != nil {
				t.Fatal("MFA connect omitted token path")
			}
			previousToken, err := os.ReadFile(mfaTokenPath)
			if err != nil || len(previousToken) == 0 {
				t.Fatal("MFA login did not persist credentials")
			}
			// Wrong length deterministically fails; a wrong secret could happen
			// to produce the same six-digit code as the enrolled secret.
			writeMFAConfig("mfaadmin", "Terminal-secret-123", 8)
			failure("connect")
			currentToken, err := os.ReadFile(mfaTokenPath)
			if err != nil || !bytes.Equal(previousToken, currentToken) {
				t.Fatal("failed MFA login replaced valid cached credentials")
			}
			writeMFAConfig("mfaadmin-prompt", "", 6)
			t.Run("prompted_password_with_MFA", func(t *testing.T) {
				output := securityTerminalCommand(t, "login", "security", "local", "connect", "--config", config, "--ca-file", certFile)
				if !json.Valid(output) || !bytes.Contains(output, []byte(`"success"`)) {
					t.Fatal("prompted MFA login did not return successful JSON")
				}
			})
			writeConfig("mfaadmin-interactive", "", "")
			t.Run("fully_interactive_MFA", func(t *testing.T) {
				output := securityTerminalCommand(t, "login-mfa", "security", "local", "connect", "--config", config, "--ca-file", certFile)
				if !json.Valid(output) || !bytes.Contains(output, []byte(`"success"`)) {
					t.Fatal("interactive MFA login did not return successful JSON")
				}
				jsonCall("metadata") // The interactively obtained credentials authorize real admin requests.
			})
			writeMFAConfig("mfaadmin-reload", "Terminal-secret-123", 6)
			// API-key generation output is accepted by the real local store and
			// JSON login client, without constructing a separate CLI protocol.
			// File-backed identity stores require a stop/start for configuration
			// changes; local reload above uses their coordinated admin API instead.
			if err := caddy.Stop(); err != nil {
				t.Fatal("cannot stop persistent-store fixture")
			}
			if err := f.reload("disable admin api"); err != nil {
				message := strings.ReplaceAll(err.Error(), hash, "[hash]")
				for _, secret := range f.secrets {
					message = strings.ReplaceAll(message, secret, "[secret]")
				}
				t.Fatal("cannot disable admin API:", message)
			}
			failure("metadata")
			// Metadata may authenticate before discovering that the admin API
			// is disabled. Its consumed one-time code cannot be used by connect.
			waitForFreshFixtureTOTP(t, database, "mfaadmin-reload")
			jsonCall("connect") // Login remains independent of admin API enablement.
		})
	}
}
