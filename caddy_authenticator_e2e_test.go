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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func TestCaddyAuthenticatorVersionE2E(t *testing.T) {
	version, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	binary := filepath.Join(binDir, "caddy-authenticator")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	for _, tc := range []struct {
		name, expected string
		args           []string
	}{
		{
			name:     "go install fallback",
			args:     []string{"install", "-mod=readonly", "./cmd/caddy-authenticator"},
			expected: "caddy-authenticator " + strings.TrimSpace(string(version)) + "\n",
		},
		{
			name:     "linker metadata",
			args:     []string{"build", "-mod=readonly", "-ldflags", "-X main.appVersion=1.2.345 -X main.gitBranch=fixture -X main.gitCommit=abc123 -X main.buildUser=builder -X main.buildDate=2026-09-16", "-o", binary, "./cmd/caddy-authenticator"},
			expected: "caddy-authenticator 1.2.345, branch: fixture, commit: abc123, build on 2026-09-16 by builder (",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
			defer cancel()
			build := exec.CommandContext(ctx, "go", tc.args...)
			build.Env = append(os.Environ(), "GOBIN="+binDir)
			build.WaitDelay = 5 * time.Second
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build/install authenticator: %v\n%s", err, output)
			}
			userHome := t.TempDir()
			cmd := exec.CommandContext(ctx, binary, "version")
			cmd.Env = append(os.Environ(), "HOME="+userHome, "USERPROFILE="+userHome,
				"CADDY_AUTHENTICATOR_HOME="+filepath.Join(userHome, "unused"), "CADDY_AUTHENTICATOR_PROFILE=../invalid")
			cmd.WaitDelay = 5 * time.Second
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.HasPrefix(string(output), tc.expected) {
				t.Fatalf("version banner: %q, %v", output, err)
			}
			entries, err := os.ReadDir(userHome)
			if err != nil || len(entries) != 0 {
				t.Fatal("version modified user state")
			}
		})
	}
}

func TestCaddyAuthenticatorE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthenticatorProcess$", "-test.v", "-test.timeout=280s")
	cmd.Env = append(os.Environ(), "CADDY_AUTHENTICATOR_E2E_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("caddy-authenticator through Caddy TLS: %v\n%s", err, output)
	}
}

func TestCaddyAuthenticatorProcess(t *testing.T) {
	if os.Getenv("CADDY_AUTHENTICATOR_E2E_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("CADDY_AUTHENTICATOR_PROFILE", "")
	t.Setenv("CADDY_AUTHENTICATOR_HOME", "")
	binary := filepath.Join(t.TempDir(), "caddy-authenticator")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-race", "-o", binary, "./cmd/caddy-authenticator")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authenticator: %v\n%s", err, output)
	}
	cert, key, roots := cookieTLSCertificate(t)
	database, keys := authenticationClientDatabase(t)
	for _, native := range []bool{false, true} {
		name, mount := "legacy root", ""
		if native {
			name, mount = "native nested", "/tenant/auth"
		}
		t.Run(name, func(t *testing.T) {
			f := newAuthenticationClientFixture(t, mount, database, cert, key, roots, native, native, true, false)
			home := filepath.Join(t.TempDir(), "authenticator")
			userHome := t.TempDir()
			call := func(input string, args ...string) ([]byte, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, append([]string{"--home", home, "--timeout", "10s"}, args...)...)
				cmd.Stdin = strings.NewReader(input)
				cmd.Env = append(os.Environ(), "HOME="+userHome, "USERPROFILE="+userHome)
				cmd.WaitDelay = 2 * time.Second
				return cmd.CombinedOutput()
			}
			must := func(input string, args ...string) []byte {
				t.Helper()
				out, err := call(input, args...)
				if err != nil {
					t.Fatalf("authenticator command failed: %v\n%s", err, out)
				}
				return out
			}
			configure := func(profile, user string, flags ...string) {
				t.Helper()
				args := []string{"configure", "--profile", profile, "--url", f.base + mount, "--realm", "local", "--ca-file", cert}
				if user != "" {
					args = append(args, "--username", user)
				}
				if native && user != "" {
					args = append(args, "--refresh-transport", "body")
				}
				must("", append(args, flags...)...)
			}
			passwordCA := cert
			if runtime.GOOS != "windows" {
				top, target := t.TempDir(), t.TempDir()
				if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(target, "child"), filepath.Join(top, "link")); err != nil {
					t.Fatal(err)
				}
				pem, err := os.ReadFile(cert)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "ca.pem"), pem, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(top, "ca.pem"), []byte("incorrect CA selection"), 0600); err != nil {
					t.Fatal(err)
				}
				passwordCA = filepath.Join(top, "link") + "/../ca.pem"
			}
			configure("password", "alice", "--ca-file", passwordCA)
			if _, err := call("", "configure", "--home", "", "--url", f.base+mount, "--realm", "local", "--username", "alice"); err == nil {
				t.Fatal("empty --home fell back to user state")
			}
			if _, err := os.Stat(filepath.Join(userHome, ".caddy-authenticator")); !os.IsNotExist(err) {
				t.Fatal("invalid command modified default user state")
			}
			if native {
				configure("browser", "alice", "--refresh-transport", "cookie")
				if output, err := call(lifecyclePassword, "login", "--profile", "browser", "--password-file", "-"); err == nil || !bytes.Contains(output, []byte("native credentials require")) {
					t.Fatal("browser-only completion did not require explicit native transport")
				}
			} else {
				configure("unavailable", "alice", "--refresh-transport", "body")
				if _, err := call(lifecyclePassword, "login", "--profile", "unavailable", "--password-file", "-"); err == nil {
					t.Fatal("native login succeeded without portal opt-in")
				}
			}
			out := must(lifecyclePassword+"\n", "login", "--profile", "password", "--password-file", "-")
			check := func(profile, user string) *authclient.Credentials {
				t.Helper()
				path := filepath.Join(home, "profiles", profile, "token.jwt")
				store, _ := authclient.NewFileTokenStore(path)
				credentials, err := store.Load()
				if err != nil {
					t.Fatal(err)
				}
				f.credentialAccess(t, credentials, user)
				header, err := credentials.Authorization()
				if err != nil {
					t.Fatal(err)
				}
				if got := must("", "token", "--profile", profile, "--header"); string(got) != "Authorization: "+header+"\n" {
					t.Fatal("CLI lost named token header")
				}
				for _, endpoint := range []string{"/api/server/metadata", "/api/profile"} {
					status, _, _ := registrationHTTP(t, f.http, "GET", f.base+mount+endpoint, nil, http.Header{"Accept": {"application/json"}, "Authorization": {header}})
					if status == 200 {
						t.Fatal("authentication unexpectedly required enabled management APIs")
					}
				}
				return credentials
			}
			credentials := check("password", "alice")
			if bytes.Contains(out, []byte(credentials.AccessToken)) {
				t.Fatal("login exposed token")
			}
			if native && (credentials.RefreshToken == "" || credentials.SessionID == "" || credentials.AccessExpiresAt == 0) {
				t.Fatal("native metadata was lost")
			}
			if native {
				must("", "login", "--profile", "password")
				rotated := check("password", "alice")
				if rotated.SessionID != credentials.SessionID || rotated.RefreshToken == credentials.RefreshToken || rotated.AccessToken == credentials.AccessToken {
					t.Fatal("near-expiry login did not rotate within the same family")
				}
				must(lifecyclePassword, "login", "--force", "--profile", "password", "--password-file", "-")
				credentials = check("password", "alice")
				if credentials.SessionID == rotated.SessionID {
					t.Fatal("forced login reused the old refresh family")
				}
			} else {
				cached := must("", "login", "--profile", "password")
				if !bytes.Contains(cached, []byte("Using cached credentials")) || check("password", "alice").AccessToken != credentials.AccessToken {
					t.Fatal("valid legacy token triggered reauthentication")
				}
			}
			before, _ := os.ReadFile(filepath.Join(home, "profiles", "password", "token.jwt"))
			if _, err := call("incorrect\n", "login", "--force", "--profile", "password", "--password-file", "-"); err == nil {
				t.Fatal("incorrect password accepted")
			}
			after, _ := os.ReadFile(filepath.Join(home, "profiles", "password", "token.jwt"))
			if !bytes.Equal(before, after) {
				t.Fatal("failed fresh login replaced existing credentials")
			}
			configBefore, err := os.ReadFile(filepath.Join(home, "credentials"))
			if err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(home, "profiles", "password", "auth.log")
			logBefore, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(logPath, 0700); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"configure", "--profile", "password", "--username", "bob"}, {"clear", "--profile", "password"}} {
				if _, err := call("", args...); err == nil {
					t.Fatal("command accepted an unusable profile log")
				}
			}
			configAfter, err := os.ReadFile(filepath.Join(home, "credentials"))
			if err != nil || !bytes.Equal(configBefore, configAfter) {
				t.Fatal("rejected command changed credentials")
			}
			after, err = os.ReadFile(filepath.Join(home, "profiles", "password", "token.jwt"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected command removed credentials")
			}
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(logPath, logBefore, 0600); err != nil {
				t.Fatal(err)
			}
			secretFile := filepath.Join(t.TempDir(), "totp-secret")
			if err := os.WriteFile(secretFile, []byte(authenticationClientTOTPSecret), 0600); err != nil {
				t.Fatal(err)
			}
			configure("mfa", "mfauser", "--totp-secret-file", secretFile)
			must(lifecyclePassword, "login", "--profile", "mfa", "--password-file", "-")
			mfa := check("mfa", "mfauser")
			apiFile := filepath.Join(t.TempDir(), "api-key")
			if err := os.WriteFile(apiFile, []byte(keys["mfauser"]), 0600); err != nil {
				t.Fatal(err)
			}
			configure("api", "", "--api-key-file", apiFile)
			must("", "login", "--profile", "api")
			api := check("api", "mfauser")
			if api.RefreshToken != "" || api.SessionID != "" {
				t.Fatal("API key unexpectedly created refresh authority")
			}
			if runtime.GOOS != "windows" {
				for _, mode := range []string{"default-configure", "configure"} {
					ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
					args := []string{"testdata/caddy_authenticator/terminal.py", binary, mode, "--home", home, "--profile", "wizard", "configure", "--ca-file", cert}
					if mode == "configure" {
						args = append(args, "--interactive")
					}
					if native {
						args = append(args, "--refresh-transport", "body")
					}
					wizard := exec.CommandContext(ctx, "python3", args...)
					wizard.Env = append(os.Environ(), "AUTHENTICATOR_TEST_URL="+f.base+mount)
					wizard.WaitDelay = 2 * time.Second
					output, err := wizard.CombinedOutput()
					cancel()
					if err != nil {
						t.Fatalf("setup mode %s: %v\n%s", mode, err, output)
					}
				}
				must(lifecyclePassword, "login", "--profile", "wizard", "--password-file", "-")
				check("wizard", "alice")
				configure("interactive", "mfauser")
				if output, err := call(lifecyclePassword, "login", "--profile", "interactive", "--password-file", "-"); err == nil || !bytes.Contains(output, []byte("authentication input required")) {
					t.Fatal("default login did not reject missing MFA input")
				}
				for _, mode := range []string{"login", "paste", "default-login", "interrupt", "terminate", "timeout", "invalid-utf8", "keyboard-interrupt", "eof", "totp-interrupt", "totp-timeout"} {
					previous, _ := os.ReadFile(filepath.Join(home, "profiles", "interactive", "token.jwt"))
					ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
					args := []string{"testdata/caddy_authenticator/terminal.py", binary, mode, "--home", home, "--profile", "interactive", "login", "--force"}
					if mode != "default-login" {
						args = append(args, "--interactive")
					}
					cmd := exec.CommandContext(ctx, "python3", args...)
					cmd.WaitDelay = 2 * time.Second
					output, err := cmd.CombinedOutput()
					cancel()
					if err != nil {
						t.Fatalf("terminal %s: %v\n%s", mode, err, output)
					}
					if mode != "login" && mode != "paste" {
						retained, err := os.ReadFile(filepath.Join(home, "profiles", "interactive", "token.jwt"))
						if err != nil || !bytes.Equal(previous, retained) {
							t.Fatal("interrupted prompt changed cached credentials")
						}
					}
				}
				check("interactive", "mfauser")
			}
			for _, profile := range []string{"password", "mfa", "api"} {
				logs, err := os.ReadFile(filepath.Join(home, "profiles", profile, "auth.log"))
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{lifecyclePassword, authenticationClientTOTPSecret, keys["mfauser"], credentials.AccessToken, mfa.AccessToken, api.AccessToken, credentials.RefreshToken} {
					if secret != "" && bytes.Contains(logs, []byte(secret)) {
						t.Fatal("profile log leaked a credential")
					}
				}
				for _, line := range bytes.Split(bytes.TrimSpace(logs), []byte("\n")) {
					var event map[string]string
					if json.Unmarshal(line, &event) != nil || event["time"] == "" {
						t.Fatal("invalid profile log event")
					}
				}
			}
			must("", "clear", "--profile", "password")
			if _, err := call("", "token", "--profile", "password"); err == nil {
				t.Fatal("clear retained token")
			}
			check("mfa", "mfauser")
			if native {
				configure("recovery", "alice")
				must(lifecyclePassword, "login", "--profile", "recovery", "--password-file", "-")
				original := check("recovery", "alice")
				path := filepath.Join(home, "profiles", "recovery", "token.jwt")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				f.probe.mu.Lock()
				requests, rotations := f.probe.rotationRequests, f.probe.rotations
				f.probe.cutNext = true
				f.probe.mu.Unlock()
				for i := 0; i < 2; i++ {
					if output, err := call("", "login", "--profile", "recovery"); err == nil || !bytes.Contains(output, []byte("--force")) {
						t.Fatal("uncertain refresh did not require explicit recovery")
					}
				}
				f.probe.mu.Lock()
				newRequests, newRotations := f.probe.rotationRequests-requests, f.probe.rotations-rotations
				f.probe.mu.Unlock()
				if newRequests != 1 || newRotations != 1 {
					t.Fatal("lost committed refresh was retried")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("uncertain refresh replaced saved credentials")
				}
				must(lifecyclePassword, "login", "--force", "--profile", "recovery", "--password-file", "-")
				if check("recovery", "alice").SessionID == original.SessionID {
					t.Fatal("explicit recovery retained the uncertain family")
				}
				must("", "login", "--profile", "recovery")
				check("recovery", "alice")
			}
		})
	}
	t.Run("expired access authenticates again", func(t *testing.T) {
		f := newAuthenticationClientFixture(t, "/auth", database, cert, key, roots, true, true, true, false, 4)
		home := filepath.Join(t.TempDir(), "state")
		call := func(args ...string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, append([]string{"--home", home}, args...)...)
			cmd.Stdin = strings.NewReader(lifecyclePassword)
			cmd.WaitDelay = 2 * time.Second
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("expired-token command failed: %v\n%s", err, output)
			}
		}
		call("configure", "--url", f.base+f.mount, "--realm", "local", "--username", "alice", "--ca-file", cert, "--refresh-transport", "body")
		call("login", "--password-file", "-")
		store, _ := authclient.NewFileTokenStore(filepath.Join(home, "profiles", "default", "token.jwt"))
		first, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		timer := time.NewTimer(max(0, time.Until(time.Unix(first.AccessExpiresAt, 0).Add(100*time.Millisecond))))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
		call("login", "--password-file", "-")
		fresh, err := store.Load()
		if err != nil || fresh.SessionID == first.SessionID || fresh.AccessToken == first.AccessToken {
			t.Fatal("expired credentials did not trigger fresh authentication")
		}
		f.credentialAccess(t, fresh, "alice")
	})
}
