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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	identities "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

// Execute the production command in fresh processes while another database
// handle verifies password authentication and revocation of captured evidence.
func TestCaddySQLiteIdentityCommandsE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "authcrunch")
	buildCtx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CGO-free Caddy: %v\n%s", err, output)
	}
	cfg := sqliteIdentityCLIConfig(t)
	dir := filepath.Dir(cfg.Path)
	inputPath, passwordPath := filepath.Join(dir, "input.json"), filepath.Join(dir, "password")
	const original = "  Initial-password-秘密!  "
	const replacement = "Replacement-password-秘密!"
	markers := []string{original, replacement, "private-sentinel", "Alice@example.test", cfg.Path}
	cli := func(action string, fields map[string]any, password string, success bool) {
		t.Helper()
		if err := os.WriteFile(inputPath, sqliteIdentityCLIDocument(t, cfg, fields), 0600); err != nil {
			t.Fatal(err)
		}
		args := []string{"security", "identity", action, "--config", inputPath}
		if action == "create" || action == "set-password" {
			if err := os.WriteFile(passwordPath, []byte(password+"\r\n"), 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--password-file", passwordPath)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.WaitDelay = 5 * time.Second
		data, err := cmd.CombinedOutput()
		assertAdminRedacted(t, data, markers)
		if (err == nil) != success {
			t.Fatalf("identity %s success=%v: %v\n%s", action, success, err, data)
		}
		if success && string(data) != "Identity "+action+" completed\n" {
			t.Fatal("unexpected command success output")
		}
	}
	create := map[string]any{"name": "Alice Example", "roles": []string{"viewer"}}
	cli("create", create, original, true)
	backend, err := identities.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	authenticate := func(password string, allowed bool, roles []string) requests.AuthenticationEvidence {
		t.Helper()
		r := &requests.Request{Upstream: requests.Upstream{Realm: "staff"}, User: requests.User{Username: "alice", Password: password}}
		err := backend.Request(operator.Authenticate, r)
		if (err == nil && r.Response.Authenticated) != allowed {
			t.Fatal("unexpected password authentication outcome", err)
		}
		if allowed && (!slices.Equal(r.User.Roles, roles) || r.Authentication.Method != "pwd" || r.Authentication.UserID == "") {
			t.Fatal("password authentication returned stale account metadata")
		}
		return r.Authentication
	}
	revoked := func(proof requests.AuthenticationEvidence) {
		t.Helper()
		called := false
		err := backend.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("mutation preserved captured authentication evidence")
		}
	}
	first := authenticate(original, true, []string{"viewer"})
	cli("create", create, replacement, false)
	authenticate(original, true, []string{"viewer"})
	authenticate(strings.TrimSpace(original), false, nil)
	cli("disable", map[string]any{"email": "wrong@example.test"}, "", false)
	authenticate(original, true, []string{"viewer"})
	cli("roles", map[string]any{"roles": []string{"editor", "authp/user"}}, "", true)
	revoked(first)
	proof := authenticate(original, true, []string{"editor", "authp/user"})
	cli("set-password", nil, replacement, true)
	revoked(proof)
	authenticate(original, false, nil)
	proof = authenticate(replacement, true, []string{"editor", "authp/user"})
	cli("disable", nil, "", true)
	revoked(proof)
	authenticate(replacement, false, nil)
	cli("enable", nil, "", true)
	revoked(proof)
	proof = authenticate(replacement, true, []string{"editor", "authp/user"})
	cli("delete", nil, "", true)
	revoked(proof)
	authenticate(replacement, false, nil)
	cli("delete", nil, "", false)
	cli("create", create, original, true)
	if current := authenticate(original, true, []string{"viewer"}); current.UserID == first.UserID {
		t.Fatal("recreated identity reused immutable account ID")
	}
	revoked(first)
	cfg.Realm = "other"
	cli("disable", nil, "", false)
	cfg.Realm = "staff"
	authenticate(original, true, []string{"viewer"})

	t.Run("terminal", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("Python 3 is required for terminal E2E")
		}
		if err := os.WriteFile(inputPath, sqliteIdentityCLIDocument(t, cfg, nil), 0600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"mismatch", "match"} {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			cmd := exec.CommandContext(ctx, python, "-c", sqliteIdentityTerminalDriver, binary, inputPath, mode)
			cmd.WaitDelay = 5 * time.Second
			output, err := cmd.CombinedOutput()
			cancel()
			assertAdminRedacted(t, output, markers)
			if err != nil {
				t.Fatalf("terminal %s: %v\n%s", mode, err, output)
			}
			if mode == "mismatch" {
				authenticate(original, true, []string{"viewer"})
			} else {
				authenticate(original, false, nil)
				authenticate("Terminal-identity-secret-123!", true, []string{"viewer"})
			}
		}
	})

	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	// Raw reads happen only after the active handle is closed, preserving SQLite
	// advisory locks. Neither the database nor successful output holds plaintext.
	data, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	assertAdminRedacted(t, data, []string{original, replacement, "Terminal-identity-secret-123!"})
	if info, err := os.Stat(cfg.Path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("identity database permissions are not private")
	}
}

// Drive a real PTY without disclosing its transcript on failure. Prompts must
// arrive before input; both password entries must be read with terminal echo off.
const sqliteIdentityTerminalDriver = `
import errno, os, pty, select, subprocess, sys, termios, time
master, slave = pty.openpty()
before = termios.tcgetattr(slave)
process = subprocess.Popen([sys.argv[1], "security", "identity", "set-password", "--config", sys.argv[2]], stdin=slave, stdout=slave, stderr=slave, close_fds=True)
transcript = bytearray()
password = b"Terminal-identity-secret-123!"
confirmation = password if sys.argv[3] == "match" else b"Terminal-other-secret-123!"
stage = 0
deadline = time.monotonic() + 35
try:
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            transcript.extend(chunk)
        if stage == 0 and b"Password: " in transcript:
            if termios.tcgetattr(slave)[3] & termios.ECHO:
                raise RuntimeError("first password prompt enabled echo")
            os.write(master, password + b"\r")
            stage = 1
        if stage == 1 and b"Confirm password: " in transcript:
            if termios.tcgetattr(slave)[3] & termios.ECHO:
                raise RuntimeError("confirmation prompt enabled echo")
            os.write(master, confirmation + b"\r")
            stage = 2
        if process.poll() is not None:
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                transcript.extend(chunk)
            break
    if process.poll() is None:
        raise RuntimeError("terminal command deadline exceeded")
    if stage != 2 or password in transcript or confirmation in transcript:
        raise RuntimeError("unsafe or incomplete terminal interaction")
    if (process.returncode == 0) != (sys.argv[3] == "match"):
        raise RuntimeError("unexpected terminal command outcome")
    restored = termios.tcgetattr(slave)
    # BSD sets PENDIN when returning to canonical mode after reading input.
    # It records queued-input processing rather than a user terminal setting.
    restored[3] &= ~getattr(termios, "PENDIN", 0)
    expected = list(before)
    expected[3] &= ~getattr(termios, "PENDIN", 0)
    if restored != expected:
        raise RuntimeError("terminal state not restored")
finally:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)
    termios.tcsetattr(slave, termios.TCSANOW, before)
    os.close(master)
    os.close(slave)
`
