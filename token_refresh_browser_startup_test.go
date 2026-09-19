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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaddyRefreshBrowserTrust(t *testing.T) {
	cert, _, _ := cookieTLSCertificate(t)
	prepare := func(profile, certificate string, wantError bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, certificate)
		cmd.WaitDelay = time.Second
		output, err := cmd.CombinedOutput()
		if (err != nil) != wantError {
			t.Fatalf("private trust preparation error=%t want=%t", err != nil, wantError)
		}
		if wantError && !bytes.Contains(output, []byte("unable to prepare private browser certificate trust")) {
			t.Fatal("trust failure did not preserve a diagnostic")
		}
		assertAdminRedacted(t, output, []string{"synthetic-private-certificate-input"})
	}
	profile := t.TempDir()
	prepare(profile, cert, false)
	path := filepath.Join(profile, "Default", "ServerCertificate")
	before, err := os.ReadFile(path)
	if err != nil || len(before) == 0 {
		t.Fatal("browser trust was not persisted")
	}
	prepare(profile, cert, true)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("trust preparation modified an existing profile")
	}
	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(profile, "Default"), filepath.Join(linked, "Default")); err != nil {
		t.Fatal(err)
	}
	prepare(linked, cert, true)
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("trust preparation followed a profile symlink")
	}
	malformed := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(malformed, []byte("synthetic-private-certificate-input"), 0600); err != nil {
		t.Fatal(err)
	}
	invalidProfile := t.TempDir()
	prepare(invalidProfile, malformed, true)
	if _, err := os.Stat(filepath.Join(invalidProfile, "Default")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid certificate created browser trust state")
	}
}

// These local processes exercise the launcher's readiness, diagnostics and
// cleanup boundaries. TestCaddyTokenRefreshBrowserE2E uses the same launcher
// with real Chrome and the complete TLS portal journey.
func TestCaddyRefreshBrowserStartup(t *testing.T) {
	t.Run("delayed partial endpoint and cleanup", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		profile := t.TempDir()
		cmd := exec.CommandContext(ctx, "node", "-e", `
const fs = require("node:fs"), path = require("node:path");
const file = path.join(process.argv[1], "DevToolsActivePort");
fs.writeFileSync(file, "12345\n");
setTimeout(() => fs.appendFileSync(file, "/devtools/browser/fixture\n"), 200);
setInterval(() => {}, 1000);
`, profile)
		endpoint, stop, err := startCaddyRefreshBrowser(ctx, cmd, profile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(stop)
		if endpoint != "ws://127.0.0.1:12345/devtools/browser/fixture" {
			t.Fatalf("unexpected endpoint %q", endpoint)
		}
		stop()
		stop() // Cleanup remains safe after an explicit stop.
		if cmd.ProcessState == nil {
			t.Fatal("browser process was not reaped")
		}
	})
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
		message string
	}{
		{"early failure", `console.error("fixture startup failure"); process.exit(17)`, 5 * time.Second, "exit status 17"},
		{"early successful exit", `console.error("fixture startup failure")`, 5 * time.Second, "exited before exposing a debugging endpoint"},
		{"startup deadline", `console.error("fixture startup failure"); setInterval(() => {}, 1000)`, time.Second, "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), tc.timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "node", "-e", tc.script)
			endpoint, stop, err := startCaddyRefreshBrowser(ctx, cmd, t.TempDir())
			if stop != nil {
				t.Cleanup(stop)
			}
			if err == nil || !strings.Contains(err.Error(), tc.message) || !strings.Contains(err.Error(), "fixture startup failure") {
				t.Fatalf("startup lost the failure or its diagnostic: %v", err)
			}
			if tc.name != "startup deadline" && errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("early process exit was hidden by a timeout")
			}
			if endpoint != "" || stop != nil || cmd.ProcessState == nil {
				t.Fatal("failed startup left an endpoint or an unreaped process")
			}
		})
	}
	t.Run("missing executable", func(t *testing.T) {
		profile := t.TempDir()
		cmd := exec.CommandContext(t.Context(), profile+"/missing-browser")
		_, stop, err := startCaddyRefreshBrowser(t.Context(), cmd, profile)
		if stop != nil {
			t.Cleanup(stop)
		}
		if err == nil || !strings.Contains(err.Error(), "missing-browser") {
			t.Fatalf("missing executable lost its diagnostic: %v", err)
		}
	})
}
