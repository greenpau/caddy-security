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
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

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
