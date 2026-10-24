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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The caller supplies the live production Caddy server. Chrome receives only
// private profile trust; credentials enter rendered forms, never injected state.
func runSQLiteIdentityBrowser(t *testing.T, base, cert, password string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "sqlite-identity-browser-")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("remove private SQLite identity browser profile", err)
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, cert)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private Chrome trust: %v\n%s", err, output)
	}
	var invalidTLSHits atomic.Int64
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		invalidTLSHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	// Discard expected handshake diagnostics from the negative TLS control.
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	defer untrusted.Close()
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	driver := exec.CommandContext(ctx, "node", "testdata/browser/sqlite_identity_login.cjs", endpoint, base, untrusted.URL)
	driver.Stdin = strings.NewReader(password)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	assertAdminRedacted(t, output, []string{password})
	if err != nil {
		t.Fatalf("SQLite identity browser journey: %v\n%s", err, output)
	}
	if string(output) != "SQLite identity browser passed\n" {
		t.Fatal("browser did not confirm SQLite identity login")
	}
	if invalidTLSHits.Load() != 0 {
		t.Fatal("SQLite identity browser accepted an untrusted certificate")
	}
}
