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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBrowserContextCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "--test", "testdata/browser/browser_contexts.test.cjs")
	cmd.WaitDelay = time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser context cleanup regression: %v\n%s", err, output)
	}
}

func TestCaddyCrossDeviceBrowserE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCrossDeviceBrowserProcess$", "-test.v", "-test.timeout=220s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CROSS_DEVICE_BROWSER_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy cross-device browser flow: %v\n%s", err, output)
	}
}

func TestCaddyCrossDeviceBrowserProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CROSS_DEVICE_BROWSER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	browser := caddyRefreshBrowserExecutable(t)
	cert, key, roots := cookieTLSCertificate(t)
	f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local", oidcRealm: "local"}, "enable cross-device login\ncookie cross-device session id name __Secure-DEVICE", cert, key, roots)
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "cross-device-browser-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Errorf("remove private browser profile: %v", err)
		}
	})
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	// Trust only this fixture in the disposable Chrome profile. Preserve normal
	// certificate and hostname verification, Origin and browser security rules.
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, cert)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private Chrome trust: %v\n%s", err, output)
	}
	chrome := exec.CommandContext(ctx, browser, "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	config, err := json.Marshal(map[string]string{"origin": f.base})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := json.Marshal(map[string]string{"alice": lifecyclePassword, "bob": localIdentityBobPassword})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "testdata/browser/cross_device_browser_e2e.cjs", endpoint, string(config))
	driver.Stdin = strings.NewReader(string(passwords))
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("real Chrome cross-device flow: %v\n%s", err, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatalf("browser did not complete cross-device journey: %s", output)
	}
}
