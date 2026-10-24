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
	"fmt"
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
	// The full journey keeps its existing budget; the second, sequential fixture
	// adds only a bounded nested-mount smoke check and its own cleanup.
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCrossDeviceBrowserProcess$", "-test.v", "-test.timeout=340s")
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
	repository, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		mode, mount string
		deadline    time.Duration
	}{
		{mode: "full", mount: "/auth", deadline: 3 * time.Minute},
		{mode: "smoke", mount: "/company/auth", deadline: 90 * time.Second},
	} {
		t.Run(scenario.mode, func(t *testing.T) {
			// Fixture cleanup belongs to this subtest, so Caddy stops and releases
			// its stores/listeners before the next mount is provisioned.
			screenshots, err := crossDeviceScreenshotDirectory(repository, os.Getenv("CADDY_SECURITY_CROSS_DEVICE_SCREENSHOT_DIR"), scenario.mode)
			if err != nil {
				t.Fatal(err)
			}
			f := crossDeviceFixture(t, localIdentityOptions{mount: scenario.mount, refreshRealm: "local", oidcRealm: "local"}, "enable cross-device login\ncookie cross-device session id name __Secure-DEVICE", cert, key, roots)
			runCaddyCrossDeviceBrowser(t, browser, cert, f.base, scenario.mount, scenario.mode, screenshots, scenario.deadline)
		})
	}
}

func runCaddyCrossDeviceBrowser(t *testing.T, browser, cert, origin, mount, mode, screenshots string, deadline time.Duration) {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(t.Context(), deadline)
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
	config, err := json.Marshal(map[string]string{"origin": origin, "mount": mount, "mode": mode, "screenshotDir": screenshots})
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

// Screenshots can contain live activation codes. Keep the opt-in sink private,
// reject symlink components, and never write outside this checkout's tmp tree.
func crossDeviceScreenshotDirectory(repository, configured, mode string) (string, error) {
	if configured == "" {
		return "", nil
	}
	if mode != "full" && mode != "smoke" {
		return "", fmt.Errorf("unsupported screenshot scenario")
	}
	repository, err := filepath.EvalSymlinks(repository)
	if err != nil {
		return "", fmt.Errorf("resolve screenshot repository: %w", err)
	}
	if !filepath.IsAbs(configured) {
		configured = filepath.Join(repository, configured)
	}
	configured = filepath.Clean(configured)
	base := filepath.Join(repository, "tmp")
	relative, err := filepath.Rel(base, configured)
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("screenshots must be strictly beneath the repository tmp directory")
	}
	current := repository
	parts := append([]string{"tmp"}, strings.Split(relative, string(os.PathSeparator))...)
	parts = append(parts, mode)
	for i, part := range parts {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("create screenshot directory: %w", err)
		}
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("inspect screenshot directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("screenshot path must contain only real directories")
		}
		// Existing task ancestors may be shared; the requested sink and each
		// scenario directory must be private without changing anyone's modes.
		if i >= len(parts)-2 && info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("screenshot output directory must be private")
		}
	}
	return current, nil
}

func TestCrossDeviceScreenshotDirectory(t *testing.T) {
	newRepository := func(t *testing.T) string {
		t.Helper()
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	t.Run("disabled", func(t *testing.T) {
		root := newRepository(t)
		got, err := crossDeviceScreenshotDirectory(root, "", "full")
		if err != nil || got != "" {
			t.Fatal("disabled screenshots created a sink")
		}
		if _, err := os.Lstat(filepath.Join(root, "tmp")); !os.IsNotExist(err) {
			t.Fatal("disabled screenshots touched the filesystem")
		}
	})
	t.Run("private scenario isolation", func(t *testing.T) {
		root := newRepository(t)
		for _, mode := range []string{"full", "smoke"} {
			got, err := crossDeviceScreenshotDirectory(root, "tmp/cross-device/screenshots", mode)
			want := filepath.Join(root, "tmp", "cross-device", "screenshots", mode)
			if err != nil || got != want {
				t.Fatal("scenario directory was not resolved beneath the private sink")
			}
			for _, name := range []string{filepath.Dir(got), got} {
				info, err := os.Stat(name)
				if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
					t.Fatal("screenshot output is not a private directory")
				}
			}
			if again, err := crossDeviceScreenshotDirectory(root, filepath.Dir(got), mode); err != nil || again != got {
				t.Fatal("existing private absolute sink was not accepted")
			}
		}
	})
	for _, configured := range []string{"tmp", ".", "../outside", "tmp/../../outside", "tmp-neighbor/screenshots"} {
		t.Run("reject "+configured, func(t *testing.T) {
			root := newRepository(t)
			if _, err := crossDeviceScreenshotDirectory(root, configured, "full"); err == nil {
				t.Fatal("screenshot path escaped the allowed subtree")
			}
		})
	}
	t.Run("reject scenario traversal", func(t *testing.T) {
		if _, err := crossDeviceScreenshotDirectory(newRepository(t), "tmp/screenshots", "../outside"); err == nil {
			t.Fatal("unsafe scenario name accepted")
		}
	})
	for _, position := range []string{"tmp", "ancestor", "sink", "scenario"} {
		t.Run("reject symlink "+position, func(t *testing.T) {
			root := newRepository(t)
			components := map[string]string{"tmp": "tmp", "ancestor": "tmp/task", "sink": "tmp/task/screenshots", "scenario": "tmp/task/screenshots/full"}
			link := filepath.Join(root, components[position])
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), link); err != nil {
				t.Fatal(err)
			}
			if _, err := crossDeviceScreenshotDirectory(root, "tmp/task/screenshots", "full"); err == nil {
				t.Fatal("symlink screenshot path accepted")
			}
		})
	}
	for _, kind := range []string{"file", "nonprivate sink", "nonprivate scenario"} {
		t.Run("reject "+kind, func(t *testing.T) {
			root := newRepository(t)
			sink := filepath.Join(root, "tmp", "screenshots")
			if err := os.MkdirAll(filepath.Dir(sink), 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "file" {
				if err := os.WriteFile(sink, []byte("sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if kind == "nonprivate scenario" {
					sink = filepath.Join(sink, "full")
				}
				if err := os.MkdirAll(sink, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(sink, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := crossDeviceScreenshotDirectory(root, "tmp/screenshots", "full"); err == nil {
				t.Fatal("unsafe screenshot output accepted")
			}
		})
	}
}
