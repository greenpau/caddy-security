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
	"crypto/tls"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaddyLoginDestinationsBrowserE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLoginDestinationsBrowserProcess$", "-test.v", "-test.timeout=340s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_LOGIN_DESTINATIONS_BROWSER_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy login destinations browser: %v\n%s", err, output)
	}
}

func TestCaddyLoginDestinationsBrowserProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_LOGIN_DESTINATIONS_BROWSER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	browser := caddyRefreshBrowserExecutable(t)
	cert, key, roots := cookieTLSCertificate(t, "localhost")
	for _, scenario := range []struct {
		name, mount, directive, sandbox, access string
	}{
		{"root_host_cookie", "", "cookie sandbox id name __Host-FLOW", "__Host-FLOW", "AUTHP_ACCESS_TOKEN"},
		{"nested_custom_prefix", "/tenant/auth", "cookie prefix DEST", "DEST_SANDBOX_ID", "DEST_ACCESS_TOKEN"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newLocalIdentityFixture(t, localIdentityOptions{mount: scenario.mount, configure: func(input string) string {
				input = strings.Replace(input, "enable identity stores localdb excludeddb", "enable identity store localdb\n"+scenario.directive, 1)
				input = strings.Replace(input, "validate bearer header", "validate bearer header\nset access_token cookie name "+scenario.access, 1)
				return loginDestinationsBrowserConfig(t, input)
			}}, cert, key, roots)
			runCaddyLoginDestinationsBrowser(t, f, browser, cert, map[string]string{
				"mode": "local", "origin": f.base, "mount": scenario.mount,
				"sandboxCookieName": scenario.sandbox, "accessCookieName": scenario.access,
			})
		})
	}
	t.Run("cross_site_saml_post", func(t *testing.T) {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			t.Fatal(err)
		}
		f, idp := newCrossDeviceSAMLFixture(t, cert, key, roots, pair, func(input string) string {
			return loginDestinationsBrowserConfig(t, input)
		}, "localhost")
		runCaddyLoginDestinationsBrowser(t, f, browser, cert, map[string]string{
			"mode": "saml", "origin": f.base, "mount": "/auth", "idpOrigin": idp,
			"sandboxCookieName": "AUTHP_SANDBOX_ID", "accessCookieName": "AUTHP_ACCESS_TOKEN",
		})
	})
}

func loginDestinationsBrowserConfig(t *testing.T, input string) string {
	t.Helper()
	var host string
	for line := range strings.SplitSeq(input, "\n") {
		if site, found := strings.CutPrefix(line, "https://"); found {
			host = strings.Fields(site)[0]
		}
	}
	if host == "" {
		t.Fatal("missing browser fixture TLS origin")
	}
	trust := "trust login redirect uri domain exact " + host + " path exact /resource\n"
	input = strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\n"+trust, 1)
	// SAML request/relay identifiers can appear in request URIs and Location.
	// Both Caddy encoders need explicit redaction in addition to their normal
	// Cookie/Set-Cookie/Authorization protection. AuthCrunch's external-login
	// DEBUG event separately records its redirect in the top-level url field.
	input = strings.Replace(input, "format json", "format filter {\nwrap json\nfields {\nrequest>uri delete\nresp_headers>Location delete\nurl delete\n}\n}", 1)
	return strings.Replace(input, "fields {\n    resp_headers>Location delete", "fields {\n    request>uri delete\n    resp_headers>Location delete", 1)
}

func runCaddyLoginDestinationsBrowser(t *testing.T, f *localIdentityFixture, browser, cert string, config map[string]string) {
	t.Helper()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "login-destinations-browser-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Errorf("remove private login destinations browser profile: %v", err)
		}
	})
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
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
	// Transfer only the synthetic credential inventory through a private file.
	// Browser stdout and assertion errors must remain free of credential values.
	config["secretFile"] = filepath.Join(t.TempDir(), "browser-secrets.json")
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "testdata/browser/login_destinations_browser_e2e.cjs", endpoint, string(encoded))
	driver.Stdin = strings.NewReader(lifecyclePassword)
	driver.WaitDelay = time.Second
	output, driverErr := driver.CombinedOutput()
	info, inventoryErr := os.Stat(config["secretFile"])
	if inventoryErr == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Size() <= 512*1024 {
		data, err := os.ReadFile(config["secretFile"])
		var secrets []string
		if err != nil || json.Unmarshal(data, &secrets) != nil || len(secrets) == 0 {
			t.Error("browser credential inventory was unreadable or empty")
		} else {
			f.secrets = append(f.secrets, secrets...)
		}
	} else {
		t.Error("browser credential inventory was missing, oversized, or not private")
	}
	assertAdminRedacted(t, output, f.secrets)
	if driverErr != nil {
		t.Fatalf("real Chrome login destinations: %v\n%s", driverErr, output)
	}
	var result struct {
		Passed bool `json:"passed"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed {
		t.Fatal("browser did not complete login destination assertions")
	}
}
