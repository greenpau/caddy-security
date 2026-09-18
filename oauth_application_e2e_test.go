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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// Isolate Caddy globals and inspect all DEBUG-level process output, including
// failures and reloads, for leaked application credentials.
func TestCaddyOAuthApplicationsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOAuthApplicationsProcess$", "-test.v", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_APPLICATIONS_CHILD=1")
	cmd.Env = append(cmd.Env, "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if bytes.Contains(output, []byte(applicationTestSecret)) {
		t.Fatal("Caddy errors or routine logs exposed an application client secret")
	}
	if err != nil {
		t.Fatalf("Caddy OAuth application registration: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("provisioning app instance")) {
		t.Fatal("fixture did not capture provisioning logs")
	}
}

func TestCaddyOAuthApplicationsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_APPLICATIONS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	source, err := os.ReadFile("testdata/caddyfile_adapt/testcase_security_oauth_applications.Caddyfile")
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile, roots := cookieTLSCertificate(t)
	address := lifecycleAddress(t)
	input := strings.Replace(string(source), "http://127.0.0.1:9080 {", fmt.Sprintf("https://%s {\n tls %q %q", address, certFile, keyFile), 1)
	input = strings.Replace(input, "\tadmin off", "\tdebug\n\tadmin off", 1)
	// Reload closes the retired server's idle connections. Use a new connection
	// for each request so non-idempotent login POSTs cannot race that shutdown.
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "https://" + address
	adapt := func(source string) []byte {
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(source), nil)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	active := func() *App {
		app, err := caddy.ActiveContext().App("security")
		if err != nil {
			t.Fatal(err)
		}
		return app.(*App)
	}
	checkPortal := func() {
		if token := lifecycleLogin(t, client, base); token == "" {
			t.Fatal("local portal did not authenticate")
		}
		for _, path := range []string{"/auth/.well-known/openid-configuration", "/auth/oidc/authorize", "/auth/oidc/token"} {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("unexpected public provider route %s: %d", path, resp.StatusCode)
			}
			if bytes.Contains(body, []byte(applicationTestSecret)) {
				t.Fatal("HTTP response exposed client secret")
			}
		}
	}
	var previous *App
	var expected []*oidc.OAuthApplicationConfig
	data := adapt(input)
	for i := range 3 {
		next := adapt(input)
		if !bytes.Equal(data, next) {
			t.Fatal("repeated adaptation changed registration")
		}
		if err := caddy.Load(next, true); err != nil {
			t.Fatal(err)
		}
		app := active()
		if app == previous {
			t.Fatal("forced reload reused security app instance")
		}
		if _, err := app.getPortal("myportal"); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			expected = app.Config.OAuthApplications
		}
		if diff := cmp.Diff(expected, app.Config.OAuthApplications); diff != "" {
			t.Fatal("reload changed application registration")
		}
		if len(app.Config.OAuthApplications) != 3 || app.Config.AuthenticationPortals[0].OIDCProvider != nil {
			t.Fatal("registration enabled a provider or lost applications")
		}
		if previous != nil {
			assertServerClosed(t, previous)
		}
		checkPortal()
		previous = app
	}
	// A rejected Caddyfile adaptation must leave the live registration usable.
	// Include global header dispatch, which runs before the application parser.
	for _, tc := range []struct{ name, declaration, want string }{
		{"grouped kind", `oauth "application website" ` + applicationTestSecret + " {\n}\n", "expected oauth application, oauth registration store, or oauth identity provider header"},
		{"grouped header", `"oauth application ` + applicationTestSecret + `" website {` + "\n}\n", "unsupported security directive"},
		{"empty application", "oauth application empty {\n}\n", "explicit or persisted client_id"},
		{"quoted opening brace", strings.Replace(applicationTestBlock("quoted", ""), " {", ` "{"`, 1), "requires a block"},
		{"consent outside application", strings.Replace(applicationTestBlock("trailing", ""), "}\n", "} skip_consent on\n", 1), "closing brace must end its line"},
		{"closing brace as client id", "oauth application incomplete {\nclient_secret " + applicationTestSecret + "\nredirect_uri https://app.example.test/callback\nclient_id }\n", "unexpected closing brace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := strings.Replace(input, "\tsecurity {", "\tsecurity {\n"+tc.declaration, 1)
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil)
			if err == nil {
				t.Fatal("malformed Caddyfile was accepted")
			}
			if strings.Contains(err.Error(), applicationTestSecret) {
				t.Fatal("Caddyfile error exposed client secret")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
			if active() != previous {
				t.Fatal("invalid adaptation replaced live registration")
			}
			checkPortal()
		})
	}
	t.Run("unterminated security block", func(t *testing.T) {
		// Put the malformed application last, so another declaration cannot
		// happen to reject it before the global parser checks its own scope.
		block := strings.TrimSuffix(applicationTestBlock("dangling", ""), "}\n") + "client_name \"}\"\n"
		invalid := strings.Replace(input, "\n\t}\n}\n", "\n"+block+"\t}\n}\n", 1)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil)
		if err == nil || len(data) != 0 {
			t.Fatal("unterminated security block was accepted")
		}
		if strings.Contains(err.Error(), applicationTestSecret) {
			t.Fatal("security block error exposed client secret")
		}
		if !strings.Contains(err.Error(), "unterminated security block") {
			t.Fatalf("unexpected error: %v", err)
		}
		if active() != previous {
			t.Fatal("invalid adaptation replaced live registration")
		}
		checkPortal()
	})
	// Native JSON uses the same root collection and must reject invalid candidate
	// registrations before replacing the live app. Its errors must stay redacted.
	for _, failure := range []string{"duplicate", "missing credentials", "short secret", "nil client"} {
		t.Run(failure, func(t *testing.T) {
			var candidate struct {
				Apps    map[string]json.RawMessage `json:"apps"`
				Admin   json.RawMessage            `json:"admin"`
				Logging json.RawMessage            `json:"logging"`
			}
			if err := json.Unmarshal(data, &candidate); err != nil {
				t.Fatal(err)
			}
			var app App
			if err := json.Unmarshal(candidate.Apps["security"], &app); err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "duplicate":
				app.Config.OAuthApplications = append(app.Config.OAuthApplications, app.Config.OAuthApplications[0])
			case "missing credentials":
				app.Config.OAuthApplications[0].Client.ClientSecret = ""
			case "short secret":
				app.Config.OAuthApplications[0].Client.ClientSecret = "tiny"
			case "nil client":
				app.Config.OAuthApplications[0].Client = nil
			}
			candidate.Apps["security"], err = json.Marshal(&app)
			if err != nil {
				t.Fatal(err)
			}
			invalid, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			wantError := "oidc client secrets require 32 to 1024 bytes"
			switch failure {
			case "duplicate":
				wantError = "duplicate oauth application nickname"
			case "nil client":
				wantError = "oidc client is nil"
			}
			if err := caddy.Load(invalid, true); err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("invalid native registration: %v, want %s", err, wantError)
			}
			if active() != previous {
				t.Fatal("invalid reload replaced live registration")
			}
			checkPortal()
		})
	}
	// Remove a declaration and reload; no registry or previous Config may make it
	// implicitly available. Reintroducing it later uses its explicit credentials.
	start := strings.Index(input, "\t\toauth application native {")
	end := start + strings.Index(input[start:], "\n\t\t}") + len("\n\t\t}")
	removed := adapt(input[:start] + input[end:])
	if err := caddy.Load(removed, true); err != nil {
		t.Fatal(err)
	}
	app := active()
	if len(app.Config.OAuthApplications) != 2 {
		t.Fatal("removed application survived reload")
	}
	if _, err := app.Config.GetOAuthApplication("native"); err == nil {
		t.Fatal("removed nickname remains registered")
	}
	if len(previous.Config.OAuthApplications) != 3 {
		t.Fatal("removal mutated old snapshot")
	}
	checkPortal()
	rotated := adapt(strings.ReplaceAll(input, applicationTestSecret, applicationTestSecret+"-rotated"))
	if err := caddy.Load(rotated, true); err != nil {
		t.Fatal(err)
	}
	current, err := active().Config.GetOAuthApplication("website")
	if err != nil {
		t.Fatal(err)
	}
	if current.Client.ClientID != expected[0].Client.ClientID || current.Client.ClientSecret != applicationTestSecret+"-rotated" {
		t.Fatal("explicit secret rotation changed client identity")
	}
	if expected[0].Client.ClientSecret != applicationTestSecret {
		t.Fatal("new registration mutated old snapshot")
	}
	native, err := active().Config.GetOAuthApplication("native")
	if err != nil {
		t.Fatal(err)
	}
	if native.Client.ClientID != "native-protocol-id" || native.Client.ClientSecret != "" {
		t.Fatal("reintroduced public registration changed credentials")
	}
	checkPortal()
}
