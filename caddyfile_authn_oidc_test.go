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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

const oidcTestBody = `issuer https://auth.example.test/auth
realms employees contractors
signing key files "/private/provider keys/current.pem" "/private/provider keys/previous.pem"
applications website
`

func oidcTestPortal(body string) string {
	return "authentication portal myportal {\n" + body + "\n}\n"
}

func oidcTestBlock(body string) string { return "oidc provider {\n" + body + "\n}\n" }

func parseOIDCTestPortal(t *testing.T, body string) (*App, error) {
	t.Helper()
	app := &App{Config: authcrunch.NewConfig()}
	if err := parseApplicationTestConfig(applicationTestBlock("website", ""), app.Config); err != nil {
		t.Fatal(err)
	}
	d := caddyfile.NewTestDispenser(oidcTestPortal(body))
	d.Next()
	err := parseCaddyfileAuthentication(d, app)
	return app, err
}

func TestParseCaddyfileOIDCProvider(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		values     [5]int
	}{
		{"defaults", oidcTestBody, [5]int{28800, 300, 10000, 1024, 10000}},
		{"explicit enabled and zero defaults", "enabled\n" + oidcTestBody + "session lifetime 0\ntoken lifetime 0\nmax sessions 0\nmax pending requests 0\nmax grants 0\n", [5]int{28800, 300, 10000, 1024, 10000}},
		{"all settings", oidcTestBody + "session lifetime 7200\ntoken lifetime 600\nmax sessions 42\nmax pending requests 43\nmax grants 44\n", [5]int{7200, 600, 42, 43, 44}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The parser must neither generate credentials nor read/create keys.
			reader := rand.Reader
			rand.Reader = registrationNoRandomness{}
			defer func() { rand.Reader = reader }()
			app, err := parseOIDCTestPortal(t, oidcTestBlock(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			p := app.Config.AuthenticationPortals[0]
			want := &oidc.Config{
				Enabled: true, Issuer: "https://auth.example.test/auth", Realms: []string{"employees", "contractors"},
				SigningKeyFiles:        []string{"/private/provider keys/current.pem", "/private/provider keys/previous.pem"},
				Clients:                []*oidc.ClientConfig{app.Config.OAuthApplications[0].Client},
				SessionLifetimeSeconds: tc.values[0], TokenLifetimeSeconds: tc.values[1],
				MaxSessions: tc.values[2], MaxPendingRequests: tc.values[3], MaxGrants: tc.values[4],
			}
			if diff := cmp.Diff(want, p.OIDCProvider); diff != "" {
				t.Fatal(diff)
			}
			if p.CookieConfig == nil || p.API == nil {
				t.Fatal("OIDC was attached after portal validation/defaults")
			}
			p.OIDCProvider.Clients[0].RedirectURIs[0] = "https://changed.example.test/callback"
			if app.Config.OAuthApplications[0].Client.RedirectURIs[0] != "https://app.example.test/callback" {
				t.Fatal("provider aliases the named application")
			}
		})
	}
	for _, body := range []string{"", oidcTestBlock("disabled"), oidcTestBlock("disabled\napplications website")} {
		app, err := parseOIDCTestPortal(t, body)
		if err != nil {
			t.Fatal(err)
		}
		p := app.Config.AuthenticationPortals[0].OIDCProvider
		if body == "" {
			if p != nil || len(app.OIDCProviderDirectives) != 0 {
				t.Fatal("absent provider did not stay nil")
			}
		} else if p == nil || p.Enabled {
			t.Fatal("disabled provider was lost or enabled")
		}
	}
}

func TestCaddyfileOIDCProviderRejects(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"empty", oidcTestBlock(""), "canonical HTTPS"},
		{"two disabled", oidcTestBlock("disabled") + oidcTestBlock("disabled"), "already configured"},
		{"two enabled", oidcTestBlock(oidcTestBody) + oidcTestBlock(oidcTestBody), "already configured"},
		{"disabled then enabled", oidcTestBlock("disabled") + oidcTestBlock(oidcTestBody), "already configured"},
		{"empty then disabled", oidcTestBlock("") + oidcTestBlock("disabled"), "already configured"},
		{"bad header", "oidc provider extra {\ndisabled\n}\n", "expected oidc provider"},
		{"missing block", "oidc provider\n", "expected unquoted"},
		{"quoted brace", "oidc provider \"{\"\ndisabled\n}\n", "expected unquoted"},
		{"quoted value cannot close portal", "oidc provider {\ndisabled\nissuer \"}\"\n", "unterminated authentication portal block"},
		{"nested", oidcTestBlock("disabled {\nissuer ignored\n}\n"), "nested registration/provider"},
		{"trailing setting", "oidc provider {\ndisabled\n} issuer https://auth.example.test\n", "unterminated security block"},
		{"brace as value", "oidc provider {\nissuer }\n", "unexpected closing brace"},
	}
	for _, tc := range []struct{ name, statement, want string }{
		{"unknown", "mystery on", "unsupported"},
		{"boolean enabled", "enabled true", "does not take arguments"},
		{"boolean disabled", "disabled false", "does not take arguments"},
		{"conflicting state", "enabled\ndisabled", "duplicate"},
		{"grouped keywords", `"session lifetime" 30`, "unsupported"},
		{"partially grouped keywords", `max "pending requests" 30`, "unsupported"},
		{"underscores", "max_sessions 30", "unsupported"},
		{"duration", "token lifetime 5m", "invalid oidc provider integer"},
		{"overflow", "max grants 999999999999999999999999", "invalid oidc provider integer"},
		{"negative", "max grants -1", "outside supported bounds"},
		{"over limit", "token lifetime 3601", "outside supported bounds"},
		{"missing count", "max sessions", "argument count"},
		{"extra count", "max sessions 10 20", "argument count"},
		{"empty argument", `max grants ""`, "invalid registration/provider argument"},
	} {
		cases = append(cases, struct{ name, body, want string }{tc.name, oidcTestBlock(oidcTestBody + tc.statement), tc.want})
	}
	for _, setting := range []string{"issuer https://auth.example.test/auth", "realms employees", "signing key files /private/key.pem", "applications website", "session lifetime 60", "token lifetime 60", "max sessions 10", "max pending requests 10", "max grants 10", "enabled"} {
		cases = append(cases, struct{ name, body, want string }{"duplicate " + setting, oidcTestBlock(setting + "\n" + setting), "duplicate"})
	}
	for _, issuer := range []string{"http://auth.example.test/auth", "https://AUTH.example.test/auth", "https://auth.example.test/auth/", "https://auth.example.test/a/../auth", "https://auth.example.test/auth?query", "https://auth.example.test/auth#fragment", "https://auth.example.test/%61uth", "https://user@auth.example.test/auth", "https://[auth.example.test]/auth", "https://[127.0.0.1]:8443/auth", "https://2001:db8::1:8443/auth"} {
		cases = append(cases, struct{ name, body, want string }{"issuer " + issuer, oidcTestBlock(strings.Replace(oidcTestBody, "https://auth.example.test/auth", issuer, 1)), "canonical HTTPS"})
	}
	for _, issuer := range []string{"https://auth.example.test:65536/auth", "https://auth.example.test:999999999999999999999/auth", "https://auth.example.test:/auth"} {
		cases = append(cases, struct{ name, body, want string }{"issuer " + issuer, oidcTestBlock(strings.Replace(oidcTestBody, "https://auth.example.test/auth", issuer, 1)), "oidc issuer port"})
	}
	for _, mount := range []string{"/api/provider", "/sandbox/provider", "/oauth2/provider", "/portal"} {
		cases = append(cases, struct{ name, body, want string }{"reserved " + mount, oidcTestBlock(strings.Replace(oidcTestBody, "https://auth.example.test/auth", "https://auth.example.test"+mount, 1)), "reserved portal route"})
	}
	for _, state := range []string{"", "disabled\n"} {
		for _, tc := range []struct{ body, want string }{
			{"applications missing", "unregistered oidc application"},
			{"applications website website", "duplicate oidc application"},
			{"applications", "argument count"},
			{`applications ""`, "invalid registration/provider argument"},
			{"unknown value", "unsupported"},
		} {
			cases = append(cases, struct{ name, body, want string }{state + tc.body, oidcTestBlock(state + tc.body), tc.want})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := "{\nsecurity {\n" + oidcTestPortal(tc.body) + applicationTestBlock("website", "") + "}\n}\n"
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if err == nil || len(data) != 0 || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("adapt error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCaddyfileOIDCProviderApplicationOrder(t *testing.T) {
	portal := oidcTestPortal(oidcTestBlock(oidcTestBody))
	application := applicationTestBlock("website", "")
	file := filepath.Join(t.TempDir(), "applications.Caddyfile")
	if err := os.WriteFile(file, []byte(application), 0600); err != nil {
		t.Fatal(err)
	}
	for _, declarations := range []string{portal + application, application + portal, portal + fmt.Sprintf("import %q\n", file), fmt.Sprintf("import %q\n", file) + portal} {
		app := adaptApplicationTestConfig(t, declarations)
		if app.Config.AuthenticationPortals[0].OIDCProvider != nil {
			t.Fatal("adapted JSON must retain directives rather than client snapshots")
		}
		if err := app.Config.ConfigureOIDCProvider(app.Config.AuthenticationPortals[0], app.OIDCProviderDirectives["myportal"]); err != nil {
			t.Fatal(err)
		}
		if got := app.Config.AuthenticationPortals[0].OIDCProvider.Clients[0].ClientID; got != "protocol-id" {
			t.Fatalf("restored client ID = %q", got)
		}
	}
	// Snippet definitions live outside the global block; Caddy expands them
	// before our collection pass, just like file imports.
	input := "(portal_block) {\n" + portal + "}\n(app_block) {\n" + application + "}\n{\nsecurity {\nimport portal_block\nimport app_block\n}\n}\n"
	if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err != nil {
		t.Fatal(err)
	}
}

func TestCaddyfileOIDCProviderReferences(t *testing.T) {
	for _, state := range []string{"enabled", "disabled"} {
		for _, duplicateID := range []bool{true, false} {
			body := strings.Replace(oidcTestBody, "applications website", "applications other website", 1)
			other := applicationTestBlock("other", "")
			if !duplicateID {
				other = strings.Replace(other, "protocol-id", "other-protocol-id", 1)
			}
			input := "{\nsecurity {\n" + oidcTestPortal(oidcTestBlock(state+"\n"+body)) + applicationTestBlock("website", "") + other + "}\n}\n"
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if duplicateID {
				if err == nil || !strings.Contains(err.Error(), "duplicate oidc client_id") {
					t.Fatalf("duplicate selected client IDs: %v", err)
				}
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Apps struct {
					Security App `json:"security"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			app := &document.Apps.Security
			p := app.Config.AuthenticationPortals[0]
			if err := app.Config.ConfigureOIDCProvider(p, app.OIDCProviderDirectives[p.Name]); err != nil {
				t.Fatal(err)
			}
			if len(p.OIDCProvider.Clients) != 2 || p.OIDCProvider.Clients[0].ClientID != "other-protocol-id" || p.OIDCProvider.Clients[1].ClientID != "protocol-id" {
				t.Fatal("provider did not preserve application selection order")
			}
		}
	}
	file := filepath.Join(t.TempDir(), "provider.Caddyfile")
	if err := os.WriteFile(file, []byte(oidcTestBlock("disabled")), 0600); err != nil {
		t.Fatal(err)
	}
	input := "{\nsecurity {\n" + oidcTestPortal(fmt.Sprintf("import %q\nimport %q\n", file, file)) + "}\n}\n"
	if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("repeated imported provider: %v", err)
	}
}

func TestOIDCProviderJSONRestoration(t *testing.T) {
	// A private file is only a path-validation fixture here. Actual PEM parsing
	// and construction are exercised through Caddy in TestCaddyOIDCProviderE2E.
	key := filepath.Join(registrationTestDirectory(t), "quoted key.pem")
	if err := os.WriteFile(key, []byte("runtime reads this key"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"", "disabled", "disabled\napplications website", strings.Replace(oidcTestBody, `"/private/provider keys/current.pem" "/private/provider keys/previous.pem"`, fmt.Sprintf("%q", key), 1)} {
		portal := oidcTestPortal("")
		if body != "" {
			portal = oidcTestPortal(oidcTestBlock(body))
		}
		app := adaptApplicationTestConfig(t, portal+applicationTestBlock("website", ""))
		for range 2 {
			data, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			var restored App
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := restored.resolveOAuthRegistrationConfig(t.Context(), restored.Config); err != nil {
				t.Fatal(err)
			}
			provider := restored.Config.AuthenticationPortals[0].OIDCProvider
			if body == "" && provider != nil || body != "" && provider == nil {
				t.Fatal("JSON restoration changed provider presence")
			}
			// Next round uses supported native JSON with the completed snapshot.
			restored.OIDCProviderDirectives = nil
			app = &restored
		}
	}
	for _, state := range []string{"enabled", "disabled"} {
		for _, failure := range []string{"nil application", "nil client", "duplicate IDs", "unknown portal", "duplicate provider"} {
			t.Run(state+"/"+failure, func(t *testing.T) {
				app := adaptApplicationTestConfig(t, oidcTestPortal(oidcTestBlock("disabled\napplications website\nissuer https://auth.example.test/auth\nrealms employees\nsigning key files "+fmt.Sprintf("%q", key)))+applicationTestBlock("website", ""))
				app.OIDCProviderDirectives["myportal"][0] = state
				var want string
				switch failure {
				case "nil application":
					app.Config.OAuthApplications[0] = nil
					want = "application at position 1 is nil"
				case "nil client":
					app.Config.OAuthApplications[0].Client = nil
					want = "client is nil"
				case "duplicate IDs":
					app.Config.OAuthApplications = append(app.Config.OAuthApplications, &oidc.OAuthApplicationConfig{Name: "alias", Client: app.Config.OAuthApplications[0].Client})
					app.OIDCProviderDirectives["myportal"][1] = "applications website alias"
					want = "duplicate oidc client_id"
				case "unknown portal":
					app.Config.AuthenticationPortals = nil
					want = "unknown portal"
				case "duplicate provider":
					app.Config.AuthenticationPortals[0].OIDCProvider = &authn.OIDCProviderConfig{}
					want = "already configured"
				}
				if err := app.resolveOAuthRegistrationConfig(t.Context(), app.Config); err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("restoration error = %v, want %q", err, want)
				}
			})
		}
	}
}
