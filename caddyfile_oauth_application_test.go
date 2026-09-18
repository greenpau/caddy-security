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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

const applicationTestSecret = "synthetic-application-secret-0123456789"

func TestOAuthApplicationRequestObjectKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	directives := "request_object_signing_alg RS256\nrequest_object_key first " + n + " AQAB\nrequest_object_key second " + n + " AQAB"
	app := adaptApplicationTestConfig(t, applicationTestBlock("website", directives))
	client := app.Config.OAuthApplications[0].Client
	if client.RequestObjectSigningAlg != "RS256" || !client.RequirePKCE || client.SkipConsent {
		t.Fatal("Request Object configuration weakened authentication defaults")
	}
	want := []oidc.RequestObjectKey{{KeyID: "first", Modulus: n, Exponent: "AQAB"}, {KeyID: "second", Modulus: n, Exponent: "AQAB"}}
	if diff := cmp.Diff(want, client.RequestObjectKeys); diff != "" {
		t.Fatal(diff)
	}
	for _, body := range []string{"request_object_signing_alg RS256", "request_object_key missing-values", "request_object_key first invalid AQAB", directives + "\nrequest_object_key first " + n + " AQAB", "request_object_signing_alg HS256"} {
		if err := parseApplicationTestConfig(applicationTestBlock("website", body), authcrunch.NewConfig()); err == nil {
			t.Fatal("accepted invalid Request Object registration")
		}
	}
}

func applicationTestBlock(name, directives string) string {
	return fmt.Sprintf("oauth application %s {\nclient_id protocol-id\nclient_secret %s\nredirect_uri https://app.example.test/callback\n%s\n}\n", name, applicationTestSecret, directives)
}

func parseApplicationTestConfig(input string, cfg *authcrunch.Config) error {
	d := caddyfile.NewTestDispenser(input)
	d.Next()
	return parseCaddyfileOAuthApplication(d, cfg)
}

func adaptApplicationTestConfig(t *testing.T, declarations string) *App {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+declarations+"\n}\n}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Apps struct {
			Security *App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if config.Apps.Security == nil {
		t.Fatal("missing security app")
	}
	return config.Apps.Security
}

func TestParseCaddyfileOAuthApplication(t *testing.T) {
	for _, method := range []string{"", "client_secret_basic", "client_secret_post", "none"} {
		t.Run("method/"+method, func(t *testing.T) {
			block := applicationTestBlock("website", "client_name \"Website Display Name\"")
			if method != "" {
				block = strings.Replace(block, "client_id", "token_endpoint_auth_method "+method+"\nclient_id", 1)
			}
			if method == "none" {
				block = strings.ReplaceAll(block, "client_secret "+applicationTestSecret+"\n", "")
			}
			cfg := authcrunch.NewConfig()
			if err := parseApplicationTestConfig(block, cfg); err != nil {
				t.Fatal(err)
			}
			wantMethod := method
			if wantMethod == "" {
				wantMethod = "client_secret_basic"
			}
			wantSecret := applicationTestSecret
			if method == "none" {
				wantSecret = ""
			}
			want := &oidc.OAuthApplicationConfig{Name: "website", Client: &oidc.ClientConfig{
				ClientID: "protocol-id", ClientName: "Website Display Name", ClientSecret: wantSecret,
				TokenEndpointAuthMethod: wantMethod, RequirePKCE: true,
				RedirectURIs: []string{"https://app.example.test/callback"}, Scopes: []string{"openid", "profile", "email"},
			}}
			if diff := cmp.Diff([]*oidc.OAuthApplicationConfig{want}, cfg.OAuthApplications); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for _, field := range []string{"require_pkce", "skip_consent"} {
		for _, value := range []string{"true", "yes", "on", "1", "false", "no", "off", "0"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				cfg := authcrunch.NewConfig()
				if err := parseApplicationTestConfig(applicationTestBlock("web", field+" "+value), cfg); err != nil {
					t.Fatal(err)
				}
				client := cfg.OAuthApplications[0].Client
				got := client.RequirePKCE
				if field == "skip_consent" {
					got = client.SkipConsent
				}
				want := value == "true" || value == "yes" || value == "on" || value == "1"
				if got != want {
					t.Fatalf("%s = %v, want %v", field, got, want)
				}
			})
		}
	}
}

func TestParseCaddyfileOAuthApplicationExactTokens(t *testing.T) {
	// Record-edge tabs/NBSP, commas, embedded quotes and spaces exercise both
	// Caddy tokenization and the shared CSV codec without normalizing data.
	nickname := `website "nickname"`
	clientID := `protocol, "identifier"`
	display := "Website, \"Display Name\"\t\u00a0"
	secret := applicationTestSecret + ", \"quoted\"\t\u00a0"
	callbacks := []string{"https://App.example.test:443/a%2Fb?x=a%2fb&y=one,two", "https://app.example.test/callback?next=%2F&x=+"}
	input := fmt.Sprintf("oauth application %q {\nclient_id %q\nclient_name %q\nclient_secret %q\nredirect_uri %s\nredirect_uri %s\nscopes openid email\n}\n", nickname, clientID, display, secret, callbacks[0], callbacks[1])
	// Caddy only unescapes quotes/backslashes; put whitespace inside quotes as
	// literal bytes rather than Go's backslash-t representation.
	input = strings.ReplaceAll(input, `\t`, "\t")
	input = strings.ReplaceAll(input, `\u00a0`, "\u00a0")
	app := adaptApplicationTestConfig(t, input)
	want := &oidc.OAuthApplicationConfig{Name: nickname, Client: &oidc.ClientConfig{
		ClientID: clientID, ClientName: display, ClientSecret: secret, TokenEndpointAuthMethod: "client_secret_basic", RequirePKCE: true,
		RedirectURIs: callbacks, Scopes: []string{"openid", "email"},
	}}
	if diff := cmp.Diff(want, app.Config.OAuthApplications[0]); diff != "" {
		t.Fatal(diff)
	}
}

func TestParseCaddyfileOAuthApplicationMalformed(t *testing.T) {
	valid := applicationTestBlock("web", "")
	cases := []struct{ name, input, want string }{
		{"missing nickname", "oauth application {\n}", "header with one nickname"},
		{"extra header argument", "oauth application web " + applicationTestSecret + " {\n}", "header with one nickname"},
		{"wrong header", "oauth provider web {\n}", "header with one nickname"},
		{"grouped header", `"oauth application" web {` + "\n}", "header with one nickname"},
		{"missing block", "oauth application web", "requires a block"},
		{"unterminated block", strings.TrimSuffix(valid, "}\n"), "unterminated oauth application block"},
		{"empty block", "oauth application web {\n}", "explicit or persisted client_id"},
		{"empty nickname", strings.Replace(valid, "application web", `application ""`, 1), "invalid oauth application header"},
		{"padded nickname", strings.Replace(valid, "application web", `application " web "`, 1), "nickname"},
		{"nested block", applicationTestBlock("web", "scopes {\nopenid\n}"), "nested oauth application"},
		{"empty nested block", applicationTestBlock("web", "scopes {\n}"), "nested oauth application"},
		{"scalar nested block", strings.Replace(valid, "client_secret "+applicationTestSecret, "client_secret "+applicationTestSecret+" {\n}", 1), "nested oauth application"},
		{"unknown field redacted", applicationTestBlock("web", applicationTestSecret+" value"), "unsupported oidc application directive"},
		{"extra scalar", applicationTestBlock("web", "client_name display "+applicationTestSecret), "requires one value"},
		{"empty scalar", applicationTestBlock("web", `client_name ""`), "empty or invalid"},
		{"trailing empty argument", applicationTestBlock("web", `scopes openid ""`), "empty or invalid"},
		{"missing scalar", applicationTestBlock("web", "client_name"), "invalid oidc application directive"},
		{"missing list", applicationTestBlock("web", "scopes"), "invalid oidc application directive"},
		{"repeated list", applicationTestBlock("web", "scopes openid\nscopes email"), "duplicate oidc application directive scopes"},
		{"repeated scalar", applicationTestBlock("web", "client_secret "+applicationTestSecret), "duplicate oidc application directive client_secret"},
		{"split list", applicationTestBlock("web", "scopes openid\nemail"), "invalid oidc application directive"},
		{"grouped list", applicationTestBlock("web", `scopes "openid email"`), "include openid"},
		{"spaced alias", applicationTestBlock("web", "client name display"), "unsupported oidc application directive"},
		{"plural callbacks removed", applicationTestBlock("web", "redirect_uris "+applicationTestSecret), "unsupported oidc application directive"},
		{"multiple callbacks per statement", applicationTestBlock("web", "redirect_uri https://first.example.test/callback https://second.example.test/callback"), "requires one value"},
		{"missing id", strings.Replace(valid, "client_id protocol-id\n", "", 1), "explicit or persisted client_id"},
		{"missing secret", strings.Replace(valid, "client_secret "+applicationTestSecret+"\n", "", 1), "explicit or persisted client_secret"},
		{"short secret", strings.Replace(valid, applicationTestSecret, "tiny", 1), "32 to 1024 bytes"},
		{"long secret", strings.Replace(valid, applicationTestSecret, strings.Repeat("s", 1025), 1), "32 to 1024 bytes"},
		{"invalid id", strings.Replace(valid, "protocol-id", `" padded-id "`, 1), "invalid oidc client_id"},
		{"long id", strings.Replace(valid, "protocol-id", strings.Repeat("i", 257), 1), "invalid oidc client_id"},
		{"unknown auth method", applicationTestBlock("web", "token_endpoint_auth_method "+applicationTestSecret), "unsupported oidc token endpoint"},
		{"boolean redacted", applicationTestBlock("web", "require_pkce "+applicationTestSecret), "invalid oidc application boolean"},
		{"provider state grammar", applicationTestBlock("web", "require_pkce enabled"), "invalid oidc application boolean"},
		{"refresh state grammar", applicationTestBlock("web", "skip_consent disabled"), "invalid oidc application boolean"},
		{"public secret", applicationTestBlock("web", "token_endpoint_auth_method none"), "cannot have a secret"},
		{"public without PKCE", strings.Replace(applicationTestBlock("web", "token_endpoint_auth_method none\nrequire_pkce off"), "client_secret "+applicationTestSecret+"\n", "", 1), "require PKCE"},
		{"invalid callback redacted", strings.Replace(valid, "https://app.example.test/callback", applicationTestSecret, 1), "redirect_uri"},
		{"duplicate callback", strings.Replace(valid, "https://app.example.test/callback", "https://app.example.test/callback\nredirect_uri https://app.example.test/callback", 1), "distinct redirect_uris"},
		{"newline in display", applicationTestBlock("web", "client_name \"Display\nName\""), "empty or invalid"},
		{"NUL in secret", strings.Replace(valid, applicationTestSecret, applicationTestSecret+"\x00", 1), "empty or invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authcrunch.NewConfig()
			err := parseApplicationTestConfig(tc.input, cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %s", err, tc.want)
			}
			for _, secret := range []string{applicationTestSecret, "tiny", strings.Repeat("s", 1025)} {
				if strings.Contains(err.Error(), secret) {
					t.Fatal("error exposed client secret")
				}
			}
			if len(cfg.OAuthApplications) != 0 {
				t.Fatal("invalid declaration changed registry")
			}
		})
	}
}

func TestCaddyfileOAuthApplicationBlockBoundaries(t *testing.T) {
	valid := applicationTestBlock("web", "")
	for _, tc := range []struct{ name, input string }{
		{"quoted opening brace", strings.Replace(valid, " {", ` "{"`, 1)},
		{"consent after closing brace", strings.Replace(valid, "}\n", "} skip_consent on\n", 1)},
		{"PKCE after closing brace", strings.Replace(valid, "}\n", "} require_pkce off\n", 1)},
		{"callback after closing brace", strings.Replace(valid, "}\n", "} redirect_uri https://other.example.test/callback\n", 1)},
		{"opening after closing brace", strings.Replace(valid, "}\n", "} {\n}\n", 1)},
		{"quoted closing brace", strings.Replace(valid, "}\n", "\"}\"\n", 1)},
		{"closing brace as name", strings.Replace(valid, "}\n", "client_name }\n", 1)},
		{"closing brace as id", strings.Replace(strings.Replace(valid, "client_id protocol-id\n", "", 1), "}\n", "client_id }\n", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authcrunch.NewConfig()
			if err := parseApplicationTestConfig(tc.input, cfg); err == nil {
				t.Fatal("malformed block boundary was accepted by application parser")
			}
			if len(cfg.OAuthApplications) != 0 {
				t.Fatal("malformed block boundary registered an application")
			}
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+tc.input+"}\n}\n"), nil)
			if err == nil || len(data) != 0 {
				t.Fatal("malformed block boundary was accepted by global adapter")
			}
			if strings.Contains(err.Error(), applicationTestSecret) {
				t.Fatal("block diagnostic exposed client secret")
			}
		})
	}
	t.Run("comment after closing brace", func(t *testing.T) {
		first := strings.Replace(valid, "}\n", "} # End of the first application.\n", 1)
		cfg := adaptApplicationTestConfig(t, first+applicationTestBlock("second", "")).Config
		if len(cfg.OAuthApplications) != 2 || cfg.OAuthApplications[0].Name != "web" || cfg.OAuthApplications[1].Name != "second" {
			t.Fatal("closing-brace comment changed declaration boundaries")
		}
	})
}

func TestCaddyfileOAuthApplicationEnclosingBlock(t *testing.T) {
	// Caddy's initial parser counts brace-valued quoted arguments as structural
	// braces. The application can then consume the security block's closing
	// brace, so the global adapter must check its own nesting after collection.
	for _, field := range []string{"client_id", "client_name"} {
		t.Run(field, func(t *testing.T) {
			block := applicationTestBlock("web", "")
			if field == "client_id" {
				block = strings.Replace(block, "client_id protocol-id\n", "", 1)
			}
			block = strings.TrimSuffix(block, "}\n") + field + " \"}\"\n"
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+block+"}\n}\n"), nil)
			if err == nil || len(data) != 0 {
				t.Fatal("unterminated security block returned a configuration")
			}
			if strings.Contains(err.Error(), applicationTestSecret) {
				t.Fatal("enclosing-block error exposed client secret")
			}
			if !strings.Contains(err.Error(), "unterminated security block") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCaddyfileOAuthApplicationHeaderErrors(t *testing.T) {
	// Exercise the global dispatcher as well as the application parser: grouped
	// headers must not fall through to errors that echo a misplaced credential.
	for _, tc := range []struct{ name, declaration, want string }{
		{"missing kind", "oauth\n", "expected oauth application, oauth registration store, or oauth identity provider header"},
		{"grouped kind and nickname", `oauth "application web" ` + applicationTestSecret + " {\n}\n", "expected oauth application, oauth registration store, or oauth identity provider header"},
		{"grouped header", `"oauth application ` + applicationTestSecret + `" web {` + "\n}\n", "unsupported security directive"},
		{"grouped kind and secret", `oauth "application ` + applicationTestSecret + `" {` + "\n}\n", "expected oauth application, oauth registration store, or oauth identity provider header"},
		{"extra argument", "oauth application web " + applicationTestSecret + " {\n}\n", "header with one nickname"},
		{"empty block", "oauth application web {\n}\n", "explicit or persisted client_id"},
		{"missing block", "oauth application web\n", "requires a block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "application.caddy")
			if err := os.WriteFile(path, []byte(tc.declaration), 0600); err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{tc.declaration, fmt.Sprintf("import %q\n", path)} {
				data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+source+"}\n}\n"), nil)
				if err == nil {
					t.Fatal("malformed application header was accepted")
				}
				if strings.Contains(err.Error(), applicationTestSecret) {
					t.Fatal("header diagnostic exposed client secret")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want %s", err, tc.want)
				}
				if len(data) != 0 {
					t.Fatal("failed adaptation returned a partial configuration")
				}
			}
		})
	}
}

func TestCaddyfileOAuthApplicationDuplicatesAndImports(t *testing.T) {
	block := applicationTestBlock("web", "")
	dir := t.TempDir()
	imported := filepath.Join(dir, "application.caddy")
	if err := os.WriteFile(imported, []byte(block), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, source string }{
		{"identical", "{\nsecurity {\n" + block + block + "}\n}\n"},
		{"different client same nickname", "{\nsecurity {\n" + block + strings.Replace(block, "protocol-id", "other-id", 1) + "}\n}\n"},
		{"file imported twice", fmt.Sprintf("{\nsecurity {\nimport %q\nimport %q\n}\n}\n", imported, imported)},
		{"import conflicts with inline", fmt.Sprintf("{\nsecurity {\nimport %q\n%s}\n}\n", imported, block)},
		{"snippet imported twice", "(application) {\n" + block + "}\n{\nsecurity {\nimport application\nimport application\n}\n}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(tc.source), nil)
			if err == nil || !strings.Contains(err.Error(), "duplicate oauth application nickname") {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), applicationTestSecret) {
				t.Fatal("error exposed client secret")
			}
		})
	}
	// Imported applications retain their normal body and quoted values.
	cfg := adaptApplicationTestConfig(t, fmt.Sprintf("import %q\n", imported)).Config
	if got := cfg.OAuthApplications; len(got) != 1 || got[0].Name != "web" {
		t.Fatal("import lost application")
	}
	before, _ := json.Marshal(cfg)
	missing := strings.Replace(block, "client_secret "+applicationTestSecret+"\n", "", 1)
	if err := parseApplicationTestConfig(missing, cfg); err == nil || !strings.Contains(err.Error(), "explicit or persisted client_secret") {
		t.Fatalf("adaptation reused existing credentials: %v", err)
	}
	if err := parseApplicationTestConfig(block, cfg); err == nil {
		t.Fatal("duplicate accepted")
	}
	after, _ := json.Marshal(cfg)
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate insertion mutated registry")
	}
	// Duplicate protocol IDs are a provider-level constraint, not a nickname collision.
	cfg = adaptApplicationTestConfig(t, block+applicationTestBlock("other", "")).Config
	if len(cfg.OAuthApplications) != 2 {
		t.Fatal("distinct nicknames were coalesced")
	}
}

func TestCaddyfileOAuthApplicationAssembly(t *testing.T) {
	portal := "authentication portal myportal {\nenable identity store localdb\n}\n"
	store := "local identity store localdb {\nrealm local\npath :memory:\n}\n"
	application := applicationTestBlock("web", "")
	first := adaptApplicationTestConfig(t, application+portal+store)
	last := adaptApplicationTestConfig(t, portal+store+application)
	if diff := cmp.Diff(unpack(t, first.Config), unpack(t, last.Config)); diff != "" {
		t.Fatal(diff)
	}
	// The earlier provider must not be resolved before a later registration.
	// A malformed application's diagnostic wins over the unknown provider driver.
	input := "{\nsecurity {\noauth identity provider upstream {\ndriver invalid\n}\n" + strings.Replace(application, "client_id protocol-id\n", "", 1) + "}\n}\n"
	_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err == nil || !strings.Contains(err.Error(), "explicit or persisted client_id") {
		t.Fatalf("applications were not collected first: %v", err)
	}
	// Even if Caddy supplies a previous value, adaptation uses only declarations.
	d := caddyfile.NewTestDispenser("security {\n" + portal + store + "}\n")
	raw, err := parseCaddyfile(d, first)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("oauth_applications")) {
		t.Fatal("removed application survived adaptation")
	}
}

func TestCaddyfileOAuthApplicationJSONSnapshots(t *testing.T) {
	original := adaptApplicationTestConfig(t, applicationTestBlock("web", "require_pkce no\nskip_consent yes"))
	cfg := original.Config
	named, err := cfg.GetOAuthApplication("web")
	if err != nil {
		t.Fatal(err)
	}
	clients, err := cfg.GetOAuthApplications()
	if err != nil {
		t.Fatal(err)
	}
	// Resolve two independent provider snapshots without exposing a Caddy OP route.
	for _, name := range []string{"first", "second"} {
		portal := &authn.PortalConfig{Name: name}
		if err := cfg.ConfigureOIDCProvider(portal, []string{"issuer https://auth.example.test/auth", "realms local", "signing key files private.pem", "applications web"}); err != nil {
			t.Fatal(err)
		}
		if err := cfg.AddAuthenticationPortal(portal); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored App
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := json.Marshal(&restored)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(unpack(t, string(data)), unpack(t, string(roundtrip))); diff != "" {
		t.Fatal(diff)
	}
	// False PKCE is omitted by native JSON but must remain false on decode.
	if restored.Config.OAuthApplications[0].Client.RequirePKCE {
		t.Fatal("roundtrip enabled PKCE")
	}
	if _, exists := unpack(t, string(data))["config"].(map[string]any)["oauth_applications"]; !exists {
		t.Fatal("missing root oauth_applications")
	}
	named.Client.ClientSecret = "changed"
	named.Client.Scopes[0] = "changed"
	clients["web"].RedirectURIs[0] = "changed"
	cfg.AuthenticationPortals[0].OIDCProvider.Clients[0].ClientSecret = "changed"
	cfg.AuthenticationPortals[0].OIDCProvider.Clients[0].Scopes[0] = "changed"
	cfg.OAuthApplications[0].Client.RedirectURIs[0] = "changed"
	for _, client := range []*oidc.ClientConfig{cfg.AuthenticationPortals[1].OIDCProvider.Clients[0], restored.Config.AuthenticationPortals[0].OIDCProvider.Clients[0], restored.Config.OAuthApplications[0].Client} {
		if client.ClientSecret != applicationTestSecret || client.Scopes[0] != "openid" || client.RedirectURIs[0] != "https://app.example.test/callback" {
			t.Fatal("named/client/provider snapshots share mutable data")
		}
	}
	// A later adaptation cannot rotate a previously assembled provider's client.
	updated := adaptApplicationTestConfig(t, strings.ReplaceAll(applicationTestBlock("web", ""), applicationTestSecret, applicationTestSecret+"-rotated"))
	if updated.Config.OAuthApplications[0].Client.ClientSecret == cfg.AuthenticationPortals[1].OIDCProvider.Clients[0].ClientSecret {
		t.Fatal("rotation was not explicit and independent")
	}
}
