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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

const oauthParserBase = `realm upstream
 driver generic
 client_id client
 client_secret synthetic-secret
 base_auth_url https://base.example/path
 metadata_url https://discovery.example/metadata
`

func parseOAuthTest(body string) (*authcrunch.Config, error) {
	d := caddyfile.NewTestDispenser("provider {\n" + body + "\n}")
	d.Next()
	cfg := &authcrunch.Config{}
	err := parseCaddyfileOAuthIdentityProvider(d, &App{Config: cfg}, "upstream", nil)
	return cfg, err
}

func oauthTestParams(t *testing.T, body string) map[string]any {
	t.Helper()
	cfg, err := parseOAuthTest(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.IdentityProviders) != 1 || cfg.IdentityProviders[0].Name != "upstream" || cfg.IdentityProviders[0].Kind != "oauth" {
		t.Fatal("provider registration changed")
	}
	data, err := json.Marshal(cfg.IdentityProviders[0].Params)
	if err != nil {
		t.Fatal(err)
	}
	return unpack(t, string(data))
}

func TestOAuthSharedParserFields(t *testing.T) {
	scalars := map[string]string{
		"domain_name": "example.test", "server_id": "server", "tenant_id": "tenant", "region": "region", "user_pool_id": "pool",
		"issuer": "https://Issuer.example/Exact/", "access_token_audience": "resource-api", "authorization_url": "https://idp.example/authorize", "token_url": "https://idp.example/token",
		"identity_token_cookie_name": "EXTERNAL", "identity_token_field_name": "access_token", "user_info_roles_field_name": "custom_roles",
	}
	for key, value := range scalars {
		for _, spelling := range []string{key, strings.ReplaceAll(key, "_", " ")} {
			t.Run(spelling, func(t *testing.T) {
				params := oauthTestParams(t, oauthParserBase+spelling+" "+value)
				if params[key] != value {
					t.Fatalf("%s changed: %v", key, params[key])
				}
			})
		}
	}
	for _, key := range []string{"realm", "driver", "client_id", "client_secret", "base_auth_url", "metadata_url"} {
		t.Run(key+" alias", func(t *testing.T) {
			want := oauthTestParams(t, oauthParserBase)
			got := oauthTestParams(t, strings.Replace(oauthParserBase, key+" ", strings.ReplaceAll(key, "_", " ")+" ", 1))
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
	for _, key := range []string{"scopes", "response_type", "required_token_fields", "user_group_filters", "user_org_filters", "user_info_fields"} {
		for _, spelling := range []string{key, strings.ReplaceAll(key, "_", " ")} {
			t.Run(spelling, func(t *testing.T) {
				params := oauthTestParams(t, oauthParserBase+spelling+` "first, value" second`)
				if diff := cmp.Diff([]any{"first, value", "second"}, params[key]); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	}
	for _, key := range []string{"delay_start", "retry_attempts", "retry_interval"} {
		for _, spelling := range []string{key, strings.ReplaceAll(key, "_", " ")} {
			t.Run(spelling, func(t *testing.T) {
				params := oauthTestParams(t, oauthParserBase+spelling+" 17")
				if params[key] != float64(17) {
					t.Fatal("retry integer changed")
				}
			})
		}
	}
}

func TestOAuthLegacyTranslations(t *testing.T) {
	for _, tc := range []struct{ old, modern string }{
		{"disable metadata_discovery", "metadata discovery disabled"}, {"disable key verification", "key verification disabled"},
		{"disable pass_grant_type", "pass grant type disabled"}, {"disable response type", "response type parameter disabled"},
		{"disable scope", "scope disabled"}, {"disable nonce", "nonce disabled"}, {"disable pkce", "pkce disabled"},
		{"disable email claim check", "email claim check disabled"}, {"disable tls_verification", "tls verification disabled"},
		{"enable accept_header", "accept header enabled"}, {"enable js callback", "js callback enabled"}, {"enable logout", "logout enabled"},
		{"enable id token cookie", "identity token cookie enabled"},
		{"enable id token cookie access_token", "identity token cookie enabled\nidentity_token_field_name access_token"},
		{"enable id token cookie access_token CUSTOM", "identity token cookie enabled\nidentity token field name access_token\nidentity token cookie name CUSTOM"},
		{"extract email roles from userinfo", "user_info_fields email roles"},
		{`icon "Sign in" priority 20 text black gray`, `login icon text "Sign in"
login icon priority 20
login icon text color black
login icon text background color gray`},
		{"icon priority 0 text black", "login icon priority 0\nlogin icon text color black"},
		{`icon "Sign in" "custom class"`, `login icon text "Sign in"
login icon class_name "custom class"`},
		{`icon "Sign in" "custom class" blue white text black gray priority 20`, `login icon text "Sign in"
login icon class name "custom class"
login icon color blue
login icon background color white
login icon text color black
login icon text background color gray
login icon priority 20`},
	} {
		t.Run(tc.old, func(t *testing.T) {
			got, want := oauthTestParams(t, oauthParserBase+tc.old), oauthTestParams(t, oauthParserBase+tc.modern)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatal(diff)
			}
			// Both spellings must share the same duplicate tracking over the block.
			for _, body := range []string{tc.old + "\n" + tc.modern, tc.modern + "\n" + tc.old} {
				cfg, err := parseOAuthTest(oauthParserBase + body)
				if err == nil || len(cfg.IdentityProviders) != 0 {
					t.Fatal("duplicate alias accepted or partially registered")
				}
			}
		})
	}
	for _, key := range []string{"scopes", "user_group_filters", "user_org_filters", "response_type"} {
		params := oauthTestParams(t, oauthParserBase+key+" first\nissuer exact\n"+key+" second")
		if diff := cmp.Diff([]any{"first", "second"}, params[key]); diff != "" {
			t.Fatal(diff)
		}
	}
	for _, state := range []string{"metadata discovery", "key verification", "pass grant type", "response type parameter", "scope", "nonce", "pkce", "email claim check", "tls verification", "accept header", "js callback", "logout", "identity token cookie"} {
		for _, value := range []string{"enabled", "disabled"} {
			oauthTestParams(t, oauthParserBase+state+" "+value)
		}
	}
}

func TestOAuthParserRejectsAmbiguousOrMalformedInput(t *testing.T) {
	cases := []string{
		"issuer", "issuer one two", `issuer ""`, "access token audience", "access_token_audience one two",
		"issuer exact\nissuer other", "access_token_audience first\naccess token audience second",
		"user_group_filters first\nuser group filters second", "required_token_fields id_token\nrequired token fields access_token",
		"client id another", "retry_attempts 2\nretry attempts 3", "nonce enabled\nnonce disabled", "nonce true", "nonce_disabled true",
		"login icon color blue\nlogin icon color red", "icon SignIn priority 0\nlogin icon priority 2", "login icon text_color blue\nlogin icon text color red",
		"jwks key same first.pem\njwks key same second.pem", "jwks key missing", "authorization_url https://idp.example/auth\ntoken_url https://idp.example/token\njwks key id missing.pem",
		"authorization_url https://idp.example/auth\ntoken_url https://idp.example/token\njwks key private testdata/oauth/87329db33bf_pri.pem", "identity_token_field_name nope", "retry_attempts nope", "user_group_filters [",
		"logout_url https://example.test/logout", "logout url https://example.test/logout",
		"unknown synthetic-secret", "app_secret synthetic-secret", "server_name example", "acs_url example",
		"extract email from elsewhere", "enable id token cookie id_token NAME extra", "enable id_token cookie",
		"enable id token cookie_suffix", "disabled extra", "disabled\ndisabled",
		"issuer exact {\nignored value\n}", "issuer exact {\n}", "issuer exact {}", `"access token audience" resource`, `disable "key verification"`,
		"issuer \"line\nbreak\"", `client_secret ""`,
	}
	for _, body := range cases {
		t.Run(strings.ReplaceAll(body, "\n", ";"), func(t *testing.T) {
			cfg, err := parseOAuthTest(oauthParserBase + body)
			if err == nil || len(cfg.IdentityProviders) != 0 {
				t.Fatal("invalid block accepted or partially registered")
			}
			if strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "missing.pem") {
				t.Fatal("error exposed a supplied value")
			}
		})
	}
	for _, key := range []string{"scopes", "user_group_filters", "user_org_filters", "response_type"} {
		if _, err := parseOAuthTest(oauthParserBase + key); err == nil {
			t.Fatal("empty list accepted")
		}
	}
}

func TestOAuthParserDefaultsAndNoDiscovery(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(500) }))
	defer upstream.Close()
	params := oauthTestParams(t, strings.Replace(oauthParserBase, "https://discovery.example/metadata", upstream.URL, 1)+"delay_start 7")
	if requests.Load() != 0 {
		t.Fatal("parsing fetched discovery")
	}
	if _, ok := params["issuer"]; ok {
		t.Fatal("issuer inferred from base URL")
	}
	if params["retry_attempts"] != float64(2) || params["retry_interval"] != float64(7) {
		t.Fatal("delay defaults changed")
	}
	if _, ok := params["server_name"]; ok {
		t.Fatal("derived server name leaked into shared params")
	}
	for _, tc := range []struct{ driver, extra, scope string }{
		{"github", "", "read:user"}, {"facebook", "", "email"}, {"google", "", "openid"}, {"discord", "", "identify"}, {"azure", "", "openid"},
		{"gitlab", "", "openid"}, {"linkedin", "", "openid"}, {"nextcloud", "base_auth_url https://nextcloud.example", "email"},
		{"cognito", "region region\nuser_pool_id pool", "openid"}, {"okta", "domain_name tenant.example\nserver_id server", "openid"},
	} {
		t.Run(tc.driver, func(t *testing.T) {
			body := fmt.Sprintf("realm upstream\ndriver %s\nclient_id client\nclient_secret secret\n%s", tc.driver, tc.extra)
			params := oauthTestParams(t, body)
			if params["scopes"].([]any)[0] != tc.scope {
				t.Fatal("driver scope changed")
			}
			if tc.driver == "google" && params["client_id"] != "client.apps.googleusercontent.com" {
				t.Fatal("Google client ID default changed")
			}
			if tc.driver == "azure" && params["tenant_id"] != "common" {
				t.Fatal("Azure tenant default changed")
			}
			if tc.driver == "github" || tc.driver == "facebook" || tc.driver == "discord" {
				if diff := cmp.Diff([]any{"access_token"}, params["required_token_fields"]); diff != "" {
					t.Fatal(diff)
				}
			}
		})
	}
	for _, name := range []string{"github", "google", "facebook"} {
		d := caddyfile.NewTestDispenser("provider")
		d.Next()
		cfg := &authcrunch.Config{}
		if err := parseCaddyfileOAuthIdentityProvider(d, &App{Config: cfg}, name, []string{"client", "secret"}); err != nil {
			t.Fatal(err)
		}
		if len(cfg.IdentityProviders) != 1 {
			t.Fatal("shortcut not registered")
		}
	}
	cfg, err := parseOAuthTest("disabled")
	if err != nil || len(cfg.IdentityProviders) != 0 {
		t.Fatal("disabled marker changed")
	}
}

func TestOAuthStaticPublicKeysAndQuotedValues(t *testing.T) {
	body := strings.Replace(oauthParserBase, "client_secret synthetic-secret", `client_secret "  synthetic, secret  "`, 1) + `
 authorization_url https://idp.example/authorize
 token_url https://idp.example/token
 jwks key ed testdata/oauth/upstream_ed25519_pub.pem
 jwks key rsa testdata/oauth/87329db33bf_pub.pem
 issuer "https://Issuer.example/Exact/"
 `
	params := oauthTestParams(t, body)
	if params["client_secret"] != "  synthetic, secret  " {
		t.Fatal("quoted credential changed during encoding")
	}
	if diff := cmp.Diff(map[string]any{"ed": "testdata/oauth/upstream_ed25519_pub.pem", "rsa": "testdata/oauth/87329db33bf_pub.pem"}, params["jwks_keys"]); diff != "" {
		t.Fatal(diff)
	}
	if params["issuer"] != "https://Issuer.example/Exact/" {
		t.Fatal("issuer normalized")
	}
	for _, key := range []string{"key_verification_disabled", "tls_insecure_skip_verify", "nonce_disabled", "pkce_disabled"} {
		if params[key] == true {
			t.Fatal("static key configuration disabled verification")
		}
	}
	// Domain validation remains in the shared parser, including the existing
	// restriction to RSA/Ed25519 static PEM. EC remains supported through JWKS.
	ec := newOAuthE2EKey(t, "ec", "ES256")
	if _, err := parseOAuthTest(body + fmt.Sprintf("jwks key ec %q", ec.pem(t, false))); err == nil {
		t.Fatal("unsupported static EC public key accepted")
	}
}

func TestOAuthLegacyIconRejectsHiddenFields(t *testing.T) {
	for _, body := range []string{
		"icon SignIn text red text blue",
		"icon SignIn text red gray text blue white",
		"icon SignIn text red priority 2 text blue",
		"icon SignIn class red blue ignored",
		"icon SignIn text red gray ignored",
		"icon SignIn text",
		"icon SignIn text priority 2",
		"icon SignIn priority 2 3",
	} {
		t.Run(body, func(t *testing.T) {
			cfg, err := parseOAuthTest(oauthParserBase + body)
			if err == nil || len(cfg.IdentityProviders) != 0 {
				t.Fatal("legacy icon silently discarded or overwrote fields")
			}
		})
	}
}

func TestOAuthRetryIntegerPrecision(t *testing.T) {
	const value = "9007199254740993"
	cfg, err := parseOAuthTest(oauthParserBase + "retry_attempts " + value)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.IdentityProviders[0].Params["retry_attempts"]; got != json.Number(value) {
		t.Fatalf("retry integer lost precision: %v", got)
	}
}

func TestOAuthQuotedTokenBoundaries(t *testing.T) {
	for _, suffix := range []string{"\t", "\u00a0", "\u2003"} {
		t.Run(fmt.Sprintf("U+%04X", []rune(suffix)[0]), func(t *testing.T) {
			for _, key := range []string{"client_secret", "issuer", "access_token_audience"} {
				value := "exact-value" + suffix
				body := oauthParserBase
				if key == "client_secret" {
					body = strings.Replace(body, "client_secret synthetic-secret\n", "", 1)
				}
				params := oauthTestParams(t, body+key+` "`+value+`"`)
				if params[key] != value {
					t.Errorf("%s lost quoted whitespace", key)
				}
			}
			value := "exact-value" + suffix
			params := oauthTestParams(t, oauthParserBase+`user_info_fields "`+value+`"`+"\n"+`icon "`+value+`"`)
			if diff := cmp.Diff([]any{value}, params["user_info_fields"]); diff != "" {
				t.Error(diff)
			}
			if params["login_icon"].(map[string]any)["text"] != value {
				t.Error("legacy icon lost quoted whitespace")
			}
			key, err := os.ReadFile("testdata/oauth/upstream_ed25519_pub.pem")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "public.pem"+suffix)
			if err := os.WriteFile(path, key, 0600); err != nil {
				t.Fatal(err)
			}
			params = oauthTestParams(t, oauthParserBase+"authorization_url https://idp.example/authorize\ntoken_url https://idp.example/token\njwks key ed \""+path+"\"")
			if params["jwks_keys"].(map[string]any)["ed"] != path {
				t.Error("static key path lost quoted whitespace")
			}
		})
	}
}

func FuzzOAuthDirectiveEncoding(f *testing.F) {
	for _, value := range []string{"secret\t", "issuer\u2003", "audience\u00a0", `quotes " and commas,`, " leading", "trailing ", "back\\slash"} {
		f.Add("issuer", value)
	}
	f.Fuzz(func(t *testing.T, first, second string) {
		args := []string{"user_info_fields", first, second}
		if validateOAuthDirectiveTokens(args) != nil {
			return
		}
		decoded, err := cfgutil.DecodeArgs(encodeOAuthDirective(args))
		if err != nil {
			t.Fatal("encoded directive cannot be decoded")
		}
		if diff := cmp.Diff(args, decoded); diff != "" {
			t.Fatal(diff)
		}
	})
}
