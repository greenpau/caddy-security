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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestCaddyTokenRefreshE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyTokenRefreshProcess$", "-test.v", "-test.timeout=220s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_TOKEN_REFRESH_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS token refresh: %v\n%s", err, output)
	}
}

type caddyTokenRefreshFixture struct {
	base, mount, input string
	client             *http.Client
	keys               []map[string]string
}

// Every runtime field comes from the Caddyfile parser, including root mounts and
// placeholders. No refresh configuration or authentication evidence is injected.
func newCaddyTokenRefreshFixture(t *testing.T, mount, body, cookies string, lifetime int, cert, key string, roots *x509.CertPool, adapters ...func([]byte) []byte) *caddyTokenRefreshFixture {
	t.Helper()
	base := "https://" + lifecycleAddress(t)
	crypto := newJWKSKeyFiles(t, "RSA", "refresh")
	stores := ""
	for _, realm := range []string{"employees", "contractors", "guests"} {
		stores += fmt.Sprintf(`
 local identity store %sdb {
  realm %s
  path :memory:
  user alice {
   email alice@example.test
   password %s
   roles authp/user
  }
 }
`, realm, realm, lifecyclePassword)
	}
	body = strings.ReplaceAll(body, "PUBLIC_ORIGIN", base)
	body = strings.ReplaceAll(body, "BASE_PATH", mount)
	cookies = strings.ReplaceAll(cookies, "PUBLIC_HOST", strings.TrimPrefix(base, "https://"))
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  %s
  authentication portal myportal {
   enable identity stores employeesdb contractorsdb guestsdb
   crypto default token lifetime 600
   %s
   %s
   %s
  }
 }
}
%s {
 tls %q %q
 route %s* {
  authenticate with myportal
 }
}`, stores, crypto.signer("refresh")+fmt.Sprintf("\ncrypto key refresh token lifetime %d", lifetime), cookies, body, base, cert, key, strings.TrimSuffix(mount, "/")+"/")
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, adapt := range adapters {
		data = adapt(data)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	f := &caddyTokenRefreshFixture{base: base, mount: strings.TrimSuffix(mount, "/"), input: input, client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	status, _, raw := registrationHTTP(t, f.client, "GET", base+f.mount+"/.well-known/jwks.json", nil, nil)
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if status != 200 || json.Unmarshal(raw, &doc) != nil || len(doc.Keys) != 1 {
		t.Fatal("public access JWKS unavailable")
	}
	f.keys = doc.Keys
	return f
}
func (f *caddyTokenRefreshFixture) browser(t *testing.T) *http.Client {
	t.Helper()
	client := *f.client
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	return &client
}
func (f *caddyTokenRefreshFixture) headers() http.Header {
	return http.Header{"Origin": {f.base}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"}}
}
func (f *caddyTokenRefreshFixture) post(t *testing.T, client *http.Client, path string, body any, headers http.Header, status int) (apiauth.AuthResponse, []*http.Cookie) {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", f.base+f.mount+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("POST %s: %d, want %d: %.300s", path, resp.StatusCode, status, raw)
	}
	var result apiauth.AuthResponse
	if status != 404 {
		if json.Unmarshal(raw, &result) != nil {
			t.Fatal("invalid JSON auth response")
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("authentication response permits caching")
		}
	}
	if (client.Jar != nil || headers.Get("Origin") != "") && result.RefreshToken != "" {
		t.Fatal("browser exposed refresh credential in JSON")
	}
	return result, resp.Cookies()
}
func (f *caddyTokenRefreshFixture) login(t *testing.T, client *http.Client, realm, transport string, status int) (apiauth.AuthResponse, []*http.Cookie) {
	t.Helper()
	var headers http.Header
	if client.Jar != nil {
		headers = f.headers()
	}
	req := apiauth.AuthRequest{Username: "alice", Realm: realm, RefreshTransport: transport}
	begin, _ := f.post(t, client, "/login", req, headers, 200)
	if begin.Authenticated || begin.SandboxID == "" || begin.SandboxSecret == "" || begin.NextChallenge != "password" {
		t.Fatal("missing real password challenge")
	}
	req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = begin.SandboxID, begin.SandboxSecret, "password", lifecyclePassword
	return f.post(t, client, "/login", req, headers, status)
}
func tokenRefreshActiveCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}
func (f *caddyTokenRefreshFixture) claims(t *testing.T, raw, realm string, lifetime int) map[string]any {
	t.Helper()
	claims := verifyCaddyJWKSSignature(t, f.keys, raw, "RS512", "refresh")
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || !iatOK || exp-iat != float64(lifetime) || exp <= float64(time.Now().Unix()) || iat > float64(time.Now().Unix()) || claims["sub"] != "alice" || claims["origin"] != realm {
		t.Fatalf("wrong identity or bounded lifetime: %+v", claims)
	}
	status, _, _ := registrationHTTP(t, f.client, "GET", f.base+f.mount+"/whoami", nil, http.Header{"Authorization": {"Bearer " + raw}, "Accept": {"application/json"}})
	if status != 200 {
		t.Fatal("issued access token not usable")
	}
	return claims
}
func (f *caddyTokenRefreshFixture) metadata(t *testing.T, result apiauth.AuthResponse, claims map[string]any) {
	t.Helper()
	iat := int64(claims["iat"].(float64))
	if !result.Authenticated || result.SessionID == "" || claims["sid"] != result.SessionID || claims["iss"] != f.base+f.mount || result.AccessExpiresAt != int64(claims["exp"].(float64)) || result.RefreshExpiresAt-iat != 90 || result.SessionExpiresAt-iat != 240 {
		t.Fatal("refresh metadata does not match signed claims or configured timeouts")
	}
}

func TestCaddyTokenRefreshProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_TOKEN_REFRESH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	t.Setenv("TOKEN_REFRESH_E2E_SHARED", "INHERITED_REFRESH")
	t.Setenv("TOKEN_REFRESH_E2E_OVERRIDE", "CUSTOM_REFRESH")
	required := "realms employees contractors\npublic origin PUBLIC_ORIGIN\nbase path BASE_PATH\naccess lifetime 45\nidle timeout 90\nabsolute timeout 240\n"
	for _, tc := range []struct {
		name, mount, cookies, extra, refreshName, accessName string
		signer, lifetime                                     int
	}{
		{"root inherited prefix", "/", "cookie prefix PORTAL", "", "PORTAL_REFRESH_TOKEN", "PORTAL_ACCESS_TOKEN", 120, 45},
		{"nested inherited shared name", "/other", "cookie prefix PORTAL\ncookie refresh token name {env.TOKEN_REFRESH_E2E_SHARED}", "", "INHERITED_REFRESH", "PORTAL_ACCESS_TOKEN", 120, 45},
		{"nested explicit override and signing cap", "/tenant/auth", "cookie prefix PORTAL\ncookie refresh token name SHARED_REFRESH\ncookie access token name SHARED_REFRESH", "cookie name CUSTOM_REFRESH\nbody transport disabled", "CUSTOM_REFRESH", "SHARED_REFRESH", 20, 20},
		{"root deferred override frees default name", "/", "cookie prefix PORTAL\ncookie access token name PORTAL_REFRESH_TOKEN", "cookie name {env.TOKEN_REFRESH_E2E_OVERRIDE}", "CUSTOM_REFRESH", "PORTAL_REFRESH_TOKEN", 120, 45},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaddyTokenRefreshFixture(t, tc.mount, tokenRefreshTestBlock(required+tc.extra), tc.cookies, tc.signer, cert, key, roots)
			for _, realm := range []string{"employees", "contractors"} {
				t.Run(realm, func(t *testing.T) {
					browser := f.browser(t)
					f.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: realm, RefreshTransport: "body"}, nil, 400)
					login, cookies := f.login(t, browser, realm, "", 200)
					refresh := tokenRefreshActiveCookie(t, cookies, tc.refreshName)
					access := tokenRefreshActiveCookie(t, cookies, tc.accessName)
					claims := f.claims(t, access.Value, realm, tc.lifetime)
					f.metadata(t, login, claims)
					if refresh.Path != tc.mount || refresh.Domain != "" || !refresh.Secure || !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode || refresh.Expires.Unix() != login.RefreshExpiresAt {
						t.Fatal("refresh cookie scope or security changed")
					}
					if login.AccessToken != "" || login.RefreshToken != "" {
						t.Fatal("browser JSON disclosed tokens")
					}
					f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": refresh.Value}, nil, 403)
					// Origin, required header, and fetch metadata are enforced in the Caddy pipeline.
					for _, headers := range []http.Header{{"Origin": {"https://attacker.example"}, "X-Authcrunch-Refresh": {"1"}}, {"Origin": {f.base}}, {"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}, "Sec-Fetch-Site": {"cross-site"}}} {
						f.post(t, browser, "/api/refresh_token", struct{}{}, headers, 403)
					}
					// Cookie refresh succeeds even with an unusable access cookie.
					location, _ := url.Parse(f.base + f.mount + "/")
					browser.Jar.SetCookies(location, []*http.Cookie{{Name: tc.accessName, Value: "expired-or-malformed", Path: "/", Secure: true}})
					rotated, cookies := f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
					next := tokenRefreshActiveCookie(t, cookies, tc.refreshName)
					nextClaims := f.claims(t, tokenRefreshActiveCookie(t, cookies, tc.accessName).Value, realm, tc.lifetime)
					if next.Value == refresh.Value || rotated.SessionID != login.SessionID || rotated.SessionExpiresAt != login.SessionExpiresAt || nextClaims["jti"] == claims["jti"] || nextClaims["auth_time"] != claims["auth_time"] {
						t.Fatal("rotation changed binding or reused credential/token identity")
					}
					// Replay detection must revoke the remaining member of the same family.
					old := f.headers()
					old.Set("Cookie", tc.refreshName+"="+refresh.Value)
					f.post(t, f.client, "/api/refresh_token", struct{}{}, old, 401)
					f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 401)
				})
			}
			guest := f.browser(t)
			_, previousCookies := f.login(t, guest, "employees", "", 200)
			previousRefresh := tokenRefreshActiveCookie(t, previousCookies, tc.refreshName)
			login, cookies := f.login(t, guest, "guests", "", 200)
			claims := f.claims(t, login.AccessToken, "guests", tc.signer)
			if login.SessionID != "" || claims["sid"] != nil {
				t.Fatal("unselected realm received a refresh family")
			}
			for _, c := range cookies {
				if c.Name == tc.refreshName && c.Value != "" && c.MaxAge >= 0 {
					t.Fatal("unselected realm received refresh cookie")
				}
			}
			f.post(t, guest, "/api/refresh_token", struct{}{}, f.headers(), 401)
			old := f.headers()
			old.Set("Cookie", tc.refreshName+"="+previousRefresh.Value)
			f.post(t, f.client, "/api/refresh_token", struct{}{}, old, 401)
			// Rejected runtime candidates must leave the serving portal available.
			for _, tc := range []struct{ old, next, want string }{
				{"realms employees contractors", "realms missing", "exactly one store"},
				{"enable identity stores employeesdb contractorsdb guestsdb", "enable identity store guestsdb", "exactly one store"},
				{"realm contractors", "realm employees", "same"},
			} {
				input := strings.Replace(f.input, tc.old, tc.next, 1)
				data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
				if err == nil {
					err = caddy.Load(data, true)
				}
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("runtime candidate rejection: %v, want %s", err, tc.want)
				}
				status, _, _ := registrationHTTP(t, f.client, "GET", f.base+f.mount+"/.well-known/jwks.json", nil, nil)
				if status != 200 {
					t.Fatal("failed candidate disrupted active portal")
				}
			}
		})
	}
	t.Run("unsupported stores and effective cookie collisions", func(t *testing.T) {
		f := newCaddyTokenRefreshFixture(t, "/auth", tokenRefreshTestBlock(required+"cookie name CUSTOM_REFRESH"), "cookie prefix PORTAL", 120, cert, key, roots)
		browser := f.browser(t)
		login, _ := f.login(t, browser, "employees", "", 200)
		for _, override := range []string{"PORTAL_ACCESS_TOKEN", "PORTAL_OIDC_SESSION_ID", "{env.TOKEN_REFRESH_COLLISION}"} {
			t.Setenv("TOKEN_REFRESH_COLLISION", "PORTAL_SANDBOX_ID")
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(strings.Replace(f.input, "cookie name CUSTOM_REFRESH", "cookie name "+override, 1)), nil)
			if err == nil {
				err = caddy.Load(data, true)
			}
			if err == nil || !strings.Contains(err.Error(), "invalid cookie configuration") {
				t.Fatalf("effective refresh cookie collision: %v", err)
			}
		}
		for _, value := range []string{"SHARED_REFRESH\t", "SHARED_REFRESH\u00a0"} {
			for _, mode := range []string{"literal", "runtime"} {
				name := `"` + value + `"`
				if mode == "runtime" {
					t.Setenv("TOKEN_REFRESH_INVALID_SHARED_COOKIE", value)
					name = "{env.TOKEN_REFRESH_INVALID_SHARED_COOKIE}"
				}
				input := strings.Replace(f.input, "cookie prefix PORTAL", "cookie prefix PORTAL\ncookie refresh token name "+name, 1)
				data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
				if err == nil {
					err = caddy.Load(data, true)
				}
				if err == nil || !strings.Contains(err.Error(), "invalid refresh cookie name") {
					t.Fatalf("%s shared cookie value normalized before validation: %v", mode, err)
				}
				rotated, _ := f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
				if rotated.SessionID != login.SessionID {
					t.Fatal("rejected cookie candidate replaced the active refresh family")
				}
			}
		}
		// Restored app snapshots must reject records the shared CSV decoder would
		// otherwise silently ignore, before replacing the serving runtime.
		for _, statement := range []string{
			"cookie prefix PORTAL\ncookie access token name HIDDEN",
			"cookie prefix PORTAL\r\ncookie access token name HIDDEN",
			"cookie prefix PORTAL\r",
		} {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
			if err != nil {
				t.Fatal(err)
			}
			var config caddy.Config
			if err := json.Unmarshal(data, &config); err != nil {
				t.Fatal(err)
			}
			var app App
			if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
				t.Fatal(err)
			}
			app.PortalCookieDirectives = map[string][]string{"myportal": {statement}}
			config.AppsRaw["security"], err = json.Marshal(&app)
			if err != nil {
				t.Fatal(err)
			}
			data, err = json.Marshal(&config)
			if err != nil {
				t.Fatal(err)
			}
			if err := caddy.Load(data, true); err == nil || !strings.Contains(err.Error(), "invalid cookie statement") {
				t.Fatalf("hidden cookie record in saved JSON: %v", err)
			}
			rotated, _ := f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
			if rotated.SessionID != login.SessionID {
				t.Fatal("rejected JSON candidate replaced the active refresh family")
			}
		}
		// A configured LDAP backend is usable for ordinary portal authentication,
		// but lacks the local credential-version contract needed for refresh.
		ldap := `ldap identity store directory {
   realm directory
   servers {
    ldap://127.0.0.1:1
   }
   username "cn=reader,dc=example,dc=test"
   password synthetic-directory-password
   search_base_dn "dc=example,dc=test"
   search_user_filter "(uid=%s)"
   groups {
    "cn=users,dc=example,dc=test" authp/user
   }
  }
  `
		input := strings.Replace(f.input, "authentication portal myportal {", ldap+"authentication portal myportal {", 1)
		input = strings.Replace(input, "enable identity stores employeesdb contractorsdb guestsdb", "enable identity stores employeesdb contractorsdb guestsdb directory", 1)
		input = strings.Replace(input, "realms employees contractors", "realms directory", 1)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err == nil {
			err = caddy.Load(data, true)
		}
		if err == nil || !strings.Contains(err.Error(), "does not support refresh identity verification") {
			t.Fatalf("unsupported realm rejected for wrong reason: %v", err)
		}
		// The prior runtime still owns its functioning refresh store.
		f.login(t, f.browser(t), "employees", "", 200)
	})
	t.Run("native capacity and rotations", func(t *testing.T) {
		// Numeric and state placeholders are resolved by actual Caddy provisioning.
		t.Setenv("TOKEN_REFRESH_E2E_BODY", "enabled")
		t.Setenv("TOKEN_REFRESH_E2E_LIMIT", "1")
		f := newCaddyTokenRefreshFixture(t, "/auth", tokenRefreshTestBlock(required+"body transport {env.TOKEN_REFRESH_E2E_BODY}\nmax sessions {env.TOKEN_REFRESH_E2E_LIMIT}\nmax rotations 1\ncookie name NATIVE_REFRESH"), "cookie prefix PORTAL", 120, cert, key, roots)
		f.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "guests", RefreshTransport: "body"}, nil, 400)
		login, cookies := f.login(t, f.client, "employees", "body", 200)
		if login.RefreshToken == "" || login.RefreshTokenName != "NATIVE_REFRESH" || len(cookies) != 0 {
			t.Fatal("native transport did not issue private JSON credentials exclusively")
		}
		claims := f.claims(t, login.AccessToken, "employees", 45)
		f.metadata(t, login, claims)
		f.login(t, f.client, "contractors", "body", 503)
		f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, f.headers(), 403)
		rotated, _ := f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, nil, 200)
		if rotated.RefreshToken == login.RefreshToken || rotated.SessionID != login.SessionID || rotated.SessionExpiresAt != login.SessionExpiresAt {
			t.Fatal("capacity failure disrupted existing family")
		}
		f.claims(t, rotated.AccessToken, "employees", 45)
		f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": rotated.RefreshToken}, nil, 401)
		// Exhaustion reclaims capacity; logout also reclaims and revokes the family.
		next, _ := f.login(t, f.client, "contractors", "body", 200)
		f.post(t, f.client, "/api/logout", map[string]string{"refresh_token": next.RefreshToken}, nil, 200)
		f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": next.RefreshToken}, nil, 401)
		// Enabling native transport does not opt an ordinary browser into it.
		browser := f.browser(t)
		ordinary, cookies := f.login(t, browser, "employees", "", 200)
		if ordinary.RefreshToken != "" || ordinary.AccessToken != "" {
			t.Fatal("body transport enabled changed implicit browser transport")
		}
		previous := tokenRefreshActiveCookie(t, cookies, "NATIVE_REFRESH")
		// Fresh browser authentication can replace its family at capacity, including
		// when switching between selected realms. The retired credential stays dead.
		replacement, cookies := f.login(t, browser, "contractors", "", 200)
		if replacement.SessionID == ordinary.SessionID || replacement.SessionID == "" {
			t.Fatal("fresh browser login did not replace the family at capacity")
		}
		f.claims(t, tokenRefreshActiveCookie(t, cookies, "PORTAL_ACCESS_TOKEN").Value, "contractors", 45)
		old := f.headers()
		old.Set("Cookie", "NATIVE_REFRESH="+previous.Value)
		f.post(t, f.client, "/api/refresh_token", struct{}{}, old, 401)
		f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
		f.post(t, browser, "/api/logout", struct{}{}, f.headers(), 200)
		f.login(t, f.client, "employees", "body", 200)
	})
	for _, body := range []string{"", tokenRefreshTestBlock("disabled\ncookie name PORTAL_ACCESS_TOKEN\nbody transport enabled\naccess lifetime 45")} {
		t.Run("access only "+body, func(t *testing.T) {
			f := newCaddyTokenRefreshFixture(t, "/auth", body, "cookie prefix PORTAL\ncookie refresh token name SHARED_REFRESH", 120, cert, key, roots)
			login, _ := f.login(t, f.browser(t), "employees", "", 200)
			if login.AccessTokenName != "PORTAL_ACCESS_TOKEN" {
				t.Fatal("disabled override changed cookie names")
			}
			claims := f.claims(t, login.AccessToken, "employees", 120)
			if login.SessionID != "" || claims["sid"] != nil {
				t.Fatal("absent/disabled refresh changed access-only behavior")
			}
			// Disabled override deliberately collides with access. Construction and login
			// prove it was not applied to the cookie factory.
			f.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "employees", RefreshTransport: "body"}, nil, 400)
			f.post(t, f.client, "/api/refresh_token", struct{}{}, nil, 404)
		})
	}
	t.Run("mount and origin alignment", func(t *testing.T) {
		f := newCaddyTokenRefreshFixture(t, "/auth", tokenRefreshTestBlock(required), "", 120, cert, key, roots)
		for _, tc := range []struct{ old, next string }{{"base path /auth", "base path /different"}, {"public origin " + f.base, "public origin https://untrusted.example"}} {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(strings.Replace(f.input, tc.old, tc.next, 1)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := caddy.Load(data, true); err != nil {
				t.Fatal(err)
			}
			f.client.CloseIdleConnections()
			f.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "employees"}, f.headers(), 403)
		}
	})
}
