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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
)

func TestCaddyOIDCProviderE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOIDCProviderProcess$", "-test.v", "-test.timeout=100s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_OIDC_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if bytes.Contains(output, []byte(applicationTestSecret)) || bytes.Contains(output, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("OIDC provisioning logs exposed client credentials or signing keys")
	}
	if err != nil {
		t.Fatalf("Caddy OIDC provider: %v\n%s", err, output)
	}
}

func TestCaddyOIDCProviderProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_OIDC_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	cert, tlsKey, roots := cookieTLSCertificate(t)
	address := lifecycleAddress(t)
	base := "https://" + address
	keyDir := registrationTestDirectory(t)
	keyPaths := []string{filepath.Join(keyDir, "first key.pem"), filepath.Join(keyDir, "second key.pem")}
	// Test setup explicitly supplies existing keys; adaptation must never make
	// them. Use independent keys to verify that the two issuers stay independent.
	for _, path := range keyPaths {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	badKey := filepath.Join(keyDir, "invalid.pem")
	if err := os.WriteFile(badKey, []byte("invalid PEM material"), 0600); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	adapt := func(input string) []byte {
		t.Helper()
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	active := func(t *testing.T) *App {
		app, err := caddy.ActiveContext().App("security")
		if err != nil {
			t.Fatal(err)
		}
		return app.(*App)
	}
	portal := func(name, mount, prefix, key, application string) string {
		return fmt.Sprintf(`authentication portal %s {
 oidc provider {
  issuer %s%s
  realms employees contractors
  signing key files %q
  applications %s
 }
 enable identity store employeesdb contractorsdb guestsdb
 crypto key sign-verify synthetic-oidc-portal-signing-key
 cookie prefix %s
 cookie path %s
}
`, name, base, mount, key, application, prefix, mount)
	}
	application := func(name string) string {
		return fmt.Sprintf(`oauth application %s {
 client_id %s-client
 client_secret %s
 redirect_uri https://rp.example.test/callback
 skip_consent on
}
`, name, name, applicationTestSecret)
	}
	var stores string
	for _, realm := range []string{"employees", "contractors", "guests"} {
		stores += fmt.Sprintf(`local identity store %sdb {
 realm %s
 path :memory:
 user alice {
  email alice@%s.example.test
  password %s
  roles authp/user
 }
}
`, realm, realm, realm, lifecyclePassword)
	}
	source := func(two bool) string {
		declarations := portal("myportal", "/auth", "FIRST", keyPaths[0], "website")
		routes := "route /auth/* {\nauthenticate with myportal\n}\n"
		if two {
			declarations += portal("second", "/other", "SECOND", keyPaths[1], "otherapp")
			routes += "route /other/* {\nauthenticate with second\n}\n"
		}
		return fmt.Sprintf("{\nadmin off\npersist_config off\nauto_https off\nsecurity {\n%s%s%s%s}\n}\nhttps://%s {\ntls %q %q\n%s}\n", declarations, stores, application("website"), application("otherapp"), address, cert, tlsKey, routes)
	}
	discover := func(t *testing.T, mount string) {
		t.Helper()
		status, _, body := registrationHTTP(t, client, "GET", base+mount+"/.well-known/openid-configuration", nil, nil)
		var document map[string]any
		if status != 200 || json.Unmarshal(body, &document) != nil {
			t.Fatalf("discovery status = %d", status)
		}
		for key, want := range map[string]string{"issuer": base + mount, "authorization_endpoint": base + mount + "/oidc/authorize", "token_endpoint": base + mount + "/oidc/token", "jwks_uri": base + mount + "/oidc/jwks"} {
			if document[key] != want {
				t.Fatalf("discovery %s = %v, want %s", key, document[key], want)
			}
		}
	}
	login := func(t *testing.T, mount, realm string) []*http.Cookie {
		t.Helper()
		f := &caddyCookieFixture{client: client, base: base}
		f.request(t, "GET", mount+"/login?fresh=1", nil, nil, 200)
		start := f.request(t, "POST", mount+"/login", url.Values{"username": {"alice"}, "realm": {realm}}, nil, 303)
		sandbox := start.Header.Get("Location")
		if !strings.Contains(sandbox, "/sandbox/") {
			t.Fatal("missing login sandbox")
		}
		proof := f.request(t, "POST", sandbox, url.Values{"secret": {lifecyclePassword}}, nil, 303)
		finish := f.request(t, "GET", sandbox, nil, nil, 303)
		return append(proof.Cookies(), finish.Cookies()...)
	}
	newJar := func(t *testing.T) {
		var err error
		client.Jar, err = cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	checkExchange := func(t *testing.T, mount, nickname string) registrationRPResult {
		t.Helper()
		registration, err := active(t).Config.GetOAuthApplication(nickname)
		if err != nil {
			t.Fatal(err)
		}
		return registrationRPExchange(t, client, base+mount, registration.Client, "incorrect-client-secret")
	}
	loginRequired := func(t *testing.T, browser *http.Client, headers http.Header) {
		t.Helper()
		query := url.Values{"client_id": {"website-client"}, "redirect_uri": {"https://rp.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}, "code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("A", 43)}}
		status, responseHeaders, _ := registrationHTTP(t, browser, "GET", base+"/auth/oidc/authorize?"+query.Encode(), nil, headers)
		redirect, err := url.Parse(responseHeaders.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusFound || redirect.Scheme != "https" || redirect.Host != "rp.example.test" || redirect.Path != "/callback" || redirect.Query().Get("error") != "login_required" || redirect.Query().Get("code") != "" {
			t.Fatalf("unauthenticated authorization: status=%d error=%q", status, redirect.Query().Get("error"))
		}
	}
	data := adapt(source(false))
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	discover(t, "/auth")
	subjects := make(map[string]string)
	for _, scenario := range []string{"fresh browser", "same browser"} {
		newJar(t)
		var previousSession string
		var previousGrant string
		for _, realm := range []string{"employees", "contractors", "guests"} {
			t.Run("realm/"+scenario+"/"+realm, func(t *testing.T) {
				if scenario == "fresh browser" {
					newJar(t)
				}
				cookies := login(t, "/auth", realm)
				value := jarCookie(t, client.Jar, base+"/auth", "FIRST_OIDC_SESSION_ID")
				if scenario == "same browser" && previousSession != "" {
					// Cookie deletion alone cannot prove server-side revocation.
					// Replay the old session without the browser's current cookies.
					replay := *client
					replay.Jar = nil
					loginRequired(t, &replay, http.Header{"Cookie": {"FIRST_OIDC_SESSION_ID=" + previousSession}})
					if value == previousSession {
						t.Fatal("realm switch retained the previous OIDC session")
					}
					status, headers, body := registrationHTTP(t, client, "GET", base+"/auth/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + previousGrant}})
					oidcRPResponse{status: status, header: headers, body: body}.failure(t, 401, "invalid_token")
				}
				previousSession = value
				if realm == "guests" {
					if value != "" {
						t.Fatal("unselected attached realm received an OIDC session")
					}
					loginRequired(t, client, nil)
					return
				}
				if value == "" {
					t.Fatal("selected realm did not receive an OIDC session")
				}
				cookie := issuedCookie(t, cookies, "FIRST_OIDC_SESSION_ID")
				if cookie.Path != "/auth" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
					t.Fatal("OIDC session cookie has unsafe scope/attributes")
				}
				identity := checkExchange(t, "/auth", "website")
				previousGrant = identity.accessToken
				if identity.email != "alice@"+realm+".example.test" {
					t.Fatal("OIDC userinfo returned an identity from the wrong realm")
				}
				for otherRealm, subject := range subjects {
					if (otherRealm == realm) != (subject == identity.subject) {
						t.Fatal("OIDC subjects must be stable per identity and distinct across realms")
					}
				}
				subjects[realm] = identity.subject
			})
		}
	}
	// Keep an already authenticated browser throughout rejected replacements.
	newJar(t)
	login(t, "/auth", "employees")
	previous := active(t)
	mutate := func(t *testing.T, data []byte, change func(*App)) []byte {
		t.Helper()
		var document map[string]json.RawMessage
		var apps map[string]json.RawMessage
		var app App
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(document["apps"], &apps); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(apps["security"], &app); err != nil {
			t.Fatal(err)
		}
		change(&app)
		apps["security"] = caddyconfig.JSON(&app, nil)
		document["apps"] = caddyconfig.JSON(apps, nil)
		return caddyconfig.JSON(document, nil)
	}
	// Browsers remove leading zeroes from ports before sending the request.
	// Accepting this candidate used to replace a working provider with one
	// whose exact-origin check rejects its own discovery and login requests.
	parsedOrigin, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	invalidOrigin := mutate(t, data, func(app *App) {
		app.OIDCProviderDirectives["myportal"][0] = "issuer https://" + parsedOrigin.Hostname() + ":0" + parsedOrigin.Port() + "/auth"
	})
	if err := caddy.Load(invalidOrigin, true); err == nil {
		status, _, _ := registrationHTTP(t, client, "GET", base+"/auth/.well-known/openid-configuration", nil, nil)
		t.Fatalf("noncanonical origin replaced the active provider; discovery now returns %d", status)
	} else if !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("noncanonical origin rejected for the wrong reason: %v", err)
	}
	if active(t) != previous {
		t.Fatal("rejected noncanonical origin replaced active deployment")
	}
	checkExchange(t, "/auth", "website")
	for _, tc := range []struct {
		name, want string
		change     func(*App)
	}{
		{"noncanonical Unicode issuer", "canonical ASCII hostname", func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://bücher.example.test/auth"
		}},
		{"malformed DNS issuer", "invalid issuer hostname", func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://auth..example.test/auth"
		}},
		{"noncanonical IPv6 issuer", "canonical ASCII hostname", func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://[0:0:0:0:0:0:0:1]/auth"
		}},
		{"ambiguous IPv4 issuer", "noncanonical IPv4 hostname", func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://127.1/auth"
		}},
		{"invalid issuer port", "oidc issuer port", func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://127.0.0.1:65536/auth"
		}},
		{"missing realm", "exactly one local store", func(app *App) { app.OIDCProviderDirectives["myportal"][1] = "realms missing" }},
		{"unattached realm", "exactly one local store", func(app *App) {
			app.Config.AuthenticationPortals[0].IdentityStores = []string{"employeesdb", "guestsdb"}
		}},
		{"ambiguous local realm", "same", func(app *App) { app.Config.IdentityStores[1].Params["realm"] = "employees" }},
		{"missing key", "OIDC provider key", func(app *App) {
			app.OIDCProviderDirectives["myportal"][2] = encodeOAuthDirective([]string{"signing", "key", "files", filepath.Join(keyDir, "missing.pem")})
		}},
		{"invalid key material", "oidc signing key", func(app *App) {
			app.OIDCProviderDirectives["myportal"][2] = encodeOAuthDirective([]string{"signing", "key", "files", badKey})
		}},
		{"unknown application", "unregistered oidc application", func(app *App) { app.OIDCProviderDirectives["myportal"][3] = "applications missing" }},
		{"nil application", "application at position 1 is nil", func(app *App) { app.Config.OAuthApplications[0] = nil }},
		{"nil client", "client is nil", func(app *App) { app.Config.OAuthApplications[0].Client = nil }},
		{"duplicate client IDs", "duplicate oidc client_id", func(app *App) {
			app.Config.OAuthApplications[1].Client.ClientID = app.Config.OAuthApplications[0].Client.ClientID
			app.OIDCProviderDirectives["myportal"][3] = "applications website otherapp"
		}},
		{"refresh origin mismatch", "origin/mount must agree", func(app *App) {
			app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"employees"}, PublicOrigin: "https://other.example.test", BasePath: "/auth"}
		}},
		{"refresh mount mismatch", "origin/mount must agree", func(app *App) {
			app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"employees"}, PublicOrigin: base, BasePath: "/different"}
		}},
		{"LDAP realm", "must use a local identity store", func(app *App) {
			app.Config.IdentityStores = append(app.Config.IdentityStores, &ids.IdentityStoreConfig{Name: "ldapdb", Kind: "ldap", Params: map[string]any{
				"realm": "directory", "servers": []any{map[string]any{"address": "ldap://127.0.0.1:1"}},
				"bind_username": "cn=test", "bind_password": "synthetic", "search_base_dn": "dc=example,dc=test", "search_user_filter": "(uid=%s)",
				"groups": []any{map[string]any{"dn": "cn=users", "roles": []string{"authp/user"}}},
			}})
			app.Config.AuthenticationPortals[0].IdentityStores = append(app.Config.AuthenticationPortals[0].IdentityStores, "ldapdb")
			app.OIDCProviderDirectives["myportal"][1] = "realms directory"
		}},
	} {
		t.Run("rejected replacement/"+tc.name, func(t *testing.T) {
			candidate := mutate(t, data, tc.change)
			if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("replacement error = %v, want %q", err, tc.want)
			}
			if active(t) != previous {
				t.Fatal("failed candidate replaced active deployment")
			}
			discover(t, "/auth")
			checkExchange(t, "/auth", "website")
		})
	}
	// Upstream login providers cannot share a selected local realm. Validation
	// must reject this before attempting any upstream discovery/network access.
	conflict := strings.Replace(source(false), "security {", `security {
oauth identity provider upstream {
 realm employees
 driver github
 client_id synthetic-upstream-client
 client_secret synthetic-upstream-secret
}
`, 1)
	conflict = strings.Replace(conflict, "enable identity store employeesdb", "enable identity provider upstream\nenable identity store employeesdb", 1)
	if err := caddy.Load(adapt(conflict), true); err == nil || !strings.Contains(err.Error(), "same") {
		t.Fatalf("conflicting upstream realm: %v", err)
	}
	checkExchange(t, "/auth", "website")
	validProvider := fmt.Sprintf("oidc provider {\n  issuer %s/auth\n  realms employees contractors\n  signing key files %q\n  applications website\n }", base, keyPaths[0])
	if strings.Count(source(false), validProvider) != 1 {
		t.Fatal("provider replacement fixture no longer matches its source")
	}
	for _, tc := range []struct{ name, body, want string }{
		{"duplicate blocks", oidcTestBlock("disabled") + oidcTestBlock("disabled"), "already configured"},
		{"disabled unknown application", oidcTestBlock("disabled\napplications missing"), "unregistered oidc application"},
		{"disabled invalid integer", oidcTestBlock("disabled\nmax grants several"), "invalid oidc provider integer"},
		{"unterminated portal", "oidc provider {\ndisabled\nissuer \"}\"\n", "unterminated authentication portal block"},
	} {
		t.Run("rejected adaptation/"+tc.name, func(t *testing.T) {
			// Replace the existing provider, so a second block cannot mask the
			// particular invalid value or boundary that this case exercises.
			invalid := strings.Replace(source(false), validProvider, tc.body, 1)
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("adaptation error = %v, want %q", err, tc.want)
			}
			if active(t) != previous {
				t.Fatal("failed adaptation changed active deployment")
			}
			checkExchange(t, "/auth", "website")
		})
	}
	if _, err := os.Stat(filepath.Join(keyDir, "missing.pem")); !os.IsNotExist(err) {
		t.Fatal("missing provider key was generated during failed construction")
	}
	// Two independent providers share a listener but use disjoint issuer mounts,
	// client sets, signing keys, and cookie names. One browser can use both.
	two := adapt(source(true))
	if err := caddy.Load(two, true); err != nil {
		t.Fatal(err)
	}
	newJar(t)
	discover(t, "/auth")
	discover(t, "/other")
	login(t, "/auth", "employees")
	firstCookie := jarCookie(t, client.Jar, base+"/auth", "FIRST_OIDC_SESSION_ID")
	if jarCookie(t, client.Jar, base+"/other", "FIRST_OIDC_SESSION_ID") != "" {
		t.Fatal("first provider cookie escaped its issuer mount")
	}
	login(t, "/other", "contractors")
	if jarCookie(t, client.Jar, base+"/auth", "SECOND_OIDC_SESSION_ID") != "" || jarCookie(t, client.Jar, base+"/auth", "FIRST_OIDC_SESSION_ID") != firstCookie {
		t.Fatal("second provider login changed first provider session")
	}
	first, second := checkExchange(t, "/auth", "website"), checkExchange(t, "/other", "otherapp")
	if first.keyID == second.keyID {
		t.Fatal("independent issuers shared signing keys")
	}
	for _, tc := range []struct {
		mount, clientID, cookie, foreignSession string
		foreign                                 registrationRPResult
	}{
		{"/other", "otherapp-client", "SECOND_OIDC_SESSION_ID", firstCookie, first},
		{"/auth", "website-client", "FIRST_OIDC_SESSION_ID", jarCookie(t, client.Jar, base+"/other", "SECOND_OIDC_SESSION_ID"), second},
	} {
		status, _, _ := registrationHTTP(t, client, "GET", base+tc.mount+"/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tc.foreign.accessToken}})
		if status != 401 {
			t.Fatal("one issuer accepted the other issuer's grant")
		}
		status, _, data := registrationHTTP(t, client, "GET", base+tc.mount+"/oidc/jwks", nil, nil)
		var keys oidcRPKeys
		if status != 200 || json.Unmarshal(data, &keys) != nil {
			t.Fatal("issuer JWKS unavailable")
		}
		for _, key := range keys.Keys {
			if key["kid"] == tc.foreign.keyID {
				t.Fatal("issuer published another portal's key")
			}
		}
		query := url.Values{"client_id": {tc.clientID}, "redirect_uri": {"https://rp.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}, "code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("A", 43)}}
		replay := *client
		replay.Jar = nil
		status, headers, _ := registrationHTTP(t, &replay, "GET", base+tc.mount+"/oidc/authorize?"+query.Encode(), nil, http.Header{"Cookie": {tc.cookie + "=" + tc.foreignSession}})
		location, err := url.Parse(headers.Get("Location"))
		if err != nil || status != 302 || location.Query().Get("error") != "login_required" || location.Query().Get("code") != "" {
			t.Fatal("foreign session was accepted under the target issuer's cookie name")
		}
	}
	// A code from the first provider is unknown to the second even when the
	// caller authenticates with the second provider's own selected credentials.
	rp := &oidcRPFixture{client: client, base: base, mount: "/auth", issuer: base + "/auth"}
	rp.discover(t)
	params := rp.authorization("website-client")
	params.Set("redirect_uri", "https://rp.example.test/callback")
	code := rp.callback(t, rp.authorize(t, params), params, "")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {params.Get("redirect_uri")}, "code_verifier": {oidcRPVerifier}}
	rp.request(t, "POST", base+"/other/oidc/token", form, oidcRPAuth("otherapp-client", form)).failure(t, 400, "invalid_grant")
	rp.tokens(t, rp.exchange(t, "website-client", code, params.Get("redirect_uri"), oidcRPVerifier), params)
	// Logging out one portal must not revoke the other's existing access grant.
	status, _, _ := registrationHTTP(t, client, "GET", base+"/other/logout", nil, nil)
	if status != 302 {
		t.Fatalf("second portal logout status %d", status)
	}
	status, _, _ = registrationHTTP(t, client, "GET", base+"/other/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + second.accessToken}})
	if status != 401 {
		t.Fatal("second portal logout did not revoke its own grant")
	}
	status, _, _ = registrationHTTP(t, client, "GET", base+"/auth/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + first.accessToken}})
	if status != 200 {
		t.Fatal("second portal logout revoked first portal grant")
	}
	checkExchange(t, "/auth", "website")
	login(t, "/other", "contractors")
	for _, tc := range []struct{ mount, clientID string }{{"/auth", "otherapp-client"}, {"/other", "website-client"}} {
		query := url.Values{"client_id": {tc.clientID}, "redirect_uri": {"https://rp.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("A", 43)}}
		status, headers, _ := registrationHTTP(t, client, "GET", base+tc.mount+"/oidc/authorize?"+query.Encode(), nil, nil)
		if status != http.StatusBadRequest || headers.Get("Location") != "" {
			t.Fatal("provider accepted the other portal's selected client")
		}
	}
	for _, mount := range []string{"/auth", "/auth/nested", ""} {
		candidate := mutate(t, two, func(app *App) { app.OIDCProviderDirectives["second"][0] = "issuer " + base + mount })
		if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), "non-overlapping issuer mounts") {
			t.Fatalf("overlapping issuer accepted: %v", err)
		}
		checkExchange(t, "/auth", "website")
		checkExchange(t, "/other", "otherapp")
	}
	for _, native := range []bool{false, true} {
		candidate := mutate(t, two, func(app *App) {
			app.OIDCProviderDirectives["myportal"][0] = "issuer https://auth.example.test/auth"
			app.OIDCProviderDirectives["second"][0] = "issuer https://auth.example.test./auth"
			if native {
				for _, portal := range app.Config.AuthenticationPortals {
					if err := app.Config.ConfigureOIDCProvider(portal, app.OIDCProviderDirectives[portal.Name]); err != nil {
						t.Fatal(err)
					}
				}
				app.OIDCProviderDirectives = nil
			}
		})
		previous := active(t)
		if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), "non-overlapping issuer mounts") {
			t.Fatalf("cookie host alias accepted: %v", err)
		}
		if active(t) != previous {
			t.Fatal("rejected host alias replaced active configuration")
		}
		checkExchange(t, "/auth", "website")
		checkExchange(t, "/other", "otherapp")
	}
	// Explicit refresh configuration uses native JSON until its own Caddyfile
	// surface is implemented. Matching canonical origins and mounts must work.
	matching := mutate(t, two, func(app *App) {
		app.Config.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"employees", "contractors"}, PublicOrigin: base, BasePath: "/auth"}
	})
	if err := caddy.Load(matching, true); err != nil {
		t.Fatal(err)
	}
	newJar(t)
	login(t, "/auth", "employees")
	t.Run("refresh browser logout", func(t *testing.T) {
		grant := checkExchange(t, "/auth", "website")
		oldSession := jarCookie(t, client.Jar, base+"/auth", "FIRST_OIDC_SESSION_ID")
		status, _, body := registrationHTTP(t, client, "GET", base+"/auth/logout", nil, nil)
		if status != 200 || !bytes.Contains(body, []byte("Sign out")) || oldSession == "" {
			t.Fatal("refresh browser logout did not require confirmation")
		}
		headers := http.Header{"Authorization": {"Bearer " + grant.accessToken}}
		status, _, _ = registrationHTTP(t, client, "GET", base+"/auth/oidc/userinfo", nil, headers)
		if status != 200 {
			t.Fatal("viewing logout confirmation revoked the OP grant")
		}
		req, err := http.NewRequestWithContext(t.Context(), "POST", base+"/auth/api/logout", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = http.Header{"Content-Type": {"application/json"}, "Origin": {base}, "X-Authcrunch-Refresh": {"1"}}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result map[string]bool
		if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&result) != nil || !result["logged_out"] {
			t.Fatal("refresh browser logout failed")
		}
		status, _, _ = registrationHTTP(t, client, "GET", base+"/auth/oidc/userinfo", nil, headers)
		if status != 401 {
			t.Fatal("completed refresh browser logout retained the OP grant")
		}
		loginRequired(t, client, nil)
		replay := *client
		replay.Jar = nil
		loginRequired(t, &replay, http.Header{"Cookie": {"FIRST_OIDC_SESSION_ID=" + oldSession}})
	})
	discover(t, "/other")
	// Restore native JSON snapshots through real Caddy construction as well.
	native := mutate(t, two, func(app *App) {
		for _, portal := range app.Config.AuthenticationPortals {
			if err := app.Config.ConfigureOIDCProvider(portal, app.OIDCProviderDirectives[portal.Name]); err != nil {
				t.Fatal(err)
			}
		}
		app.OIDCProviderDirectives = nil
	})
	if err := caddy.Load(native, true); err != nil {
		t.Fatal(err)
	}
	newJar(t)
	login(t, "/auth", "employees")
	checkExchange(t, "/auth", "website")
	discover(t, "/other")
	for _, present := range []bool{true, false} {
		candidate := mutate(t, data, func(app *App) {
			app.OIDCProviderDirectives = nil
			if present {
				app.OIDCProviderDirectives = map[string][]string{"myportal": {"disabled"}}
			}
		})
		if err := caddy.Load(candidate, true); err != nil {
			t.Fatal(err)
		}
		newJar(t)
		login(t, "/auth", "employees")
		for _, path := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/authorize"} {
			status, _, _ := registrationHTTP(t, client, "GET", base+"/auth"+path, nil, nil)
			if status != 404 {
				t.Fatalf("disabled/absent provider served %s: %d", path, status)
			}
		}
	}
}
