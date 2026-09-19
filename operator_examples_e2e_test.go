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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestCaddyOperatorExamplesE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOperatorExamplesProcess$", "-test.v", "-test.timeout=220s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_OPERATOR_EXAMPLES_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	assertAdminRedacted(t, output, []string{lifecyclePassword, applicationTestSecret, oauthE2ESecret, "BEGIN PRIVATE KEY"})
	if err != nil {
		t.Fatalf("operator examples: %v\n%s", err, output)
	}
}

func TestCaddyOperatorExamplesProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_OPERATOR_EXAMPLES_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t, "localhost")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	for _, name := range []string{"legacy-access", "local-token-refresh", "upstream-oauth", "named-applications", "oidc-token-refresh", "admin-private-export"} {
		for _, format := range []string{"caddyfile", "native-json"} {
			t.Run(name+"/"+format, func(t *testing.T) {
				testOperatorExample(t, name, format, cert, key, roots, pair)
			})
		}
	}
}

func operatorExampleDirectory(t *testing.T, name, format string) string {
	t.Helper()
	if root := os.Getenv("CADDY_SECURITY_EXAMPLE_EVIDENCE"); root != "" {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			t.Fatal("example evidence root must already exist")
		}
		root, err = filepath.Abs(root)
		if err != nil || !strings.HasPrefix(root, filepath.Join(cwd, "tmp")+string(filepath.Separator)) {
			t.Fatal("example evidence must stay in repository tmp")
		}
		dir := filepath.Join(root, name+"-"+format)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal("example evidence must be new")
		}
		return dir
	}
	return registrationTestDirectory(t)
}

func testOperatorExample(t *testing.T, name, format, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	t.Helper()
	dir := operatorExampleDirectory(t, name, format)
	copyFile := func(source, name string) string {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	access, second := newJWKSKeyFiles(t, "RSA", "access"), newJWKSKeyFiles(t, "RSA", "access")
	op, secondOP := newOIDCRPKey(t, "op"), newOIDCRPKey(t, "second-op")
	upstream := newOAuthE2EUpstream(t, pair, "Ed25519")
	f := &compositionFixture{upstream: upstream}
	f.resource = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("X-Protected-Upstream", "reached")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(f.resource.Close)
	base := "https://" + lifecycleAddress(t)
	upstream.callback = base + "/auth/oauth2/upstream/authorization-code-callback"
	store := &OAuthRegistrationStoreConfig{Path: filepath.Join(dir, "registrations")}
	if err := store.initialize(t.Context()); err != nil {
		t.Fatal(err)
	}
	registrationTestCreate(t, store, "client_id basic", "client_secret "+applicationTestSecret)
	env := map[string]string{
		"EXAMPLE_ORIGIN": base, "EXAMPLE_RESOURCE": f.resource.URL,
		"EXAMPLE_PASSWORD": lifecyclePassword, "EXAMPLE_LOG": filepath.Join(dir, "caddy.log"),
		"EXAMPLE_EMPLOYEES_DB":   filepath.Join(dir, "employees.json"),
		"EXAMPLE_CONTRACTORS_DB": filepath.Join(dir, "contractors.json"),
		"EXAMPLE_GUESTS_DB":      filepath.Join(dir, "guests.json"),
		"EXAMPLE_TLS_CERT":       copyFile(cert, "tls.pem"), "EXAMPLE_TLS_KEY": copyFile(key, "tls.key"),
		"EXAMPLE_ACCESS_KEY":        copyFile(access.private, "access.pem"),
		"EXAMPLE_ACCESS_PUBLIC_KEY": copyFile(access.public, "access-public.pem"),
		"EXAMPLE_SECOND_ACCESS_KEY": copyFile(second.private, "second-access.pem"),
		"EXAMPLE_OP_KEY":            copyFile(op.private, "op.pem"), "EXAMPLE_SECOND_OP_KEY": copyFile(secondOP.private, "second-op.pem"),
		"EXAMPLE_REGISTRATION_STORE": store.Path,
		"EXAMPLE_UPSTREAM_ORIGIN":    upstream.server.URL,
		"EXAMPLE_UPSTREAM_CLIENT_ID": upstream.clientID, "EXAMPLE_UPSTREAM_SECRET": upstream.clientSecret,
		"EXAMPLE_UPSTREAM_IDENTITY_PEM": copyFile(upstream.identity.pem(t, false), "upstream-identity.pem"),
		"EXAMPLE_UPSTREAM_ACCESS_PEM":   copyFile(upstream.access.pem(t, false), "upstream-access.pem"),
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	privateEnv, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "environment.private.json"), privateEnv, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.ReadFile(filepath.Join("assets/config/integration", name+".Caddyfile"))
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertAdminRedacted(t, data, []string{lifecyclePassword, applicationTestSecret, oauthE2ESecret, "BEGIN PRIVATE KEY"})
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, data, "", "  "); err != nil {
		t.Fatal(err)
	}
	for file, value := range map[string][]byte{"Caddyfile": input, "native.json": pretty.Bytes()} {
		if err := os.WriteFile(filepath.Join(dir, file), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A complete native config has to retain the host-owned registration digest
	// and deferred provider/refresh statements. Do not hand-copy library bodies.
	if format == "native-json" {
		data, err = os.ReadFile(filepath.Join(dir, "native.json"))
		if err != nil {
			t.Fatal(err)
		}
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&config); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
		log, err := os.ReadFile(env["EXAMPLE_LOG"])
		if err != nil {
			t.Error(err)
		}
		upstream.mu.Lock()
		defer upstream.mu.Unlock()
		assertAdminRedacted(t, log, append(append(f.secrets, upstream.issuedSecrets...), lifecyclePassword, applicationTestSecret, oauthE2ESecret, "BEGIN PRIVATE KEY"))
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	f.caddyTokenRefreshFixture = &caddyTokenRefreshFixture{base: base, mount: "/auth", client: &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	f.inspectResponse = func(t *testing.T, status int, body []byte, cookies []*http.Cookie) {
		assertAdminRedacted(t, body, []string{lifecyclePassword, applicationTestSecret, oauthE2ESecret, "BEGIN PRIVATE KEY"})
		var result apiauth.AuthResponse
		_ = json.Unmarshal(body, &result)
		for _, value := range []string{result.AccessToken, result.RefreshToken, result.SandboxSecret} {
			if value != "" {
				f.secrets = append(f.secrets, value)
			}
		}
		for _, cookie := range cookies {
			if cookie.Value != "" && (strings.Contains(cookie.Name, "TOKEN") || strings.Contains(cookie.Name, "OIDC_SESSION")) {
				f.secrets = append(f.secrets, cookie.Value)
			}
		}
	}
	_, _, raw := registrationHTTP(t, f.client, "GET", base+"/auth/.well-known/jwks.json", nil, nil)
	var jwks struct{ Keys []map[string]string }
	if json.Unmarshal(raw, &jwks) != nil || len(jwks.Keys) != 1 {
		t.Fatal("example lacks public access JWKS")
	}
	f.keys = jwks.Keys
	refresh := name == "local-token-refresh" || name == "oidc-token-refresh"
	for _, realm := range []string{"employees", "contractors", "guests"} {
		browser := f.browser(t)
		result, cookies := f.login(t, browser, realm, "", 200)
		accessToken := result.AccessToken
		if refresh && realm != "guests" {
			accessToken = tokenRefreshActiveCookie(t, cookies, "AUTHP_ACCESS_TOKEN").Value
			f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
		} else if result.SessionID != "" {
			t.Fatal("unselected/disabled refresh realm received session authority")
		}
		f.resourceStatus(t, accessToken, "/protected", 204)
		if name == "oidc-token-refresh" {
			if realm == "guests" {
				if jarCookie(t, browser.Jar, base+"/auth/portal", "AUTHP_OIDC_SESSION_ID") != "" {
					t.Fatal("unselected realm received an OP session")
				}
			} else {
				operatorExampleOP(t, f, browser, "/auth")
			}
		}
	}
	f.resourceStatus(t, "", "/protected", 401)
	f.resourceStatus(t, "", "/authentic/protected", 401)
	if refresh {
		native, _ := f.login(t, f.client, "employees", "body", 200)
		if native.AccessToken == "" || native.RefreshToken == "" {
			t.Fatal("native transport omitted credentials")
		}
		f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, nil, 200)
	}
	if name == "oidc-token-refresh" {
		second := *f.caddyTokenRefreshFixture
		second.mount = "/other"
		browser := second.browser(t)
		_, cookies := second.login(t, browser, "employees", "", 200)
		tokenRefreshActiveCookie(t, cookies, "SECOND_RENEWAL")
		operatorExampleOP(t, f, browser, "/other")
	}
	if name == "upstream-oauth" {
		operatorExampleOAuth(t, f)
	}
	browser := f.browser(t)
	login, cookies := f.login(t, browser, "employees", "", 200)
	credential := login.AccessToken
	if refresh {
		credential = tokenRefreshActiveCookie(t, cookies, "AUTHP_ACCESS_TOKEN").Value
	}
	status, headers, body := registrationHTTP(t, f.client, "GET", base+"/auth/api/server/private_keys", nil, http.Header{"Authorization": {"Bearer " + credential}})
	want := 404
	if name == "admin-private-export" {
		want = 200
	}
	if status != want || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("private export: status %d want %d", status, want)
	}
	if want == 404 {
		assertAdminRedacted(t, body, []string{"PRIVATE KEY"})
	}
}

func operatorExampleOP(t *testing.T, f *compositionFixture, browser *http.Client, mount string) {
	t.Helper()
	rp := &oidcRPFixture{client: browser, base: f.base, mount: mount, issuer: f.base + mount}
	rp.discover(t)
	for _, client := range []string{"basic", "public"} {
		params := rp.authorization(client)
		response := rp.approve(t, rp.authorize(t, params), "allow")
		code := rp.callback(t, response, params, "")
		tokens, claims := rp.tokens(t, rp.exchange(t, client, code, oidcRPCallback, oidcRPVerifier), params)
		f.secrets = append(f.secrets, tokens.ID, tokens.Access)
		rp.userinfo(t, tokens, claims, "alice@example.test")
		f.resourceStatus(t, tokens.ID, "/protected", 401)
		f.resourceStatus(t, tokens.Access, "/protected", 401)
	}
}

func operatorExampleOAuth(t *testing.T, f *compositionFixture) {
	t.Helper()
	for _, failure := range []string{"", "identity issuer", "access audience"} {
		f.upstream.mu.Lock()
		f.upstream.failure = failure
		f.upstream.mu.Unlock()
		browser := f.browser(t)
		location := f.base + "/auth/oauth2/upstream"
		var status int
		for range 3 {
			var headers http.Header
			status, headers, _ = registrationHTTP(t, browser, "GET", location, nil, nil)
			location = headers.Get("Location")
		}
		access := jarCookie(t, browser.Jar, f.base+"/auth/portal", "AUTHP_ACCESS_TOKEN")
		if failure == "identity issuer" {
			if status != 401 || access != "" {
				t.Fatal("upstream issuer rejection failed")
			}
			continue
		}
		if status != 303 || access == "" {
			t.Fatal("upstream example did not authenticate")
		}
		f.secrets = append(f.secrets, access)
		claims := verifyCaddyJWKSSignature(t, f.keys, access, "RS512", "access")
		if strings.Contains(fmt.Sprint(claims["roles"]), "resource/editor") != (failure == "") {
			t.Fatal("supplemental access-token audience did not constrain roles")
		}
		f.resourceStatus(t, access, "/protected", 204)
	}
}
