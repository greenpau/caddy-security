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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const oidcRPVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
const oidcRPCallback = "https://rp.example.test/callback?registered=yes"
const oidcRPMFASecret = "0123456789abcdef0123456789abcdef"

type oidcRPResponse struct {
	status int
	header http.Header
	body   []byte
}

func (r oidcRPResponse) requireStatus(t *testing.T, want int) {
	t.Helper()
	if r.status != want {
		// Never dump tokens, checkpoint secrets or cookies on assertion failures.
		t.Fatalf("HTTP status %d, want %d", r.status, want)
	}
}

func (r oidcRPResponse) noStore(t *testing.T) {
	t.Helper()
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		t.Fatal("OIDC response lost no-store/no-cache")
	}
}

func (r oidcRPResponse) failure(t *testing.T, status int, code string) {
	t.Helper()
	r.requireStatus(t, status)
	r.noStore(t)
	var body map[string]any
	if json.Unmarshal(r.body, &body) != nil || body["error"] != code || body["access_token"] != nil {
		t.Fatalf("expected protocol error %q", code)
	}
}

type oidcRPFixture struct {
	client              *http.Client
	base, mount, issuer string
	discovery           map[string]any
	requestKey          *rsa.PrivateKey
}

func TestCaddyOIDCRelyingPartyE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOIDCRelyingPartyProcess$", "-test.v", "-test.timeout=165s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_OIDC_RP_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if bytes.Contains(output, []byte(applicationTestSecret)) || bytes.Contains(output, []byte(oidcRPMFASecret)) || bytes.Contains(output, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("RP test logs exposed credentials or private keys")
	}
	if err != nil {
		t.Fatalf("Caddy TLS relying party: %v\n%s", err, output)
	}
}

func newOIDCRPKey(t *testing.T, name string) jwksKeyFiles {
	t.Helper()
	key := newJWKSKeyFiles(t, "RSA", name)
	if err := os.Chmod(filepath.Dir(key.private), 0700); err != nil {
		t.Fatal(err)
	}
	// macOS temporary roots include /var -> /private/var. Supply the physical
	// test-owned path to the production storage validator, which forbids links.
	var err error
	key.private, err = filepath.EvalSymlinks(key.private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newOIDCRPFixture(t *testing.T, mount, cert, tlsKey string, roots *x509.CertPool) *oidcRPFixture {
	t.Helper()
	address := lifecycleAddress(t)
	f := &oidcRPFixture{base: "https://" + address, mount: mount}
	f.issuer = f.base + mount
	opKey := newOIDCRPKey(t, "op")
	accessKey := newJWKSKeyFiles(t, "RSA", "access")
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"alice", "mfauser"} {
		if err := db.AddUser(&requests.Request{User: requests.User{Username: username, Email: username + "@example.test", Password: lifecyclePassword, Roles: []string{"authp/user"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "mfauser", Email: "mfauser@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "Caddy RP E2E", Secret: oidcRPMFASecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}}); err != nil {
		t.Fatal(err)
	}
	for _, user := range db.Users {
		if user.Username == "alice" {
			user.Profile = &identity.Profile{GivenName: "Alice", PhoneNumber: "+1 202-555-0100", PhoneNumberVerified: new(false), Address: &identity.Address{Country: "US"}}
		}
	}
	identityData, err := json.Marshal(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, identityData, 0600); err != nil {
		t.Fatal(err)
	}
	f.requestKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var applications strings.Builder
	for _, client := range []string{"basic", "trusted", "post", "public", "native4", "native6"} {
		auth, secret, redirect, consent := "client_secret_basic", "client_secret "+applicationTestSecret, oidcRPCallback, "on"
		switch client {
		case "basic":
			consent = "off"
		case "post":
			auth = "client_secret_post"
		case "public", "native4", "native6":
			auth, secret = "none", ""
		}
		if client == "native4" {
			redirect = "http://127.0.0.1:1/callback?registered=yes"
		}
		if client == "native6" {
			redirect = "http://[::1]:1/callback?registered=yes"
		}
		fmt.Fprintf(&applications, "oauth application %s {\nclient_id %s\n%s\ntoken_endpoint_auth_method %s\nredirect_uri %s\nskip_consent %s\n}\n", client, client, secret, auth, redirect, consent)
	}
	fmt.Fprintf(&applications, "oauth application capabilities {\nclient_id capabilities\nclient_secret %s\nredirect_uri %s\nscopes openid profile email address phone offline_access\nrequest_object_signing_alg RS256\nrequest_object_key rp-key %s AQAB\n}\n", applicationTestSecret, oidcRPCallback, base64.RawURLEncoding.EncodeToString(f.requestKey.N.Bytes()))
	matcher := "/*"
	if mount != "" {
		matcher = mount + " " + mount + "/*"
	}
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 security {
  %s
  local identity store localdb {
   realm local
   path %q
  }
  authentication portal myportal {
   enable identity store localdb
   %s
   cookie prefix RP
   oidc provider {
    issuer %s
    realms local
    signing key files %q
    applications basic trusted post public native4 native6 capabilities
    acr urn:example:password pwd
    refresh lifetime 3600
    max refresh tokens 32
   }
  }
  authorization policy app_policy {
   %s
   set auth url %s/login
   validate bearer header
   allow roles authp/user
  }
 }
}
https://%s {
 tls %q %q
 @portal path %s
 route {
  route @portal {
   authenticate with myportal
  }
  route {
   authorize with app_policy
   respond "protected application"
  }
 }
}
`, applications.String(), dbPath, accessKey.signer("access"), f.issuer, opKey.private, accessKey.verifier("access"), f.issuer, address, cert, tlsKey, matcher)
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(config, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	f.client = &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f.newBrowser(t)
	f.discover(t)
	return f
}

func (f *oidcRPFixture) newBrowser(t *testing.T) {
	t.Helper()
	var err error
	f.client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *oidcRPFixture) request(t *testing.T, method, target string, form url.Values, headers http.Header) oidcRPResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.issuer + target
	}
	status, header, body := registrationHTTP(t, f.client, method, target, form, headers)
	return oidcRPResponse{status, header, body}
}

func (f *oidcRPFixture) endpoint(t *testing.T, name string) string {
	t.Helper()
	endpoint, ok := f.discovery[name].(string)
	if !ok || endpoint == "" {
		t.Fatalf("discovery endpoint %s missing", name)
	}
	return endpoint
}

func (f *oidcRPFixture) discover(t *testing.T) {
	t.Helper()
	r := f.request(t, "GET", "/.well-known/openid-configuration", nil, http.Header{"Accept": {"text/html"}, "Authorization": {"Bearer invalid-portal-token"}})
	r.requireStatus(t, 200)
	r.noStore(t)
	if r.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("consent header policy affected discovery")
	}
	if json.Unmarshal(r.body, &f.discovery) != nil {
		t.Fatal("invalid discovery")
	}
	for name, suffix := range map[string]string{"issuer": "", "authorization_endpoint": "/oidc/authorize", "token_endpoint": "/oidc/token", "userinfo_endpoint": "/oidc/userinfo", "jwks_uri": "/oidc/jwks", "revocation_endpoint": "/oidc/revoke"} {
		if f.discovery[name] != f.issuer+suffix {
			t.Fatalf("discovery lost canonical %s", name)
		}
	}
	for name, want := range map[string][]string{
		"response_types_supported": {"code"}, "response_modes_supported": {"query", "form_post"}, "grant_types_supported": {"authorization_code", "refresh_token"}, "id_token_signing_alg_values_supported": {"RS256"}, "token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"}, "code_challenge_methods_supported": {"S256"}, "request_object_signing_alg_values_supported": {"none", "RS256"},
	} {
		got, ok := f.discovery[name].([]any)
		var values []string
		for _, v := range got {
			s, _ := v.(string)
			values = append(values, s)
		}
		if !ok || !slices.Equal(values, want) {
			t.Fatalf("unexpected discovery capability %s", name)
		}
	}
	for _, name := range []string{"registration_endpoint", "end_session_endpoint", "request_object_encryption_alg_values_supported", "request_object_encryption_enc_values_supported", "token_endpoint_auth_signing_alg_values_supported"} {
		if _, ok := f.discovery[name]; ok {
			t.Fatalf("unsupported discovery capability %s", name)
		}
	}
	if f.discovery["request_parameter_supported"] != true || f.discovery["request_uri_parameter_supported"] != false {
		t.Fatal("incorrect request object advertisement")
	}
}

func (f *oidcRPFixture) authorization(client string) url.Values {
	digest := sha256.Sum256([]byte(oidcRPVerifier))
	return url.Values{"client_id": {client}, "redirect_uri": {oidcRPCallback}, "response_type": {"code"}, "scope": {"openid profile email"}, "state": {rand.Text() + " & symbols=+"}, "nonce": {rand.Text() + " + exact"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
}

func (f *oidcRPFixture) authorize(t *testing.T, params url.Values) oidcRPResponse {
	t.Helper()
	return f.request(t, "GET", f.endpoint(t, "authorization_endpoint")+"?"+params.Encode(), nil, nil)
}

func (f *oidcRPFixture) loginStart(t *testing.T) string {
	t.Helper()
	r := f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
	r.requireStatus(t, 303)
	sandbox := r.header.Get("Location")
	location, err := url.Parse(sandbox)
	if err != nil || !strings.HasPrefix(location.Path, f.mount+"/sandbox/") || location.Host != strings.TrimPrefix(f.base, "https://") {
		t.Fatal("login did not reach the mounted sandbox")
	}
	f.request(t, "POST", sandbox, url.Values{"secret": {lifecyclePassword}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
	return sandbox
}

func (f *oidcRPFixture) login(t *testing.T) {
	t.Helper()
	f.request(t, "GET", f.loginStart(t), nil, nil).requireStatus(t, 303)
}

// Parse forms as a relying party/browser would, preserving HTML entity decoding.
func oidcRPForm(t *testing.T, body []byte) oidcRPBrowserForm {
	t.Helper()
	form, err := parseOIDCRPForm(body)
	if err != nil {
		t.Fatal(err)
	}
	return form
}

func (f *oidcRPFixture) approve(t *testing.T, r oidcRPResponse, decision string) oidcRPResponse {
	t.Helper()
	r.requireStatus(t, 200)
	r.noStore(t)
	if r.header.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("consent policy would suppress browser Origin")
	}
	form := oidcRPForm(t, r.body)
	if form.action != f.issuer+"/oidc/continue" || len(form.values["csrf"]) != 1 || form.values.Get("csrf") == "" || !slices.Contains(form.decisions, decision) {
		t.Fatal("invalid consent action, CSRF token or decision control")
	}
	form.values.Set("decision", decision)
	return f.request(t, "POST", form.action, form.values, http.Header{"Origin": {f.base}})
}

func (f *oidcRPFixture) callback(t *testing.T, r oidcRPResponse, params url.Values, failure string) string {
	t.Helper()
	if r.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("consent header policy affected the authorization response")
	}
	code, err := verifyOIDCRPCallback(r, params, f.issuer, failure)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func oidcRPAuth(client string, form url.Values) http.Header {
	headers := make(http.Header)
	switch client {
	case "post":
		form.Set("client_id", client)
		form.Set("client_secret", applicationTestSecret)
	case "public", "native4", "native6":
		form.Set("client_id", client)
	default:
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(client)+":"+url.QueryEscape(applicationTestSecret))))
	}
	return headers
}

func (f *oidcRPFixture) exchange(t *testing.T, client, code, redirect, verifier string) oidcRPResponse {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	return f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth(client, form))
}

type oidcRPTokens struct {
	Access  string `json:"access_token"`
	ID      string `json:"id_token"`
	Type    string `json:"token_type"`
	Expires int    `json:"expires_in"`
}

func (f *oidcRPFixture) keys(t *testing.T) oidcRPKeys {
	t.Helper()
	r := f.request(t, "GET", f.endpoint(t, "jwks_uri"), nil, nil)
	r.requireStatus(t, 200)
	var keys oidcRPKeys
	if json.Unmarshal(r.body, &keys) != nil || len(keys.Keys) == 0 {
		t.Fatal("invalid OP JWKS")
	}
	return keys
}

func (f *oidcRPFixture) tokens(t *testing.T, r oidcRPResponse, params url.Values) (oidcRPTokens, oidcRPClaims) {
	t.Helper()
	r.requireStatus(t, 200)
	r.noStore(t)
	var tokens oidcRPTokens
	var fields map[string]any
	if json.Unmarshal(r.body, &tokens) != nil || json.Unmarshal(r.body, &fields) != nil || tokens.Type != "Bearer" || tokens.Expires <= 0 {
		t.Fatal("invalid token response")
	}
	if _, exists := fields["refresh_token"]; exists {
		t.Fatal("unsupported OIDC refresh token issued")
	}
	claims, _, err := verifyOIDCRPToken(tokens.ID, tokens.Access, f.issuer, params.Get("client_id"), params.Get("nonce"), f.keys(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tokens, claims
}

func (f *oidcRPFixture) userinfo(t *testing.T, tokens oidcRPTokens, claims oidcRPClaims, email string) {
	t.Helper()
	r := f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + tokens.Access}})
	r.requireStatus(t, 200)
	r.noStore(t)
	var info map[string]any
	if json.Unmarshal(r.body, &info) != nil || info["sub"] != claims.Subject || info["email"] != email {
		t.Fatal("UserInfo identity or subject binding failed")
	}
}

func (f *oidcRPFixture) jsonLogin(t *testing.T, data map[string]any) map[string]any {
	t.Helper()
	body, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+"/login", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Origin", f.base)
	response, err := f.client.Do(r)
	if err != nil {
		t.Fatal("JSON login HTTP request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("JSON login status %d", response.StatusCode)
	}
	var result map[string]any
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result) != nil {
		t.Fatal("invalid JSON login response")
	}
	return result
}

func TestCaddyOIDCRelyingPartyProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_OIDC_RP_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, tlsKey, roots := cookieTLSCertificate(t)
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run("mount="+mount, func(t *testing.T) {
			f := newOIDCRPFixture(t, mount, cert, tlsKey, roots)
			t.Run("routing", f.testRouting)
			t.Run("clients and responses", f.testClients)
			t.Run("consent", f.testConsent)
			t.Run("fresh authentication", f.testFreshAuthentication)
			t.Run("MFA", f.testMFA)
			t.Run("bindings", f.testBindings)
			t.Run("logout and revocation", f.testLogoutRevocation)
			t.Run("token purposes", f.testTokenPurposes)
			t.Run("CORS", f.testCORS)
			t.Run("request objects", f.testRequestObjects)
			t.Run("claims signed requests and refresh", f.testCapabilities)
			if mount != "" {
				t.Run("native loopback", f.testLoopback)
			}
		})
	}
}
