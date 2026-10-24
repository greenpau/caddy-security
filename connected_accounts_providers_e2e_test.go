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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/system"
)

func TestCaddyConnectedProvidersE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyConnectedProvidersProcess$", "-test.v", "-test.timeout=350s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CONNECTED_PROVIDERS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy connected-provider acceptance: %v\n%s", err, output)
	}
}

func TestCaddyConnectedProvidersProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CONNECTED_PROVIDERS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("load connected-provider TLS fixture")
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal("initialize isolated provider trust")
	}
	oauthE2ESystemRoots = roots
	t.Run("signed_SAML_attachment", func(t *testing.T) { testConnectedAccountsSAML(t, cert, key, roots, pair) })
	t.Run("LDAP_browser_Basic_and_System", func(t *testing.T) { testConnectedAccountsLDAP(t, cert, key, roots) })
	t.Run("external_MFA_cross_device", func(t *testing.T) { testConnectedAccountsCrossDevice(t, cert, key, roots, pair) })
	for _, state := range []string{"disabled", "expired"} {
		t.Run("default_password_"+state, func(t *testing.T) { testConnectedAccountsPasswordHistory(t, cert, key, roots, state) })
	}
}

func testConnectedAccountsSAML(t *testing.T, cert, key string, roots *x509.CertPool, pair tls.Certificate) {
	f, issuer := newCrossDeviceSAMLFixture(t, cert, key, roots, pair, func(input string) string {
		input = strings.Replace(input, "saml identity provider saml_upstream {", "saml identity provider saml_upstream {\nattach to local identity store localdb", 1)
		input = strings.Replace(input, "enable identity provider saml_upstream", "enable identity provider saml_upstream\nenable identity store localdb\ncookie path /", 1)
		input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at /auth", 1)
		return loginDestinationsBrowserConfig(t, input)
	})
	login := func() string {
		t.Helper()
		browser := crossDeviceBrowser(t, f.oidcRPFixture).client
		begin := connectedAccountsSend(t, f, browser, "GET", "/saml/cross-device", nil, nil)
		begin.requireStatus(t, 302)
		location, err := url.Parse(begin.header.Get("Location"))
		if err != nil || location.Scheme+"://"+location.Host != issuer || location.Path != "/sso" {
			t.Fatal("SAML initiation left the controlled IdP")
		}
		f.secrets = append(f.secrets, location.Query().Get("SAMLRequest"), location.Query().Get("RelayState"))
		assertion := connectedAccountsSend(t, f, browser, "GET", location.String(), nil, nil)
		assertion.requireStatus(t, 200)
		form := providerDestinationSAMLForm(t, assertion.body)
		f.secrets = append(f.secrets, form.values.Get("SAMLResponse"), form.values.Get("RelayState"))
		callback := connectedAccountsSend(t, f, browser, "POST", form.action, strings.NewReader(form.values.Encode()), http.Header{
			"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {issuer}, "Sec-Fetch-Site": {"cross-site"},
		})
		callback.requireStatus(t, 303)
		claims := connectedAccountsVerifyAccess(t, f, connectedAccountsCookie(t, f, browser, "AUTHP_ACCESS_TOKEN"))
		id := claims["id"].(string)
		record := connectedProviderRecord(t, f.database, id)
		subject, _ := json.Marshal([]string{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", issuer + "/metadata", "urn:caddy:cross-device", "saml-user@example.test"})
		connectedProviderAutomaticRecord(t, record, "saml_upstream", "saml", issuer+"/metadata", string(subject))
		if fmt.Sprint(claims["amr"]) != "[federated]" {
			t.Fatal("signed SAML identity asserted local factors")
		}
		return id
	}
	if first, next := login(), login(); first != next {
		t.Fatal("repeat signed SAML assertion changed the attached local ID")
	}
}

const connectedAccountsSystemKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testConnectedAccountsLDAP(t *testing.T, cert, key string, roots *x509.CertPool) {
	address, verified := challengeLDAPServer(t, cert, key)
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/tenant/auth", configure: func(input string) string {
		store := fmt.Sprintf(`ldap identity store directory {
 realm directory
 servers {
  %s
 }
 trusted_authority %q
 username cn=service,dc=example,dc=test
 password SyntheticBindPassword42!
 search_base_dn dc=example,dc=test
 enable full automatic group mapping
 fallback roles authp/user directory/member
 attach to local identity store localdb
}
`, address, cert)
		input = strings.Replace(input, "authentication portal myportal {", store+"authentication portal myportal {\nenable identity store directory\ncookie path /\ncrypto key internal system "+connectedAccountsSystemKey, 1)
		input = strings.Replace(input, "authorization policy app_policy {", "authorization policy app_policy {\nwith basic auth portal myportal realm directory\ndisable auth redirect\ninject header X-Connected-Identity from id", 1)
		input = strings.Replace(input, "route /resource {", "route /basic-resource {\nauthorize with app_policy\nrespond \"{http.request.header.X-Connected-Identity}|{http.auth.user.roles}\"\n}\nroute /resource {", 1)
		input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at /tenant/auth", 1)
		input = loginDestinationsBrowserConfig(t, input)
		// Connection redirects carry a private operation in their destination.
		// Keep DEBUG evidence while redacting both redirect event field shapes.
		return strings.Replace(input, "url delete", "url delete\nredirect_url delete\nredirect_url_any delete", 1)
	}}, cert, key, roots)
	f.secrets = append(f.secrets, connectedAccountsSystemKey, "SyntheticBindPassword42!")
	login := func(client *http.Client, username, password string, success bool) string {
		t.Helper()
		connectedAccountsSend(t, f, client, "GET", "/login?fresh=1", nil, nil).requireStatus(t, 200)
		start := connectedAccountsForm(t, f, client, f.issuer+"/login?fresh=1", url.Values{"username": {username}, "realm": {"directory"}})
		start.requireStatus(t, 303)
		sandbox := start.header.Get("Location")
		checked := connectedAccountsForm(t, f, client, sandbox, url.Values{"secret": {password}})
		if !success {
			checked.requireStatus(t, 401)
			if connectedAccountsCookie(t, f, client, "AUTHP_ACCESS_TOKEN") != "" {
				t.Fatal("failed directory authentication issued access")
			}
			return ""
		}
		checked.requireStatus(t, 303)
		connectedAccountsSend(t, f, client, "GET", sandbox, nil, nil).requireStatus(t, 303)
		return connectedAccountsCookie(t, f, client, "AUTHP_ACCESS_TOKEN")
	}
	newBrowser := func() *http.Client { return crossDeviceBrowser(t, f.oidcRPFixture).client }
	before, err := os.ReadFile(f.database)
	if err != nil {
		t.Fatal("capture pre-authentication local store")
	}
	login(newBrowser(), "alice", "incorrect-directory-password", false)
	after, err := os.ReadFile(f.database)
	if err != nil || string(before) != string(after) || verified.Load() != 0 {
		t.Fatal("wrong directory password changed the attached store")
	}
	browser := newBrowser()
	claims := connectedAccountsVerifyAccess(t, f, login(browser, "alice", lifecyclePassword, true))
	id := claims["id"].(string)
	connectedProviderAutomaticRecord(t, connectedProviderRecord(t, f.database, id), "directory", "ldap", "directory", "cn=alice,dc=example,dc=test")
	aliceID := localIdentityRecord(t, f.database, "alice").ID
	if id == aliceID || verified.Load() == 0 {
		t.Fatal("LDAP matched by display email or skipped the verified Bind")
	}
	alias := connectedAccountsVerifyAccess(t, f, login(newBrowser(), "alice@example.test", lifecyclePassword, true))
	if alias["id"] != id {
		t.Fatal("LDAP aliases changed the bound-DN identity")
	}
	connectedAccountsConnect(t, f, browser, "alice")
	if current := connectedAccountsVerifyAccess(t, f, login(newBrowser(), "alice", lifecyclePassword, true)); current["id"] != aliceID || !slices.Contains(current["roles"].([]any), any("alice")) {
		t.Fatal("connected LDAP login lost the target ID or local roles")
	}
	keyBytes, err := system.ParseKeyFromString(connectedAccountsSystemKey)
	if err != nil {
		t.Fatal("parse fixture System API key")
	}
	encryptor, err := system.NewEncryptor("internal", keyBytes)
	if err != nil {
		t.Fatal("create fixture System API encryptor")
	}
	direct := func(systemStatus int) {
		t.Helper()
		basic := base64.StdEncoding.EncodeToString([]byte("alice:" + lifecyclePassword))
		f.secrets = append(f.secrets, basic)
		r := connectedAccountsSend(t, f, f.plain, "GET", f.base+"/basic-resource", nil, http.Header{"Authorization": {"Basic " + basic}, "X-Auth-Realm": {"directory"}})
		if systemStatus == 200 {
			r.requireStatus(t, 200)
			parts := strings.Split(string(r.body), "|")
			if len(parts) != 2 || parts[0] != aliceID || !slices.Contains(strings.Fields(parts[1]), "alice") {
				t.Fatal("Caddy Basic authorization lost the attached local ID or roles")
			}
		} else {
			r.requireStatus(t, 401)
		}
		encoded, err := encryptor.EncryptMessage(&system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "directory", Username: "alice", Password: lifecyclePassword, Address: "198.51.100.10"})
		if err != nil {
			t.Fatal("encrypt directory System API request")
		}
		f.secrets = append(f.secrets, encoded)
		r = connectedAccountsSend(t, f, f.plain, "POST", "/api/system", strings.NewReader(encoded), http.Header{"Content-Type": {"text/plain; charset=UTF-8"}})
		r.requireStatus(t, systemStatus)
		message, err := encryptor.DecryptMessage(string(r.body))
		if systemStatus != 200 {
			if err == nil {
				t.Fatal("rejected directory System API request issued an assertion")
			}
			return
		}
		f.secrets = append(f.secrets, string(r.body))
		result, ok := message.(*system.AuthResponseMessage)
		if err != nil || !ok || !result.Authenticated || result.UserData["id"] != aliceID || result.UserData["sub"] != "alice" || fmt.Sprint(result.UserData["amr"]) != "[federated]" || !slices.Contains(result.UserData["roles"].([]any), any("alice")) {
			t.Fatal("encrypted directory assertion lost attached identity, roles or verified methods")
		}
	}
	direct(200)
	admin := f.formLogin(t, "admin", lifecyclePassword, false)
	f.admin(t, admin, "overwrite_auth_challenges", map[string]any{"challenges": []string{"password"}})
	direct(403)
	f.formLogin(t, "alice", lifecyclePassword, false)
	f.profile(t, map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{}}, 200)
	direct(200)
	f.formLogin(t, "alice", lifecyclePassword, false)
	f.profile(t, map[string]any{"kind": "add_user_app_multi_factor_authenticator", "title": "DirectoryFactor", "description": "", "secret": authenticationClientTOTPSecret, "period": 30, "digits": 6}, 200)
	direct(403)

	// Browser Basic may enter the local checkpoint; the direct interfaces above
	// cannot satisfy it. Complete the actual HTML TOTP before accepting access.
	browser = newBrowser()
	basic := base64.StdEncoding.EncodeToString([]byte("alice:" + lifecyclePassword))
	r := connectedAccountsSend(t, f, browser, "GET", "/basic/login/directory", nil, http.Header{"Authorization": {"Basic " + basic}})
	r.requireStatus(t, 303)
	sandbox := r.header.Get("Location")
	if !strings.Contains(sandbox, "/tenant/auth/sandbox/") || r.header.Get("Authorization") != "" || connectedAccountsCookie(t, f, browser, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("directory Basic browser bypassed its local factor")
	}
	connectedAccountsSend(t, f, browser, "GET", sandbox, nil, nil).requireStatus(t, 200)
	waitForFreshFixtureTOTP(t, f.database, "alice")
	code := authenticationClientTOTP()
	f.secrets = append(f.secrets, code)
	connectedAccountsForm(t, f, browser, sandbox, url.Values{"passcode": {code}}).requireStatus(t, 303)
	connectedAccountsSend(t, f, browser, "GET", sandbox, nil, nil).requireStatus(t, 303)
	completed := connectedAccountsVerifyAccess(t, f, connectedAccountsCookie(t, f, browser, "AUTHP_ACCESS_TOKEN"))
	if completed["id"] != aliceID || !slices.Contains(completed["amr"].([]any), any("federated")) || !slices.Contains(completed["amr"].([]any), any("otp")) {
		t.Fatal("directory Basic browser lost its verified external and local factors")
	}
	f.json(t, browser, "/api/profile", map[string]any{"kind": "fetch_user_api_keys"}, "", http.Header{"Origin": {f.base}}).requireStatus(t, 501)
	f.admin(t, admin, "disable", nil)
	direct(401)
	login(newBrowser(), "alice", lifecyclePassword, false)
}

func testConnectedAccountsPasswordHistory(t *testing.T, cert, key string, roots *x509.CertPool, state string) {
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", mfa: true, seed: func(t *testing.T, path string) {
		// Fixture setup occurs before Caddy opens the file. Runtime policy changes
		// below cross the authenticated administration API.
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("read unavailable-password fixture")
		}
		var snapshot identity.Database
		if json.Unmarshal(data, &snapshot) != nil {
			t.Fatal("decode unavailable-password fixture")
		}
		for _, user := range snapshot.Users {
			if user.Username == "alice" {
				user.AuthChallengeRules = nil
				for _, password := range user.Passwords {
					password.Disabled, password.Expired = state == "disabled", state == "expired"
				}
				user.CredentialVersion++
			}
		}
		snapshot.Revision++
		data, err = json.Marshal(snapshot)
		if err != nil || os.WriteFile(path, data, 0600) != nil {
			t.Fatal("write unavailable-password fixture")
		}
	}, configure: func(input string) string {
		return challengePolicyInput(input, "")
	}}, cert, key, roots)
	request := apiauth.AuthRequest{Username: "alice", Realm: "local"}
	start := localIdentityAuth(t, f.json(t, f.client, "/login", request, ""))
	if start.Authenticated || start.NextChallenge != "password" {
		t.Fatal("unavailable password silently selected a factor-only policy")
	}
	request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "password", lifecyclePassword
	localIdentityRejectedAuth(t, f.json(t, f.client, "/login", request, ""), 401)
	f.noCredentials(t)
	admin := f.formLogin(t, "admin", lifecyclePassword, false)
	f.admin(t, admin, "overwrite_auth_challenges", map[string]any{"challenges": []string{"totp"}})
	f.newBrowser(t)
	request = apiauth.AuthRequest{Username: "alice", Realm: "local"}
	start = localIdentityAuth(t, f.json(t, f.client, "/login", request, ""))
	if start.Authenticated || start.NextChallenge != "totp" {
		t.Fatal("explicit available-factor policy did not select TOTP")
	}
	request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "totp", authenticationClientTOTP()
	f.secrets = append(f.secrets, request.SandboxSecret, request.ChallengeResponse)
	completed := localIdentityAuth(t, f.json(t, f.client, "/login", request, ""))
	if !completed.Authenticated || completed.AccessToken == "" {
		t.Fatal("explicit factor-only native login did not issue access")
	}
	f.secrets = append(f.secrets, completed.AccessToken)
	challengeClaims(t, f, completed.AccessToken, "otp")
	f.assertResource(t, completed.AccessToken)
}
