// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"html"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type connectedAccountsOptions struct {
	mount                              string
	localMFA, providerRefresh, localOP bool
	seed                               func(*testing.T, string)
	configure                          func(string) string
}

type caddyConnectedAccountsFixture struct {
	*localIdentityFixture
	upstream, secondUpstream *oauthE2EUpstream
	cert                     string
	contracts                *openAPIContracts
}

func newCaddyConnectedAccountsFixture(t *testing.T, options connectedAccountsOptions, cert, key string, roots *x509.CertPool, pair tls.Certificate) *caddyConnectedAccountsFixture {
	t.Helper()
	f := &caddyConnectedAccountsFixture{cert: cert, contracts: newOpenAPIContracts(t)}
	f.upstream, f.secondUpstream = newOAuthE2EUpstream(t, pair, "EdDSA"), newOAuthE2EUpstream(t, pair, "EdDSA")
	for name, u := range map[string]*oauthE2EUpstream{"upstream": f.upstream, "second": f.secondUpstream} {
		u.fixedSubject, u.accessMode = "connected-"+name+"-subject", "userinfo"
		u.identityClaims = map[string]any{"email": "alice@example.test"}
		u.userInfoClaims = map[string]any{"email": "alice@example.test", "name": "External account " + name}
	}
	local := localIdentityOptions{mount: options.mount, mfa: options.localMFA, seed: options.seed}
	if options.providerRefresh {
		local.refreshRealm = "local"
	}
	if options.localOP {
		local.oidcRealm = "local"
	}
	local.configure = func(input string) string {
		var base string
		for line := range strings.SplitSeq(input, "\n") {
			if strings.HasPrefix(line, "https://") {
				base = strings.Fields(line)[0]
			}
		}
		if base == "" {
			t.Fatal("connected account fixture lacks its TLS origin")
		}
		var providers strings.Builder
		for i, u := range []*oauthE2EUpstream{f.upstream, f.secondUpstream} {
			name := []string{"upstream", "second"}[i]
			u.mu.Lock()
			u.callback = base + options.mount + "/oauth2/" + name + "/authorization-code-callback"
			u.mu.Unlock()
			fmt.Fprintf(&providers, `oauth identity provider %s {
 driver generic
 realm %s
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 scopes openid profile email
 user_info_fields all
 attach to local identity store localdb
}
`, name, name, oauthE2EClient, oauthE2ESecret, u.server.URL, u.server.URL)
		}
		input = strings.Replace(input, "authentication portal myportal {", providers.String()+`authentication portal myportal {
 enable identity providers upstream second
 cookie path /
 transform user {
  match realm upstream
  action add role authp/user
 }
 transform user {
  match realm second
  action add role authp/user
 }
`, 1)
		input = strings.Replace(input, "enable identity stores localdb excludeddb", "enable identity store localdb", 1)
		if options.providerRefresh {
			input = strings.Replace(input, "realms local\npublic origin", "realms local upstream second\nprovider revalidation upstream snapshot\nprovider revalidation second snapshot\nmax sessions 8\npublic origin", 1)
		}
		mount := options.mount
		if mount == "" {
			mount = "/"
		}
		input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at "+mount, 1)
		input = strings.Replace(input, "level DEBUG", "level INFO", 1)
		input = strings.Replace(input, "format json", "format filter {\nwrap json\nfields {\nresp_headers>Location delete\n}\n}", 1)
		// The fresh login and sandbox pages retain the connection destination;
		// same-origin browser Referer headers can carry its private ticket.
		input = strings.ReplaceAll(input, "resp_headers>Location delete", "resp_headers>Location delete\nrequest>uri delete\nrequest>headers>Referer delete")
		if options.configure != nil {
			input = options.configure(input)
		}
		return input
	}
	f.localIdentityFixture = newLocalIdentityFixture(t, local, cert, key, roots)
	f.secrets = append(f.secrets, oauthE2ESecret)
	t.Cleanup(func() {
		for _, u := range []*oauthE2EUpstream{f.upstream, f.secondUpstream} {
			u.mu.Lock()
			f.secrets = append(f.secrets, u.issuedSecrets...)
			u.mu.Unlock()
		}
	})
	return f
}

func (f *caddyConnectedAccountsFixture) browser(t *testing.T) *http.Client {
	t.Helper()
	return crossDeviceBrowser(t, f.oidcRPFixture).client
}

// Calls retain the supplied browser jar. Explicit negative replay headers use
// f.plain instead; never restore jar cookies with their Path metadata stripped.
func connectedAccountsSend(t *testing.T, f *localIdentityFixture, client *http.Client, method, target string, body io.Reader, headers http.Header) oidcRPResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.issuer + target
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal("cannot construct connected account request")
	}
	maps.Copy(req.Header, headers)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("connected account verified TLS request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("connected account response was unbounded or lacked verified TLS")
	}
	r := oidcRPResponse{response.StatusCode, response.Header.Clone(), raw}
	for _, cookie := range response.Cookies() {
		if cookie.Name != "AUTHP_SESSION_ID" && cookie.Value != "" && cookie.MaxAge >= 0 {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	var auth apiauth.AuthResponse
	if json.Unmarshal(raw, &auth) == nil {
		f.secrets = append(f.secrets, auth.SandboxSecret, auth.AccessToken, auth.RefreshToken)
	}
	return r
}

func (f *caddyConnectedAccountsFixture) send(t *testing.T, client *http.Client, method, target string, body io.Reader, headers http.Header) oidcRPResponse {
	t.Helper()
	r := connectedAccountsSend(t, f.localIdentityFixture, client, method, target, body, headers)
	absolute := target
	if strings.HasPrefix(absolute, "/") {
		absolute = f.issuer + absolute
	}
	u, err := url.Parse(absolute)
	if err == nil && u.Scheme+"://"+u.Host == f.base && (method == "GET" || method == "POST") {
		path := strings.TrimPrefix(u.Path, f.mount)
		if (path == "/connected-accounts" || path == "/connected-accounts/") && method == "GET" {
			f.contracts.AssertResponse(t, method, "/connected-accounts", r.status, r.header, r.body)
		} else if strings.HasPrefix(path, "/connected-accounts/") && len(strings.TrimPrefix(path, "/connected-accounts/")) == 48 {
			f.contracts.AssertResponse(t, method, "/connected-accounts/{ticket}", r.status, r.header, r.body)
		}
	}
	return r
}

func connectedAccountsForm(t *testing.T, f *localIdentityFixture, client *http.Client, target string, values url.Values) oidcRPResponse {
	t.Helper()
	return connectedAccountsSend(t, f, client, "POST", target, strings.NewReader(values.Encode()), http.Header{"Origin": {f.base}, "Content-Type": {"application/x-www-form-urlencoded"}})
}

func connectedAccountsCookie(t *testing.T, f *localIdentityFixture, client *http.Client, name string) string {
	t.Helper()
	if client.Jar == nil {
		t.Fatal("connected account browser has no cookie jar")
	}
	u, _ := url.Parse(f.issuer + "/portal")
	for _, cookie := range client.Jar.Cookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func connectedAccountsVerifyAccess(t *testing.T, f *localIdentityFixture, token string) map[string]any {
	t.Helper()
	if token == "" {
		t.Fatal("connected account login omitted access credential")
	}
	f.secrets = append(f.secrets, token)
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "access")
	if id, ok := claims["id"].(string); !ok || id == "" {
		t.Fatal("connected access lacks immutable identity")
	}
	if exp, ok := claims["exp"].(float64); !ok || exp <= float64(time.Now().Unix()) {
		t.Fatal("connected access lacks current lifetime")
	}
	issuer, ok := claims["iss"].(string)
	u, err := url.Parse(issuer)
	if !ok || err != nil || u.Scheme+"://"+u.Host != f.base || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (f.mount != "" && u.Path != f.mount && !strings.HasPrefix(u.Path, f.mount+"/")) {
		t.Fatal("connected access issuer escaped the verified mounted portal")
	}
	f.assertResource(t, token)
	return claims
}

func (f *caddyConnectedAccountsFixture) verifyAccess(t *testing.T, token string) map[string]any {
	t.Helper()
	return connectedAccountsVerifyAccess(t, f.localIdentityFixture, token)
}

func (f *caddyConnectedAccountsFixture) login(t *testing.T, client *http.Client, realm string, want int) oidcRPResponse {
	t.Helper()
	u := f.upstream
	if realm == "second" {
		u = f.secondUpstream
	} else if realm != "upstream" {
		t.Fatal("unknown fixture provider")
	}
	r := f.send(t, client, "GET", "/oauth2/"+realm, nil, nil)
	r.requireStatus(t, 302)
	location, err := url.Parse(r.header.Get("Location"))
	if err != nil || location.Scheme+"://"+location.Host != u.server.URL || location.Path != "/authorize" {
		t.Fatal("connected OAuth initiation escaped trusted issuer")
	}
	f.secrets = append(f.secrets, location.Query().Get("state"), location.Query().Get("nonce"))
	r = f.send(t, client, "GET", location.String(), nil, nil)
	r.requireStatus(t, 302)
	callback, err := url.Parse(r.header.Get("Location"))
	if err != nil || callback.Scheme+"://"+callback.Host != f.base || callback.Path != f.mount+"/oauth2/"+realm+"/authorization-code-callback" {
		t.Fatal("connected OAuth callback escaped mounted origin")
	}
	f.secrets = append(f.secrets, callback.Query().Get("code"), callback.Query().Get("state"))
	r = f.send(t, client, "GET", callback.String(), nil, nil)
	r.requireStatus(t, want)
	r.noStore(t)
	return r
}

func connectedAccountsPage(t *testing.T, r oidcRPResponse) {
	t.Helper()
	r.requireStatus(t, 200)
	r.noStore(t)
	if !strings.HasPrefix(r.header.Get("Content-Type"), "text/html") || r.header.Get("Referrer-Policy") != "strict-origin" || !strings.Contains(r.header.Get("Content-Security-Policy"), "form-action 'self'") || !strings.Contains(r.header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("connected page lost its fixed HTML/origin policy")
	}
}

type connectedAccountsOperation struct{ endpoint, csrf, loginURL string }

func connectedAccountsOperationForm(t *testing.T, f *localIdentityFixture, r oidcRPResponse) connectedAccountsOperation {
	t.Helper()
	connectedAccountsPage(t, r)
	action := regexp.MustCompile(`action="([^"]*/connected-accounts/[^"]+)"`).FindAllSubmatch(r.body, -1)
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindAllSubmatch(r.body, -1)
	if len(action) != 1 || len(csrf) != 1 {
		t.Fatal("connected page omitted its unique native form")
	}
	raw := html.UnescapeString(string(action[0][1]))
	base, _ := url.Parse(f.base)
	u, err := base.Parse(raw)
	if err != nil || u.Scheme+"://"+u.Host != f.base || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, f.mount+"/connected-accounts/") || len(strings.TrimPrefix(u.Path, f.mount+"/connected-accounts/")) != 48 {
		t.Fatal("connected form escaped its exact mounted ticket")
	}
	o := connectedAccountsOperation{endpoint: u.String(), csrf: html.UnescapeString(string(csrf[0][1]))}
	f.secrets = append(f.secrets, o.csrf, strings.TrimPrefix(u.Path, f.mount+"/connected-accounts/"), o.endpoint)
	return o
}

func connectedAccountsBegin(t *testing.T, f *localIdentityFixture, client *http.Client) connectedAccountsOperation {
	t.Helper()
	o := connectedAccountsOperationForm(t, f, connectedAccountsSend(t, f, client, "GET", "/connected-accounts/", nil, http.Header{"Accept": {"application/json"}}))
	r := connectedAccountsForm(t, f, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"start"}})
	r.requireStatus(t, 303)
	o.loginURL = r.header.Get("Location")
	u, err := url.Parse(o.loginURL)
	if err != nil || u.Scheme+"://"+u.Host != f.base || u.Path != f.mount+"/login" || u.Query().Get("fresh") != "1" || u.Query().Get("redirect_url") != o.endpoint {
		t.Fatal("connection did not bind fresh local sign-in")
	}
	f.secrets = append(f.secrets, o.loginURL)
	return o
}

func connectedAccountsStartLocal(t *testing.T, f *localIdentityFixture, client *http.Client, target, username string) string {
	t.Helper()
	connectedAccountsSend(t, f, client, "GET", target, nil, nil).requireStatus(t, 200)
	r := connectedAccountsForm(t, f, client, target, url.Values{"username": {username}, "realm": {"local"}})
	r.requireStatus(t, 303)
	location := r.header.Get("Location")
	u, err := url.Parse(location)
	if err != nil || u.Scheme+"://"+u.Host != f.base || !strings.HasPrefix(u.Path, f.mount+"/sandbox/") || u.RawQuery != "" {
		t.Fatal("connection local proof escaped mounted sandbox")
	}
	return location
}

func connectedAccountsFinishLocal(t *testing.T, f *localIdentityFixture, client *http.Client, sandbox, username string) oidcRPResponse {
	t.Helper()
	password := lifecyclePassword
	if username == "bob" {
		password = localIdentityBobPassword
	}
	connectedAccountsForm(t, f, client, sandbox, url.Values{"secret": {password}}).requireStatus(t, 303)
	user := localIdentityRecord(t, f.database, username)
	if user == nil {
		t.Fatal("connection target missing")
	}
	if len(user.MfaTokens) > 0 {
		connectedAccountsSend(t, f, client, "GET", sandbox, nil, nil).requireStatus(t, 200)
		waitForFreshFixtureTOTP(t, f.database, username)
		code := authenticationClientTOTP()
		f.secrets = append(f.secrets, code)
		connectedAccountsForm(t, f, client, sandbox, url.Values{"passcode": {code}}).requireStatus(t, 303)
	}
	r := connectedAccountsSend(t, f, client, "GET", sandbox, nil, nil)
	r.requireStatus(t, 303)
	return r
}

// Provider-independent: the caller supplies an already authenticated external
// browser. The proof follows the actual mounted HTML path and native forms.
func connectedAccountsConnect(t *testing.T, f *localIdentityFixture, client *http.Client, username string) string {
	t.Helper()
	o := connectedAccountsBegin(t, f, client)
	sandbox := connectedAccountsStartLocal(t, f, client, o.loginURL, username)
	r := connectedAccountsFinishLocal(t, f, client, sandbox, username)
	if r.header.Get("Location") != o.endpoint {
		t.Fatal("connection proof lost its exact return destination")
	}
	review := connectedAccountsOperationForm(t, f, connectedAccountsSend(t, f, client, "GET", o.endpoint, nil, nil))
	if review.endpoint != o.endpoint || review.csrf != o.csrf {
		t.Fatal("connection review changed operation")
	}
	token := connectedAccountsCookie(t, f, client, "AUTHP_ACCESS_TOKEN")
	connectedAccountsVerifyAccess(t, f, token)
	r = connectedAccountsForm(t, f, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}})
	connectedAccountsPage(t, r)
	if !bytes.Contains(r.body, []byte(`role="status"`)) {
		t.Fatal("connection did not report committed result")
	}
	connectedAccountsForm(t, f, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}}).requireStatus(t, 410)
	return token
}

func (f *caddyConnectedAccountsFixture) connect(t *testing.T, client *http.Client, realm, username string) string {
	t.Helper()
	f.login(t, client, realm, 303)
	return connectedAccountsConnect(t, f.localIdentityFixture, client, username)
}

func connectedAccountsRecordID(t *testing.T, f *localIdentityFixture, id string) *identity.User {
	t.Helper()
	data, err := os.ReadFile(f.database)
	if err != nil {
		t.Fatal("cannot read quiescent connection account snapshot")
	}
	var file struct{ Users []*identity.User }
	if json.Unmarshal(data, &file) != nil {
		t.Fatal("invalid connection account snapshot")
	}
	for _, user := range file.Users {
		if user.ID == id {
			return user
		}
	}
	t.Fatal("connection identity was absent from selected local store")
	return nil
}

func connectedAccountsMove(t *testing.T, before, after, source *identity.User, count int) {
	t.Helper()
	if after.ID != before.ID || after.ExternallyProvisioned || len(after.ExternalAccounts) != count || after.CredentialVersion <= before.CredentialVersion || !source.Disabled || len(source.ExternalAccounts) != 0 {
		t.Fatal("connection did not atomically retain target and retire source")
	}
	for _, field := range []struct{ before, after any }{{before.Roles, after.Roles}, {before.Passwords, after.Passwords}, {before.AuthChallengeRules, after.AuthChallengeRules}} {
		a, _ := json.Marshal(field.before)
		b, _ := json.Marshal(field.after)
		if !bytes.Equal(a, b) {
			t.Fatal("connection changed target credentials, roles or policy")
		}
	}
	if len(before.MfaTokens) != len(after.MfaTokens) {
		t.Fatal("connection changed target factor inventory")
	}
	for i, factor := range before.MfaTokens {
		prior, next := *factor, *after.MfaTokens[i]
		// A real TOTP proof advances replay state; connection does not copy or
		// replace enrolled factor material or policy.
		prior.LastTOTPCounter, next.LastTOTPCounter = nil, nil
		a, _ := json.Marshal(prior)
		b, _ := json.Marshal(next)
		if !bytes.Equal(a, b) {
			t.Fatal("connection replaced target factor material")
		}
	}
}

func TestCaddyConnectedAccountsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyConnectedAccountsProcess$", "-test.v", "-test.timeout=340s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CONNECTED_ACCOUNTS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy connected account acceptance: %v\n%s", err, output)
	}
}

func TestCaddyConnectedAccountsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CONNECTED_ACCOUNTS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	fixture := func(t *testing.T, o connectedAccountsOptions) *caddyConnectedAccountsFixture {
		return newCaddyConnectedAccountsFixture(t, o, cert, key, roots, pair)
	}
	t.Run("root_two_providers", func(t *testing.T) {
		f := fixture(t, connectedAccountsOptions{})
		var previousIDs []string
		for i, realm := range []string{"upstream", "second"} {
			client := f.browser(t)
			f.login(t, client, realm, 303)
			token := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN")
			claims := f.verifyAccess(t, token)
			id := claims["id"].(string)
			before := localIdentityRecord(t, f.database, "alice")
			source := connectedAccountsRecordID(t, f.localIdentityFixture, id)
			if id == before.ID || slices.Contains(previousIDs, id) || !source.ExternallyProvisioned || source.Username == "alice" || len(source.EmailAddresses) != 0 || len(source.Passwords) != 0 || len(source.MfaTokens) != 0 || len(source.APIKeys) != 0 || len(source.ExternalAccounts) != 1 {
				t.Fatal("provider display email selected or privileged an existing local identity")
			}
			previousIDs = append(previousIDs, id)
			u := f.upstream
			if realm == "second" {
				u = f.secondUpstream
			}
			tuple := source.ExternalAccounts[0]
			if tuple.Provider != realm || tuple.Kind != "oauth" || tuple.Issuer != u.server.URL || tuple.Subject != u.fixedSubject || tuple.Email != "alice@example.test" || slices.ContainsFunc(source.Roles, func(role *identity.Role) bool { return role.String() == "authp/admin" }) {
				t.Fatal("automatic identity lost verified tuple or acquired administrator role")
			}
			f.login(t, client, realm, 303)
			repeated := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
			if repeated["id"] != id || repeated["nonce"] == nil || repeated["nonce"] == "" || repeated["nonce"] == claims["nonce"] {
				t.Fatal("repeat upstream subject changed local identity")
			}
			if i == 0 {
				admin := f.browser(t)
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, admin, f.issuer+"/login?fresh=1", "admin")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, admin, s, "admin")
				f.admin(t, connectedAccountsCookie(t, f.localIdentityFixture, admin, "AUTHP_ACCESS_TOKEN"), "overwrite_roles", map[string]any{"username": source.Username, "email": "", "roles": []string{"source-only"}})
				f.login(t, client, realm, 303)
				current := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
				if !slices.Contains(current["roles"].([]any), any("source-only")) {
					t.Fatal("source role control did not reach verified external issuance")
				}
				source = connectedAccountsRecordID(t, f.localIdentityFixture, id)
			}
			connectedAccountsConnect(t, f.localIdentityFixture, client, "alice")
			after := localIdentityRecord(t, f.database, "alice")
			retired := connectedAccountsRecordID(t, f.localIdentityFixture, id)
			connectedAccountsMove(t, before, after, retired, i+1)
			if retired.CredentialVersion <= source.CredentialVersion {
				t.Fatal("connection did not invalidate source proof")
			}
			f.login(t, client, realm, 303)
			final := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
			if final["id"] != before.ID || slices.Contains(final["roles"].([]any), any("source-only")) || !slices.Contains(final["roles"].([]any), any("alice")) {
				t.Fatal("connected provider did not retain target UUID")
			}
		}
	})
	t.Run("nested_authority", func(t *testing.T) {
		testCaddyConnectedAccountsAuthority(t, fixture(t, connectedAccountsOptions{mount: "/tenant/auth"}))
	})
	t.Run("freshness", func(t *testing.T) {
		testCaddyConnectedAccountsFreshness(t, fixture(t, connectedAccountsOptions{mount: "/tenant/auth"}))
	})
	t.Run("noninteractive_credentials", func(t *testing.T) {
		key := "000000000000000000000021" + strings.Repeat("A", 40)
		f := fixture(t, connectedAccountsOptions{mount: "/tenant/auth", providerRefresh: true, seed: func(t *testing.T, path string) {
			db, err := identity.NewDatabase(path)
			if err != nil {
				t.Fatal("cannot open fixture account store")
			}
			if err := db.AddAPIKey(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: key, Usage: "api", Comment: "Synthetic connected-account authority key"}}); err != nil {
				t.Fatal("cannot seed fixture API key")
			}
		}})
		f.secrets = append(f.secrets, key)
		testCaddyConnectedAccountsNoninteractive(t, f, key)
	})
	t.Run("browser", func(t *testing.T) {
		runCaddyConnectedAccountsBrowser(t, fixture(t, connectedAccountsOptions{mount: "/tenant/auth", localMFA: true, localOP: true}))
	})
}

func testCaddyConnectedAccountsAuthority(t *testing.T, f *caddyConnectedAccountsFixture) {
	t.Helper()
	client := f.browser(t)
	f.login(t, client, "upstream", 303)
	access := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN")
	sid := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_SESSION_ID")
	o := connectedAccountsOperationForm(t, f.localIdentityFixture, f.send(t, client, "GET", "/connected-accounts/", nil, http.Header{"Accept": {"application/json"}}))
	for _, tc := range []struct {
		name, cookie, bearer, query string
		status                      int
	}{
		{"no_session", "AUTHP_ACCESS_TOKEN=" + access, "", "", 401},
		{"empty_session", "AUTHP_ACCESS_TOKEN=" + access + "; AUTHP_SESSION_ID=", "", "", 401},
		{"duplicate_session", "AUTHP_ACCESS_TOKEN=" + access + "; AUTHP_SESSION_ID=" + sid + "; AUTHP_SESSION_ID=" + sid, "", "", 401},
		{"no_access", "AUTHP_SESSION_ID=" + sid, "", "", 302},
		{"empty_access", "AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=", "", "", 302},
		{"duplicate_access", "AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=" + access + "; AUTHP_ACCESS_TOKEN=" + access, "", "", 302},
		{"bearer", "AUTHP_SESSION_ID=" + sid, access, "", 302},
		{"query", "AUTHP_SESSION_ID=" + sid, "", "?access_token=" + url.QueryEscape(access), 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{"Cookie": {tc.cookie}}
			if tc.bearer != "" {
				h.Set("Authorization", "Bearer "+tc.bearer)
			}
			r := f.send(t, f.plain, "GET", o.endpoint+tc.query, nil, h)
			r.requireStatus(t, tc.status)
			r.noStore(t)
			providerDestinationNoIssuance(t, r)
		})
	}
	valid := url.Values{"csrf": {o.csrf}, "action": {"start"}}
	for _, tc := range []struct {
		name        string
		origin      []string
		media, body string
		status      int
	}{
		{"missing_origin", nil, "application/x-www-form-urlencoded", valid.Encode(), 403},
		{"wrong_origin", []string{"https://outside.invalid"}, "application/x-www-form-urlencoded", valid.Encode(), 403},
		{"duplicate_origin", []string{f.base, f.base}, "application/x-www-form-urlencoded", valid.Encode(), 403},
		{"csrf", []string{f.base}, "application/x-www-form-urlencoded", "csrf=wrong&action=start", 403},
		{"duplicate_field", []string{f.base}, "application/x-www-form-urlencoded", valid.Encode() + "&csrf=" + o.csrf, 400},
		{"extra_field", []string{f.base}, "application/x-www-form-urlencoded", valid.Encode() + "&extra=value", 400},
		{"wrong_media", []string{f.base}, "application/json", `{}`, 415},
		{"body_bound", []string{f.base}, "application/x-www-form-urlencoded", "csrf=" + strings.Repeat("x", 4097), 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.send(t, client, "POST", o.endpoint, strings.NewReader(tc.body), http.Header{"Origin": tc.origin, "Content-Type": {tc.media}})
			r.requireStatus(t, tc.status)
			providerDestinationNoIssuance(t, r)
		})
	}
	r := f.send(t, client, "DELETE", o.endpoint, nil, nil)
	r.requireStatus(t, 405)
	if r.header.Get("Allow") != "GET, POST" {
		t.Fatal("connection method boundary omitted Allow")
	}
	other := f.browser(t)
	f.login(t, other, "upstream", 303)
	connectedAccountsForm(t, f.localIdentityFixture, other, o.endpoint, valid).requireStatus(t, 410)
	r = connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, valid)
	r.requireStatus(t, 303)
	o.loginURL = r.header.Get("Location")
	foreign := f.send(t, other, "GET", o.loginURL, nil, nil)
	foreign.requireStatus(t, 200)
	if bytes.Contains(foreign.body, []byte(o.endpoint)) || bytes.Contains(foreign.body, []byte(url.QueryEscape(o.endpoint))) {
		t.Fatal("foreign browser retained connection destination")
	}
	sandbox := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
	connectedAccountsFinishLocal(t, f.localIdentityFixture, client, sandbox, "alice")
	for _, method := range []string{"GET", "POST"} {
		h := http.Header{"Cookie": {"AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=" + access}, "Origin": {f.base}, "Content-Type": {"application/x-www-form-urlencoded"}}
		r := f.send(t, f.plain, method, o.endpoint, strings.NewReader(url.Values{"csrf": {o.csrf}, "action": {"connect"}}.Encode()), h)
		r.requireStatus(t, 302)
		providerDestinationNoIssuance(t, r)
	}
	connectedAccountsPage(t, f.send(t, client, "GET", o.endpoint, nil, nil))
	r = connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}})
	connectedAccountsPage(t, r)
	f.contracts.AssertResponse(t, "POST", "/connected-accounts/{ticket}", r.status, r.header, r.body)
	r = connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}})
	r.requireStatus(t, 410)
	f.contracts.AssertResponse(t, "POST", "/connected-accounts/{ticket}", r.status, r.header, r.body)
}

func testCaddyConnectedAccountsFreshness(t *testing.T, f *caddyConnectedAccountsFixture) {
	t.Helper()
	for _, kind := range []string{"prior_local", "unrelated_html", "superseded_html", "native_json", "cancel", "logout", "source_changed"} {
		t.Run(kind, func(t *testing.T) {
			var priorLocal string
			if kind == "prior_local" {
				local := f.browser(t)
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, local, f.issuer+"/login?fresh=1", "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, local, s, "alice")
				priorLocal = connectedAccountsCookie(t, f.localIdentityFixture, local, "AUTHP_ACCESS_TOKEN")
				f.verifyAccess(t, priorLocal)
			}
			client := f.browser(t)
			f.login(t, client, "upstream", 303)
			o := connectedAccountsBegin(t, f.localIdentityFixture, client)
			switch kind {
			case "prior_local":
				sid := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_SESSION_ID")
				r := f.send(t, f.plain, "POST", o.endpoint, strings.NewReader(url.Values{"csrf": {o.csrf}, "action": {"connect"}}.Encode()), http.Header{"Origin": {f.base}, "Content-Type": {"application/x-www-form-urlencoded"}, "Cookie": {"AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=" + priorLocal}})
				r.requireStatus(t, 403)
				providerDestinationNoIssuance(t, r)
				// No clock sleep: the bound new HTML flow succeeds independently of
				// whether the two real logins happened within one Unix second.
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, s, "alice")
				connectedAccountsPage(t, f.send(t, client, "GET", o.endpoint, nil, nil))
				connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"cancel"}}).requireStatus(t, 303)
			case "unrelated_html":
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, client, f.issuer+"/login?fresh=1", "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, s, "alice")
				f.send(t, client, "GET", o.endpoint, nil, nil).requireStatus(t, 403)
			case "superseded_html":
				a := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
				b := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, a, "alice")
				f.send(t, client, "GET", o.endpoint, nil, nil).requireStatus(t, 403)
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, b, "alice")
				connectedAccountsPage(t, f.send(t, client, "GET", o.endpoint, nil, nil))
				connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"cancel"}}).requireStatus(t, 303)
			case "native_json":
				start := apiauth.AuthRequest{Username: "alice", Realm: "local"}
				call := func(request apiauth.AuthRequest) apiauth.AuthResponse {
					data, _ := json.Marshal(request)
					r := f.send(t, client, "POST", o.loginURL, bytes.NewReader(data), http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}, "Origin": {f.base}})
					return localIdentityAuth(t, r)
				}
				state := call(start)
				start.SandboxID, start.SandboxSecret = state.SandboxID, state.SandboxSecret
				start.ChallengeKind, start.ChallengeResponse = "password", lifecyclePassword
				completed := call(start)
				if !completed.Authenticated {
					t.Fatal("native freshness control did not authenticate")
				}
				f.verifyAccess(t, completed.AccessToken)
				sid := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_SESSION_ID")
				r := f.send(t, f.plain, "GET", o.endpoint, nil, http.Header{"Cookie": {"AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=" + completed.AccessToken}})
				r.requireStatus(t, 302)
				providerDestinationNoIssuance(t, r)
			case "cancel":
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, s, "alice")
				connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"cancel"}}).requireStatus(t, 303)
				f.send(t, client, "GET", o.endpoint, nil, nil).requireStatus(t, 410)
			case "logout":
				f.send(t, client, "GET", "/logout", nil, nil).requireStatus(t, 302)
				f.login(t, client, "upstream", 303)
				f.send(t, client, "GET", o.endpoint, nil, nil).requireStatus(t, 410)
			case "source_changed":
				claims := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
				source := connectedAccountsRecordID(t, f.localIdentityFixture, claims["id"].(string))
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, s, "alice")
				admin := f.browser(t)
				a := connectedAccountsStartLocal(t, f.localIdentityFixture, admin, f.issuer+"/login?fresh=1", "admin")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, admin, a, "admin")
				f.admin(t, connectedAccountsCookie(t, f.localIdentityFixture, admin, "AUTHP_ACCESS_TOKEN"), "disable", map[string]any{"username": source.Username, "email": ""})
				r := connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}})
				r.requireStatus(t, 409)
				providerDestinationNoIssuance(t, r)
				connectedAccountsForm(t, f.localIdentityFixture, client, o.endpoint, url.Values{"csrf": {o.csrf}, "action": {"connect"}}).requireStatus(t, 410)
			}
			if len(localIdentityRecord(t, f.database, "alice").ExternalAccounts) != 0 {
				t.Fatal("rejected or canceled proof connected an account")
			}
		})
	}
}

func testCaddyConnectedAccountsNoninteractive(t *testing.T, f *caddyConnectedAccountsFixture, key string) {
	t.Helper()
	for _, kind := range []string{"api_key", "renewal"} {
		t.Run(kind, func(t *testing.T) {
			client := f.browser(t)
			f.login(t, client, "upstream", 303)
			o := connectedAccountsBegin(t, f.localIdentityFixture, client)
			if kind == "api_key" {
				payload, _ := json.Marshal(apiauth.AuthRequest{Realm: "local", APIKey: key})
				r := f.send(t, f.plain, "POST", "/login", bytes.NewReader(payload), http.Header{"Content-Type": {"application/json"}, "Accept": {"application/json"}})
				auth := localIdentityAuth(t, r)
				if !auth.Authenticated || auth.AccessToken == "" || len(r.header.Values("Set-Cookie")) != 0 {
					t.Fatal("API-key control did not remain access-only")
				}
				f.verifyAccess(t, auth.AccessToken)
				sid := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_SESSION_ID")
				r = f.send(t, f.plain, "GET", o.endpoint, nil, http.Header{"Cookie": {"AUTHP_SESSION_ID=" + sid + "; AUTHP_ACCESS_TOKEN=" + auth.AccessToken}})
				r.requireStatus(t, 302)
				providerDestinationNoIssuance(t, r)
			} else {
				s := connectedAccountsStartLocal(t, f.localIdentityFixture, client, f.issuer+"/login?fresh=1", "alice")
				connectedAccountsFinishLocal(t, f.localIdentityFixture, client, s, "alice")
				prior := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN")
				r := f.send(t, client, "POST", "/api/refresh_token", strings.NewReader(`{}`), http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}, "Content-Type": {"application/json"}})
				auth := localIdentityAuth(t, r)
				next := connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN")
				if !auth.Authenticated || next == prior || auth.AccessToken != "" || auth.RefreshToken != "" {
					t.Fatal("renewal freshness control did not rotate private browser credentials")
				}
				f.verifyAccess(t, next)
				r = f.send(t, client, "GET", o.endpoint, nil, nil)
				r.requireStatus(t, 403)
				providerDestinationNoIssuance(t, r)
			}
			if len(localIdentityRecord(t, f.database, "alice").ExternalAccounts) != 0 {
				t.Fatal("noninteractive credential confirmed a connection")
			}
		})
	}
}
