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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// All scenarios run in one isolated Caddy process, sequentially. Only bounded
// HTTP workers in the disposal scenario run concurrently. No sibling suite or
// alternate authentication implementation participates in this qualification.
func TestCaddyCompositionE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCompositionProcess$", "-test.v", "-test.timeout=270s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_COMPOSITION_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	for _, secret := range []string{lifecyclePassword, oauthE2ESecret, applicationTestSecret, "PRIVATE KEY-----"} {
		if bytes.Contains(output, []byte(secret)) {
			t.Fatal("composition process leaked a credential into diagnostics")
		}
	}
	if err != nil {
		t.Fatalf("Caddy composition: %v\n%s", err, output)
	}
}

type compositionOptions struct {
	upstream, applications, op, refresh, custom, two bool
	capacity                                         int
	refreshRealms                                    string
}

type compositionFixture struct {
	*caddyTokenRefreshFixture
	opts                                              compositionOptions
	address, cert, tlsKey, secondBase, input, logPath string
	access, secondAccess, opKey, secondOP             jwksKeyFiles
	store                                             *OAuthRegistrationStoreConfig
	registration                                      *oidc.ClientConfig
	upstream                                          *oauthE2EUpstream
	resource                                          *httptest.Server
	hits                                              atomic.Int64
	secrets                                           []string
}

func newCompositionFixture(t *testing.T, opts compositionOptions, cert, key string, roots *x509.CertPool, upstream *oauthE2EUpstream) *compositionFixture {
	t.Helper()
	if opts.capacity == 0 {
		opts.capacity = 4
	}
	if opts.refreshRealms == "" {
		opts.refreshRealms = "employees contractors"
	}
	f := &compositionFixture{opts: opts, address: lifecycleAddress(t), cert: cert, tlsKey: key, upstream: upstream}
	f.access, f.secondAccess = newJWKSKeyFiles(t, "RSA", "refresh"), newJWKSKeyFiles(t, "RSA", "second")
	f.opKey, f.secondOP = newOIDCRPKey(t, "op"), newOIDCRPKey(t, "second-op")
	f.store, _ = registrationTestStore(t)
	registrationTestCreate(t, f.store, "client_id composed-client", "client_secret "+applicationTestSecret)
	s, err := f.store.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	app, err := s.application(t.Context(), "website", "v1")
	s.root.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.registration = app.Client
	f.resource = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		w.Header().Set("X-Protected-Upstream", "reached")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(f.resource.Close)
	_, port, _ := net.SplitHostPort(f.address)
	f.secondBase = "https://other.example.test:" + port
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.HasPrefix(address, "other.example.test:") {
				address = f.address
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	f.caddyTokenRefreshFixture = &caddyTokenRefreshFixture{base: "https://" + f.address, mount: "/auth", client: &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	f.inspectResponse = func(t *testing.T, status int, raw []byte, cookies []*http.Cookie) {
		assertAdminRedacted(t, raw, []string{lifecyclePassword, applicationTestSecret, oauthE2ESecret, "PRIVATE KEY-----"})
		if status >= 400 {
			assertAdminRedacted(t, raw, f.secrets)
		}
		var result apiauth.AuthResponse
		if json.Unmarshal(raw, &result) == nil {
			for _, value := range []string{result.AccessToken, result.RefreshToken, result.SandboxSecret} {
				if value != "" {
					f.secrets = append(f.secrets, value)
				}
			}
		}
		for _, cookie := range cookies {
			// The ordinary SESSION_ID is a request-correlation value logged by
			// AuthCrunch, not a login credential. Track the authority-bearing
			// cookies, including the separate opaque OIDC session credential.
			credential := cookie.Name == f.accessName() || cookie.Name == f.refreshName() || cookie.Name == f.oidcName() || cookie.Name == "SECOND_ACCESS_TOKEN" || cookie.Name == "SECOND_RENEWAL" || cookie.Name == "SECOND_OIDC_SESSION_ID"
			if credential && cookie.Value != "" && cookie.MaxAge >= 0 {
				f.secrets = append(f.secrets, cookie.Value)
			}
		}
	}
	f.logPath = t.TempDir() + "/caddy.log"
	f.input = f.configuration(t)
	if opts.upstream {
		upstream.mu.Lock()
		upstream.callback = f.base + "/auth/oauth2/upstream/authorization-code-callback"
		upstream.mu.Unlock()
	}
	f.load(t, f.input)
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
		logs, err := os.ReadFile(f.logPath)
		if err != nil {
			t.Error(err)
			return
		}
		if f.upstream != nil {
			f.upstream.mu.Lock()
			f.secrets = append(f.secrets, f.upstream.issuedSecrets...)
			f.upstream.mu.Unlock()
		}
		assertAdminRedacted(t, logs, append(f.secrets, lifecyclePassword, applicationTestSecret, oauthE2ESecret, "PRIVATE KEY-----"))
	})
	status, _, raw := registrationHTTP(t, f.client, "GET", f.base+"/auth/.well-known/jwks.json", nil, nil)
	var doc struct{ Keys []map[string]string }
	if status != 200 || json.Unmarshal(raw, &doc) != nil || len(doc.Keys) != 1 {
		t.Fatal("portal JWKS missing or OP key mixed into portal verification")
	}
	f.keys = doc.Keys
	return f
}

func (f *compositionFixture) configuration(t *testing.T) string {
	var security strings.Builder
	for _, realm := range []string{"employees", "contractors"} {
		fmt.Fprintf(&security, `local identity store %sdb {
 realm %s
 path :memory:
 user alice {
  email alice@example.test
  password %s
  roles authp/user
 }
 user admin {
  email admin@example.test
  password %s
  roles authp/admin authp/user
 }
}
`, realm, realm, lifecyclePassword, lifecyclePassword)
	}
	if f.opts.upstream {
		fmt.Fprintf(&security, `oauth identity provider upstream {
 realm upstream
 driver generic
 client_id %s
 client_secret %s
 base_auth_url %s
 authorization_url %s/authorize
 token_url %s/token
 issuer %s
 access token audience resource-api
 jwks key identity %q
 jwks key access %q
}
`, f.upstream.clientID, f.upstream.clientSecret, f.upstream.server.URL, f.upstream.server.URL, f.upstream.server.URL, f.upstream.server.URL, f.upstream.identity.pem(t, false), f.upstream.access.pem(t, false))
	}
	if f.opts.applications || f.opts.op {
		fmt.Fprintf(&security, `oauth registration store {
 path %q
}
oauth application website {
 registration v1
 redirect_uri https://rp.example.test/callback
 skip_consent on
}
oauth application public {
 client_id composed-public
 token_endpoint_auth_method none
 redirect_uri https://public.example.test/callback
}
`, f.store.Path)
	}
	portal := func(name, origin, mount, prefix string, access, op jwksKeyFiles) {
		fmt.Fprintf(&security, "authentication portal %s {\nenable identity stores employeesdb contractorsdb\nenable admin api\n%s\n", name, access.signer("refresh"))
		if f.opts.upstream {
			security.WriteString("enable identity provider upstream\n")
		}
		if prefix != "" {
			fmt.Fprintf(&security, "cookie prefix %s\ncookie refresh token name %s_RENEWAL\n", prefix, prefix)
		}
		fmt.Fprintf(&security, "cookie path %s\n", mount)
		if f.opts.op {
			fmt.Fprintf(&security, "oidc provider {\nissuer %s%s\nrealms employees contractors\nsigning key files %q\napplications website public\nmax sessions %d\n}\n", origin, mount, op.private, f.opts.capacity)
		}
		if f.opts.refresh {
			fmt.Fprintf(&security, "token refresh {\nrealms %s\npublic origin %s\nbase path %s\naccess lifetime 300\nidle timeout 600\nabsolute timeout 1800\nmax sessions %d\n}\n", f.opts.refreshRealms, origin, mount, f.opts.capacity)
		}
		security.WriteString("}\n")
	}
	prefix := ""
	if f.opts.custom {
		prefix = "COMPOSED"
	}
	portal("myportal", f.base, "/auth", prefix, f.access, f.opKey)
	if f.opts.two {
		portal("second", f.secondBase, "/other", "SECOND", f.secondAccess, f.secondOP)
	}
	policy := func(name, cookie string, access jwksKeyFiles) {
		fmt.Fprintf(&security, "authorization policy %s {\n%s\ndisable auth redirect\nvalidate bearer header\nset access_token cookie name %s\nallow roles authp/user resource/editor\n}\n", name, access.verifier("refresh"), cookie)
	}
	policy("app_policy", f.accessName(), f.access)
	if f.opts.two {
		policy("second_policy", "SECOND_ACCESS_TOKEN", f.secondAccess)
	}
	site := func(origin, mount, portal, policy string) string {
		return fmt.Sprintf(`%s {
 tls %q %q
 @portal path %s %s/*
 route {
  route %s/resource {
   authorize with %s
   reverse_proxy %s
  }
  route @portal {
   authenticate with %s
  }
  route {
   authorize with %s
   reverse_proxy %s
  }
 }
}
`, origin, f.cert, f.tlsKey, mount, mount, mount, policy, f.resource.URL, portal, policy, f.resource.URL)
	}
	config := fmt.Sprintf("{\nadmin off\npersist_config off\nauto_https off\nlog {\nlevel INFO\noutput file %q\n}\nsecurity {\n%s}\n}\n%s", f.logPath, security.String(), site(f.base, "/auth", "myportal", "app_policy"))
	if f.opts.two {
		config += site(f.secondBase, "/other", "second", "second_policy")
	}
	return config
}

func (f *compositionFixture) accessName() string {
	if f.opts.custom {
		return "COMPOSED_ACCESS_TOKEN"
	}
	return "AUTHP_ACCESS_TOKEN"
}
func (f *compositionFixture) refreshName() string {
	if f.opts.custom {
		return "COMPOSED_RENEWAL"
	}
	return "AUTHP_REFRESH_TOKEN"
}
func (f *compositionFixture) oidcName() string {
	if f.opts.custom {
		return "COMPOSED_OIDC_SESSION_ID"
	}
	return "AUTHP_OIDC_SESSION_ID"
}

func (f *compositionFixture) adapt(t *testing.T, input string) []byte {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(applicationTestSecret)) {
		t.Fatal("private registration escaped into adapted config")
	}
	return data
}
func (f *compositionFixture) load(t *testing.T, input string) {
	t.Helper()
	if err := caddy.Load(f.adapt(t, input), true); err != nil {
		t.Fatal(err)
	}
}
func (f *compositionFixture) active(t *testing.T) *App {
	t.Helper()
	app, err := caddy.ActiveContext().App("security")
	if err != nil {
		t.Fatal(err)
	}
	return app.(*App)
}

func (f *compositionFixture) resourceStatus(t *testing.T, token, path string, want int) {
	t.Helper()
	before := f.hits.Load()
	headers := http.Header{}
	if token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	status, response, body := registrationHTTP(t, f.client, "GET", f.base+path, nil, headers)
	wantHits := before
	if want == 204 {
		wantHits++
	}
	if status != want || (response.Get("X-Protected-Upstream") != "") != (want == 204) || f.hits.Load() != wantHits {
		t.Fatalf("protected %s: status=%d expected=%d upstream delta=%d", path, status, want, f.hits.Load()-before)
	}
	if want != 204 {
		if response.Get("Cache-Control") != "no-store" {
			t.Fatal("authorization denial permits caching")
		}
		assertAdminRedacted(t, body, f.secrets)
	}
}
func (f *compositionFixture) browserLogin(t *testing.T, client *http.Client, realm string, want int) (apiauth.AuthResponse, []*http.Cookie) {
	t.Helper()
	result, cookies := f.login(t, client, realm, "", want)
	if want >= 400 {
		if result.AccessToken != "" || result.RefreshToken != "" || result.Authenticated {
			t.Fatal("failed completion disclosed credentials")
		}
		for _, c := range cookies {
			if c.MaxAge >= 0 && (c.Name == f.accessName() || c.Name == f.refreshName() || c.Name == f.oidcName()) && c.Value != "" {
				t.Fatal("failed completion set an active credential")
			}
		}
	}
	return result, cookies
}

func (f *compositionFixture) exchange(t *testing.T, browser *http.Client) registrationRPResult {
	t.Helper()
	tokens := registrationRPExchange(t, browser, f.base+"/auth", f.registration, "incorrect-composition-secret")
	f.secrets = append(f.secrets, tokens.idToken, tokens.accessToken)
	return tokens
}

func TestCaddyCompositionProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_COMPOSITION_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t, "other.example.test")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	for _, tc := range []struct {
		name string
		opts compositionOptions
	}{
		{"absent", compositionOptions{}},
		{"upstream only", compositionOptions{upstream: true}},
		{"applications only", compositionOptions{applications: true}},
		{"OP only", compositionOptions{op: true}},
		{"refresh only", compositionOptions{refresh: true}},
		{"custom cookies only", compositionOptions{custom: true}},
		{"combined", compositionOptions{upstream: true, applications: true, op: true, refresh: true, custom: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newOAuthE2EUpstream(t, pair, "RS256")
			f := newCompositionFixture(t, tc.opts, cert, key, roots, u)
			browser := f.browser(t)
			result, cookies := f.browserLogin(t, browser, "employees", 200)
			access := result.AccessToken
			if tc.opts.refresh {
				access = tokenRefreshActiveCookie(t, cookies, f.accessName()).Value
			}
			if access == "" {
				t.Fatal("login did not produce access credential")
			}
			f.secrets = append(f.secrets, access)
			f.resourceStatus(t, access, "/protected", 204)
			f.resourceStatus(t, "", "/protected", 401)
			f.resourceStatus(t, "invalid-composition-bearer", "/protected", 401)
			for _, path := range []string{"/authentic/protected", "/auth-other/oidc/userinfo", "/auth/../protected", "/auth/%2e%2e/protected", "/auth%252f../protected", "/other/protected"} {
				f.resourceStatus(t, "", path, 401)
			}
			wantDiscovery := 404
			if tc.opts.op {
				wantDiscovery = 200
			}
			status, _, _ := registrationHTTP(t, f.client, "GET", f.base+"/auth/.well-known/openid-configuration", nil, nil)
			if status != wantDiscovery {
				t.Fatalf("OP feature status=%d want=%d", status, wantDiscovery)
			}
			if tc.opts.refresh {
				if result.SessionID == "" {
					t.Fatal("refresh feature did not issue family")
				}
				before := f.hits.Load()
				status, response, _ := registrationHTTP(t, browser, "GET", f.base+"/auth/resource", nil, nil)
				if status != 204 || response.Get("X-Protected-Upstream") != "reached" || f.hits.Load() != before+1 {
					t.Fatal("scoped access cookie did not authorize the protected upstream")
				}
				f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
			} else {
				f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 404)
			}
			if tc.opts.op {
				tokens := f.exchange(t, browser)
				for _, token := range []string{tokens.idToken, tokens.accessToken} {
					f.resourceStatus(t, token, "/protected", 401)
					status, headers, body := registrationHTTP(t, f.client, "GET", f.base+"/auth/whoami", nil, http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}})
					if status != 401 || headers.Get("Cache-Control") != "no-store" {
						t.Fatalf("OP credential portal denial: status=%d", status)
					}
					assertAdminRedacted(t, body, []string{token})
				}
				status, headers, body := registrationHTTP(t, f.client, "GET", f.base+"/auth/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + access}})
				if status != 401 || headers.Get("Cache-Control") != "no-store" {
					t.Fatal("portal JWT authorized UserInfo or failure cacheable")
				}
				assertAdminRedacted(t, body, []string{access})
			}
			if tc.opts.upstream {
				testCompositionOAuth(t, f)
			}
			gate, err := f.active(t).getGatekeeper("app_policy")
			if err != nil {
				t.Fatal(err)
			}
			gate.Close()
			f.resourceStatus(t, access, "/protected", 503)
		})
	}
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement custom=%t", custom), func(t *testing.T) {
			f := newCompositionFixture(t, compositionOptions{op: true, refresh: true, custom: custom, capacity: 1}, cert, key, roots, nil)
			testCompositionReplacement(t, f)
		})
		t.Run(fmt.Sprintf("completion recovery custom=%t", custom), func(t *testing.T) {
			f := newCompositionFixture(t, compositionOptions{op: true, refresh: true, custom: custom, capacity: 1, refreshRealms: "employees"}, cert, key, roots, nil)
			testCompositionRecovery(t, f)
		})
	}
	t.Run("reload and isolation", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, pair, "RS256")
		f := newCompositionFixture(t, compositionOptions{upstream: true, applications: true, op: true, refresh: true, custom: true, two: true}, cert, key, roots, u)
		testCompositionReload(t, f)
	})
	t.Run("edge trust", func(t *testing.T) {
		f := newCompositionFixture(t, compositionOptions{op: true, refresh: true, custom: true, capacity: 8}, cert, key, roots, nil)
		testCompositionEdge(t, f, pair)
	})
	t.Run("current roles", func(t *testing.T) {
		f := newCompositionFixture(t, compositionOptions{op: true, refresh: true, custom: true}, cert, key, roots, nil)
		testCompositionRoles(t, f)
	})
	t.Run("pending disposal", func(t *testing.T) {
		f := newCompositionFixture(t, compositionOptions{op: true, refresh: true, custom: true}, cert, key, roots, nil)
		testCompositionDisposal(t, f)
	})
	t.Run("real browser composition", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, pair, "RS256")
		f := newCompositionFixture(t, compositionOptions{upstream: true, applications: true, op: true, refresh: true, custom: true, capacity: 1}, cert, key, roots, u)
		state := &tokenRefreshBrowserState{staleRelease: make(chan struct{})}
		currentTokenRefreshBrowserProbe.Store(state)
		data := tokenRefreshBrowserAdapter(t, f.mount)(f.adapt(t, f.input))
		if err := caddy.Load(data, true); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
		defer cancel()
		runCaddyRefreshBrowser(t, ctx, caddyRefreshBrowserExecutable(t), cert, f.base, f.mount, f.refreshName(), f.accessName(), "composition")
	})
}

func testCompositionOAuth(t *testing.T, f *compositionFixture) {
	t.Helper()
	for _, failure := range []string{"", "identity issuer", "access audience"} {
		f.upstream.mu.Lock()
		f.upstream.failure = failure
		f.upstream.mu.Unlock()
		browser := f.browser(t)
		location := f.base + "/auth/oauth2/upstream"
		var status int
		for step := range 3 {
			var headers http.Header
			var body []byte
			status, headers, body = registrationHTTP(t, browser, "GET", location, nil, nil)
			if step == 2 {
				f.upstream.mu.Lock()
				f.secrets = append(f.secrets, f.upstream.issuedSecrets...)
				f.upstream.mu.Unlock()
				assertAdminRedacted(t, body, f.secrets)
				if status >= 400 && headers.Get("Cache-Control") != "no-store" {
					t.Fatal("upstream login failure permits caching")
				}
			}
			if step < 2 {
				if status != 302 {
					t.Fatalf("upstream OAuth step %d status=%d", step, status)
				}
				location = headers.Get("Location")
			}
		}
		access := jarCookie(t, browser.Jar, f.base+"/auth/portal", f.accessName())
		if failure == "identity issuer" {
			if status != 401 || access != "" {
				t.Fatal("untrusted upstream issuer authenticated")
			}
			continue
		}
		if status != 303 || access == "" {
			t.Fatalf("upstream login status=%d", status)
		}
		f.secrets = append(f.secrets, access)
		claims := verifyCaddyJWKSSignature(t, f.keys, access, "RS512", "refresh")
		hasEditor := false
		if roles, ok := claims["roles"].([]any); ok {
			for _, role := range roles {
				if role == "resource/editor" {
					hasEditor = true
				}
			}
		}
		if hasEditor != (failure == "") {
			t.Fatal("supplemental OAuth audience boundary changed")
		}
		f.resourceStatus(t, access, "/protected", 204)
		if jarCookie(t, browser.Jar, f.base+"/auth/portal", f.refreshName()) != "" || jarCookie(t, browser.Jar, f.base+"/auth/portal", f.oidcName()) != "" {
			t.Fatal("upstream OAuth supplied local refresh or downstream login evidence")
		}
	}
}

func (f *compositionFixture) userinfoStatus(t *testing.T, token string, want int) {
	t.Helper()
	status, headers, body := registrationHTTP(t, f.client, "GET", f.base+"/auth/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + token}})
	if status != want || headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("UserInfo status=%d want=%d or cacheable response", status, want)
	}
	assertAdminRedacted(t, body, []string{token})
}

func (f *compositionFixture) replay(t *testing.T, value, sid string) {
	t.Helper()
	headers := f.headers()
	headers.Set("Cookie", f.refreshName()+"="+value)
	headers.Set("X-Authcrunch-Refresh-Session", sid)
	result, _ := f.post(t, f.client, "/api/refresh_token", struct{}{}, headers, 401)
	if result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatal("failed refresh exposed credentials")
	}
}

func testCompositionReplacement(t *testing.T, f *compositionFixture) {
	browser := f.browser(t)
	first, cookies := f.browserLogin(t, browser, "employees", 200)
	oldRefresh := tokenRefreshActiveCookie(t, cookies, f.refreshName()).Value
	oldOP := f.exchange(t, browser)
	// One live slot: a separate browser cannot consume it, but a proven
	// replacement in the owning browser can switch realm at capacity.
	f.browserLogin(t, f.browser(t), "employees", 503)
	replacement, cookies := f.browserLogin(t, browser, "contractors", 200)
	if replacement.SessionID == "" || replacement.SessionID == first.SessionID {
		t.Fatal("realm replacement retained old refresh identity")
	}
	newRefresh := tokenRefreshActiveCookie(t, cookies, f.refreshName())
	access := tokenRefreshActiveCookie(t, cookies, f.accessName())
	f.claims(t, access.Value, "contractors", 300)
	for _, cookie := range []*http.Cookie{newRefresh, access, tokenRefreshActiveCookie(t, cookies, f.oidcName())} {
		if cookie.Path != "/auth" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatal("composed credential cookie scope/flags changed")
		}
	}
	f.replay(t, oldRefresh, first.SessionID)
	f.userinfoStatus(t, oldOP.accessToken, 401)
	newOP := f.exchange(t, browser)
	if newOP.subject == oldOP.subject {
		t.Fatal("two realms shared downstream subject")
	}
	rotated, cookies := f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
	if rotated.SessionID != replacement.SessionID {
		t.Fatal("rotation changed family")
	}
	current := tokenRefreshActiveCookie(t, cookies, f.refreshName())
	f.replay(t, newRefresh.Value, replacement.SessionID)
	// A spent-token replay revokes the replacement family, including its newest
	// credential. The already signed access JWT remains stateless until expiry.
	f.replay(t, current.Value, replacement.SessionID)
	f.resourceStatus(t, access.Value, "/protected", 204)
	f.post(t, browser, "/api/logout", struct{}{}, f.headers(), 200)
	f.browserLogin(t, browser, "employees", 200)
	_, deleted := f.post(t, browser, "/api/logout", struct{}{}, f.headers(), 200)
	for _, path := range []string{"/auth", "/auth/api/refresh_token"} {
		found := false
		for _, c := range deleted {
			if c.Name == f.refreshName() && c.Path == path && c.MaxAge < 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("logout omitted refresh tombstone for %s", path)
		}
	}
}

func testCompositionRecovery(t *testing.T, f *compositionFixture) {
	holder := f.browser(t)
	f.browserLogin(t, holder, "contractors", 200)
	if jarCookie(t, holder.Jar, f.base+"/auth/portal", f.oidcName()) == "" || jarCookie(t, holder.Jar, f.base+"/auth/portal", f.refreshName()) != "" {
		t.Fatal("bottleneck must occupy only the OP store")
	}
	login := f.browser(t)
	// Refresh issuance precedes OP completion. The OP is full but the refresh
	// store is empty; failure must reclaim the just-issued refresh family.
	f.browserLogin(t, login, "employees", 503)
	f.post(t, holder, "/api/logout", struct{}{}, f.headers(), 200)
	result, cookies := f.browserLogin(t, login, "employees", 200)
	if result.SessionID == "" {
		t.Fatal("failed OP completion leaked refresh capacity")
	}
	f.claims(t, tokenRefreshActiveCookie(t, cookies, f.accessName()).Value, "employees", 300)
	rotated, _ := f.post(t, login, "/api/refresh_token", struct{}{}, f.headers(), 200)
	if rotated.SessionID != result.SessionID {
		t.Fatal("recovered login cannot rotate")
	}
	f.exchange(t, login)
}

func testCompositionReload(t *testing.T, f *compositionFixture) {
	browser := f.browser(t)
	login, cookies := f.browserLogin(t, browser, "employees", 200)
	access := tokenRefreshActiveCookie(t, cookies, f.accessName()).Value
	refresh := tokenRefreshActiveCookie(t, cookies, f.refreshName()).Value
	tokens := f.exchange(t, browser)
	second := &caddyTokenRefreshFixture{base: f.secondBase, mount: "/other", client: f.client, inspectResponse: f.inspectResponse}
	secondBrowser := second.browser(t)
	secondLogin, secondCookies := second.login(t, secondBrowser, "contractors", "", 200)
	secondAccess := tokenRefreshActiveCookie(t, secondCookies, "SECOND_ACCESS_TOKEN").Value
	secondRefresh := tokenRefreshActiveCookie(t, secondCookies, "SECOND_RENEWAL").Value
	secondResourceStatus, secondResourceHeaders, _ := registrationHTTP(t, secondBrowser, "GET", f.secondBase+"/other/resource", nil, nil)
	if secondResourceStatus != 204 || secondResourceHeaders.Get("X-Protected-Upstream") != "reached" {
		t.Fatal("second portal's scoped access cookie did not authorize its resource")
	}
	secondTokens := registrationRPExchange(t, secondBrowser, f.secondBase+"/other", f.registration, "incorrect-secret")
	f.secrets = append(f.secrets, secondTokens.idToken, secondTokens.accessToken)
	if secondTokens.keyID == tokens.keyID || secondTokens.subject == tokens.subject {
		t.Fatal("independent issuers shared OP key or subject")
	}
	f.resourceStatus(t, secondAccess, "/protected", 401)
	for _, cookie := range secondCookies {
		if cookie.Value != "" && cookie.MaxAge >= 0 && (cookie.Name == "SECOND_ACCESS_TOKEN" || cookie.Name == "SECOND_RENEWAL" || cookie.Name == "SECOND_OIDC_SESSION_ID") {
			if cookie.Path != "/other" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly {
				t.Fatal("second portal cookie escaped scope")
			}
		}
	}
	for _, target := range []string{f.base + "/other/portal", f.secondBase + "/other/portal"} {
		for _, name := range []string{f.accessName(), f.refreshName(), f.oidcName()} {
			if jarCookie(t, browser.Jar, target, name) != "" {
				t.Fatal("cookie escaped portal host/mount")
			}
		}
	}
	// Copy and rename credentials in both directions: host/path and cookie
	// names are browser delivery controls, not the server-side trust boundary.
	for _, crossing := range []struct {
		target                          *caddyTokenRefreshFixture
		accessName, refreshName, opName string
		access, refresh, sid, session   string
		tokens                          registrationRPResult
	}{
		{second, "SECOND_ACCESS_TOKEN", "SECOND_RENEWAL", "SECOND_OIDC_SESSION_ID", access, refresh, login.SessionID, tokenRefreshActiveCookie(t, cookies, f.oidcName()).Value, tokens},
		{f.caddyTokenRefreshFixture, f.accessName(), f.refreshName(), f.oidcName(), secondAccess, secondRefresh, secondLogin.SessionID, tokenRefreshActiveCookie(t, secondCookies, "SECOND_OIDC_SESSION_ID").Value, secondTokens},
	} {
		target := crossing.target
		for _, path := range []string{"/protected", target.mount + "/whoami", target.mount + "/oidc/userinfo"} {
			for _, token := range []string{crossing.access, crossing.tokens.idToken, crossing.tokens.accessToken} {
				before := f.hits.Load()
				status, response, body := registrationHTTP(t, f.client, "GET", target.base+path, nil, http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}})
				if status != 401 || response.Get("Cache-Control") != "no-store" || response.Get("X-Protected-Upstream") != "" || f.hits.Load() != before {
					t.Fatalf("cross-issuer %s denial: status=%d", path, status)
				}
				assertAdminRedacted(t, body, f.secrets)
			}
		}
		headers := target.headers()
		headers.Set("Cookie", crossing.refreshName+"="+crossing.refresh)
		headers.Set("X-Authcrunch-Refresh-Session", crossing.sid)
		target.post(t, f.client, "/api/refresh_token", struct{}{}, headers, 401)
		query := url.Values{"client_id": {f.registration.ClientID}, "response_type": {"code"}, "redirect_uri": {f.registration.RedirectURIs[0]}, "scope": {"openid"}, "state": {"isolation"}, "nonce": {"isolation"}, "prompt": {"none"}, "code_challenge_method": {"S256"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}}
		issuer := target.base + target.mount
		status, response, body := registrationHTTP(t, f.client, "GET", issuer+"/oidc/authorize?"+query.Encode(), nil, http.Header{"Cookie": {crossing.opName + "=" + crossing.session + "; " + crossing.accessName + "=" + crossing.access}})
		if _, err := verifyOIDCRPCallback(oidcRPResponse{status: status, header: response, body: body}, query, issuer, "login_required"); err != nil {
			t.Fatal(err)
		}
		assertAdminRedacted(t, body, f.secrets)
	}
	status, _, body := registrationHTTP(t, f.client, "GET", f.secondBase+"/other/.well-known/openid-configuration", nil, nil)
	var discovery map[string]any
	if status != 200 || json.Unmarshal(body, &discovery) != nil || discovery["issuer"] != f.secondBase+"/other" {
		t.Fatal("second issuer lost host/mount")
	}
	saved := registrationSnapshot(t, f.store.Path)
	keyBefore := make(map[string][]byte)
	for _, keys := range []jwksKeyFiles{f.access, f.secondAccess, f.opKey, f.secondOP} {
		data, err := os.ReadFile(keys.private)
		if err != nil || len(data) == 0 {
			t.Fatal("read persisted signing key")
		}
		keyBefore[keys.private] = data
	}
	old := f.active(t)
	bad := strings.Replace(f.input, f.opKey.private, f.opKey.private+".missing", 1)
	if err := caddy.Load(f.adapt(t, bad), true); err == nil {
		t.Fatal("invalid replacement activated")
	}
	if f.active(t) != old {
		t.Fatal("failed replacement displaced active deployment")
	}
	f.resourceStatus(t, access, "/protected", 204)
	f.userinfoStatus(t, tokens.accessToken, 200)
	secondStatus, secondHeaders, _ := registrationHTTP(t, f.client, "GET", f.secondBase+"/other/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + secondTokens.accessToken}})
	if secondStatus != 200 || secondHeaders.Get("Cache-Control") != "no-store" {
		t.Fatal("failed reload displaced second issuer grant")
	}
	secondRotated, _ := second.post(t, secondBrowser, "/api/refresh_token", struct{}{}, second.headers(), 200)
	if secondRotated.SessionID != secondLogin.SessionID {
		t.Fatal("failed reload displaced second portal")
	}
	rotated, cookies := f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
	if rotated.SessionID != login.SessionID {
		t.Fatal("failed replacement lost volatile family")
	}
	refresh = tokenRefreshActiveCookie(t, cookies, f.refreshName()).Value
	f.load(t, f.input)
	assertServerClosed(t, old)
	if diff := cmp.Diff(saved, registrationSnapshot(t, f.store.Path)); diff != "" {
		t.Fatal("reload changed immutable registrations")
	}
	for path, before := range keyBefore {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("reload changed persisted signing key")
		}
	}
	f.resourceStatus(t, access, "/protected", 204)
	f.userinfoStatus(t, tokens.accessToken, 401)
	second.post(t, secondBrowser, "/api/refresh_token", struct{}{}, second.headers(), 401)
	secondStatus, secondHeaders, _ = registrationHTTP(t, f.client, "GET", f.secondBase+"/other/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + secondTokens.accessToken}})
	if secondStatus != 401 || secondHeaders.Get("Cache-Control") != "no-store" {
		t.Fatal("second issuer grant survived replacement")
	}
	f.replay(t, refresh, login.SessionID)
	f.browserLogin(t, browser, "employees", 200)
	next := f.exchange(t, browser)
	// :memory: identities are freshly provisioned on replacement; their UUIDs
	// and pairwise subjects are not durable. Only registration/key identity is.
	if next.keyID != tokens.keyID {
		t.Fatal("replacement changed persisted provider key")
	}
}
