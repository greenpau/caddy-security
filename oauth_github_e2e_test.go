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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// Isolate Caddy globals, fixture trust roots and ProxyFromEnvironment's cache.
// Production GitHub URLs remain unchanged and TLS verification stays enabled.
func TestCaddyGithubTransformsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyGithubTransformsProcess$", "-test.v", "-test.timeout=150s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_GITHUB_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Caddy GitHub transform journeys: %v\n%s", err, output)
	}
	t.Logf("Caddy GitHub transform journeys:\n%s", output)
}

type githubTransformCase struct {
	name, id, login, driver, realm, matcher, orgFilter, orgBody string
	additionalMatcher                                           string
	wantID                                                      string
	wantOrgs                                                    []string
	allow, reject                                               bool
	orgStatus                                                   int
}

func TestCaddyGithubTransformsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_GITHUB_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, keyFile, roots := cookieTLSCertificate(t, "github.com", "api.github.com", "api.linkedin.com")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	signingKey := newOAuthE2EKey(t, "github-fixture", "EdDSA")
	var mu sync.Mutex
	var scenario githubTransformCase
	var callback, state, nonce string
	var exchanges, profiles, organizations int
	var upstream *httptest.Server
	upstream = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/metadata":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": upstream.URL, "authorization_endpoint": upstream.URL + "/authorize",
				"token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys",
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{signingKey.public}})
		case "/login/oauth/authorize", "/authorize":
			q := r.URL.Query()
			if q.Get("client_id") != oauthE2EClient || q.Get("redirect_uri") != callback || q.Get("state") == "" {
				http.Error(w, "invalid authorization", http.StatusBadRequest)
				return
			}
			state, nonce = q.Get("state"), q.Get("nonce")
			redirect, _ := url.Parse(callback)
			values := redirect.Query()
			values.Set("state", state)
			values.Set("code", "synthetic-code")
			redirect.RawQuery = values.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		case "/login/oauth/access_token", "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", 400)
				return
			}
			if state == "" || r.Form.Get("state") != state || r.Form.Get("client_id") != oauthE2EClient ||
				r.Form.Get("client_secret") != oauthE2ESecret || r.Form.Get("redirect_uri") != callback ||
				r.Form.Get("code") != "synthetic-code" {
				http.Error(w, "invalid exchange", http.StatusBadRequest)
				return
			}
			state = ""
			exchanges++
			token, err := signingKey.sign(map[string]any{"iss": upstream.URL, "sub": "linkedin-user", "aud": oauthE2EClient,
				"nonce": nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}, "")
			if err != nil {
				http.Error(w, "signing failure", 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-access", "token_type": "Bearer", "id_token": token})
		case "/user", "/v2/userinfo":
			profiles++
			prefix := "token "
			if scenario.driver == "linkedin" {
				prefix = "Bearer "
			}
			if r.Header.Get("Authorization") != prefix+"synthetic-access" {
				http.Error(w, "unauthenticated", 401)
				return
			}
			profile := map[string]any{
				"login": scenario.login, "sub": "linkedin-user", "name": "Alice", "email": "alice@example.test",
				"organizations_url": "https://api.github.com/users/" + scenario.login + "/orgs",
				// Fetched evidence, not these untrusted fields, must establish identity.
				"github_id": "123", "github_orgs": []string{"acme"}, "origin": "github",
				"roles": []string{"github_id", "github_orgs", "github-member"}, "groups": []string{"github.com/acme/members"},
			}
			if scenario.id != "" {
				profile["id"] = json.RawMessage(scenario.id)
			}
			_ = json.NewEncoder(w).Encode(profile)
		case "/user/emails":
			if r.Header.Get("Authorization") != "token synthetic-access" {
				http.Error(w, "unauthenticated", 401)
				return
			}
			_, _ = io.WriteString(w, `[{"email":"alice@example.test","primary":true,"verified":true}]`)
		default:
			if r.URL.Path == "/users/"+scenario.login+"/orgs" {
				organizations++
				if r.Header.Get("Authorization") != "token synthetic-access" {
					http.Error(w, "unauthenticated", 401)
					return
				}
				if scenario.orgStatus != 0 {
					w.WriteHeader(scenario.orgStatus)
				}
				_, _ = io.WriteString(w, scenario.orgBody)
				return
			}
			http.NotFound(w, r)
		}
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	proxy := newGithubTransformProxy(t, upstream.Listener.Addr().String())
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
	cases := []githubTransformCase{
		{name: "exact", id: "123", matcher: "match github id exact 123", wantID: "123", allow: true},
		{name: "renamed account", login: "renamed-alice", id: "123", matcher: "match github id exact 123", wantID: "123", allow: true},
		{name: "exact miss", id: "124", matcher: "match github id exact 123", wantID: "124"},
		{name: "regex", id: "456", matcher: "match github id regex ^(123|456)$", wantID: "456", allow: true},
		{name: "regex miss", id: "1234", matcher: "match github id regex ^123$", wantID: "1234"},
		{name: "large integer", id: "9007199254740993", matcher: "match github id exact 9007199254740993", wantID: "9007199254740993", allow: true},
		{name: "large neighbor", id: "9007199254740992", matcher: "match github id exact 9007199254740993", wantID: "9007199254740992"},
		{name: "maximum integer", id: "18446744073709551615", matcher: "match github id exact 18446744073709551615", wantID: "18446744073709551615", allow: true},
		{name: "missing ID cannot use spoofed claim", matcher: "match github id regex .*"},
		{name: "zero", id: "0", reject: true},
		{name: "negative", id: "-1", reject: true},
		{name: "null", id: "null", reject: true},
		{name: "fraction", id: "123.5", reject: true},
		{name: "string", id: `"123"`, reject: true},
		{name: "overflow", id: "18446744073709551616", reject: true},
		{name: "other driver named github", driver: "linkedin", realm: "github", id: "123", matcher: "match github id exact 123"},
		{name: "ID and org", id: "123", wantID: "123", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme"}]`, wantOrgs: []string{"acme"}, allow: true},
		{name: "ID and org wrong ID", id: "124", wantID: "124", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme"}]`, wantOrgs: []string{"acme"}},
		{name: "ID and org wrong org", id: "123", wantID: "123", matcher: "match github id exact 123", additionalMatcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"other"}]`, wantOrgs: []string{"other"}},
		{name: "organization exact", matcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"other"},{"login":"acme"}]`, wantOrgs: []string{"other", "acme"}, allow: true},
		{name: "organization regex", matcher: "match github org regex ^acme(-labs)?$", orgFilter: ".*", orgBody: `[{"login":"acme-labs"}]`, wantOrgs: []string{"acme-labs"}, allow: true},
		{name: "organization miss", matcher: "match github org exact acme", orgFilter: ".*", orgBody: `[{"login":"acme-labs"}]`, wantOrgs: []string{"acme-labs"}},
		{name: "organization regex miss", matcher: "match github org regex ^acme$", orgFilter: ".*", orgBody: `[{"login":"my-acme"}]`, wantOrgs: []string{"my-acme"}},
		{name: "organization filtered", matcher: "match github org exact acme", orgFilter: "^other$", orgBody: `[{"login":"acme"},{"login":"other"}]`, wantOrgs: []string{"other"}},
		{name: "organization lookup not enabled", matcher: "match github org regex .*"},
		{name: "no memberships", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `[]`},
		{name: "malformed organization login", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `[{"login":123},{"login":null},{"login":""}]`},
		{name: "organization API denial", matcher: "match github org regex .*", orgFilter: ".*", orgStatus: 403, orgBody: `[{"login":"acme"}]`},
		{name: "organization malformed JSON", matcher: "match github org regex .*", orgFilter: ".*", orgBody: `{`},
		{name: "other driver organization spoof", driver: "linkedin", realm: "github", matcher: "match github org exact acme", orgFilter: ".*"},
	}

	cases = append(cases,
		githubTransformCase{name: "organization case sensitive", matcher: "match github org exact Acme", orgFilter: ".*", orgBody: `[{"login":"acme"}]`, wantOrgs: []string{"acme"}},
		githubTransformCase{name: "quoted case insensitive regex", matcher: `match github org regex "(?i)^ACME(-labs)?$"`, orgFilter: ".*", orgBody: `[{"login":"acme-labs"}]`, wantOrgs: []string{"acme-labs"}, allow: true},
		githubTransformCase{name: "regex search semantics", matcher: "match github org regex acme", orgFilter: ".*", orgBody: `[{"login":"my-acme-labs"}]`, wantOrgs: []string{"my-acme-labs"}, allow: true},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.login == "" {
				tc.login = "alice"
			}
			if tc.driver == "" {
				tc.driver = "github"
			}
			if tc.realm == "" {
				tc.realm = "engineering"
			}
			if tc.matcher == "" {
				tc.matcher = "match github id regex .*"
			}
			addr := lifecycleAddress(t)
			mu.Lock()
			scenario, exchanges, profiles, organizations = tc, 0, 0, 0
			callback = "https://" + addr + "/auth/oauth2/" + tc.realm + "/authorization-code-callback"
			mu.Unlock()
			f := newCaddyGithubFixture(t, tc, addr, upstream.URL, certFile, keyFile, roots)
			token := loginCaddyGithub(t, f, tc)
			mu.Lock()
			gotExchanges, gotProfiles, gotOrgs := exchanges, profiles, organizations
			mu.Unlock()
			if gotExchanges != 1 || gotProfiles != 1 {
				t.Fatal("OAuth exchange and profile fetch were not exercised")
			}
			wantOrgCalls := 0
			if !tc.reject && tc.driver == "github" && tc.orgFilter != "" {
				wantOrgCalls = 1
			}
			if gotOrgs != wantOrgCalls {
				t.Fatalf("organization API calls = %d, want %d", gotOrgs, wantOrgCalls)
			}
			if tc.reject {
				return
			}
			parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(oauthE2EPortalKey), nil },
				jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(), jwt.WithJSONNumber())
			if err != nil || !parsed.Valid {
				t.Fatal("portal token failed independent signature verification")
			}
			claims := parsed.Claims.(jwt.MapClaims)
			id, hasID := claims["github_id"]
			if hasID != (tc.wantID != "") || (hasID && id != tc.wantID) {
				t.Fatal("incorrect GitHub ID in signed claims")
			}
			if tc.driver == "github" {
				if claims["sub"] != "github.com/"+tc.login {
					t.Fatal("existing subject behavior changed")
				}
				if tc.wantID != "" {
					metadata, ok := claims["metadata"].(map[string]any)
					if !ok || metadata["id"] != json.Number(tc.wantID) {
						t.Fatal("numeric metadata ID lost precision or changed type")
					}
				}
			} else if claims["sub"] != "linkedin-user" {
				t.Fatal("other driver's identity was not exercised")
			}
			var orgs []string
			if values, exists := claims["github_orgs"]; exists {
				list, ok := values.([]any)
				if !ok {
					t.Fatal("organization claim is not a list")
				}
				for _, value := range list {
					org, ok := value.(string)
					if !ok {
						t.Fatal("organization claim contains a non-string")
					}
					orgs = append(orgs, org)
				}
			}
			if diff := cmp.Diff(tc.wantOrgs, orgs); diff != "" {
				t.Fatal(diff)
			}
			roles, _ := claims["roles"].([]any)
			if slices.Contains(roles, any("github-member")) != tc.allow {
				t.Fatal("transform role disagrees with expected matcher result")
			}
			for _, org := range tc.wantOrgs {
				if !slices.Contains(roles, any("github.com/"+org+"/members")) {
					t.Fatal("legacy organization group was lost")
				}
			}
		})
	}
}

func newCaddyGithubFixture(t *testing.T, tc githubTransformCase, addr, upstream, certFile, keyFile string, roots *x509.CertPool) *caddyOAuthFixture {
	t.Helper()
	provider := fmt.Sprintf("driver %s\nrealm %s\nclient_id %s\nclient_secret %s\n", tc.driver, tc.realm, oauthE2EClient, oauthE2ESecret)
	if tc.driver != "github" {
		provider += "base_auth_url " + upstream + "\nmetadata_url " + upstream + "/metadata\n"
	}
	if tc.orgFilter != "" {
		provider += "user_org_filters " + tc.orgFilter + "\n"
	}
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 servers {
  protocols h1 h2
 }
 log {
  level ERROR
 }
 security {
  oauth identity provider upstream {
   %s
  }
  authentication portal myportal {
   enable identity provider upstream
   crypto key sign-verify %s
   transform user {
    %s
    %s
    match realm %s
    action add role github-member
   }
  }
  authorization policy members {
   crypto key verify %s
   set token sources cookie
   set auth url /auth/login
   allow roles github-member
  }
 }
}
https://%s {
 tls %q %q
 route /auth/* {
  authenticate with myportal
 }
 route /protected {
  authorize with members
  respond protected-resource 200
 }
}`, provider, oauthE2EPortalKey, tc.matcher, tc.additionalMatcher, tc.realm, oauthE2EPortalKey, addr, certFile, keyFile)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Reload adapted JSON through the public Caddy load/provision/start path.
	// Persisted matchers must retain their provider-specific spelling.
	var document struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	cfg := document.Apps.Security.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
	expectedMatchers := []string{}
	for _, line := range []string{tc.matcher, tc.additionalMatcher} {
		if line == "" {
			continue
		}
		args, err := cfgutil.DecodeArgs(line)
		if err != nil {
			t.Fatal(err)
		}
		expectedMatchers = append(expectedMatchers, cfgutil.EncodeArgs(args))
	}
	expectedMatchers = append(expectedMatchers, "exact match realm "+tc.realm)
	if diff := cmp.Diff(expectedMatchers, cfg.Matchers); diff != "" {
		t.Fatal(diff)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored transformer.Config
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(cfg, &restored); diff != "" {
		t.Fatal(diff)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment}
	t.Cleanup(tr.CloseIdleConnections)
	return &caddyOAuthFixture{base: "https://" + addr, client: &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func loginCaddyGithub(t *testing.T, f *caddyOAuthFixture, tc githubTransformCase) string {
	t.Helper()
	client := *f.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	location := f.base + "/auth/oauth2/" + tc.realm
	var response *http.Response
	for step := range 3 {
		response, _ = f.request(t, &client, location)
		if step < 2 {
			if response.StatusCode != http.StatusFound {
				t.Fatalf("OAuth redirect %d: HTTP %d", step, response.StatusCode)
			}
			location = response.Header.Get("Location")
		}
	}
	token := jarCookie(t, client.Jar, f.base+"/protected", "AUTHP_ACCESS_TOKEN")
	want := http.StatusSeeOther
	if tc.reject {
		want = http.StatusUnauthorized
	}
	if response.StatusCode != want {
		t.Fatalf("OAuth callback: HTTP %d, want %d", response.StatusCode, want)
	}
	if tc.reject {
		if token != "" || response.Header.Get("Authorization") != "" {
			t.Fatal("invalid identity issued portal credentials")
		}
		for _, c := range response.Cookies() {
			if c.Name == "AUTHP_ACCESS_TOKEN" && c.Value != "" && c.MaxAge >= 0 {
				t.Fatal("invalid identity issued a cookie")
			}
		}
	} else if token == "" {
		t.Fatal("valid OAuth login did not issue a token")
	}
	protected, body := f.request(t, &client, f.base+"/protected")
	want = http.StatusForbidden
	if tc.allow {
		want = http.StatusOK
	} else if tc.reject {
		want = http.StatusFound
	}
	if protected.StatusCode != want {
		t.Fatalf("protected route: HTTP %d, want %d", protected.StatusCode, want)
	}
	if tc.allow {
		if string(body) != "protected-resource" {
			t.Fatal("protected handler did not run")
		}
	} else if strings.Contains(string(body), "protected-resource") {
		t.Fatal("nonmatching user reached protected handler")
	}
	return token
}

func newGithubTransformProxy(t *testing.T, target string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var workers sync.WaitGroup
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || (r.Host != "github.com:443" && r.Host != "api.github.com:443" && r.Host != "api.linkedin.com:443") {
			http.Error(w, "proxy target rejected", http.StatusForbidden)
			return
		}
		upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			http.Error(w, "upstream unavailable", 502)
			return
		}
		client, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		deadline := time.Now().Add(15 * time.Second)
		_ = client.SetDeadline(deadline)
		_ = upstream.SetDeadline(deadline)
		mu.Lock()
		connections[client], connections[upstream] = true, true
		workers.Add(1)
		mu.Unlock()
		_, _ = fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			defer workers.Done()
			done := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
			_, _ = io.Copy(client, upstream)
			client.Close()
			upstream.Close()
			<-done
			mu.Lock()
			delete(connections, client)
			delete(connections, upstream)
			mu.Unlock()
		}()
	}))
	t.Cleanup(func() {
		proxy.Close()
		mu.Lock()
		for connection := range connections {
			connection.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return proxy
}
