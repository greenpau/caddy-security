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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the production Caddy command with local, independently signed OIDC
// assertions and verified TLS. No portal or authenticate route is present.
func TestCaddyDirectOAuthE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy: %v\n%s", err, output)
	}
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprintf("custom_%t", custom), func(t *testing.T) {
			f := newDirectCaddy(t, binary, custom)
			f.journeys(t)
			t.Run("termination", func(t *testing.T) { f.termination(t, custom) })
			if !custom {
				f.browserJourney(t)
				t.Run("pending_expiry", func(t *testing.T) { f.pendingExpiry(t) })
			}
			f.lifecycle(t)
		})
	}
}

type directCaddy struct {
	*persistentCaddy
	provider                                                     *oauthE2EUpstream
	hits                                                         atomic.Int64
	cert, key, basePath, sessionCookie, loginCookie, otherOrigin string
	httpOrigin                                                   string
	configData                                                   []byte
	pinnedOrigin                                                 bool
}

func newDirectCaddy(t *testing.T, binary string, custom bool) *directCaddy {
	t.Helper()
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	f := &directCaddy{persistentCaddy: newPersistentCaddy(t, binary, cert, key, roots), cert: cert, key: key, basePath: "/_authcrunch/oauth2/direct", sessionCookie: "AUTHZ_direct_SESSION", loginCookie: "AUTHZ_direct_LOGIN", pinnedOrigin: custom}
	f.otherOrigin = "https://" + lifecycleAddress(t)
	f.httpOrigin = "http://" + lifecycleAddress(t)
	f.provider = newOAuthE2EUpstream(t, pair, "EdDSA")
	f.provider.failure = "identity no roles"
	protected := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.TLS == nil {
			t.Error("protected upstream did not use TLS")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"uri": r.RequestURI, "email": r.Header.Get("X-Token-User-Email"), "user": r.Header.Get("X-Caddy-User"), "roles": r.Header.Get("X-Token-User-Roles"), "cookies": r.Header.Get("Cookie")})
	}))
	protected.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	protected.StartTLS()
	t.Cleanup(protected.Close)
	options := ""
	if custom {
		f.basePath = "/private/oauth"
		f.sessionCookie = "__Host-APP_SESSION"
		f.loginCookie = "__Host-APP_LOGIN"
		t.Setenv("DIRECT_E2E_ORIGIN", f.base)
		t.Setenv("DIRECT_E2E_CAPACITY", "100")
		options = "oauth public origin {env.DIRECT_E2E_ORIGIN}\noauth base path /private/oauth\noauth session cookie name __Host-APP_SESSION\noauth login cookie name __Host-APP_LOGIN\noauth maximum sessions {env.DIRECT_E2E_CAPACITY}"
	}
	f.provider.callback = f.base + f.basePath + "/authorization-code-callback"
	security := fmt.Sprintf(`authorization policy direct {
 use oauth identity provider upstream
 %s
 inject headers with claims
 validate method path
 validate source address
 enable strip token
 bypass uri exact /public
 bypass uri prefix %s
 acl rule {
  match path /denied
  deny stop
 }
 acl rule {
  match method DELETE
  deny stop
 }
 allow roles authp/user
}
authorization policy jwt_rejection {
 crypto key verify synthetic-direct-oauth-regression-key
 disable auth redirect
 validate bearer header
 allow roles viewer
}
authorization policy narrow {
 use oauth identity provider upstream
 oauth base path /narrow/oauth
 allow roles authp/admin
}
authorization policy second {
 use oauth identity provider upstream
 oauth base path /second/oauth
 allow roles authp/user
}
authorization policy limits {
 use oauth identity provider upstream
 oauth base path /limits/oauth
 oauth session lifetime 2
 oauth maximum sessions 1
 oauth maximum pending logins 2
 allow roles authp/user
}
oauth identity provider upstream {
 driver generic
 realm upstream
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 scopes openid profile email
}`, options, f.basePath, oauthE2EClient, oauthE2ESecret, f.provider.server.URL, f.provider.server.URL)
	proxy := fmt.Sprintf(`reverse_proxy %s {
 header_up X-Caddy-User {http.auth.user.id}
}`, protected.URL)
	routes := fmt.Sprintf(`route /favicon.ico {
 respond "" 404
}
route /auth/.well-known/jwks.json {
 respond "" 404
}
route /jwt/* {
 authorize with jwt_rejection
 %s
}
route /narrow/* {
 authorize with narrow
 %s
}
route /second/* {
 authorize with second
 %s
}
route /limits/* {
 authorize with limits
 %s
}
route {
 authorize with direct
 %s
}
handle_errors {
 respond "CADDY_ERROR:{err.status_code}" {err.status_code}
}`, proxy, proxy, proxy, proxy, proxy)
	input := f.input(security, routes, cert, key)
	input = strings.Replace(input, fmt.Sprintf("  state {\n   directory %q\n  }\n", f.directory), "", 1)
	input = strings.Replace(input, " auto_https off", " auto_https off\n servers {\n trusted_proxies static 127.0.0.1/32\n }", 1)
	input += fmt.Sprintf("\n%s {\n tls %q %q\n route {\n authorize with direct\n %s\n }\n}\n", f.otherOrigin, cert, key, proxy)
	input += fmt.Sprintf("\n%s {\n route {\n authorize with direct\n %s\n }\n}\n", f.httpOrigin, proxy)
	f.configData = f.write(t, input)
	// Restore only serialized JSON into the actual binary.
	f.start(t)
	if custom {
		restored := persistentRequest(t, f.client, "GET", "http://"+f.admin+"/config/apps/security/", nil, nil, 200)
		if !strings.Contains(string(restored.body), "{env.DIRECT_E2E_ORIGIN}") || !strings.Contains(string(restored.body), "oauth_authorization_directives") {
			t.Fatal("provisioning replaced declarative OAuth snapshots")
		}
	}
	return f
}

func (f *directCaddy) request(t *testing.T, c *http.Client, method, target string, headers http.Header, status int, upstream bool) oidcRPResponse {
	t.Helper()
	before := f.hits.Load()
	response := persistentRequest(t, c, method, target, nil, headers, status)
	delta := f.hits.Load() - before
	want := int64(0)
	if upstream {
		want = 1
	}
	if delta != want {
		t.Fatalf("%s %s invoked upstream %d times, want %d", method, target, delta, want)
	}
	if !upstream && strings.Contains(string(response.body), "CADDY_ERROR") {
		t.Fatal("handled response entered handle_errors")
	}
	if !upstream && response.header.Get("Cache-Control") != "no-store" {
		t.Fatal("handled response missing no-store")
	}
	expectedBody := http.StatusText(status) + "\n"
	if status == 403 && !strings.Contains(target, "/logout") && !strings.Contains(target, "authorization-code-callback") {
		expectedBody = "Forbidden"
	}
	if !upstream && method != "HEAD" && status >= 400 && string(response.body) != expectedBody {
		t.Fatalf("handled body changed: %q", response.body)
	}
	return response
}
func (f *directCaddy) begin(t *testing.T, c *http.Client, target string) string {
	t.Helper()
	first := f.request(t, c, "GET", f.base+target, nil, 302, false)
	u, err := url.Parse(first.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != strings.TrimPrefix(f.provider.server.URL, "https://") {
		t.Fatal("foreign provider redirect")
	}
	callback := persistentRequest(t, c, "GET", u.String(), nil, nil, 302)
	return callback.header.Get("Location")
}
func (f *directCaddy) setCallback(path string) {
	f.provider.mu.Lock()
	defer f.provider.mu.Unlock()
	f.provider.callback = f.base + path + "/authorization-code-callback"
}
func (f *directCaddy) cookieHeaders(c *http.Client) http.Header {
	u, _ := url.Parse(f.base)
	r := &http.Request{Header: make(http.Header)}
	for _, cookie := range c.Jar.Cookies(u) {
		r.AddCookie(cookie)
	}
	return r.Header
}
func (f *directCaddy) noSession(t *testing.T, c *http.Client) {
	t.Helper()
	u, _ := url.Parse(f.base)
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == f.sessionCookie {
			t.Fatal("rejected login created session")
		}
	}
}

func (f *directCaddy) journeys(t *testing.T) {
	t.Run("baseline_identity_and_request_policy", func(t *testing.T) {
		c := f.persistentCaddy.browser(t)
		target := "/files/a%20b?x=one%26two&x=three+four"
		callback := f.begin(t, c, target)
		done := f.request(t, c, "GET", callback, nil, 303, false)
		if done.header.Get("Location") != target {
			t.Fatal("escaped return URI changed")
		}
		cookies := (&http.Response{Header: done.header}).Cookies()
		if len(done.header.Values("Set-Cookie")) != 2 {
			t.Fatalf("lost callback cookies: %v", done.header.Values("Set-Cookie"))
		}
		names := make(map[string]bool)
		for _, cookie := range cookies {
			if names[cookie.Name] {
				t.Fatal("duplicated callback cookie")
			}
			names[cookie.Name] = true
			if cookie.Name == f.sessionCookie && (cookie.Value == "" || cookie.MaxAge != 900) {
				t.Fatal("missing absolute session cookie lifetime")
			}
			if cookie.Name == f.loginCookie && (cookie.Value != "" || cookie.MaxAge >= 0) {
				t.Fatal("completed login cookie was not cleared")
			}
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" || (cookie.Name != f.sessionCookie && cookie.Name != f.loginCookie) {
				t.Fatal("incorrect OAuth cookie")
			}
		}
		response := f.request(t, c, "GET", f.base+target, nil, 200, true)
		var claims map[string]string
		if err := json.Unmarshal(response.body, &claims); err != nil {
			t.Fatal(err)
		}
		if claims["uri"] != target || claims["email"] == "" || claims["user"] == "" || !strings.Contains(claims["roles"], "authp/user") || strings.Contains(claims["roles"], "authp/admin") || strings.Contains(claims["cookies"], f.sessionCookie+"=") {
			t.Fatalf("bad authorized metadata: %v", claims)
		}
		f.request(t, c, "GET", f.base+"/denied", nil, 403, false)
		f.request(t, c, "DELETE", f.base+"/files", nil, 403, false)
		f.request(t, c, "GET", f.base+"/files", http.Header{"X-Forwarded-For": {"198.51.100.9"}}, 403, false)
		f.request(t, c, "GET", f.base+"/files", nil, 200, true)
		bypass := f.request(t, c, "GET", f.base+"/public", http.Header{"X-Token-User-Email": {"spoof@example.test"}, "X-Token-User-Roles": {"authp/admin"}, "X-Caddy-User": {"spoof"}}, 200, true)
		if err := json.Unmarshal(bypass.body, &claims); err != nil {
			t.Fatal(err)
		}
		if claims["email"] != "" || claims["roles"] != "" || claims["user"] != "" {
			t.Fatal("bypass admitted spoofed identity")
		}
		raw := f.cookieHeaders(c)
		session := ""
		for _, cookie := range (&http.Request{Header: raw}).Cookies() {
			if cookie.Name == f.sessionCookie {
				session = cookie.Value
			}
		}
		if session == "" {
			t.Fatal("session isolation requires an issued credential")
		}
		wrongOriginStatus := http.StatusUnauthorized
		if f.pinnedOrigin {
			wrongOriginStatus = http.StatusBadRequest
		}
		f.request(t, f.client, "POST", f.otherOrigin+"/files", raw, wrongOriginStatus, false)
		for _, policy := range []string{"second", "narrow"} {
			// Even the correct destination cookie name cannot transplant a
			// credential from a different policy using the same provider.
			header := http.Header{"Cookie": {"AUTHZ_" + policy + "_SESSION=" + session}}
			f.request(t, f.client, "POST", f.base+"/"+policy+"/files", header, 401, false)
		}
		f.request(t, c, "GET", f.base+"/files", nil, 200, true)
		for _, header := range []http.Header{{"Authorization": {"Bearer " + session}}, {"Authorization": {"Basic c3Bvb2Y6c3Bvb2Y="}}, {"Cookie": {"access_token=" + session}}} {
			f.request(t, f.client, "POST", f.base+"/files", header, 401, false)
		}
		f.request(t, f.client, "POST", f.base+"/files?access_token="+url.QueryEscape(session), nil, 401, false)
		f.request(t, c, "GET", callback, nil, 400, false)
		f.request(t, c, "GET", f.base+f.basePath+"/logout", nil, 405, false)
		f.request(t, c, "POST", f.base+f.basePath+"/logout", http.Header{"Origin": {"https://hostile.example"}}, 403, false)
		logout := f.request(t, c, "POST", f.base+f.basePath+"/logout", http.Header{"Origin": {f.base}}, 204, false)
		if len(logout.header.Values("Set-Cookie")) != 2 || len(logout.body) != 0 {
			t.Fatal("logout response changed")
		}
		f.request(t, f.client, "POST", f.base+"/files", raw, 401, false)
	})
	t.Run("unhandled_JWT_error_route", func(t *testing.T) {
		before := f.hits.Load()
		response := persistentRequest(t, f.client, "GET", f.base+"/jwt/private", nil, nil, 401)
		if string(response.body) != "CADDY_ERROR:401" || f.hits.Load() != before {
			t.Fatal("unhandled denial lost Caddy error handling or called upstream")
		}
	})
	t.Run("protocol_rejections", func(t *testing.T) {
		for _, failure := range []string{"identity nonce", "identity missing nonce", "identity signature", "identity issuer", "identity audience", "identity expired", "identity malformed", "identity missing subject", "provider error"} {
			t.Run(failure, func(t *testing.T) {
				f.provider.mu.Lock()
				f.provider.failure = failure
				f.provider.mu.Unlock()
				c := f.persistentCaddy.browser(t)
				callback := f.begin(t, c, "/files")
				f.request(t, c, "GET", callback, nil, 401, false)
				f.noSession(t, c)
			})
		}
		f.provider.mu.Lock()
		f.provider.failure = "identity no roles"
		f.provider.mu.Unlock()
	})
	t.Run("callback_binding", func(t *testing.T) {
		for _, mode := range []string{"missing state", "duplicate state", "bad state", "missing code", "duplicate code", "malformed query", "empty code", "direct token", "wrong browser", "wrong origin", "encoded callback", "POST", "HEAD"} {
			t.Run(mode, func(t *testing.T) {
				c := f.persistentCaddy.browser(t)
				callback := f.begin(t, c, "/files")
				u, _ := url.Parse(callback)
				q := u.Query()
				client := c
				method := "GET"
				status := 400
				switch mode {
				case "missing state":
					q.Del("state")
				case "duplicate state":
					q.Add("state", q.Get("state"))
				case "bad state":
					q.Set("state", "malformed")
				case "empty code":
					q.Set("code", "")
				case "missing code":
					q.Del("code")
				case "duplicate code":
					q.Add("code", q.Get("code"))
				case "direct token":
					q.Set("id_token", "forged")
					q.Del("code")
				case "wrong browser":
					client = f.persistentCaddy.browser(t)
				case "wrong origin":
					u.Host = strings.TrimPrefix(f.otherOrigin, "https://")
				case "encoded callback":
					u.RawPath = strings.Replace(u.Path, "authorization", "%61uthorization", 1)
				case "POST", "HEAD":
					method = mode
					status = 405
				}
				u.RawQuery = q.Encode()
				if mode == "malformed query" {
					u.RawQuery += "&code=%zz"
				}
				// Origin is bound even when an attacker manually transplants the browser cookie.
				var headers http.Header
				if mode == "wrong origin" {
					headers = f.cookieHeaders(c)
					client = f.client
				}
				f.request(t, client, method, u.String(), headers, status, false)
				f.noSession(t, c)
				f.request(t, c, "GET", callback, nil, 303, false)
			})
		}
	})
	t.Run("methods_namespace_and_forwarded_origin", func(t *testing.T) {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
			f.request(t, f.client, method, f.base+"/files", nil, 401, false)
		}
		for _, method := range []string{"GET", "HEAD"} {
			response := f.request(t, f.persistentCaddy.browser(t), method, f.base+"/files?redirect_url=https://hostile.example", http.Header{"X-Forwarded-Host": {"hostile.example"}, "X-Forwarded-Proto": {"http"}, "X-Forwarded-Uri": {"https://hostile.example"}}, 302, false)
			location, _ := url.Parse(response.header.Get("Location"))
			if location.Query().Get("redirect_uri") != f.base+f.basePath+"/authorization-code-callback" {
				t.Fatal("forwarded headers selected callback")
			}
		}
		f.request(t, f.client, "GET", f.base+f.basePath+"/unknown", nil, 404, false)
		f.request(t, f.client, "GET", f.base+f.basePath+"/authorization-code-callback", nil, 400, false)
	})

	t.Run("hostile_return_target", func(t *testing.T) {
		c := f.persistentCaddy.browser(t)
		target := "/files?redirect_url=https://hostile.example&return_to=%2f%2fhostile.example"
		callback := f.begin(t, c, target)
		done := f.request(t, c, "GET", callback, nil, 303, false)
		if done.header.Get("Location") != target {
			t.Fatal("foreign return target selected")
		}
		f.request(t, f.persistentCaddy.browser(t), "GET", f.base+"//hostile.example/private", nil, 400, false)
	})
	t.Run("narrow_and_shared_provider", func(t *testing.T) {
		f.setCallback("/narrow/oauth")
		c := f.persistentCaddy.browser(t)
		callback := f.begin(t, c, "/narrow/files")
		f.request(t, c, "GET", callback, nil, 403, false)
		f.setCallback(f.basePath)
		c = f.persistentCaddy.browser(t)
		callback = f.begin(t, c, "/files")
		f.request(t, c, "GET", callback, nil, 303, false)
		f.setCallback("/second/oauth")
		second := f.begin(t, c, "/second/files")
		f.request(t, c, "GET", second, nil, 303, false)
		f.request(t, c, "GET", f.base+"/second/files", nil, 200, true)
		f.request(t, c, "POST", f.base+"/second/oauth/logout", http.Header{"Origin": {f.base}}, 204, false)
		f.request(t, c, "GET", f.base+"/files", nil, 200, true)
		f.request(t, c, "POST", f.base+"/second/files", nil, 401, false)
		f.setCallback(f.basePath)
	})
	t.Run("shared_provider_pending_isolation", func(t *testing.T) {
		c := f.persistentCaddy.browser(t)
		first := f.begin(t, c, "/files")
		f.setCallback("/second/oauth")
		defer f.setCallback(f.basePath)
		second := f.begin(t, c, "/second/files")
		f.request(t, c, "POST", f.base+f.basePath+"/logout", http.Header{"Origin": {f.base}}, 204, false)
		f.request(t, c, "GET", first, nil, 400, false)
		f.request(t, c, "GET", second, nil, 303, false)
		f.request(t, c, "GET", f.base+"/second/files", nil, 200, true)
	})
	t.Run("concurrent_replay", func(t *testing.T) {
		c := f.persistentCaddy.browser(t)
		callback := f.begin(t, c, "/files")
		headers := f.cookieHeaders(c)
		before := f.hits.Load()
		results := make(chan int, 2)
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { code, _, _ := registrationHTTP(t, f.client, "GET", callback, nil, headers); results <- code })
		}
		wg.Wait()
		close(results)
		counts := map[int]int{}
		for status := range results {
			counts[status]++
		}
		if counts[303] != 1 || counts[400] != 1 || f.hits.Load() != before {
			t.Fatalf("callback replay: %v", counts)
		}
	})
	t.Run("limits_expiry_replacement_and_cancel", func(t *testing.T) { f.limits(t) })
}

func (f *directCaddy) limits(t *testing.T) {
	f.setCallback("/limits/oauth")
	defer f.setCallback(f.basePath)
	a, b := f.persistentCaddy.browser(t), f.persistentCaddy.browser(t)
	callback := f.begin(t, a, "/limits/files")
	// Replacing the active browser login releases its previous provider state.
	for range 5 {
		old := callback
		callback = f.begin(t, a, "/limits/files")
		f.request(t, a, "GET", old, nil, 400, false)
	}
	second := f.begin(t, b, "/limits/files")
	f.request(t, f.persistentCaddy.browser(t), "GET", f.base+"/limits/files", nil, 503, false)
	f.request(t, a, "GET", callback, nil, 303, false)
	f.request(t, b, "GET", second, nil, 503, false)
	// Wait past absolute expiry; no request refreshes the lifetime.
	timer := time.NewTimer(2200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("expiry deadline")
	}
	f.request(t, a, "POST", f.base+"/limits/files", nil, 401, false)
	callback = f.begin(t, b, "/limits/files")
	f.request(t, b, "GET", callback, nil, 303, false)
	f.request(t, b, "POST", f.base+"/limits/oauth/logout", http.Header{"Origin": {f.base}}, 204, false)
	a = f.persistentCaddy.browser(t)
	callback = f.begin(t, a, "/limits/files")
	entered, release := make(chan struct{}), make(chan struct{})
	f.provider.mu.Lock()
	f.provider.exchangeEntered = entered
	f.provider.exchangeRelease = release
	f.provider.mu.Unlock()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	finished := make(chan oidcRPResponse, 1)
	go func() {
		code, header, body := registrationHTTP(t, a, "GET", callback, nil, nil)
		finished <- oidcRPResponse{code, header, body}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("exchange not entered")
	}
	before := f.hits.Load()
	f.request(t, a, "POST", f.base+"/limits/oauth/logout", http.Header{"Origin": {f.base}}, 204, false)
	unblock()
	select {
	case response := <-finished:
		if response.status != 401 || string(response.body) != "Unauthorized\n" {
			t.Fatal("cancel changed body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exchange did not return")
	}
	if f.hits.Load() != before {
		t.Fatal("canceled exchange ran upstream")
	}
	f.request(t, a, "POST", f.base+"/limits/files", nil, 401, false)
}

func (f *directCaddy) lifecycle(t *testing.T) {
	t.Helper()
	f.setCallback(f.basePath)
	c := f.persistentCaddy.browser(t)
	callback := f.begin(t, c, "/files")
	f.request(t, c, "GET", callback, nil, 303, false)
	pending := f.persistentCaddy.browser(t)
	callback = f.begin(t, pending, "/files")
	cmd := f.command(t, "reload", "--force", "--config", f.config)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reload: %v\n%s", err, output)
	}
	f.request(t, c, "POST", f.base+"/files", nil, 401, false)
	f.request(t, pending, "GET", callback, nil, 400, false)
	callback = f.begin(t, c, "/files")
	f.request(t, c, "GET", callback, nil, 303, false)
	f.request(t, c, "GET", f.base+"/files", nil, 200, true)
	stop := f.command(t, "stop", "--address", f.admin)
	if output, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("stop: %v\n%s", err, output)
	}
	select {
	case err := <-f.done:
		if err != nil {
			t.Fatal(err)
		}
		f.done = nil
		_ = f.log.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("Caddy shutdown timed out")
	}
	f.start(t)
	f.request(t, c, "POST", f.base+"/files", nil, 401, false)
	callback = f.begin(t, c, "/files")
	f.request(t, c, "GET", callback, nil, 303, false)
	f.request(t, c, "GET", f.base+"/files", nil, 200, true)
}

func (f *directCaddy) browserJourney(t *testing.T) {
	t.Helper()
	browser := caddyRefreshBrowserExecutable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "direct-oauth-browser-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error(err)
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, f.cert)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private browser trust: %v\n%s", err, output)
	}
	var invalidTLSHits atomic.Int64
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { invalidTLSHits.Add(1); w.WriteHeader(204) }))
	defer untrusted.Close()
	chrome := exec.CommandContext(ctx, browser, "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile, "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "--disable-quic", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	before := f.hits.Load()
	driver := exec.CommandContext(ctx, "node", "testdata/browser/authorization_oauth_browser.cjs", endpoint, f.base, f.basePath, untrusted.URL)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("browser direct OAuth: %v\n%s", err, output)
	}
	if strings.TrimSpace(string(output)) != "direct OAuth browser passed" || f.hits.Load()-before != 1 || invalidTLSHits.Load() != 0 {
		t.Fatalf("browser evidence mismatch: %s upstream=%d invalidTLS=%d", output, f.hits.Load()-before, invalidTLSHits.Load())
	}
}

// Pending login lifetime is deliberately fixed by AuthCrunch. Let actual time
// pass through the built binary; changing a private clock would not prove the
// consumer's retained transaction, cookie, and provider-state behavior.
func (f *directCaddy) pendingExpiry(t *testing.T) {
	f.setCallback("/limits/oauth")
	defer f.setCallback(f.basePath)
	a, b := f.persistentCaddy.browser(t), f.persistentCaddy.browser(t)
	callback := f.begin(t, a, "/limits/files")
	headers := f.cookieHeaders(a)
	f.begin(t, b, "/limits/files")
	f.request(t, f.persistentCaddy.browser(t), "GET", f.base+"/limits/files", nil, 503, false)
	t.Log("waiting for the fixed 300-second pending-login lifetime")
	timer := time.NewTimer(301 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("pending expiry deadline")
	}
	f.request(t, f.client, "GET", callback, headers, 400, false)
	c := f.persistentCaddy.browser(t)
	callback = f.begin(t, c, "/limits/files")
	f.request(t, c, "GET", callback, nil, 303, false)
	f.request(t, c, "POST", f.base+"/limits/oauth/logout", http.Header{"Origin": {f.base}}, 204, false)
}

func (f *directCaddy) termination(t *testing.T, pinned bool) {
	c := f.persistentCaddy.browser(t)
	external, _ := url.Parse(f.base)
	internalRequest := func(path string, status int, upstream bool) oidcRPResponse {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), "GET", f.httpOrigin+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = external.Host
		request.Header = f.cookieHeaders(c)
		request.Header.Set("X-Forwarded-Host", "hostile.example")
		request.Header.Set("X-Forwarded-Proto", "https")
		before := f.hits.Load()
		response, err := f.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		result := oidcRPResponse{response.StatusCode, response.Header, body}
		result.requireStatus(t, status)
		c.Jar.SetCookies(external, response.Cookies())
		want := int64(0)
		if upstream {
			want = 1
		}
		if f.hits.Load()-before != want || strings.Contains(string(body), "CADDY_ERROR") {
			t.Fatal("termination response changed chain outcome")
		}
		return result
	}
	if !pinned {
		internalRequest("/files", 400, false)
		return
	}
	first := internalRequest("/files", 302, false)
	destination, _ := url.Parse(first.header.Get("Location"))
	if destination.Query().Get("redirect_uri") != f.base+f.basePath+"/authorization-code-callback" {
		t.Fatal("termination did not pin HTTPS origin")
	}
	provider := persistentRequest(t, c, "GET", destination.String(), nil, nil, 302)
	callback, _ := url.Parse(provider.header.Get("Location"))
	internalRequest(callback.RequestURI(), 303, false)
	internalRequest("/files", 200, true)
}
