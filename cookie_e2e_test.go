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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
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
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"golang.org/x/net/publicsuffix"
)

// This fixture owns a real TLS Caddy listener and a browser-style cookie jar.
// OIDC and refresh integrations should extend it with their stricter cookie
// attributes, request origins, rotations, and revocation behavior.
func TestCaddyCookiesE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCookiesProcess$", "-test.v", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_COOKIE_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS Caddy cookies: %v\n%s", err, output)
	}
}

type caddyCookieFixture struct {
	client *http.Client
	base   string
	config []byte
}

func cookieTLSCertificate(t *testing.T, dnsNames ...string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Cookie test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	template.DNSNames = dnsNames
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("certificate not trusted")
	}
	return certFile, keyFile, roots
}

func newCaddyCookieFixture(t *testing.T, host, mount, directives, policy, certFile, keyFile string, roots *x509.CertPool) *caddyCookieFixture {
	t.Helper()
	addr := lifecycleAddress(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	directives += "\ntrust login redirect uri domain exact " + net.JoinHostPort(host, port) + " path exact /app/protected"
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  local identity store localdb {
   realm local
   path :memory:
   user alice {
    email alice@example.com
    password %s
    roles authp/user
   }
  }
  authentication portal portal {
   enable identity store localdb
   crypto key sign-verify synthetic-cookie-integration-key
   %s
  }
  authentication portal other {
   enable identity store localdb
   crypto key sign-verify synthetic-cookie-integration-key
   cookie prefix OTHER
  }
  authorization policy policy {
   crypto key verify synthetic-cookie-integration-key
   allow roles authp/user
   set token sources cookie
   %s
  }
  authorization policy defaults {
   crypto key verify synthetic-cookie-integration-key
   allow roles authp/user
   set token sources cookie
  }
 }
}
https://:%s {
 bind 127.0.0.1
 tls %s %s
 @protected path /app/* /application /outside
 route {
  route /other/* {
   authenticate with other
  }
  route /app/defaults {
   authorize with defaults
   respond allowed 200
  }
  route @protected {
   authorize with policy
   respond allowed 200
  }
  route %s/* {
   authenticate with portal
  }
  route {
   authorize with policy
   respond allowed 200
  }
 }
}`, lifecyclePassword, directives, policy, port, certFile, keyFile, mount)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)
	return &caddyCookieFixture{client: client, base: "https://" + net.JoinHostPort(host, port), config: data}
}

func (f *caddyCookieFixture) request(t *testing.T, method, target string, form url.Values, headers http.Header, status int) *http.Response {
	t.Helper()
	if !strings.HasPrefix(target, "https://") {
		target = f.base + target
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(req.Header, headers)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", f.base)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("%s %s: got %d, want %d; location=%s body=%.300s", method, req.URL.Path, resp.StatusCode, status, resp.Header.Get("Location"), payload)
	}
	return resp
}

func (f *caddyCookieFixture) login(t *testing.T, base string) []*http.Cookie {
	t.Helper()
	page := f.request(t, "GET", base+"/login?redirect_url="+url.QueryEscape(f.base+"/app/protected"), nil, nil, 200)
	issued := page.Cookies()
	start := f.request(t, "POST", base+"/login", url.Values{"username": {"alice"}, "realm": {"local"}}, nil, 303)
	issued = append(issued, start.Cookies()...)
	sandbox := start.Header.Get("Location")
	if !strings.Contains(sandbox, "/sandbox/") {
		t.Fatalf("missing sandbox redirect: %q", sandbox)
	}
	proof := f.request(t, "POST", sandbox, url.Values{"secret": {lifecyclePassword}}, nil, 303)
	issued = append(issued, proof.Cookies()...)
	finish := f.request(t, "GET", sandbox, nil, nil, 303)
	return append(issued, finish.Cookies()...)
}

func jarCookie(t *testing.T, jar http.CookieJar, target, name string) string {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func issuedCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name && c.Value != "delete" {
			return c
		}
	}
	t.Fatalf("cookie %s was not issued", name)
	return nil
}

func matchingCookieDeletion(t *testing.T, original *http.Cookie, cookies []*http.Cookie) {
	t.Helper()
	for _, deletion := range cookies {
		if deletion.Name != original.Name || deletion.MaxAge >= 0 || deletion.Domain != original.Domain || deletion.Path != original.Path {
			continue
		}
		if deletion.Secure != original.Secure || deletion.HttpOnly != original.HttpOnly || deletion.SameSite != original.SameSite || deletion.Expires.IsZero() || !deletion.Expires.Before(time.Now()) {
			t.Fatalf("deletion does not match issuance for %s", original.Name)
		}
		return
	}
	t.Fatalf("missing Max-Age=0 deletion for %s", original.Name)
}

func (f *caddyCookieFixture) rejectCookieReload(t *testing.T, change func(*App)) {
	t.Helper()
	var config caddy.Config
	if err := json.Unmarshal(f.config, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	change(&app)
	raw, err := json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	config.AppsRaw["security"] = raw
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(raw, true); err == nil {
		t.Fatal("invalid cookie configuration replaced the active deployment")
	}
	f.request(t, "GET", "/app/protected", nil, nil, 200)
}

func TestCaddyCookiesProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_COOKIE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cases := []struct {
		root                                                  bool
		name, host, directives, session, access, domain, path string
		sibling                                               bool
	}{
		{name: "defaults", host: "login.example.com", session: "AUTHP_SESSION_ID", access: "AUTHP_ACCESS_TOKEN", path: "/"},
		{name: "legacy_prefix_only", host: "login.example.com", directives: "set cookie name prefix portal", session: "PORTAL_SESSION_ID", access: "PORTAL_ACCESS_TOKEN", path: "/"},
		{name: "explicit_authp_names", host: "login.example.com", directives: "cookie session id name AUTHP_SESSION_ID\ncookie access token name AUTHP_LOGIN_ACCESS", session: "AUTHP_SESSION_ID", access: "AUTHP_LOGIN_ACCESS", path: "/"},
		{name: "prefix", host: "login.example.com", directives: "cookie prefix PORTAL", session: "PORTAL_SESSION_ID", access: "PORTAL_ACCESS_TOKEN", path: "/"},
		{name: "explicit_before_prefix", host: "login.example.com", directives: "cookie access token name LOGIN_ACCESS\ncookie session id name LOGIN_SESSION\ncookie prefix PORTAL", session: "LOGIN_SESSION", access: "LOGIN_ACCESS", path: "/"},
		{name: "explicit_old_default", host: "login.example.com", directives: "cookie access token name AUTHP_ACCESS_TOKEN\ncookie prefix PORTAL", session: "PORTAL_SESSION_ID", access: "AUTHP_ACCESS_TOKEN", path: "/"},
		{name: "domain_and_path", host: "login.example.com", directives: "cookie prefix PORTAL\ncookie domain example.com path /app\ncookie domain example.com lifetime 600\ncookie domain example.com same site strict", session: "PORTAL_SESSION_ID", access: "PORTAL_ACCESS_TOKEN", domain: "example.com", path: "/app", sibling: true},
		{name: "domain_stripped", host: "login.example.com", directives: "cookie domain example.com strip domain enabled\ncookie domain example.com path /app", session: "AUTHP_SESSION_ID", access: "AUTHP_ACCESS_TOKEN", path: "/app"},
		{name: "public_suffix_guess", host: "tenant.fly.dev", directives: "cookie guess domain", session: "AUTHP_SESSION_ID", access: "AUTHP_ACCESS_TOKEN", path: "/"},
		{name: "legacy", host: "login.example.com", directives: "set session_id cookie name LOGIN_SESSION\nset cookie name prefix portal\nset access_token cookie name LOGIN_ACCESS", session: "LOGIN_SESSION", access: "LOGIN_ACCESS", path: "/"},
		{name: "runtime_placeholders", host: "login.example.com", directives: "cookie prefix {env.COOKIE_E2E_PREFIX}\ncookie domain {env.COOKIE_E2E_DOMAIN} path /app", session: "PORTAL_SESSION_ID", access: "PORTAL_ACCESS_TOKEN", domain: "example.com", path: "/app", sibling: true},
		{name: "legacy_literal_path", host: "login.example.com", directives: "cookie prefix PORTAL\ncookie default path {env.COOKIE_E2E_PATH}", session: "PORTAL_SESSION_ID", access: "PORTAL_ACCESS_TOKEN", path: "/app {literal}"},
		{name: "secure_names", host: "login.example.com", directives: "cookie prefix __Secure-PORTAL\ncookie domain example.com path /app", session: "__Secure-PORTAL_SESSION_ID", access: "__Secure-PORTAL_ACCESS_TOKEN", domain: "example.com", path: "/app", sibling: true},
		{name: "host_names", host: "login.example.com", directives: "cookie session id name __Host-SESSION\ncookie access token name __Host-ACCESS", session: "__Host-SESSION", access: "__Host-ACCESS", path: "/"},
		{name: "host_root", host: "login.example.com", directives: "cookie prefix __Host-PORTAL\ncookie identity token name __Secure-PORTAL_ID_TOKEN", session: "__Host-PORTAL_SESSION_ID", access: "__Host-PORTAL_ACCESS_TOKEN", path: "/", root: true},
	}
	t.Setenv("COOKIE_E2E_PREFIX", "PORTAL")
	t.Setenv("COOKIE_E2E_DOMAIN", "example.com")
	t.Setenv("COOKIE_E2E_PATH", "/app {literal}")
	certFile, keyFile, roots := cookieTLSCertificate(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := ""
			if tc.name != "defaults" {
				policy = fmt.Sprintf("set session_id cookie name %s\nset access_token cookie name %s", tc.session, tc.access)
			}
			mount := "/auth"
			if tc.root {
				mount = ""
			}
			policy += "\nset auth url " + mount + "/login"
			protectedPath := "/app/protected"
			if tc.name == "legacy_literal_path" {
				protectedPath = tc.path + "/protected"
			}
			f := newCaddyCookieFixture(t, tc.host, mount, tc.directives, policy, certFile, keyFile, roots)
			f.request(t, "GET", protectedPath, nil, nil, 302)
			issued := f.login(t, mount)
			for _, name := range []string{tc.access, tc.session} {
				c := issuedCookie(t, issued, name)
				path := "/"
				if name == tc.access {
					path = tc.path
				}
				if c.Domain != tc.domain || c.Path != path || !c.Secure || !c.HttpOnly {
					t.Fatalf("wrong scope/attributes for %s: domain=%s path=%s secure=%v httpOnly=%v", name, c.Domain, c.Path, c.Secure, c.HttpOnly)
				}
			}
			if tc.name == "domain_and_path" {
				c := issuedCookie(t, issued, tc.access)
				if c.MaxAge != 600 || c.SameSite != http.SameSiteStrictMode {
					t.Fatal("domain attributes lost")
				}
			}
			if tc.root {
				for _, name := range []string{"__Host-PORTAL_REDIRECT_URL", "__Host-PORTAL_SANDBOX_ID"} {
					original := issuedCookie(t, issued, name)
					if original.Path != "/" || original.Domain != "" || !original.Secure || !original.HttpOnly {
						t.Fatalf("invalid host cookie attributes for %s", name)
					}
					matchingCookieDeletion(t, original, issued)
				}
			}
			f.request(t, "GET", protectedPath, nil, nil, 200)
			token := jarCookie(t, f.client.Jar, f.base+protectedPath, tc.access)
			if token == "" {
				t.Fatal("access cookie not retained")
			}
			expected := 200
			if tc.path != "/" {
				expected = 302
			}
			f.request(t, "GET", "/application", nil, nil, expected)
			f.request(t, "GET", "/outside", nil, nil, expected)
			u, _ := url.Parse(f.base)
			sibling := "app.example.com"
			if tc.host == "tenant.fly.dev" {
				sibling = "other.fly.dev"
			}
			u.Host = net.JoinHostPort(sibling, u.Port())
			expected = 302
			if tc.sibling {
				expected = 200
			}
			f.request(t, "GET", u.String()+protectedPath, nil, nil, expected)
			u.Host = net.JoinHostPort("notexample.com", u.Port())
			f.request(t, "GET", u.String()+protectedPath, nil, nil, 302)
			plain, _ := url.Parse(f.base + protectedPath)
			plain.Scheme = "http"
			if jarCookie(t, f.client.Jar, plain.String(), tc.access) != "" {
				t.Fatal("secure access cookie escaped onto HTTP")
			}
			expected = 302
			if tc.access == "AUTHP_ACCESS_TOKEN" {
				expected = 200
			}
			f.request(t, "GET", "/app/defaults", nil, nil, expected)

			// A valid access JWT in another role or transport must not authenticate.
			jar := f.client.Jar
			f.client.Jar = nil
			for _, name := range []string{tc.session, "AUTHP_REFRESH_TOKEN", "PORTAL_REFRESH_TOKEN", "AUTHP_ID_TOKEN", "PORTAL_OIDC_SESSION_ID", "OTHER_ACCESS_TOKEN"} {
				f.request(t, "GET", protectedPath, nil, http.Header{"Cookie": {name + "=" + token}}, 302)
			}
			f.request(t, "GET", protectedPath, nil, http.Header{"Authorization": {"Bearer " + token}}, 302)
			f.request(t, "GET", protectedPath+"?access_token="+url.QueryEscape(token), nil, nil, 302)
			f.request(t, "GET", protectedPath, nil, http.Header{"X-Api-Key": {token}}, 302)
			f.request(t, "GET", protectedPath, nil, http.Header{"Cookie": {tc.access + "=" + token}}, 200)
			// No implicit name sharing even with another portal in the same app/key set.
			f.request(t, "GET", "/app/defaults", nil, http.Header{"Cookie": {"OTHER_ACCESS_TOKEN=" + token}}, 302)
			f.client.Jar = jar

			if tc.name == "runtime_placeholders" {
				for _, value := range []string{"", "bad prefix"} {
					t.Setenv("COOKIE_E2E_PREFIX", value)
					if err := caddy.Load(f.config, true); err == nil {
						t.Fatal("invalid replacement loaded")
					}
					f.request(t, "GET", protectedPath, nil, nil, 200)
				}
				t.Setenv("COOKIE_E2E_PREFIX", "PORTAL")
			}
			if tc.name == "defaults" {
				f.rejectCookieReload(t, func(app *App) {
					app.Config.AuthenticationPortals[0].CookieConfig.Domains = map[string]*cookie.DomainConfig{
						"{env.COOKIE_E2E_DOMAIN}": {Domain: "{env.COOKIE_E2E_DOMAIN}", Path: "/private"},
						"example.com":             {Domain: "example.com", Path: "/", Seq: 1},
					}
				})
				f.rejectCookieReload(t, func(app *App) {
					cookies := app.Config.AuthenticationPortals[0].CookieConfig
					cookies.AccessTokenCookieName = cookies.SessionIDCookieName
				})
				f.rejectCookieReload(t, func(app *App) {
					cookies := app.Config.AuthenticationPortals[0].CookieConfig
					cookies.AccessTokenCookieName = "__Host-ACCESS"
					cookies.Path = "/app"
				})
				otherJar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
				if err != nil {
					t.Fatal(err)
				}
				f.client.Jar = otherJar
				f.login(t, "/other")
				if jarCookie(t, otherJar, f.base+protectedPath, "OTHER_ACCESS_TOKEN") == "" {
					t.Fatal("other portal did not issue its cookie")
				}
				f.request(t, "GET", "/app/defaults", nil, nil, 302)
				f.request(t, "GET", protectedPath, nil, nil, 302)
				f.client.Jar = jar
			}
			logout := f.request(t, "GET", mount+"/logout", nil, nil, 302)
			for _, raw := range logout.Header.Values("Set-Cookie") {
				if _, err := http.ParseSetCookie(raw); err != nil {
					t.Fatal("logout emitted an empty or malformed cookie header")
				}
			}
			for _, name := range []string{tc.access, tc.session} {
				original := issuedCookie(t, issued, name)

				matchingCookieDeletion(t, original, logout.Cookies())
				if jarCookie(t, jar, f.base+protectedPath, name) != "" {
					t.Fatalf("logout retained %s", name)
				}
			}
			f.request(t, "GET", protectedPath, nil, nil, 302)
			if tc.sibling {
				u, _ := url.Parse(f.base)
				u.Host = net.JoinHostPort("app.example.com", u.Port())
				f.request(t, "GET", u.String()+protectedPath, nil, nil, 302)
			}
		})
	}
}
