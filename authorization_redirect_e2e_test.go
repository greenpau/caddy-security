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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/publicsuffix"
)

func TestCaddyAuthorizationRedirectE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthorizationRedirectProcess$", "-test.v", "-test.timeout=210s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_REDIRECT_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Caddy redirect journeys: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

type authorizationRedirectFixture struct {
	address, application, portal, input string
	cert, key                           string
	roots                               *x509.CertPool
	upstream                            *oauthE2EUpstream
}

func newAuthorizationRedirectFixture(t *testing.T) *authorizationRedirectFixture {
	t.Helper()
	f := &authorizationRedirectFixture{address: lifecycleAddress(t)}
	_, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	f.application = "https://app.example.test:" + port
	f.portal = "https://auth.example.test:" + port
	f.cert, f.key, f.roots = cookieTLSCertificate(t, "app.example.test", "auth.example.test")
	pair, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = f.roots
	f.upstream = newOAuthE2EUpstream(t, pair, "Ed25519")
	f.upstream.callback = f.portal + "/oauth2/upstream/authorization-code-callback"
	var policies, routes strings.Builder
	for _, mode := range []string{"local", "oauth", "js", "custom", "disabled", "status"} {
		authURL, extra := f.portal+"/login", ""
		switch mode {
		case "oauth":
			authURL = f.upstream.callback
		case "js":
			extra = "enable js redirect"
		case "custom":
			authURL += "?source=application"
			extra = "set redirect query parameter return_to"
		case "disabled":
			authURL += "?source=application"
			extra = "disable auth redirect query"
		case "status":
			extra = "set redirect status 307"
		}
		fmt.Fprintf(&policies, `authorization policy %s {
 crypto key verify %s
 allow roles authp/user
 set token sources cookie
 set auth url %s
 %s
}
`, mode, oauthE2EPortalKey, authURL, extra)
		if mode != "local" {
			fmt.Fprintf(&routes, `@%s header X-Test-Policy %s
 route @%s {
  authorize with %s
  header X-Protected-User {http.auth.user.id}
  respond "{http.request.uri}" 200
 }
`, mode, mode, mode, mode)
		}
	}
	f.input = fmt.Sprintf(`{
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
    email alice@example.test
    password %s
    roles authp/user
   }
  }
  oauth identity provider upstream {
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
  authentication portal myportal {
   enable identity store localdb
   enable identity provider upstream
   crypto key sign-verify %s
   cookie domain example.test
   cookie path /
   trust login redirect uri domain exact app.example.test:%s path prefix /
  }
  %s
 }
}
%s {
 bind 127.0.0.1
 tls %q %q
 header X-Test-Protocol {http.request.proto}
 authenticate with myportal
}
%s {
 bind 127.0.0.1
 tls %q %q
 route {
  header X-Test-Protocol {http.request.proto}
  %s
  authorize with local
  header X-Protected-User {http.auth.user.id}
  respond "{http.request.uri}" 200
 }
}
`, lifecyclePassword, f.upstream.clientID, f.upstream.clientSecret, f.upstream.server.URL, f.upstream.server.URL, f.upstream.server.URL, f.upstream.server.URL,
		f.upstream.identity.pem(t, false), f.upstream.access.pem(t, false), oauthE2EPortalKey, port, policies.String(), f.portal, f.cert, f.key, f.application, f.cert, f.key, routes.String())
	f.load(t, f.input)
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	return f
}

func (f *authorizationRedirectFixture) load(t *testing.T, input string) {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
}

func (f *authorizationRedirectFixture) client(t *testing.T, protocol int) *http.Client {
	t.Helper()
	tlsConfig := &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}
	var transport http.RoundTripper
	if protocol == 3 {
		h3 := &http3.Transport{TLSClientConfig: tlsConfig, Dial: func(ctx context.Context, _ string, config *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
			// Only the socket destination changes. Keep the hostname/SNI and actual
			// QUIC request parser; this transport has no TCP fallback.
			return quic.DialAddrEarly(ctx, f.address, config, quicConfig)
		}}
		t.Cleanup(func() {
			if err := h3.Close(); err != nil {
				t.Error(err)
			}
		})
		transport = h3
	} else {
		h := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: protocol == 2, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, f.address)
		}}
		t.Cleanup(h.CloseIdleConnections)
		transport = h
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: transport, Jar: jar, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (f *authorizationRedirectFixture) request(t *testing.T, client *http.Client, protocol int, method, target string, form url.Values, headers http.Header, status int) (*http.Response, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		r.Header = headers.Clone()
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", f.portal)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatalf("redirect request: %v", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s %s: status=%d want=%d body=%.200s", method, r.URL.Path, response.StatusCode, status, raw)
	}
	if response.ProtoMajor != protocol || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatalf("request did not negotiate verified HTTP/%d: %s", protocol, response.Proto)
	}
	// The provider is a separate TLS fixture; every Caddy response also reports
	// the protocol seen on the server, before authentication or authorization.
	if strings.HasPrefix(target, f.application) || strings.HasPrefix(target, f.portal) {
		if response.Header.Get("X-Test-Protocol") != response.Proto {
			t.Fatal("Caddy/client protocol mismatch")
		}
	}
	return response, string(raw)
}

func (f *authorizationRedirectFixture) login(t *testing.T, client *http.Client, protocol int, mode, location string) string {
	t.Helper()
	if mode == "oauth" {
		response, _ := f.request(t, client, protocol, "GET", location, nil, nil, 302)
		providerURL := response.Header.Get("Location")
		if !strings.HasPrefix(providerURL, f.upstream.server.URL+"/authorize?") {
			t.Fatal("did not reach synthetic provider")
		}
		// The provider uses its own verified TLS transport. Sharing the same jar
		// preserves portal cookies across the provider's real code/PKCE exchange.
		providerClient := f.upstream.server.Client()
		providerClient.Jar, providerClient.Timeout, providerClient.CheckRedirect = client.Jar, client.Timeout, client.CheckRedirect
		response, _ = f.request(t, providerClient, 1, "GET", providerURL, nil, nil, 302)
		callback := response.Header.Get("Location")
		if !strings.HasPrefix(callback, f.upstream.callback+"?") {
			t.Fatal("provider callback escaped the portal")
		}
		response, _ = f.request(t, client, protocol, "GET", callback, nil, nil, 303)
		return response.Header.Get("Location")
	}
	f.request(t, client, protocol, "GET", location, nil, nil, 200)
	start, _ := f.request(t, client, protocol, "POST", f.portal+"/login", url.Values{"username": {"alice"}, "realm": {"local"}}, nil, 303)
	sandbox := start.Header.Get("Location")
	if !strings.HasPrefix(sandbox, f.portal+"/sandbox/") {
		t.Fatal("missing password sandbox")
	}
	f.request(t, client, protocol, "POST", sandbox, url.Values{"secret": {lifecyclePassword}}, nil, 303)
	finish, _ := f.request(t, client, protocol, "GET", sandbox, nil, nil, 303)
	return finish.Header.Get("Location")
}

func TestCaddyAuthorizationRedirectProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_REDIRECT_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	f := newAuthorizationRedirectFixture(t)
	for _, protocol := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", protocol), func(t *testing.T) {
			for _, mode := range []string{"local", "oauth", "js"} {
				for _, target := range redirectTargets() {
					t.Run(mode+target, func(t *testing.T) {
						client := f.client(t, protocol)
						headers := http.Header{"X-Test-Policy": {mode}}
						authURL := f.portal + "/login"
						if mode == "oauth" {
							authURL = f.upstream.callback
						}
						expected := f.application + target
						// HEAD exercises the issue's header-only probe without following it.
						head, _ := f.request(t, client, protocol, "HEAD", expected, nil, headers, 302)
						if mode != "js" {
							assertAuthorizationRedirect(t, head.Header.Get("Location"), authURL, "redirect_url", expected)
						}
						response, body := f.request(t, client, protocol, "GET", expected, nil, headers, 302)
						if response.Header.Get("X-Protected-User") != "" || response.Header.Get("Cache-Control") != "no-store" {
							t.Fatal("unauthenticated request reached resource or became cacheable")
						}
						location := response.Header.Get("Location")
						if mode == "js" {
							expected += "#part%202"
							location = executeAuthorizationRedirect(t, body, "#part%202")
						}
						assertAuthorizationRedirect(t, location, authURL, "redirect_url", expected)
						final := f.login(t, client, protocol, mode, location)
						if final != expected {
							t.Fatalf("login return = %q, want %q (must not end at portal dashboard)", final, expected)
						}
						authorized, raw := f.request(t, client, protocol, "GET", final, nil, headers, 200)
						if raw != target || authorized.Header.Get("X-Protected-User") == "" {
							t.Fatal("cookie login did not authorize the original resource")
						}
					})
				}
			}
			t.Run("options", func(t *testing.T) {
				for _, mode := range []string{"custom", "disabled", "status"} {
					client := f.client(t, protocol)
					status := 302
					if mode == "status" {
						status = 307
					}
					target := f.application + "/files/a%2fb?x=one%26two&x=three+four"
					response, _ := f.request(t, client, protocol, "GET", target, nil, http.Header{"X-Test-Policy": {mode}}, status)
					location := response.Header.Get("Location")
					switch mode {
					case "disabled":
						if location != f.portal+"/login?source=application" {
							t.Fatal("disabled redirect query changed destination")
						}
					case "custom":
						assertAuthorizationRedirect(t, location, f.portal+"/login?source=application", "return_to", target)
					case "status":
						assertAuthorizationRedirect(t, location, f.portal+"/login", "redirect_url", target)
					}
				}
			})
			t.Run("untrusted destinations", func(t *testing.T) {
				for _, mode := range []string{"local", "oauth"} {
					client := f.client(t, protocol)
					authURL := f.portal + "/login"
					if mode == "oauth" {
						authURL = f.upstream.callback
					}
					final := f.login(t, client, protocol, mode, authURL+"?redirect_url="+url.QueryEscape("https://other.example/private"))
					if final != f.portal+"/portal" {
						t.Fatalf("untrusted post-login target not rejected: %q", final)
					}
				}
			})
			t.Run("untrusted forwarding", func(t *testing.T) {
				response, _ := f.request(t, f.client(t, protocol), protocol, "GET", f.application+"/private", nil, redirectForwardedHeaders(), 302)
				assertAuthorizationRedirect(t, response.Header.Get("Location"), f.portal+"/login", "redirect_url", f.application+"/private")
			})
		})
	}
	t.Run("browser", func(t *testing.T) { f.browser(t) })
	t.Run("proxy", func(t *testing.T) { f.proxy(t) })
}

func redirectForwardedHeaders() http.Header {
	return http.Header{"X-Forwarded-Host": {"ignored.example", "app.example.test:4443"}, "X-Forwarded-Proto": {"https", "http"}, "X-Forwarded-Port": {"9999"}, "X-Forwarded-Prefix": {"//evil.example"}, "Forwarded": {"host=evil.example;proto=https"}}
}

func (f *authorizationRedirectFixture) proxy(t *testing.T) {
	t.Helper()
	target, err := url.Parse(f.application)
	if err != nil {
		t.Fatal(err)
	}
	backend := f.client(t, 2)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = backend.Transport
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		director(r)
		r.Host = target.Host
		for name, values := range redirectForwardedHeaders() {
			r.Header[name] = values
		}
	}
	server := httptest.NewTLSServer(proxy)
	defer server.Close()
	client := server.Client()
	client.Timeout, client.CheckRedirect = backend.Timeout, backend.CheckRedirect
	for _, trusted := range []bool{false, true} {
		t.Run(fmt.Sprintf("trusted=%t", trusted), func(t *testing.T) {
			if trusted {
				f.load(t, strings.Replace(f.input, "admin off", "admin off\n servers {\n trusted_proxies static 127.0.0.1/32\n trusted_proxies_strict\n }", 1))
			}
			response, _ := f.request(t, client, 1, "GET", server.URL+"/files/a%2fb?x=one%26two&x=three+four", nil, nil, 302)
			origin := f.application
			if trusted {
				origin = "http://app.example.test:4443"
			}
			assertAuthorizationRedirect(t, response.Header.Get("Location"), f.portal+"/login", "redirect_url", origin+"/files/a%2fb?x=one%26two&x=three+four")
		})
	}
}

func (f *authorizationRedirectFixture) browser(t *testing.T) {
	t.Helper()
	browser := caddyRefreshBrowserExecutable(t)
	for _, protocol := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("HTTP%d", protocol), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			if err := os.MkdirAll("tmp", 0700); err != nil {
				t.Fatal(err)
			}
			profile, err := os.MkdirTemp("tmp", "redirect-browser-")
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
			reject := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { invalidTLSHits.Add(1); w.WriteHeader(204) })
			untrusted := httptest.NewTLSServer(reject)
			defer untrusted.Close()
			pair, err := tls.LoadX509KeyPair(f.cert, f.key)
			if err != nil {
				t.Fatal(err)
			}
			wrongName := httptest.NewUnstartedServer(reject)
			wrongName.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
			wrongName.StartTLS()
			defer wrongName.Close()
			flags := []string{"--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + profile,
				"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain",
				"--host-resolver-rules=MAP app.example.test 127.0.0.1,MAP auth.example.test 127.0.0.1"}
			if protocol == 3 {
				flags = append(flags, "--enable-quic", "--origin-to-force-quic-on="+strings.TrimPrefix(f.application, "https://")+","+strings.TrimPrefix(f.portal, "https://"))
			} else {
				flags = append(flags, "--disable-quic")
			}
			if protocol == 1 {
				flags = append(flags, "--disable-http2")
			}
			flags = append(flags, "about:blank")
			chrome := exec.CommandContext(ctx, browser, flags...)
			endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			driver := exec.CommandContext(ctx, "node", "testdata/browser/authorization_redirect_browser.cjs", endpoint, f.application, f.portal, fmt.Sprint(protocol), untrusted.URL, strings.Replace(wrongName.URL, "127.0.0.1", "localhost", 1))
			driver.Stdin = strings.NewReader(lifecyclePassword)
			driver.WaitDelay = time.Second
			output, err := driver.CombinedOutput()
			if err != nil {
				t.Fatalf("browser redirects: %v\n%s", err, output)
			}
			if strings.TrimSpace(string(output)) != "redirect browser passed" {
				t.Fatalf("missing browser completion: %s", output)
			}
			if invalidTLSHits.Load() != 0 {
				t.Fatal("browser accepted invalid TLS")
			}
		})
	}
}
