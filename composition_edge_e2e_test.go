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
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func testCompositionEdge(t *testing.T, f *compositionFixture, pair tls.Certificate) {
	// Bind authorization to the address actually signed at login. A login-only
	// claim check would miss a wrapper that trusts spoofed hints on authorize.
	f.input = strings.Replace(f.input, "validate bearer header", "validate bearer header\nvalidate source address", 1)
	f.load(t, f.input)
	hostile := http.Header{
		"X-Forwarded-Host":  {"evil.example", "other.evil.example"},
		"X-Forwarded-Proto": {"http", "http"},
		"X-Forwarded-For":   {"203.0.113.66", "198.51.100.77"},
		"X-Real-Ip":         {"192.0.2.88"}, "Forwarded": {"host=evil.example;proto=http;for=192.0.2.88"},
		"X-Forwarded-Prefix": {"/other"}, "X-Forwarded-Port": {"9999"},
	}
	discover := func(client *http.Client, target, issuer string, headers http.Header, want int) {
		t.Helper()
		status, response, raw := registrationHTTP(t, client, "GET", target+"/auth/.well-known/openid-configuration", nil, headers)
		if status != want || response.Get("Cache-Control") != "no-store" {
			t.Fatalf("edge discovery status=%d want=%d", status, want)
		}
		assertAdminRedacted(t, raw, f.secrets)
		if want == 200 {
			var doc map[string]any
			if json.Unmarshal(raw, &doc) != nil || doc["issuer"] != issuer+"/auth" {
				t.Fatal("forwarded metadata changed issuer")
			}
		}
	}
	resource := func(client *http.Client, token string, hints http.Header, want int) {
		t.Helper()
		headers := hints.Clone()
		headers.Set("Authorization", "Bearer "+token)
		before := f.hits.Load()
		status, response, body := registrationHTTP(t, client, "GET", f.base+"/protected", nil, headers)
		delta := int64(0)
		if want == 204 {
			delta = 1
		}
		if status != want || f.hits.Load() != before+delta || (response.Get("X-Protected-Upstream") != "") != (want == 204) {
			t.Fatalf("source-bound authorization status=%d want=%d upstream delta=%d", status, want, f.hits.Load()-before)
		}
		if want != 204 && response.Get("Cache-Control") != "no-store" {
			t.Fatal("source-bound denial permits caching")
		}
		assertAdminRedacted(t, body, f.secrets)
	}
	login := func(client *http.Client, extra http.Header, address string) string {
		t.Helper()
		headers := f.headers()
		for k, v := range extra {
			headers[k] = v
		}
		req := apiauth.AuthRequest{Username: "alice", Realm: "employees"}
		begin, _ := f.post(t, client, "/login", req, headers, 200)
		req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = begin.SandboxID, begin.SandboxSecret, begin.NextChallenge, lifecyclePassword
		_, cookies := f.post(t, client, "/login", req, headers, 200)
		token := tokenRefreshActiveCookie(t, cookies, f.accessName()).Value
		f.secrets = append(f.secrets, token)
		claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "refresh")
		if claims["addr"] != address || claims["iss"] != f.base+"/auth" {
			t.Fatalf("library observed wrong edge address or issuer: address=%v issuer=%v", claims["addr"], claims["iss"])
		}
		return token
	}
	discover(f.client, f.base, f.base, hostile, 200)
	directToken := login(f.browser(t), hostile, "127.0.0.1")
	for range 2 {
		resource(f.client, directToken, hostile, 204)
	}
	cleartext := "http://" + lifecycleAddress(t)
	f.load(t, f.input+"\n"+cleartext+" {\nroute /auth/* {\nauthenticate with myportal\n}\n}\n")
	request, err := http.NewRequestWithContext(t.Context(), "POST", cleartext+"/auth/api/refresh_token", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = strings.TrimPrefix(f.base, "https://")
	request.Header = f.headers()
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Host", request.Host)
	request.Header.Set("X-Forwarded-Proto", "https")
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("untrusted protocol hint converted cleartext into TLS evidence")
	}
	// Origin is end-user protocol evidence, independent of forwarded hints.
	browser := f.browser(t)
	f.browserLogin(t, browser, "employees", 200)
	for _, origin := range [][]string{{"https://evil.example"}, {f.base, f.base}, {f.base, "https://evil.example"}} {
		h := f.headers()
		h["Origin"] = origin
		f.post(t, browser, "/api/refresh_token", struct{}{}, h, 403)
	}
	f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
	for _, tc := range []struct {
		path, method string
		status       int
	}{
		{"/auth/.well-known/openid-%63onfiguration", "GET", 400},
		{"/auth/oidc%2fjwks", "GET", 400},
		{"/auth/%61pi/refresh_token", "POST", 404},
		{"/auth/api%2frefresh_token", "POST", 404},
	} {
		before := f.hits.Load()
		// Keep credentials, JSON, Origin and refresh marker valid: only the
		// encoded path may explain rejection of an otherwise usable request.
		request, err := http.NewRequestWithContext(t.Context(), tc.method, f.base+tc.path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header = f.headers()
		request.Header.Set("Content-Type", "application/json")
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<16))
		response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != tc.status || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Protected-Upstream") != "" || f.hits.Load() != before {
			t.Fatalf("encoded protocol path %s: status=%d want=%d", tc.path, response.StatusCode, tc.status)
		}
		assertAdminRedacted(t, body, f.secrets)
	}
	f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)

	// A real TLS proxy terminates the public connection and opens a separately
	// verified TLS connection to Caddy. Its Rewrite API strips client hints and
	// supplies the actual public host/protocol/peer. Caddy explicitly trusts
	// only this local peer; the library's validation stays unchanged.
	backend := f.base
	target, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &httputil.ReverseProxy{Transport: f.client.Transport, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(target)
		p.SetXForwarded()
	}}
	front := httptest.NewUnstartedServer(proxy)
	front.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	front.StartTLS()
	t.Cleanup(front.Close)
	proxied := strings.ReplaceAll(f.input, "issuer "+backend+"/auth", "issuer "+front.URL+"/auth")
	proxied = strings.ReplaceAll(proxied, "public origin "+backend, "public origin "+front.URL)
	proxied = strings.Replace(proxied, "auto_https off", "auto_https off\nservers {\ntrusted_proxies static 127.0.0.1/32\ntrusted_proxies_strict\n}", 1)
	f.load(t, proxied)
	f.base = front.URL
	discover(f.client, front.URL, front.URL, hostile, 200)
	login(f.browser(t), hostile, "127.0.0.1")
	// Talk to the trusted Caddy listener directly to exercise duplicate field
	// selection and Caddy's strict right-to-left address parsing itself.
	trusted := http.Header{
		"X-Forwarded-Host":  {"evil.example", strings.TrimPrefix(front.URL, "https://")},
		"X-Forwarded-Proto": {"http", "https"},
		"X-Forwarded-For":   {"203.0.113.66", "198.51.100.14, 127.0.0.1"},
		"X-Real-Ip":         {"192.0.2.66"},
	}
	discover(f.client, backend, front.URL, trusted, 200)
	// The request still carries the public Origin while bypassing only the
	// test proxy transport, never the Caddy trusted-proxy calculation.
	direct := *f.client
	direct.Transport = compositionTargetTransport{base: f.client.Transport, target: target}
	direct.Timeout = 5 * time.Second
	forwardedToken := login(&direct, trusted, "198.51.100.14")
	for range 2 {
		resource(&direct, forwardedToken, trusted, 204)
		wrongAddress := trusted.Clone()
		wrongAddress.Set("X-Forwarded-For", "198.51.100.15, 127.0.0.1")
		wrongAddress.Set("X-Real-Ip", "198.51.100.14")
		resource(&direct, forwardedToken, wrongAddress, 401)
		resource(&direct, forwardedToken, trusted, 204)
	}
	trusted.Set("X-Forwarded-For", "2001:db8::1, 127.0.0.1")
	login(&direct, trusted, "2001:db8::1")
	for _, mutation := range []struct{ key, value string }{
		{"X-Forwarded-Proto", "http"},
		{"X-Forwarded-Host", "evil.example"},
		{"X-Forwarded-Host", strings.TrimPrefix(front.URL, "https://") + ", evil.example"},
		{"X-Forwarded-Proto", "https, http"},
	} {
		h := trusted.Clone()
		h.Set(mutation.key, mutation.value)
		discover(f.client, backend, front.URL, h, 400)
	}
	// Missing/incorrect Origin remains denied even through a trusted proxy.
	browser = f.browser(t)
	f.browserLogin(t, browser, "employees", 200)
	for _, origin := range [][]string{nil, {"https://evil.example"}, {f.base, f.base}} {
		h := f.headers()
		h["Origin"] = origin
		f.post(t, browser, "/api/refresh_token", struct{}{}, h, 403)
	}
	f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 200)
	// A configured address header is also resolved by Caddy, not interpreted
	// independently by AuthCrunch's X-Real-IP precedence.
	customHeader := strings.Replace(proxied, "trusted_proxies_strict", "trusted_proxies_strict\nclient_ip_headers X-Test-Client X-Forwarded-For", 1)
	f.load(t, customHeader)
	trusted.Set("X-Test-Client", "198.51.100.25")
	customToken := login(&direct, trusted, "198.51.100.25")
	resource(&direct, customToken, trusted, 204)
	wrongAddress := trusted.Clone()
	wrongAddress.Set("X-Test-Client", "198.51.100.26")
	wrongAddress.Set("X-Forwarded-For", "198.51.100.25")
	wrongAddress.Set("X-Real-Ip", "198.51.100.25")
	resource(&direct, customToken, wrongAddress, 401)
	// Retain the signed token and keys while removing proxy trust. Even the
	// formerly accepted hints cannot make a direct peer impersonate its address.
	f.base = backend
	f.load(t, f.input)
	for range 2 {
		resource(f.client, forwardedToken, trusted, 401)
	}
}

type compositionTargetTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t compositionTargetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme, clone.URL.Host = t.target.Scheme, t.target.Host
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}
