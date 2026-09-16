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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type tokenRefreshHTTPCase struct {
	name, method, path, body string
	headers                  http.Header
	status                   int
}

// Reused through middleware and actual Caddy TLS. Invalid requests must fail
// before consuming a real cookie, and must never become blanket API bypasses.
func tokenRefreshHTTPCases(origin, mount, cookieName, credential string) []tokenRefreshHTTPCase {
	cases := []tokenRefreshHTTPCase{}
	for _, op := range []string{"refresh_token", "refresh_session", "logout"} {
		path := mount + "/api/" + op
		for _, c := range []tokenRefreshHTTPCase{
			{name: "missing origin", headers: http.Header{"Origin": nil}, status: 403},
			{name: "wrong origin", headers: http.Header{"Origin": {"https://foreign.example"}}, status: 403},
			{name: "duplicate origin", headers: http.Header{"Origin": {origin, origin}}, status: 403},
			{name: "missing refresh header", headers: http.Header{"X-Authcrunch-Refresh": nil}, status: 403},
			{name: "bad refresh header", headers: http.Header{"X-Authcrunch-Refresh": {"0"}}, status: 403},
			{name: "duplicate refresh header", headers: http.Header{"X-Authcrunch-Refresh": {"1", "1"}}, status: 403},
			{name: "foreign fetch site", headers: http.Header{"Sec-Fetch-Site": {"cross-site"}}, status: 403},
			{name: "navigation fetch", headers: http.Header{"Sec-Fetch-Mode": {"navigate"}}, status: 403},
			{name: "document fetch", headers: http.Header{"Sec-Fetch-Dest": {"document"}}, status: 403},
			{name: "empty precondition", headers: http.Header{"X-Authcrunch-Refresh-Session": {""}}, status: 400},
			{name: "duplicate precondition", headers: http.Header{"X-Authcrunch-Refresh-Session": {"old", "old"}}, status: 400},
			{name: "duplicate cookies", headers: http.Header{"Cookie": {cookieName + "=" + credential + "; " + cookieName + "=" + credential}}, status: 400},
			{name: "duplicate cookie headers", headers: http.Header{"Cookie": {cookieName + "=" + credential, cookieName + "=" + credential}}, status: 400},
			{name: "mixed transport", body: `{"refresh_token":"native"}`, headers: http.Header{"Cookie": {cookieName + "=" + credential}}, status: 400},
			{name: "unknown field", body: `{"unknown":true}`, status: 400},
			{name: "duplicate JSON field", body: `{"refresh_token":"a","refresh_token":"b"}`, status: 400},
			{name: "escaped duplicate JSON", body: `{"refresh_token":"a","refresh_\u0074oken":"b"}`, status: 400},
			{name: "trailing JSON", body: `{} {}`, status: 400},
			{name: "malformed JSON", body: `{`, status: 400},
			{name: "null JSON", body: `null`, status: 400},
			{name: "whitespace JSON", body: " \n\t", status: 400},
			{name: "array JSON", body: `[]`, status: 400},
			{name: "empty body credential", body: `{"refresh_token":""}`, status: 400},
			{name: "oversized JSON", body: `{` + strings.Repeat(" ", 1024) + `}`, status: 400},
			{name: "wrong content type", headers: http.Header{"Content-Type": {"text/plain"}}, status: 415},
			{name: "wrong method", method: "GET", status: 405},
			{name: "CORS preflight", method: "OPTIONS", status: 405},
			{name: "query", path: path + "?retry=1", status: 400},
			{name: "empty query", path: path + "?", status: 400},
			{name: "wrong mount", path: mount + "/wrong/api/" + op, status: 404},
			{name: "escaped mount", path: mount + "/api/%72" + strings.TrimPrefix(op, "r"), status: 404},
		} {
			// Escaped-path check only applies to names beginning with r.
			if c.name == "escaped mount" && op == "logout" {
				continue
			}
			c.name = op + "/" + c.name
			if c.method == "" {
				c.method = "POST"
			}
			if c.path == "" {
				c.path = path
			}
			if c.body == "" {
				c.body = "{}"
			}
			cases = append(cases, c)
		}
		if op != "refresh_token" {
			cases = append(cases, tokenRefreshHTTPCase{name: op + "/unexpected precondition", method: "POST", path: path, body: "{}", headers: http.Header{"X-Authcrunch-Refresh-Session": {"old"}}, status: 400})
		}
	}
	for _, path := range []string{"/api/profile", "/api/server/realms", "/api/refresh_token/", "/api/private_key"} {
		cases = append(cases, tokenRefreshHTTPCase{name: "protected" + path, method: "POST", path: mount + path, body: "{}", status: 401})
	}
	return cases
}

func tokenRefreshCaseRequest(t *testing.T, origin string, tc tokenRefreshHTTPCase) *http.Request {
	t.Helper()
	r, err := http.NewRequest(tc.method, origin+tc.path, strings.NewReader(tc.body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header = http.Header{"Cookie": {"AUTHP_SESSION_ID=synthetic-browser-session"}, "Origin": {origin}, "X-Authcrunch-Refresh": {"1"}, "Content-Type": {"application/json"}, "Accept": {"text/html"}, "Authorization": {"Bearer expired-or-invalid"}}
	for k, v := range tc.headers {
		r.Header[k] = v
	}
	return r
}

func TestAuthnTokenRefreshDelegation(t *testing.T) {
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run("mount="+mount, func(t *testing.T) {
			cfg := lifecycleConfig()
			cfg.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://issuer.example", BasePath: mount + "/", CookieName: "CUSTOM_REFRESH"}
			if mount != "" {
				cfg.AuthenticationPortals[0].RefreshTokens.BasePath = mount
			}
			app := provisionLifecycleApp(t, cfg)
			portal, err := app.getPortal("portal")
			if err != nil {
				t.Fatal(err)
			}
			middleware := &AuthnMiddleware{app: app, portal: portal}
			for _, tc := range tokenRefreshHTTPCases("https://issuer.example", mount, "CUSTOM_REFRESH", "opaque") {
				t.Run(tc.name, func(t *testing.T) {
					r := tokenRefreshCaseRequest(t, "https://issuer.example", tc)
					original := *r.URL
					headers := r.Header.Clone()
					want := httptest.NewRecorder()
					direct := r.Clone(t.Context())
					direct.Body = io.NopCloser(strings.NewReader(tc.body))
					if err := portal.ServeHTTP(t.Context(), want, direct, requests.NewRequest()); err != nil {
						t.Fatal(err)
					}
					got := httptest.NewRecorder()
					if err := middleware.ServeHTTP(got, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { t.Error("reached catch-all"); return nil })); err != nil {
						t.Fatal(err)
					}
					if got.Code != tc.status || want.Code != got.Code {
						t.Fatalf("response status %d, library %d, expected %d", got.Code, want.Code, tc.status)
					}
					var responses [2]map[string]any
					for i, recorder := range []*httptest.ResponseRecorder{want, got} {
						if err := json.Unmarshal(recorder.Body.Bytes(), &responses[i]); err != nil {
							t.Fatal(err)
						}
						stamp, _ := responses[i]["timestamp"].(string)
						if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
							t.Fatal("missing error timestamp")
						}
						delete(responses[i], "timestamp")
					}
					if diff := cmp.Diff(responses[0], responses[1]); diff != "" {
						t.Fatal(diff)
					}
					if diff := cmp.Diff(want.Header(), got.Header()); diff != "" {
						t.Fatal(diff)
					}
					if *r.URL != original || !cmp.Equal(headers, r.Header) {
						t.Fatal("middleware changed request metadata")
					}
					if tc.status == 405 && got.Header().Get("Allow") != "POST" {
						t.Fatal("wrong allowed method")
					}
					if got.Header().Get("Access-Control-Allow-Origin") != "" {
						t.Fatal("permissive CORS")
					}
				})
			}
			t.Run("embedded asset and continuation", func(t *testing.T) {
				asset, err := ui.StaticAssets.GetAsset("assets/js/refresh.js")
				if err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{"/assets/js/refresh.js", "/portal", "/login", "/login?fresh=1", "/logout"} {
					r := httptest.NewRequest("GET", "https://issuer.example"+mount+path, nil)
					r.AddCookie(&http.Cookie{Name: "CUSTOM_REFRESH", Value: "opaque"})
					w := httptest.NewRecorder()
					if err := middleware.ServeHTTP(w, r, nil); err != nil {
						t.Fatal(err)
					}
					if w.Code != 200 {
						t.Fatalf("%s: %d", path, w.Code)
					}
					body := w.Body.String()
					switch path {
					case "/assets/js/refresh.js":
						if body != asset.Content || w.Header().Get("Content-Type") != asset.ContentType {
							t.Fatal("embedded refresh client changed in Caddy")
						}
					case "/login?fresh=1":
						if strings.Contains(body, `data-action="continue"`) {
							t.Fatal("fresh login loops through continuation")
						}
					default:
						action := "continue"
						if path == "/logout" {
							action = "logout"
						}
						for _, value := range []string{`data-action="` + action + `"`, mount + "/assets/js/refresh.js", `?fresh=1`} {
							if !strings.Contains(body, value) {
								t.Fatalf("%s missing %s", path, value)
							}
						}
						if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
							t.Fatal("session page caching, referrer or framing policy changed")
						}
					}
				}
			})
		})
	}
}
