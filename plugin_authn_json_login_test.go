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
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type authenticationClientLoginCase struct {
	name, body, message string
	headers             http.Header
	status              int
	oidcError           bool
}

// Exercise the same rejections directly, through the Caddy wrapper, and over
// Caddy TLS. Even benign browser metadata is forbidden on a native request.
func authenticationClientLoginCases(origin string, native, oidcEnabled bool) []authenticationClientLoginCase {
	cases := []authenticationClientLoginCase{
		{name: "unknown JSON field", body: `{"username":"alice","realm":"local","password":"not-a-checkpoint"}`, status: 400, message: "Bad Request"},
		{name: "invalid transport", body: `{"username":"alice","realm":"local","refresh_transport":"native"}`, status: 400, message: "Bad Request"},
		{name: "API key with username", body: `{"api_key":"synthetic-key","username":"alice","realm":"local"}`, status: 400, message: "Bad Request"},
		{name: "API key with body transport", body: `{"api_key":"synthetic-key","realm":"local","refresh_transport":"body"}`, status: 400, message: "Bad Request"},
		{name: "invalid API key", body: `{"api_key":"synthetic-key","realm":"local"}`, status: 401, message: "Unauthorized"},
	}
	body := `{"username":"alice","realm":"local","refresh_transport":"body"}`
	if !native {
		return append(cases, authenticationClientLoginCase{name: "native unavailable", body: body, status: 400, message: "Native refresh is unavailable"})
	}
	for _, header := range []struct{ name, value string }{
		{"Cookie", "UNRELATED=browser"},
		{"Origin", origin},
		{"Origin", ""},
		{"Sec-Fetch-Site", "same-origin"},
		{"Sec-Fetch-Mode", "cors"},
		{"Sec-Fetch-Dest", "empty"},
	} {
		cases = append(cases, authenticationClientLoginCase{name: "native with " + header.name + "=" + header.value, body: body, headers: http.Header{header.name: {header.value}}, status: 403, message: "Invalid refresh transport", oidcError: oidcEnabled && header.name == "Origin" && header.value == ""})
	}
	return cases
}

func authenticationClientLoginError(t *testing.T, response authenticationClientHTTPResponse, tc authenticationClientLoginCase) map[string]any {
	t.Helper()
	if response.readError != nil || response.status != tc.status {
		t.Fatalf("login status %d, want %d; read error: %v", response.status, tc.status, response.readError)
	}
	if response.header.Get("Content-Type") != "application/json" || response.header.Get("Cache-Control") != "no-store" || response.header.Get("Location") != "" || response.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("login failure lost its JSON, cache, redirect or CORS contract")
	}
	var payload map[string]any
	if json.Unmarshal(response.body, &payload) != nil {
		t.Fatal("login failure was not JSON")
	}
	if tc.oidcError {
		// An enabled OP rejects invalid browser origins before JSON login.
		// Keep its OAuth error envelope rather than rewriting it as a portal error.
		if !cmp.Equal(payload, map[string]any{"error": "invalid_request"}) {
			t.Fatal("OIDC login-origin rejection was rewritten")
		}
		return payload
	}
	if len(payload) != 3 || payload["error"] != true || payload["message"] != tc.message {
		t.Fatal("login error was rewritten or exposed credential fields")
	}
	stamp, _ := payload["timestamp"].(string)
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		t.Fatal("login error lost its timestamp")
	}
	delete(payload, "timestamp")
	return payload
}

func TestAuthnJSONLoginDelegation(t *testing.T) {
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, variant := range []struct {
			name         string
			native, oidc bool
		}{{name: "legacy"}, {name: "native", native: true}, {name: "native with OIDC", native: true, oidc: true}} {
			t.Run(variant.name+mount, func(t *testing.T) {
				cfg := lifecycleConfig()
				cfg.AuthenticationPortals[0].API = &authn.APIConfig{}
				if variant.native {
					basePath := mount
					if basePath == "" {
						basePath = "/"
					}
					cfg.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://issuer.example", BasePath: basePath, BodyTransportEnabled: true}
				}
				if variant.oidc {
					key := newOIDCRPKey(t, "op")
					application, err := oidc.NewOAuthApplicationConfig("website", &oidc.ClientConfig{ClientID: "website", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://rp.example/callback"}})
					if err != nil {
						t.Fatal(err)
					}
					if err := cfg.AddOAuthApplication(application); err != nil {
						t.Fatal(err)
					}
					if err := cfg.ConfigureOIDCProvider(cfg.AuthenticationPortals[0], []string{"issuer https://issuer.example" + mount, "realms local", encodeOAuthDirective([]string{"signing", "key", "files", key.private}), "applications website"}); err != nil {
						t.Fatal(err)
					}
				}
				app := provisionLifecycleApp(t, cfg)
				portal, err := app.getPortal("portal")
				if err != nil {
					t.Fatal(err)
				}
				middleware := &AuthnMiddleware{app: app, portal: portal}
				for _, tc := range authenticationClientLoginCases("https://issuer.example", variant.native, variant.oidc) {
					t.Run(tc.name, func(t *testing.T) {
						r := httptest.NewRequest("POST", "https://issuer.example"+mount+"/login", strings.NewReader(tc.body))
						r.Header = tc.headers.Clone()
						if r.Header == nil {
							r.Header = make(http.Header)
						}
						r.Header.Set("Content-Type", "application/json")
						r.Header.Set("Accept", "application/json")
						originalURL, originalHeaders := *r.URL, r.Header.Clone()
						direct := r.Clone(t.Context())
						direct.Body = io.NopCloser(strings.NewReader(tc.body))
						want, got := httptest.NewRecorder(), httptest.NewRecorder()
						if err := portal.ServeHTTP(t.Context(), want, direct, requests.NewRequest()); err != nil {
							t.Fatal(err)
						}
						if err := middleware.ServeHTTP(got, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
							t.Error("login fell through to another handler")
							return nil
						})); err != nil {
							t.Fatal(err)
						}
						var payloads [2]map[string]any
						for i, recorder := range []*httptest.ResponseRecorder{want, got} {
							payloads[i] = authenticationClientLoginError(t, authenticationClientHTTPResponse{status: recorder.Code, header: recorder.Header(), body: recorder.Body.Bytes()}, tc)
							// Only the random tracking cookie value differs between
							// independent dispatches. Preserve its name and attributes.
							for j, raw := range recorder.Header().Values("Set-Cookie") {
								cookie, err := http.ParseSetCookie(raw)
								if err != nil || cookie.Name != "AUTHP_SESSION_ID" || cookie.Value == "" {
									t.Fatal("unexpected login error cookie")
								}
								_, attributes, _ := strings.Cut(raw, ";")
								recorder.Header()["Set-Cookie"][j] = cookie.Name + "=tracking;" + attributes
							}
						}
						if !cmp.Equal(payloads[0], payloads[1]) || !cmp.Equal(want.Header(), got.Header()) {
							t.Fatal("Caddy wrapper changed portal error metadata")
						}
						if *r.URL != originalURL || !cmp.Equal(originalHeaders, r.Header) {
							t.Fatal("Caddy wrapper changed login URL or injected request headers")
						}
					})
				}
			})
		}
	}
}

func (f *authenticationClientFixture) loginRejections(t *testing.T) {
	t.Helper()
	for _, tc := range authenticationClientLoginCases(f.base, f.body, f.oidc) {
		t.Run("login rejection/"+tc.name, func(t *testing.T) {
			response := f.jsonRequest(t, "POST", "/login", json.RawMessage(tc.body), tc.headers)
			authenticationClientLoginError(t, response, tc)
		})
	}
}
