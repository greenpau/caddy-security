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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAuthnOIDCDelegation(t *testing.T) {
	key := newOIDCRPKey(t, "op")
	cfg := lifecycleConfig()
	cfg.AuthenticationPortals[0].Name = "myportal"
	application, err := oidc.NewOAuthApplicationConfig("website", &oidc.ClientConfig{ClientID: "website", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://rp.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.AddOAuthApplication(application); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ConfigureOIDCProvider(cfg.AuthenticationPortals[0], []string{"issuer https://issuer.example/tenant/auth", "realms local", encodeOAuthDirective([]string{"signing", "key", "files", key.private}), "applications website"}); err != nil {
		t.Fatal(err)
	}
	app := provisionLifecycleApp(t, cfg)
	portal, err := app.getPortal("myportal")
	if err != nil {
		t.Fatal(err)
	}
	middleware := &AuthnMiddleware{app: app, portal: portal}
	for _, tc := range []struct {
		method, path, origin string
		status               int
	}{
		{"GET", "/.well-known/openid-configuration", "", 200},
		{"HEAD", "/oidc/jwks", "", 200},
		{"GET", "/oidc/jwks", "", 200},
		{"GET", "/oidc/authorize", "", 400},
		{"GET", "/oidc/token", "", 405},
		{"GET", "/oidc/userinfo", "", 401},
		{"GET", "/oidc/revoke", "", 405},
		{"GET", "/oidc/%74oken", "", 400},
		{"GET", "/oidc/token/", "", 404},
		{"OPTIONS", "/oidc/token", "https://rp.example", 204},
		{"OPTIONS", "/oidc/token", "https://unregistered.example", 403},
	} {
		t.Run(tc.method+tc.path+tc.origin, func(t *testing.T) {
			for _, accept := range []string{"text/html", "application/json"} {
				r := httptest.NewRequest(tc.method, "https://issuer.example/tenant/auth"+tc.path, nil)
				r.Header.Set("Accept", accept)
				r.Header.Set("Authorization", "Bearer deliberately-invalid-access-token")
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
					r.Header.Set("Access-Control-Request-Method", "POST")
				}
				original := *r.URL
				want := httptest.NewRecorder()
				if err := portal.ServeHTTP(t.Context(), want, r.Clone(t.Context()), requests.NewRequest()); err != nil {
					t.Fatal(err)
				}
				got := httptest.NewRecorder()
				next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					t.Error("portal request reached the protected catch-all")
					return nil
				})
				if err := middleware.ServeHTTP(got, r, next); err != nil {
					t.Fatal(err)
				}
				if got.Code != tc.status || got.Code != want.Code || got.Body.String() != want.Body.String() {
					t.Fatalf("portal response changed: status %d, want %d", got.Code, tc.status)
				}
				wantHeaders, gotHeaders := want.Header().Clone(), got.Header().Clone()
				if tc.path == "/oidc/authorize" && accept == "text/html" {
					for _, headers := range []http.Header{wantHeaders, gotHeaders} {
						policy, err := normalizeOIDCPagePolicy(headers.Get("Content-Security-Policy"))
						if err != nil {
							t.Fatal(err)
						}
						headers.Set("Content-Security-Policy", policy)
					}
				}
				if diff := cmp.Diff(wantHeaders, gotHeaders); diff != "" {
					t.Fatal(diff)
				}
				if *r.URL != original {
					t.Fatal("middleware rewrote the canonical request URL")
				}
			}
		})
	}
}
