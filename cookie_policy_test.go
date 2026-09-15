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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAppCookiePolicyCoordination(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "defaults", true: "explicit"}[explicit], func(t *testing.T) {
			cfg := lifecycleConfig()
			p := cfg.AuthenticationPortals[0]
			if err := p.CookieConfig.SetCookieNamePrefix("PORTAL"); err != nil {
				t.Fatal(err)
			}
			other := lifecycleConfig().AuthenticationPortals[0]
			other.Name = "other"
			if err := other.CookieConfig.SetCookieNamePrefix("OTHER"); err != nil {
				t.Fatal(err)
			}
			cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, other)
			policy := cfg.AuthorizationPolicies[0]
			policy.AllowedTokenSources = []string{"cookie"}
			policy.ValidateBearerHeader = false
			wantSession := "AUTHP_SESSION_ID"
			wantAccess := []string{"AUTHP_ACCESS_TOKEN", "access_token", "jwt_access_token"}
			if explicit {
				wantSession = "PORTAL_SESSION_ID"
				wantAccess = []string{"PORTAL_ACCESS_TOKEN", "INTENTIONAL_ALTERNATE"}
				policy.SessionIDCookieName = wantSession
				policy.AccessTokenCookieNames = wantAccess
			}
			app := provisionLifecycleApp(t, cfg)
			raw, err := json.Marshal(app.server.GetConfig())
			if err != nil {
				t.Fatal(err)
			}
			var runtime authcrunch.Config
			if err := json.Unmarshal(raw, &runtime); err != nil {
				t.Fatal(err)
			}
			got := runtime.AuthorizationPolicies[0]
			if got.SessionIDCookieName != wantSession {
				t.Fatal("session cookie mismatch")
			}
			if diff := cmp.Diff(wantAccess, got.AccessTokenCookieNames); diff != "" {
				t.Fatal(diff)
			}
			if got.ValidateBearerHeader || got.AuthProxyConfig != nil || len(got.AllowedTokenSources) != 1 || got.AllowedTokenSources[0] != "cookie" {
				t.Fatal("accepted credentials broadened")
			}
			gate, err := app.getGatekeeper("policy")
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/protected", nil)
			req.AddCookie(&http.Cookie{Name: wantSession, Value: "syntheticsession"})
			ar := requests.NewAuthorizationRequest()
			if err := gate.Authenticate(httptest.NewRecorder(), req, ar); err == nil {
				t.Fatal("session cookie authenticated without access token")
			}
			if ar.SessionID != "syntheticsession" || ar.Response.Authorized {
				t.Fatal("session ID must be read without acting as an access credential")
			}
		})
	}
}

func TestAppCookieProviderOwnership(t *testing.T) {
	for _, providerName := range []string{"", "UPSTREAM_ID"} {
		t.Run(providerName, func(t *testing.T) {
			cfg := lifecycleConfig()
			provider := lifecycleOAuth("https://127.0.0.1:1", "shared", 3600)
			provider.Params["identity_token_cookie_enabled"] = true
			if providerName != "" {
				provider.Params["identity_token_cookie_name"] = providerName
			}
			cfg.IdentityProviders = []*idp.IdentityProviderConfig{provider}
			cfg.AuthenticationPortals = nil
			for _, prefix := range []string{"ONE", "TWO"} {
				cookies := cookie.NewConfig()
				if err := cookies.SetCookieNamePrefix(prefix); err != nil {
					t.Fatal(err)
				}
				p := &authn.PortalConfig{Name: prefix, IdentityStores: []string{"local"}, IdentityProviders: []string{"shared"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify synthetic-lifecycle-signing-secret"}}
				if err := p.ConfigureCookies(cookies); err != nil {
					t.Fatal(err)
				}
				cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, p)
			}
			before, err := json.Marshal(provider)
			if err != nil {
				t.Fatal(err)
			}
			app := provisionLifecycleApp(t, cfg)
			data, err := json.Marshal(app.server.GetConfig())
			if err != nil {
				t.Fatal(err)
			}
			var runtime authcrunch.Config
			if err := json.Unmarshal(data, &runtime); err != nil {
				t.Fatal(err)
			}
			value := runtime.IdentityProviders[0].Params["identity_token_cookie_name"]
			// The dispatch config may retain an omitted field; the provider applies its
			// AUTHP default internally. Neither portal may inject its own ID name.
			if providerName != "" && value != providerName {
				t.Fatal("provider name overwritten")
			}
			if providerName == "" && value != nil && value != "AUTHP_ID_TOKEN" {
				t.Fatal("portal prefix leaked into shared provider")
			}
			after, err := json.Marshal(provider)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("declarative provider mutated")
			}
		})
	}
}

func TestPolicyCookieDirectiveValidation(t *testing.T) {
	for _, line := range []string{
		`set session_id cookie name ONE TWO`, `set session_id cookie name ""`,
		`set access_token cookie name ACCESS ""`, `set access_token cookie name ACCESS ACCESS`,
		`set access_token cookie name "bad name"`,
		"set session_id cookie name ONE\nset session_id cookie name TWO",
		"set access_token cookie name ONE\nset access_token cookie name TWO",
	} {
		if _, err := parseCookieApp("security {\nauthorization policy policy {\nallow roles authp/user\n" + line + "\n}\n}"); err == nil {
			t.Fatalf("invalid policy accepted: %s", line)
		}
	}
}

func TestAppCookieSnapshotReplacement(t *testing.T) {
	t.Setenv("COOKIE_SNAPSHOT_PATH", "/app {literal}")
	cfg := lifecycleConfig()
	cfg.AuthenticationPortals[0].CookieConfig.Path = "/old"
	cfg.AuthenticationPortals[0].CookieConfig.Lifetime = 42
	app := &App{Config: cfg, PortalCookieDirectives: map[string][]string{
		"portal": {"cookie path {env.COOKIE_SNAPSHOT_PATH}", "cookie prefix PORTAL"},
	}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	t.Cleanup(func() {
		if err := app.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	if err := app.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(app.server.GetConfig())
	if err != nil {
		t.Fatal(err)
	}
	var runtime authcrunch.Config
	if err := json.Unmarshal(raw, &runtime); err != nil {
		t.Fatal(err)
	}
	got := runtime.AuthenticationPortals[0].CookieConfig
	if got.Path != "/app {literal}" || got.Lifetime != 0 || got.AccessTokenCookieName != "PORTAL_ACCESS_TOKEN" {
		t.Fatal("cookie snapshot was merged or replaced twice")
	}
	if cfg.AuthenticationPortals[0].CookieConfig.Path != "/old" {
		t.Fatal("declarative cookie config mutated")
	}
}
