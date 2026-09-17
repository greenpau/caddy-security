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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Check the public gatekeeper result independently of the wrapper. In
// particular, nil error and a handled response are not permission to continue.
func TestAuthzResponseContract(t *testing.T) {
	for _, tc := range []struct {
		name, token                                             string
		closed, bypass, redirect, forbidden, allowed, gateError bool
		status                                                  int
	}{
		{name: "missing", gateError: true},
		{name: "invalid", token: "synthetic-secret-invalid-token", gateError: true},
		{name: "redirect", redirect: true, gateError: true, status: 302},
		{name: "forbidden", token: "valid", forbidden: true, gateError: true, status: 403},
		{name: "closed", closed: true, status: 503},
		{name: "bypassed", bypass: true, allowed: true},
		{name: "authorized", token: "valid", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &authz.PolicyConfig{Name: "contract", AuthRedirectDisabled: !tc.redirect, ValidateBearerHeader: true,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
			}
			if tc.bypass {
				policy.BypassConfigs = []*bypass.Config{{MatchType: "exact", URI: "/protected"}}
			}
			if tc.forbidden {
				policy.AccessListRules[0].Conditions = []string{"match roles administrator"}
			}
			app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
			gate, err := app.getGatekeeper("contract")
			if err != nil {
				t.Fatal(err)
			}
			if tc.closed {
				gate.Close()
			}
			request := func() *http.Request {
				r := httptest.NewRequest("GET", "https://app.example.test/protected", nil)
				token := tc.token
				if token == "valid" {
					token = authorizationPathToken(t)
				}
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				return r
			}
			ar := requests.NewAuthorizationRequest()
			raw := httptest.NewRecorder()
			raw.Code = 0 // distinguish no write from an explicit response
			err = gate.Authenticate(raw, request(), ar)
			if (err != nil) != tc.gateError || ar.Response.Bypassed != tc.bypass || ar.Response.Authorized != (tc.allowed && !tc.bypass) || raw.Code != tc.status {
				t.Fatalf("gate error=%t authorized=%t bypassed=%t status=%d", err != nil, ar.Response.Authorized, ar.Response.Bypassed, raw.Code)
			}
			wrapper := &AuthzMiddleware{app: app, gatekeeper: gate}
			response := httptest.NewRecorder()
			response.Code = 0
			response.Header().Set("Cache-Control", "public, max-age=60")
			user, allowed, err := wrapper.Authenticate(response, request())
			if allowed != tc.allowed || response.Code != tc.status || (err != nil) != tc.gateError {
				t.Fatal("wrapper changed gatekeeper decision or response")
			}
			if !allowed && (user.ID != "" || len(user.Metadata) != 0) {
				t.Fatal("denial returned identity metadata")
			}
			cacheControl := "no-store"
			if allowed {
				cacheControl = "public, max-age=60"
			}
			if response.Header().Get("Cache-Control") != cacheControl {
				t.Fatal("authorization response cache policy did not follow denial")
			}
			if tc.status != 0 {
				if response.Result().Header.Get("Cache-Control") != "no-store" {
					t.Fatal("handled denial committed cacheable headers")
				}
				if response.Body.String() != raw.Body.String() {
					t.Fatal("wrapper changed the handled response body")
				}
			}
		})
	}
}

const authorizationPathKey = "synthetic-authorization-path-signing-key"

// Independently signed fixtures isolate authorization from login. These are
// access tokens with path claims, never OIDC authentication evidence.
func authorizationPathToken(t *testing.T, paths ...string) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "path-viewer", "roles": []string{"viewer"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"acl": map[string]any{"paths": paths},
	}).SignedString([]byte(authorizationPathKey))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type authorizationPathCase struct {
	target string
	allow  bool
}

func authorizationPathCases() []authorizationPathCase {
	return []authorizationPathCase{
		{"/admin", false},
		{"/admin/../public/file", false},
		{"/admin/%2e%2e/public/file", false},
		{"/public%2Ffile", false},
		{"/public/%252e%252e/admin", false},
		{"/public/..%252fadmin", false},
		{"/public/%252e%252e/admin/%25252e%25252e/public/file", false},
		{"/public/a%252fb/../%252e%252e/admin", false},
		{"/public/%25zz/%252e%252e/admin", false},
		{"/public/%25252525252e%25252525252e/admin", false},
		{"/public/%FF/file", false},
		{"/public/%2580/file", false},
		{"/public/file", true},
		{"/public/assets/app.css?return=%2fadmin", true},
		{"/public/./assets/app.css", true},
		{"/public/100%25", true},
	}
}

func TestAuthzPathDelegation(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			policy := &authz.PolicyConfig{Name: mode, AuthRedirectDisabled: true, ValidateBearerHeader: true,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
			}
			token := authorizationPathToken(t, "/public/**", "/public/100%")
			switch mode {
			case "bypass":
				policy.BypassConfigs = []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}
				token = ""
			case "method":
				policy.ValidateMethodPath = true
				policy.AccessListRules[0].Conditions = append(policy.AccessListRules[0].Conditions, "prefix match path /public/", "match method GET")
			case "claim":
				policy.ValidateAccessListPathClaim = true
			}
			app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
			gatekeeper, err := app.getGatekeeper(mode)
			if err != nil {
				t.Fatal(err)
			}
			middleware := &AuthzMiddleware{app: app, gatekeeper: gatekeeper}
			// Repeat with a cached identity: request paths must still be checked.
			for round := range 2 {
				for _, tc := range authorizationPathCases() {
					t.Run(fmt.Sprintf("%d%s", round, tc.target), func(t *testing.T) {
						r := httptest.NewRequest("GET", "https://app.example.test"+tc.target, nil)
						if token != "" {
							r.Header.Set("Authorization", "Bearer "+token)
						}
						original, target := *r.URL, r.RequestURI
						usr, allowed, err := middleware.Authenticate(httptest.NewRecorder(), r)
						if allowed != tc.allow || (err == nil) != tc.allow {
							t.Fatalf("authorized=%t error=%v, want authorized=%t", allowed, err, tc.allow)
						}
						if *r.URL != original || r.RequestURI != target {
							t.Fatal("authorization rewrote the downstream request target")
						}
						if (!allowed || mode == "bypass") && (usr.ID != "" || len(usr.Metadata) != 0) {
							t.Fatal("denied or bypassed request received authenticated metadata")
						}
					})
				}
			}
		})
	}
}
