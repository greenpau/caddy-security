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
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
)

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
