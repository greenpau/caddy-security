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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
)

func TestParseAuthorizationOAuth(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		invalid    bool
	}{
		{"minimal", "use oauth identity provider upstream", false},
		{"all", `use oauth identity provider upstream
oauth public origin https://app.example.test
oauth base path /private/oauth
oauth session cookie name __Host-SESSION
oauth login cookie name __Host-LOGIN
oauth session lifetime 600
oauth maximum sessions 200
oauth maximum pending logins 20
validate method path`, false},
		{"duplicate", "use oauth identity provider upstream\nuse oauth identity provider other", true},
		{"missing provider", "oauth session lifetime 600", true},
		{"extra", "use oauth identity provider upstream sentinel-secret", true},
		{"invalid origin", "use oauth identity provider upstream\noauth public origin sentinel-secret", true},
		{"unknown", "use oauth identity provider upstream\noauth sentinel-secret value", true},
		{"nested empty", "use oauth identity provider upstream {\n}", true},
		{"jwt incompatible", "use oauth identity provider upstream\ncrypto key verify sentinel-secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser("authorization policy direct {\n" + tc.body + "\nallow roles authp/user\n}")
			d.Next()
			cfg := authcrunch.NewConfig()
			err := parseCaddyfileAuthorization(d, cfg)
			if tc.invalid {
				if err == nil || strings.Contains(err.Error(), "sentinel-secret") {
					t.Fatalf("expected redacted error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.AuthorizationPolicies[0]
			if p.OAuth == nil || p.OAuth.IdentityProvider != "upstream" || p.SessionIDCookieName != "" || len(p.AccessTokenCookieNames) != 0 {
				t.Fatal("incorrect direct policy mapping")
			}
			if tc.name == "all" && (!p.ValidateMethodPath || p.ValidateAccessListPathClaim || p.OAuth.SessionLifetime != 600 || p.OAuth.MaxSessions != 200) {
				t.Fatal("lost independent OAuth/ACL settings")
			}
		})
	}
}
