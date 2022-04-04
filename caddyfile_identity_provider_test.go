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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
	"testing"
)

func TestParseCaddyfileIdentityProvider(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test generic oauth identity provider",
			d: caddyfile.NewTestDispenser(`
            security {
			  oauth identity provider authp {
				realm authp
				driver generic
				client_id foo
				client_secret bar
				base_auth_url https://localhost/oauth
				response_type code
				required_token_fields access_token
				authorization_url https://localhost/oauth/authorize
				token_url https://localhost/oauth/access_token
				jwks key 87329db33bf testdata/oauth/87329db33bf_pub.pem
				disable key verification
				disable tls verification
			  }
              authentication portal myportal {
                enable identity provider authp
              }
            }`),
			want: `{
			  "config": {
				"authentication_portals": [
				  {
					"name": "myportal",
					"ui": {},
					"cookie_config": {},
					"identity_providers": [
					  "authp"
					],
					"token_validator_options": {},
					"token_grantor_options": {}
				  }
				],
				"identity_providers": [
				  {
					"name": "authp",
					"kind": "oauth",
					"params": {
					  "authorization_url": "https://localhost/oauth/authorize",
					  "base_auth_url": "https://localhost/oauth",
					  "client_id": "foo",
					  "client_secret": "bar",
					  "driver": "generic",
					  "jwks_keys": {
						"87329db33bf": "testdata/oauth/87329db33bf_pub.pem"
					  },
					  "key_verification_disabled": true,
					  "realm": "authp",
					  "required_token_fields": [
						"access_token"
					  ],
					  "response_type": [
						"code"
					  ],
					  "tls_insecure_skip_verify": true,
					  "token_url": "https://localhost/oauth/access_token"
					}
				  }
                ]
              }
            }`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			app, err := parseCaddyfile(tc.d, nil)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("expected success, got: %v", err)
				}
				if diff := cmp.Diff(err.Error(), tc.err.Error()); diff != "" {
					t.Fatalf("unexpected error: %v, want: %v", err, tc.err)
				}
				return
			}
			if tc.shouldErr {
				t.Fatalf("unexpected success, want: %v", tc.err)
			}
			got := unpack(t, string(app.(httpcaddyfile.App).Value))
			want := unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", string(app.(httpcaddyfile.App).Value))
				t.Errorf("parseCaddyfileIdentityProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
