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

func TestParseCaddyfileSingleSignOnProvider(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test aws sso provider",
			d: caddyfile.NewTestDispenser(`
            security {
			  sso provider aws {
			    entity_id caddy-authp-idp
                driver aws
				private key /tmp/authp_saml.key
				cert /tmp/authp_saml.crt
				location https://localhost/
				location https://127.0.0.1/
			  }
			  local identity store localdb {
				realm local
				path /tmp/localdb
			  }
              authentication portal myportal {
                enable identity store localdb
				enable sso provider aws
              }
            }`),
			want: `{
			  "config": {
				"authentication_portals": [
				  {
					"name": "myportal",
					"ui": {},
					"cookie_config": {},
					"identity_stores": [
					  "localdb"
					],
					"sso_providers": [
					  "aws"
					],
					"token_validator_options": {},
					"token_grantor_options": {}
				  }
				],
				"identity_stores": [
				  {
					"name": "localdb",
					"kind": "local",
					"params": {
					  "path": "/tmp/localdb",
					  "realm": "local"
					}
				  }
				],
				"sso_providers": [
				  {
				    "name": "aws",
					"driver": "aws",
					"entity_id": "caddy-authp-idp",
					"locations": ["https://localhost/", "https://127.0.0.1/"],
					"private_key_path": "/tmp/authp_saml.key",
					"cert_path": "/tmp/authp_saml.crt"
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
				t.Errorf("parseCaddyfileSingleSignOnProvider() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
