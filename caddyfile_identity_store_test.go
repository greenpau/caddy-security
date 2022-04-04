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

func TestParseCaddyfileIdentityStore(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test authdb identity store",
			d: caddyfile.NewTestDispenser(`
            security {
			  local identity store localdb {
				realm local
				path /tmp/localdb
			  }
              authentication portal myportal {
                enable identity store localdb
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
				]
			  }
            }`,
		},
		{
			name: "test msad ldap identity store",
			d: caddyfile.NewTestDispenser(`
            security {
              ldap identity store contoso.com {
                realm contoso.com
                servers {
                  ldaps://ldaps.contoso.com ignore_cert_errors
                }
                attributes {
                  name givenName
                  surname sn
                  username sAMAccountName
                  member_of memberOf
                  email mail
                }
                username "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM"
                password "P@ssW0rd123"
                search_base_dn "DC=CONTOSO,DC=COM"
                search_filter "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
                groups {
                  "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" admin
                  "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" editor
                  "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM" viewer
                }
              }
			  authentication portal myportal {
                enable identity store contoso.com
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
					  "contoso.com"
					],
					"token_validator_options": {},
					"token_grantor_options": {}
				  }
				],
				"identity_stores": [
				  {
					"name": "contoso.com",
					"kind": "ldap",
					"params": {
					  "attributes": {
						"email": "mail",
						"member_of": "memberOf",
						"name": "givenName",
						"surname": "sn",
						"username": "sAMAccountName"
					  },
					  "bind_password": "P@ssW0rd123",
					  "bind_username": "CN=authzsvc,OU=Service Accounts,OU=Administrative Accounts,DC=CONTOSO,DC=COM",
					  "groups": [
						{
						  "dn": "CN=Admins,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						  "roles": [
							"admin"
						  ]
						},
						{
						  "dn": "CN=Editors,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						  "roles": [
							"editor"
						  ]
						},
						{
						  "dn": "CN=Viewers,OU=Security,OU=Groups,DC=CONTOSO,DC=COM",
						  "roles": [
							"viewer"
						  ]
						}
					  ],
					  "realm": "contoso.com",
					  "search_base_dn": "DC=CONTOSO,DC=COM",
					  "search_user_filter": "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))",
					  "servers": [
						{
						  "address": "ldaps://ldaps.contoso.com",
						  "ignore_cert_errors": true
						}
					  ]
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
				t.Errorf("parseCaddyfileIdentityStore() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
