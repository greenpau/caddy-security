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
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func TestParseCaddyfileAuthentication(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid authentication portal config",
			d: caddyfile.NewTestDispenser(`
            security {

			  authentication portal myportal {
                crypto default token lifetime 3600
                crypto key sign-verify 01ee2688-36e4-47f9-8c06-d18483702520
				cookie domain contoso.com
				cookie insecure on
                ui {
                  links {
                    "My Website" "/app" icon "las la-star"
                    "My Identity" "/auth/whoami" icon "las la-user"
                  }
                }
                transform user {
                  match origin local
                  action add role authp/user
                  ui link "Portal Settings" /auth/settings icon "las la-cog"
                }
				enable source ip tracking
				validate source address
				enable identity provider contoso.com example.com
				enable identity provider azure okta
			  }

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
			  }

			  ldap identity store example.com {
                realm example.com
                servers {
                  ldap://ldap.forumsys.com posix_groups
                }
                attributes {
                  name cn
                  surname foo
                  username uid
                  member_of uniqueMember
                  email mail
                }
                username "cn=read-only-admin,dc=example,dc=com"
                password "password"
                search_base_dn "DC=EXAMPLE,DC=COM"
                search_filter "(&(|(uid=%s)(mail=%s))(objectClass=inetOrgPerson))"
                groups {
                  "ou=mathematicians,dc=example,dc=com" authp/admin
                  "ou=scientists,dc=example,dc=com" authp/user
                }
              }

              saml identity provider azure {
                method saml
                provider azure
                realm azure
                idp_metadata_location assets/conf/saml/azure/idp/azure_ad_app_metadata.xml
                idp_sign_cert_location assets/conf/saml/azure/idp/azure_ad_app_signing_cert.pem
                tenant_id "1b9e886b-8ff2-4378-b6c8-6771259a5f51"
                application_id "623cae7c-e6b2-43c5-853c-2059c9b2cb58"
                application_name "My Gatekeeper"
                entity_id "urn:caddy:mygatekeeper"
                acs_url https://mygatekeeper/saml
                acs_url https://mygatekeeper.local/saml
                acs_url https://192.168.10.10:3443/saml
                acs_url https://localhost:3443/saml
              }

              oauth identity provider okta {
                realm okta
                provider okta
                domain_name dev-680653.okta.com
                client_id 0oa121qw81PJW0Tj34x7
                client_secret b3aJC5E59hU18YKC7Yca3994F4qFhWiAo_ZojanF
                server_id default
                scopes openid email profile groups
              }
            }`),
			want: `{
			  "config": {
				"authentication_portals": [
				  {
					"name": "myportal",
					"ui": {
					  "private_links": [
						{
						  "link": "/app",
						  "title": "My Website",
						  "icon_name": "las la-star",
						  "icon_enabled": true
						},
						{
						  "link": "/auth/whoami",
						  "title": "My Identity",
						  "icon_name": "las la-user",
						  "icon_enabled": true
						}
					  ]
					},
					"user_transformer_configs": [
					  {
						"matchers": [
						  "exact match origin local"
						],
						"actions": [
						  "action add role authp/user",
						  "ui link \"Portal Settings\" /auth/settings icon \"las la-cog\""
						]
					  }
					],
					"cookie_config": {
					  "domains": {
						"contoso.com": {
						  "seq": 1,
						  "domain": "contoso.com",
						  "insecure": true
						}
					  },
					  "insecure": true
					},
					"identity_providers": [
					  "contoso.com",
					  "example.com",
					  "azure",
					  "okta"
					],
					"token_validator_options": {
					  "validate_source_address": true
					},
					"crypto_key_configs": [
					  {
						"id": "0",
						"usage": "sign-verify",
						"token_name": "access_token",
						"source": "config",
						"algorithm": "hmac",
						"token_lifetime": 3600,
						"token_secret": "01ee2688-36e4-47f9-8c06-d18483702520"
					  }
					],
					"crypto_key_store_config": {
					  "token_lifetime": 3600
					},
					"token_grantor_options": {
					  "enable_source_address": true
					}
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
		{
			name: "test malformed authentication portal definition",
			d: caddyfile.NewTestDispenser(`
            security {
              authentication portal myportal foo {
			    backend local assets/config/users.json local
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: Wrong argument count or unexpected line ending after '%s'", tf, 3, "foo"),
		},
		{
			name: "test unsupported authentication portal keyword",
			d: caddyfile.NewTestDispenser(`
            security {
			  authentication portal myportal {
                foo bar
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				mkcp(authnPrefix, "portal", "foo"),
				[]string{"bar"},
			),
		},
		/*
					{
						name: "test smtp credentials without address",
						d: caddyfile.NewTestDispenser(`
			            security {
			              credentials email smtp.contoso.com {
			                protocol smtp
			                username foo
			                password bar
			              }
			            }`),
						shouldErr: true,
						err: errors.ErrMalformedDirective.WithArgs(
							[]string{credPrefix, "email", "smtp.contoso.com"},
							errors.ErrCredKeyValueEmpty.WithArgs("address"),
						),
					},
					{
						name: "test unsupported credentials type",
						d: caddyfile.NewTestDispenser(`
			            security {
			              credentials foo bar {
			                protocol smtp
			                username foo
			                password bar
			              }
			            }`),
						shouldErr: true,
						err: errors.ErrMalformedDirective.WithArgs(
							credPrefix,
							[]string{"foo", "bar"},
						),
					},
		*/
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
				t.Errorf("parseCaddyfileAuthentication() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
