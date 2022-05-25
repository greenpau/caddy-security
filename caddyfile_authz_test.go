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

func TestParseCaddyfileAuthorization(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid authorization policy config",
			d: caddyfile.NewTestDispenser(`
            security {
			  authorization policy mypolicy {
			    crypto key verify 0e2fdcf8-6868-41a7-884b-7308795fc286
                set auth url /auth
				allow roles authp/admin authp/user
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
				  {
                    "auth_url_path": "/auth",
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
                    "name": "mypolicy",
                    "auth_url_path": "/auth",
                    "access_list_rules": [
                      {
                        "conditions": [
                          "match roles authp/admin authp/user"
                        ],
                        "action": "allow log debug"
                      }
                    ],
					"crypto_key_configs": [
                      {
                        "id": "0",
                        "usage": "verify",
                        "token_name": "access_token",
                        "source": "config",
                        "algorithm": "hmac",
                        "token_lifetime": 900,
                        "token_secret": "0e2fdcf8-6868-41a7-884b-7308795fc286"
                      }
                    ]
                  }
                ]
              }
            }`,
		},
		{
			name: "test valid authorization policy config with misc settings",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                crypto key verify 0e2fdcf8-6868-41a7-884b-7308795fc286
                set auth url /auth
                set token sources query
                set forbidden url /forbidden
                set redirect status 302
                set redirect query parameter return_path_url
                disable auth redirect query
                disable auth redirect
                validate path acl
                validate source address
                validate bearer header
                with basic auth portal default realm local
                with api key auth portal default realm local
                allow roles authp/admin authp/user
              }
            }`),
			want: `{
			  "config": {
				"authorization_policies": [
				  {
					"name": "mypolicy",
					"auth_url_path": "/auth",
					"disable_auth_redirect": true,
					"disable_auth_redirect_query": true,
					"auth_redirect_query_param": "return_path_url",
					"auth_redirect_status_code": 302,
					"access_list_rules": [
					  {
						"conditions": [
						  "match roles authp/admin authp/user"
						],
						"action": "allow log debug"
					  }
					],
					"crypto_key_configs": [
					  {
						"id": "0",
						"usage": "verify",
						"token_name": "access_token",
						"source": "config",
						"algorithm": "hmac",
						"token_lifetime": 900,
						"token_secret": "0e2fdcf8-6868-41a7-884b-7308795fc286"
					  }
					],
					"auth_proxy_config": {
					  "portal_name": "default",
					  "basic_auth": {
						"enabled": true,
						"realms": {
						  "local": true
						}
					  },
					  "api_key_auth": {
						"enabled": true,
						"realms": {
						  "local": true
						}
					  }
					},
					"allowed_token_sources": [
					  "query"
					],
					"forbidden_url": "/forbidden",
					"validate_bearer_header": true,
					"validate_method_path": true,
					"validate_access_list_path_claim": true,
					"validate_source_address": true
				  }
				]
              }
            }`,
		},
		{
			name: "test valid authorization policy config with custom acl",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy2 {
                crypto key verify 0e2fdcf8-6868-41a7-884b-7308795fc286
				bypass uri exact /foo
				set user identity id
				inject headers with claims
				inject header "X-Picture" from picture
				enable js redirect
                set auth url /auth
				enable strip token
				enable additional scopes
                acl rule {
                  comment allow users
                  match role authp/user
                  allow stop log info
                }
                acl rule {
                  comment default deny
                  match any
                  deny log warn
                }
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
                  {
                    "name": "mypolicy2",
                    "auth_url_path": "/auth",
			        "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
                    "redirect_with_javascript": true,
                    "access_list_rules": [
                      {
                        "comment": "comment allow users",
                        "conditions": [
                          "match role authp/user"
                        ],
                        "action": "allow stop log info"
                      },
                      {
                        "comment": "comment default deny",
                        "conditions": [
                          "match any"
                        ],
                        "action": "deny log warn"
                      }
                    ],
                    "crypto_key_configs": [
                      {
                        "id": "0",
                        "usage": "verify",
                        "token_name": "access_token",
                        "source": "config",
                        "algorithm": "hmac",
                        "token_lifetime": 900,
                        "token_secret": "0e2fdcf8-6868-41a7-884b-7308795fc286"
                      }
                    ],
					"strip_token_enabled": true,
					"additional_scopes": true,
					"user_identity_field": "id",
					"pass_claims_with_headers": true,
					"redirect_with_javascript": true,
                    "header_injection_configs": [
                      {
                        "header": "X-Picture",
                        "field": "picture"
                      }
                    ],
                    "bypass_configs": [
                      {
                        "match_type": "exact",
                        "uri": "/foo"
                      }
                    ]
                  }
                ]
              }
            }`,
		},
		{
			name: "test valid authorization policy with custom acl shortcuts",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                allow roles authp/admin authp/user
				allow roles authp/guest with get to /foo
				allow origin any
				deny iss foo
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
                  {
                    "name": "mypolicy",
					"auth_url_path": "/auth",
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
                    "access_list_rules": [
                      {
                        "conditions": ["match roles authp/admin authp/user"],
                        "action": "allow log debug"
                      },
                      {
                        "conditions": [
                          "match roles authp/guest",
                          "match method GET",
                          "partial match path /foo"
                        ],
                        "action": "allow log debug"
                      },
                      {
                        "conditions": ["field origin exists"],
                        "action": "allow log debug"
                      },
                      {
                        "conditions": ["match iss foo"],
                        "action": "deny stop log warn"
                      }
                    ],
                    "validate_method_path": true
                  }
                ]
              }
            }`,
		},
		{
			name: "test valid authorization policy with custom acl",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl rule {
                  match roles authp/admin authp/user
                  allow stop log info
                }
                acl default deny
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
                  {
                    "name": "mypolicy",
                    "auth_url_path": "/auth",
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
                    "access_list_rules": [
                      {
                        "conditions": ["match roles authp/admin authp/user"],
                        "action": "allow stop log info"
                      },
                      {
                        "conditions": ["match any"],
                        "action": "deny"
                      }
                    ]
                  }
                ]
              }
            }`,
		},
		{
			name: "test valid authorization policy with enabled login hint",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                enable login hint
				allow roles authp/admin authp/user
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
                  {
                    "name": "mypolicy",
                    "auth_url_path": "/auth",
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
					"login_hint_validators": ["email", "phone", "alphanumeric"],
					"access_list_rules": [
                      {
                        "conditions": [
                          "match roles authp/admin authp/user"
                        ],
                        "action": "allow log debug"
                      }
                    ]
                  }
                ]
              }
            }`,
		},
		{
			name: "test valid authorization policy with enabled login hint with validators",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                enable login hint with email phone
				allow roles authp/admin authp/user
              }
            }`),
			want: `{
              "config": {
                "authorization_policies": [
                  {
                    "name": "mypolicy",
                    "auth_url_path": "/auth",
                    "auth_redirect_query_param": "redirect_url",
                    "auth_redirect_status_code": 302,
					"login_hint_validators": ["email", "phone"],
                    "access_list_rules": [
                      {
                        "conditions": [
                          "match roles authp/admin authp/user"
                        ],
                        "action": "allow log debug"
                      }
                    ]
                  }
                ]
              }
            }`,
		},
		{
			name: "test malformed authorization policy definition",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy foo {
			    bypass uri /foo/bar
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: Wrong argument count or unexpected line ending after '%s'", tf, 3, "foo"),
		},
		{
			name: "test unsupported authorization policy keyword",
			d: caddyfile.NewTestDispenser(`
            security {
			  authorization policy mypolicy {
                foo bar
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				mkcp(authzPrefix, "policy", "foo"),
				[]string{"bar"},
			),
		},
		// Authorization header injection.
		{
			name: "test authorization policy injection with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                inject foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.inject: %v", tf, 4, "foo"),
		},
		{
			name: "test authorization policy header injection with too many args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                inject header bar baz foo bar
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.inject directive %q is invalid", tf, 4, "header bar baz foo bar"),
		},
		{
			name: "test authorization policy header injection with bad syntax",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
				inject header "X-Picture" foo picture
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.inject directive %q has invalid syntax", tf, 4, "header X-Picture foo picture"),
		},
		{
			name: "test authorization policy injection without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                inject
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.inject directive has no value", tf, 4),
		},
		{
			name: "test authorization policy injection without empty args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                inject header "X-Picture" from " "
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.inject %s erred: undefined field name", tf, 4, "header X-Picture from \" \""),
		},
		// Enable features.
		{
			name: "test authorization policy enable without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                enable
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.enable directive has no value", tf, 4),
		},
		{
			name: "test authorization policy injection with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                enable foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.enable: %v", tf, 4, "foo"),
		},
		// Validate features.
		{
			name: "test authorization policy validate without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                validate
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.validate directive has no value", tf, 4),
		},
		{
			name: "test authorization policy validate with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                validate foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.validate: %v", tf, 4, "foo"),
		},
		// Disabled features.
		{
			name: "test authorization policy disable without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                disable
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.disable directive has no value", tf, 4),
		},
		{
			name: "test authorization policy disable with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                disable foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.disable: %v", tf, 4, "foo"),
		},
		// Configure features.
		{
			name: "test authorization policy set without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                set
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.set directive has no value", tf, 4),
		},
		{
			name: "test authorization policy set with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                set foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.set: %v", tf, 4, "foo"),
		},
		{
			name: "test authorization policy set redirect status success",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                set redirect status 200
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.set %v directive contains invalid value", tf, 4, "redirect status 200"),
		},
		{
			name: "test authorization policy set redirect status alphanumeric",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                set redirect status foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.set %v directive failed: %v",
				tf, 4, "redirect status foo", "strconv.Atoi: parsing \"foo\": invalid syntax"),
		},
		// With features.
		{
			name: "test authorization policy with without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                with
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: security.authorization.policy.with directive has no value", tf, 4),
		},
		{
			name: "test authorization policy with with unsupported directive",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                with foo
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: unsupported directive for security.authorization.policy.with: %v", tf, 4, "foo"),
		},
		// Crypto errors.
		{
			name: "test authorization policy crypto with too little args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                crypto foo bar
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: %v", tf, 4,
				errors.ErrConfigDirectiveShort.WithArgs(
					"security.authorization.policy.crypto",
					[]string{"foo", "bar"},
				),
			),
		},
		{
			name: "test authorization policy crypto with unsupported args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                crypto foo bar baz
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: %v", tf, 4,
				errors.ErrConfigDirectiveValueUnsupported.WithArgs(
					"security.authorization.policy.crypto",
					[]string{"foo", "bar", "baz"},
				),
			),
		},
		// Bypass errors.
		{
			name: "test authorization policy bypass without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                bypass
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.bypass directive has no value",
				tf, 4,
			),
		},
		{
			name: "test authorization policy bypass with wrong args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                bypass foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.bypass %s is invalid",
				tf, 4, "foo",
			),
		},
		{
			name: "test authorization policy bypass with invalid keyword",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                bypass foo bar baz
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.bypass %s is invalid",
				tf, 4, "foo bar baz",
			),
		},
		{
			name: "test authorization policy bypass with invalid syntax",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                bypass uri bar baz
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.bypass %s erred: %v",
				tf, 4, "uri bar baz", "invalid \"bar\" bypass match type",
			),
		},
		// ACL errors.
		{
			name: "test authorization policy acl without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl directive has no value",
				tf, 4,
			),
		},
		{
			name: "test authorization policy acl rule with args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl rule foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl directive %q is too long",
				tf, 4, "rule foo",
			),
		},
		{
			name: "test authorization policy acl default with args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl default allow bar
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl directive %q is too long",
				tf, 4, "default allow bar",
			),
		},
		{
			name: "test authorization policy acl default with args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl default foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl directive %q must have either allow or deny",
				tf, 4, "default foo",
			),
		},
		{
			name: "test authorization policy acl invalid",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl directive value of %q is unsupported",
				tf, 4, "foo",
			),
		},
		{
			name: "test authorization policy acl rule without comment value",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                acl rule {
                  comment
                }
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.acl rule directive %v has no values",
				tf, 5, "comment",
			),
		},
		// ACL shortcuts errors.
		{
			name: "test authorization policy acl shortcut without args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                allow
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.allow directive has no value",
				tf, 4,
			),
		},
		{
			name: "test authorization policy acl shortcut without too few args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                allow foo
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.allow directive %q is too short",
				tf, 4, "foo",
			),
		},
		{
			name: "test authorization policy acl shortcut with unsupported args",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization policy mypolicy {
                allow roles foo method get to /foo bar
              }
            }`),
			shouldErr: true,
			err: fmt.Errorf(
				"%s:%d - Error during parsing: security.authorization.policy.allow directive value of %q is unsupported",
				tf, 4, "roles foo method get to /foo bar",
			),
		},
		// Post config processing errors.
		{
			name: "test authorization invalid keyword",
			d: caddyfile.NewTestDispenser(`
            security {
              authorization foo bar {
                baz zag
			  }
            }`),
			shouldErr: true,
			err:       errors.ErrMalformedDirective.WithArgs(authzPrefix, []string{"foo", "bar"}),
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
				t.Errorf("parseCaddyfileAuthorization() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
