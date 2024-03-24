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
	"github.com/tidwall/gjson"
	"os"
	"path"
	"testing"
)

func TestParseCaddyfileAuthenticationMisc(t *testing.T) {
	localDbEnvVar := "TMP_LOCAL_DB_PATH"
	glbTmpDir := path.Join(os.TempDir(), "tmp-caddy-security")
	err := os.Mkdir(glbTmpDir, 0750)
	if err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp(glbTmpDir, "caddyfile-tests")
	if err != nil {
		t.Fatalf("failed creating temporary directory: %v", err)
	}

	localDbPath := path.Join(tmpDir, "users.json")
	t.Logf("Local database path: %s", localDbPath)

	defer os.RemoveAll(tmpDir)

	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid authentication portal config with valid trust logout redirect uri",
			d: caddyfile.NewTestDispenser(`
            security {
				local identity store localdb {
					realm local
					path {env.TMP_LOCAL_DB_PATH}
					user webadmin {
						name Webmaster
						email webadmin@localhost.localdomain
						# echo -n 'Td45@4d269b7ec2f5ffd31ee5' | bcrypt-cli -c 10
						password "$2a$10$VLCDIncXaRFshFTGcz2aP.q.gR0O6y1i6mVDks/7WmE3JKLjPD.wu" overwrite
						roles authp/admin authp/user
					}
				}

				authentication portal myportal {
					enable identity store localdb
					trust logout redirect uri domain authcrunch.com path /foo/bar
					trust logout redirect uri domain prefix authcrunch path suffix /foo
				}
            }`),
			want: `{ "want": [
						{
							"cookie_config": {},
							"identity_stores": ["localdb"],
							"portal_admin_roles": {
								"authp/admin": true
							},
							"portal_user_roles": {
								"authp/user": true
							},
							"portal_guest_roles": {
								"authp/guest": true
							},
                            "name": "myportal",
		                    "api": {
				              "profile_enabled": true
						    },
							"token_grantor_options": {},
							"trusted_logout_redirect_uri_configs": [
								{
									"domain": "authcrunch.com",
									"domain_match_type": "exact",
									"path": "/foo/bar",
									"path_match_type": "exact"
								},
                                {
                                    "domain": "authcrunch",
                                    "domain_match_type": "prefix",
                                    "path": "/foo",
                                    "path_match_type": "suffix"
                                }
							],
							"token_validator_options": {},
							"ui": {}
						}
			]}`,
		},
	}

	t.Setenv(localDbEnvVar, localDbPath)
	defer os.Unsetenv(localDbEnvVar)

	for _, tc := range testcases {
		defer os.Unsetenv(localDbPath)

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

			tmpGot := gjson.Get(string(app.(httpcaddyfile.App).Value), "config.authentication_portals")
			tmpWant := gjson.Get(tc.want, "want")

			got := unpack(t, "{\"config\": "+tmpGot.String()+"}")
			want := unpack(t, "{\"config\": "+tmpWant.String()+"}")

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", string(app.(httpcaddyfile.App).Value))
				t.Errorf("TestParseCaddyfileAuthenticationMisc() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
