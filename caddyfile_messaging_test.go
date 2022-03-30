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

func TestParseCaddyfileMessaging(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid email provider with credentials",
			d: caddyfile.NewTestDispenser(`
            security {
			  credentials root@localhost {
			    username root
                password foobar
			  }

			  messaging email provider local_smtp_server {
			    address localhost:25
				protocol smtp
				credentials root@localhost
				sender root@localhost "Auth Portal"
				template password_recovery path/to/password_recovery.tmpl
				template registration_confirmation path/to/registration_confirmation.tmpl
				template registration_ready path/to/registration_ready.tmpl
				template registration_verdict path/to/registration_verdict.tmpl
				template mfa_otp path/to/mfa_otp.tmpl
			  }

              local identity store localdb {
                realm local
                path /tmp/localdb
              }

              authentication portal myportal {
                enable identity store localdb
              }
            }`),
			want: `{
                "credentials": {
                  "generic": [
                    {
                      "name": "root@localhost",
                      "username": "root",
                      "password": "foobar"
                    }
                  ]
                },
                "messaging": {
                  "email_providers": [
                    {
                      "name": "local_smtp_server",
                      "address": "localhost:25",
                      "protocol": "smtp",
                      "credentials": "root@localhost",
                      "sender_email": "root@localhost",
                      "sender_name": "Auth Portal",
                      "templates": {
                        "mfa_otp": "path/to/mfa_otp.tmpl",
                        "password_recovery": "path/to/password_recovery.tmpl",
                        "registration_confirmation": "path/to/registration_confirmation.tmpl",
                        "registration_ready": "path/to/registration_ready.tmpl",
						"registration_verdict": "path/to/registration_verdict.tmpl"
                      }
                    }
                  ]
                }
			}`,
		},
		{
			name: "test malformed email provider definition",
			d: caddyfile.NewTestDispenser(`
            security {
              messaging email provider local_smtp_server foo {
				address localhost:25
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: Wrong argument count or unexpected line ending after 'foo'", tf, 3),
		},
		{
			name: "test malformed non-email provider definition",
			d: caddyfile.NewTestDispenser(`
            security {
              messaging bar provider local_smtp_server {
                address localhost:25
              }
            }`),
			shouldErr: true,
			err:       errors.ErrMalformedDirective.WithArgs(msgPrefix, []string{"bar", "provider", "local_smtp_server"}),
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

			fullCfg := unpack(t, string(app.(httpcaddyfile.App).Value))
			cfg := fullCfg["config"].(map[string]interface{})

			got := make(map[string]interface{})
			for _, k := range []string{"credentials", "messaging"} {
				got[k] = cfg[k].(map[string]interface{})
			}

			want := unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Logf("JSON: %v", string(app.(httpcaddyfile.App).Value))
				t.Errorf("parseCaddyfileMessaging() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
