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

func TestParseCaddyfileCredentials(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test valid smtp credentials",
			d: caddyfile.NewTestDispenser(`
            security {
			  credentials smtp.contoso.com {
			    username foo
                password bar
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
			  "generic": [
				{
				  "name":     "smtp.contoso.com",
				  "username": "foo",
				  "password": "bar"
				}
			  ]
			}`,
		},
		{
			name: "test valid smtp credentials with optional domain",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials smtp.contoso.com {
                username foo
                password bar
                domain contoso.com
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
			  "generic": [
				{
				  "name":     "smtp.contoso.com",
				  "username": "foo",
				  "password": "bar",
				  "domain":   "contoso.com"
				}
			  ]
            }`,
		},
		{
			name: "test malformed credentials definition",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials smtp.contoso.com foo {
				username foo
				password bar
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: Wrong argument count or unexpected line ending after 'foo'", tf, 3),
		},
		{
			name: "test unsupported credentials keyword",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials smtp.contoso.com {
                foo bar
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				[]string{credPrefix, "smtp.contoso.com", "foo"},
				[]string{"bar"},
			),
		},
		{
			name: "test smtp credentials without username",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials smtp.contoso.com {
                password bar
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				[]string{credPrefix, "smtp.contoso.com"},
				errors.ErrCredKeyValueEmpty.WithArgs("username"),
			),
		},
		{
			name: "test smtp credentials without password",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials smtp.contoso.com {
                username foo
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				[]string{credPrefix, "smtp.contoso.com"},
				errors.ErrCredKeyValueEmpty.WithArgs("password"),
			),
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
			got := cfg["credentials"].(map[string]interface{})
			want := unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("parseCaddyfileCredentials() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
