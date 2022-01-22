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
			  credentials email smtp.contoso.com {
			    address smtp.contoso.com:993
				protocol smtp
				username foo
				password bar
			  }
            }`),
			want: `{
			  "config": {
			    "credentials": {
				  "email": [
				    {
				      "address":  "smtp.contoso.com:993",
					  "name":     "smtp.contoso.com",
					  "username": "foo",
					  "password": "bar",
					  "protocol": "smtp"
					}
				  ]
				}
			  }
			}`,
		},
		{
			name: "test malformed credentials definition",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials email smtp.contoso.com foo {
				username foo
				password bar
              }
            }`),
			shouldErr: true,
			err:       fmt.Errorf("%s:%d - Error during parsing: Wrong argument count or unexpected line ending after '%s'", tf, 3, "foo"),
		},
		{
			name: "test unsupported credentials keyword",
			d: caddyfile.NewTestDispenser(`
            security {
              credentials email smtp.contoso.com {
                foo bar
              }
            }`),
			shouldErr: true,
			err: errors.ErrMalformedDirective.WithArgs(
				[]string{credPrefix, "email", "foo"},
				[]string{"bar"},
			),
		},
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
				t.Errorf("parseCaddyfileCredentials() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
