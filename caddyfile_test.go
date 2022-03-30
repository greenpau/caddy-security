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
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/google/go-cmp/cmp"
)

const tf string = "Testfile"

func TestParseCaddyfileAppConfig(t *testing.T) {
	testcases := []struct {
		name      string
		d         *caddyfile.Dispenser
		want      string
		shouldErr bool
		err       error
	}{
		{
			name: "test email credentials",
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
			    "credentials": {
				  "generic": [
				    {
					  "name":     "smtp.contoso.com",
					  "username": "foo",
					  "password": "bar"
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

			fullCfg := unpack(t, string(app.(httpcaddyfile.App).Value))
			cfg := fullCfg["config"].(map[string]interface{})

			got := make(map[string]interface{})
			for _, k := range []string{"credentials"} {
				got[k] = cfg[k].(map[string]interface{})
			}

			want := unpack(t, tc.want)

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("parseCaddyfileAppConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func unpack(t *testing.T, i interface{}) (m map[string]interface{}) {
	switch v := i.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			t.Fatalf("failed to parse %q: %v", v, err)
		}
	default:
		b, err := json.Marshal(i)
		if err != nil {
			t.Fatalf("failed to marshal %T: %v", i, err)
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("failed to parse %q: %v", b, err)
		}
	}
	return m
}
