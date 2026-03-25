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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/google/go-cmp/cmp"
)

type testEnvVar struct {
	key   string
	value string
}

func parseTestEnvVars(envFilePath string) []*testEnvVar {
	entries := []*testEnvVar{}

	envData, err := os.ReadFile(envFilePath)
	if err != nil {
		return nil
	}

	lines := strings.Split(string(envData), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			entries = append(entries, &testEnvVar{
				key:   parts[0],
				value: parts[1],
			})
		}
	}
	return entries
}

func TestCaddyfileAdaptAuthenticationToJSON(t *testing.T) {
	testcases := []struct {
		name                string
		inputFileNamePrefix string
		shouldErr           bool
		err                 error
	}{
		{
			name:                "authorize plugin config",
			inputFileNamePrefix: "testcase_authorize_ok",
		},
		{
			name:                "authorize plugin config with api",
			inputFileNamePrefix: "testcase_authorize_with_api",
		},
		{
			name:                "authenticate plugin config",
			inputFileNamePrefix: "testcase_authenticate_ok",
		},
		{
			name:                "authenticate plugin config with ui",
			inputFileNamePrefix: "testcase_authenticate_with_ui",
		},
		{
			name:                "authenticate plugin config with cookie guess domain",
			inputFileNamePrefix: "testcase_authenticate_with_cookie_guess",
		},
		{
			name:                "authenticate plugin config with cookie specific domain",
			inputFileNamePrefix: "testcase_authenticate_with_cookie_domain",
		},
		{
			name:                "authenticate plugin config with cookie multi domain",
			inputFileNamePrefix: "testcase_authenticate_with_cookie_multi_domain",
		},
		{
			name:                "malformed authenticate plugin config",
			inputFileNamePrefix: "testcase_authenticate_malformed",
			shouldErr:           true,
			err:                 fmt.Errorf("parsing caddyfile tokens for 'route': parsing caddyfile tokens for 'authenticate': malformed directive: authenticate, at Caddyfile:3, at Caddyfile:4"),
		},
		{
			name:                "security app config with authentication portal connected to local identity store",
			inputFileNamePrefix: "testcase_security_authentication_portal",
		},
		{
			name:                "authenticate plugin config with malformed replacement",
			inputFileNamePrefix: "testcase_authenticate_malformed_replacement",
		},
		{
			name:                "authenticate plugin config with ok replacement",
			inputFileNamePrefix: "testcase_authenticate_ok_replacement",
		},
		{
			name:                "authenticate plugin config with credentials",
			inputFileNamePrefix: "testcase_authenticate_with_credentials",
		},
		{
			name:                "authenticate plugin config with registration",
			inputFileNamePrefix: "testcase_authenticate_with_registration",
		},
		{
			name:                "security app config with authentication portal with static secrets manager plugin",
			inputFileNamePrefix: "testcase_security_with_secrets",
			shouldErr:           true,
			err:                 fmt.Errorf("parsing caddyfile tokens for 'security': getting module named 'security.secrets.static_secrets_manager': module not registered: security.secrets.static_secrets_manager, at Caddyfile:3"),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.Caddyfile", tc.inputFileNamePrefix)
			outputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.json", tc.inputFileNamePrefix)
			envFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.env", tc.inputFileNamePrefix)

			t.Logf("output file: %s", outputFilePath)

			for _, tv := range parseTestEnvVars(envFilePath) {
				t.Logf("setting environment variable %s=%s", tv.key, tv.value)
				os.Setenv(tv.key, tv.value)
				t.Cleanup(func() {
					t.Logf("unsetting environment variable %s", tv.key)
					os.Unsetenv(tv.key)
				})
			}

			inputData, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Errorf("failed to read %s: %s", inputFilePath, err)
			}
			outputData, err := os.ReadFile(outputFilePath)
			if err != nil {
				t.Errorf("failed to read %s: %s", outputFilePath, err)
			}

			got := strings.TrimSpace(string(inputData)) + "\n"
			want := strings.TrimSpace(string(outputData))
			var prettyBuf bytes.Buffer
			err = json.Indent(&prettyBuf, []byte(want), "", "\t")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			want = prettyBuf.String()

			ok := caddytest.CompareAdapt(t, tc.inputFileNamePrefix, got, "caddyfile", want)
			if !ok && !tc.shouldErr {
				t.Errorf("failed to adapt %s", tc.inputFileNamePrefix)
				return
			}

			cfgAdapter := caddyconfig.GetAdapter("caddyfile")
			_, _, err = cfgAdapter.Adapt([]byte(got), nil)

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
		})
	}
}
