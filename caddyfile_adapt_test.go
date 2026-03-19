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
			name:                "authenticate plugin config",
			inputFileNamePrefix: "testcase_authenticate_ok",
		},
		{
			name:                "malformed authenticate plugin config",
			inputFileNamePrefix: "testcase_authenticate_malformed",
			shouldErr:           true,
			err:                 fmt.Errorf("parsing caddyfile tokens for 'route': parsing caddyfile tokens for 'authenticate': malformed directive: [authenticate], at Caddyfile:7, at Caddyfile:8"),
		},
		{
			name:                "security app config with authentication portal connected to local identity store",
			inputFileNamePrefix: "testcase_security_authentication_portal",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.Caddyfile", tc.inputFileNamePrefix)
			outputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.json", tc.inputFileNamePrefix)

			inputData, err := os.ReadFile(inputFilePath)
			if err != nil {
				t.Errorf("failed to read %s: %s", inputFilePath, err)
			}
			outputData, err := os.ReadFile(outputFilePath)
			if err != nil {
				t.Errorf("failed to read %s: %s", outputFilePath, err)
			}

			// winNewlines := regexp.MustCompile(`\r?\n`)

			got := strings.TrimSpace(string(inputData)) + "\n"

			want := strings.TrimSpace(string(outputData))
			// want = winNewlines.ReplaceAllString(want, "\n")

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

			// otherwise, adapt the Caddyfile and check for errors
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

			// if err == nil {
			// 	t.Errorf("expected error for %s but got none", inputFilePath)
			// } else {
			// 	normalizedErr := winNewlines.ReplaceAllString(err.Error(), "\n")
			// 	if !strings.Contains(normalizedErr, want) {
			// 		t.Errorf("expected error for %s to contain:\n%s\nbut got:\n%s", inputFilePath, want, normalizedErr)
			// 	}
			// }
		})
	}
}
