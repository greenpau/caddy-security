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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"

	"github.com/google/go-cmp/cmp"
)

func findKeyRecursive(data interface{}, targetKey string) interface{} {
	m, ok := data.(map[string]interface{})
	if ok {
		if val, found := m[targetKey]; found {
			return val
		}
		for _, v := range m {
			if result := findKeyRecursive(v, targetKey); result != nil {
				return result
			}
		}
	}

	s, ok := data.([]interface{})
	if ok {
		for _, item := range s {
			if result := findKeyRecursive(item, targetKey); result != nil {
				return result
			}
		}
	}

	return nil
}

func extractSecurityConfig(filePath string) (string, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	var data interface{}
	if err := json.Unmarshal(fileBytes, &data); err != nil {
		return "", err
	}

	securityKey := "security"
	result := findKeyRecursive(data, securityKey)
	if result == nil {
		return "", fmt.Errorf("key %q not found", securityKey)
	}

	resultMap, ok := result.(map[string]any)
	if !ok {
		return "", fmt.Errorf("key %q was found, but it is not an object (type: %T)", securityKey, result)
	}

	securityConfigKey := "config"
	config, exists := resultMap[securityConfigKey]
	if !exists {
		return "", fmt.Errorf("key %q has not %q key", securityKey, securityConfigKey)

	}

	output, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func convertConfigToJSON(data map[string]any) (string, error) {
	rawBytes, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	var prettyBuf bytes.Buffer
	err = json.Indent(&prettyBuf, rawBytes, "", "\t")
	if err != nil {
		return "", fmt.Errorf("error indenting JSON: %w", err)
	}

	return prettyBuf.String(), nil
}

func parseConfigAsMap(filePath string) (map[string]any, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal outer JSON: %w", err)
	}

	return raw, nil
}

func TestResolveRuntimeAppConfig(t *testing.T) {
	testcases := []struct {
		name                string
		inputFileNamePrefix string
		shouldErr           bool
		err                 error
	}{
		{
			name:                "authenticate plugin config with cookie multi domain",
			inputFileNamePrefix: "testcase_authenticate_with_cookie_multi_domain",
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
			name:                "authenticate plugin config with ui",
			inputFileNamePrefix: "testcase_authenticate_with_ui",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			inputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.json", tc.inputFileNamePrefix)
			outputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s_resolved.json", tc.inputFileNamePrefix)
			tmpInputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s_tmp_input.json", tc.inputFileNamePrefix)
			tmpOutputFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s_tmp_output.json", tc.inputFileNamePrefix)

			defer func() {
				if !t.Failed() {
					os.Remove(tmpInputFilePath)
					os.Remove(tmpOutputFilePath)
				} else {
					t.Logf("Leaving temp files for debugging: %s, %s", tmpInputFilePath, tmpOutputFilePath)
				}
			}()

			envFilePath := fmt.Sprintf("./testdata/caddyfile_adapt/%s.env", tc.inputFileNamePrefix)

			for _, tv := range parseTestEnvVars(envFilePath) {
				t.Logf("setting environment variable %s=%s", tv.key, tv.value)
				os.Setenv(tv.key, tv.value)
				t.Cleanup(func() {
					t.Logf("unsetting environment variable %s", tv.key)
					os.Unsetenv(tv.key)
				})
			}

			repl := caddy.NewReplacer()
			logger := logutil.NewLogger()
			config := authcrunch.NewConfig()

			securityConfig, err := extractSecurityConfig(inputFilePath)
			if err != nil {
				t.Fatalf("unexpected error during extractSecurityConfig: %s: %s", outputFilePath, err)
			}

			if err := os.WriteFile(tmpInputFilePath, []byte(securityConfig), 0644); err != nil {
				t.Fatalf("unexpected error during writing temp file: %s: %s", tmpInputFilePath, err)
			}

			if err := config.LoadFromJSONFile(tmpInputFilePath); err != nil {
				t.Fatalf("failed to load config %s: %s", tmpInputFilePath, err)
			}

			err = ResolveRuntimeAppConfig(context.TODO(), repl, nil, config, logger)
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

			if err := config.DumpToJSONFile(tmpOutputFilePath); err != nil {
				t.Fatalf("failed to dump config %s: %s", tmpOutputFilePath, err)
			}

			gotConfig, err := parseConfigAsMap(tmpOutputFilePath)
			if err != nil {
				t.Fatalf("failed to parse %s: %s", tmpOutputFilePath, err)
			}

			wantConfig, err := parseConfigAsMap(outputFilePath)
			if err != nil {
				t.Fatalf("failed to parse %s: %s", inputFilePath, err)
			}

			if diff := cmp.Diff(wantConfig, gotConfig); diff != "" {
				t.Errorf("PortalConfig mismatch (-want +got):\n%s", diff)
			}

			plainText, err := convertConfigToJSON(gotConfig)
			if err != nil {
				t.Fatalf("failed to convert resolved config to JSON: %v", err)
			}
			if strings.Contains(plainText, "{env.") {
				t.Fatal("found unresolved variables in resolved config")
			}

		})
	}
}
