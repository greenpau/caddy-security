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

	"github.com/caddyserver/caddy/v2"
)

func accessSignerTestModuleConfig(path string) *RSAPSSAccessSigner {
	return &RSAPSSAccessSigner{Name: "primary", KeyFile: path, KeyID: "current", Issuer: "https://auth.example.test/auth", Audience: "service-a"}
}

func TestRSAPSSAccessSignerNativeConfiguration(t *testing.T) {
	for _, raw := range []string{`null`, `{"driver":"absent"}`, `{"driver":"rsapss","name":"primary","key_file":false}`, `{"driver":"rsapss","unknown":"private-signer-diagnostic"}`} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		app := &App{AccessSignerConfigs: []json.RawMessage{json.RawMessage(raw)}}
		if _, err := ctx.LoadModule(app, "AccessSignerConfigs"); err == nil {
			cancel()
			t.Fatal("invalid native signer module accepted")
		}
		cancel()
	}
}
