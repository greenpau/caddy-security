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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

const accessSignerTestBody = "key file /private/access.pem\nkey id current\nissuer https://auth.example.test/auth\naudience service-a"

func TestRSAPSSAccessSignerParser(t *testing.T) {
	for _, suffix := range []string{"", "\nalgorithm PS256\nmax lifetime 900s"} {
		app, err := accessProfileTestAdapt("access signer rsapss primary {\n" + accessSignerTestBody + suffix + "\n}")
		if err != nil {
			t.Fatal(err)
		}
		if len(app.AccessSignerConfigs) != 1 {
			t.Fatal("signer module missing")
		}
		var module RSAPSSAccessSigner
		if json.Unmarshal(app.AccessSignerConfigs[0], &module) != nil {
			t.Fatal("invalid signer module JSON")
		}
		if module.Name != "primary" || module.KeyID != "current" || module.Algorithm != "PS256" || module.MaxLifetime != "15m0s" || module.Issuer != "https://auth.example.test/auth" {
			t.Fatal("shared parser defaults or literal values lost")
		}
	}
	path := filepath.Join(t.TempDir(), "absent", "key, {env.ACCESS_LITERAL}.pem")
	input := strings.Replace(accessSignerTestBody, "/private/access.pem", fmt.Sprintf("%q", path), 1)
	app, err := accessProfileTestAdapt("access signer rsapss primary {\n" + input + "\n}")
	if err != nil {
		t.Fatal(err)
	}
	var module RSAPSSAccessSigner
	_ = json.Unmarshal(app.AccessSignerConfigs[0], &module)
	if module.KeyFile != path {
		t.Fatal("module backend fields expanded or split")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("module parser touched key storage")
	}
	for _, order := range []bool{false, true} {
		signer := "access signer rsapss primary {\n" + accessSignerTestBody + "\n}"
		portal := "authentication portal portal {\n" + accessProfileTestVerificationKeys + "access signer primary\n" + accessProfileTestBlock(accessProfileTestBody) + "\n}"
		input := signer + "\n" + portal
		if order {
			input = portal + "\n" + signer
		}
		if _, err := accessProfileTestAdapt(input); err != nil {
			t.Fatal("signer declaration order changed adaptation")
		}
	}
}
func TestRSAPSSAccessSignerParserRejects(t *testing.T) {
	for i, body := range []string{"", accessSignerTestBody + "\nkey file second", accessSignerTestBody + "\nkey id second", accessSignerTestBody + "\nissuer second", accessSignerTestBody + "\naudience second", accessSignerTestBody + "\nalgorithm PS256\nalgorithm PS256", accessSignerTestBody + "\nmax lifetime 15m\nmax lifetime 900s", accessSignerTestBody + "\nalgorithm RS256", accessSignerTestBody + "\nmax lifetime {env.ACCESS_LIFETIME}", accessSignerTestBody + "\nmax lifetime 1.5s", accessSignerTestBody + "\nmax lifetime 86401s", accessSignerTestBody + "\nunknown private-signer-diagnostic", accessSignerTestBody + "\nkey file nested {\n}", strings.Replace(accessSignerTestBody, "key id current", "key id", 1), strings.Replace(accessSignerTestBody, "key file /private/access.pem", "key file \"\"", 1), strings.Replace(accessSignerTestBody, "key id current", "key id bad/id", 1)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := accessProfileTestAdapt("access signer rsapss primary {\n" + body + "\n}"); err == nil {
				t.Fatal("invalid shared signer body accepted")
			}
		})
	}
	for _, input := range []string{"access signer rsapss", "access signer rsapss primary extra {\n" + accessSignerTestBody + "\n}", "access signer absent primary {\n" + accessSignerTestBody + "\n}", "access signer rsapss primary", "access rsapss primary {\n" + accessSignerTestBody + "\n}"} {
		if _, err := accessProfileTestAdapt(input); err == nil {
			t.Fatal("invalid signer header or absent block accepted")
		}
	}
	module := accessSignerTestModuleConfig("unchanged.pem")
	before, _ := json.Marshal(module)
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser("primary {\n" + accessSignerTestBody)); err == nil {
		t.Fatal("truncated signer block accepted")
	}
	after, _ := json.Marshal(module)
	if string(before) != string(after) {
		t.Fatal("rejected parser input mutated module")
	}
}
