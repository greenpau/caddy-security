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

package sqlite_test

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	companion "github.com/greenpau/caddy-security/plugins/oauth-login-storage-sqlite"
)

func TestCaddyfileOAuthLoginStoreParser(t *testing.T) {
	good := "shared {\npath \"/private login, storage/logins.db\"\ntimeout 1000ms\ncapacity 37\n}"
	module := new(companion.SQLiteOAuthLoginStore)
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal("valid complete declaration failed")
	}
	if module.Name != "shared" || module.Path != "/private login, storage/logins.db" || module.Timeout != "1s" || module.Capacity != 37 {
		t.Fatal("complete encoded parser lost literals or normalization")
	}
	for name, input := range map[string]string{
		"empty":              "",
		"extra_header":       strings.Replace(good, "shared {", "shared other {", 1),
		"empty_name":         strings.Replace(good, "shared {", `"" {`, 1),
		"space_name":         strings.Replace(good, "shared {", `" shared" {`, 1),
		"missing_block":      "shared",
		"empty_block":        "shared {\n}",
		"quoted_open":        strings.Replace(good, "shared {", `shared "{"`, 1),
		"missing_close":      strings.TrimSuffix(good, "}"),
		"missing_path":       "shared {\ncapacity 1\n}",
		"empty_path":         "shared {\npath \"\"\n}",
		"extra_path":         "shared {\npath /private/logins.db extra\n}",
		"relative_path":      "shared {\npath relative.db\n}",
		"unknown":            strings.Replace(good, "capacity 37", "credential private-sentinel", 1),
		"body_name":          strings.Replace(good, "capacity 37", "name other", 1),
		"duplicate_path":     strings.Replace(good, "capacity 37", "path /private/other.db", 1),
		"duplicate_timeout":  strings.Replace(good, "capacity 37", "timeout 2s", 1),
		"duplicate_capacity": strings.Replace(good, "capacity 37", "capacity 37\ncapacity 37", 1),
		"capacity_zero":      strings.Replace(good, "capacity 37", "capacity 0", 1),
		"capacity_negative":  strings.Replace(good, "capacity 37", "capacity -1", 1),
		"capacity_overflow":  strings.Replace(good, "capacity 37", "capacity 999999999999999999999999999999", 1),
		"capacity_max":       strings.Replace(good, "capacity 37", "capacity 100001", 1),
		"capacity_dynamic":   strings.Replace(good, "capacity 37", "capacity {env.OAUTH_CAPACITY}", 1),
		"timeout_zero":       strings.Replace(good, "1000ms", "0s", 1),
		"timeout_short":      strings.Replace(good, "1000ms", "999us", 1),
		"timeout_long":       strings.Replace(good, "1000ms", "31s", 1),
		"nested":             strings.Replace(good, "capacity 37", "capacity {\nvalue 37\n}", 1),
		"empty_nested":       strings.Replace(good, "capacity 37", "capacity 37 {\n}", 1),
	} {
		t.Run(name, func(t *testing.T) {
			before := *module
			if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("invalid declaration accepted")
			}
			if *module != before {
				t.Fatal("failed parsing partially replaced module state")
			}
		})
	}
	defaults := `"}" {
path "/private/{env.LITERAL_PATH}/logins.db"
}`
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(defaults)); err != nil || module.Name != "}" || module.Path != "/private/{env.LITERAL_PATH}/logins.db" || module.Timeout != "1s" || module.Capacity != 10000 {
		t.Fatal("quoted name, literal path or defaults changed")
	}
}
