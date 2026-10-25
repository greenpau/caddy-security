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

package plugin_test

import (
	"strings"
	"testing"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

func TestOAuthLoginStoreConfig(t *testing.T) {
	base := plugin.OAuthLoginStoreConfig{Name: "pending", Driver: "sqlite", ConfigHash: strings.Repeat("ab", 32)}
	for _, value := range []string{"pending", "with spaces,comma", "ログイン", "}", strings.Repeat("n", 128)} {
		cfg := base
		cfg.Name, cfg.Driver = value, value
		before := cfg
		if err := cfg.Validate(); err != nil || cfg != before {
			t.Fatalf("valid metadata rejected or mutated: %v", err)
		}
	}
	for _, field := range []string{"name", "driver"} {
		for _, value := range []string{"", " padded", "padded ", "control\ncanary", "control\u0085canary", "invalid\xffcanary", strings.Repeat("x", 129)} {
			cfg := base
			if field == "name" {
				cfg.Name = value
			} else {
				cfg.Driver = value
			}
			before := cfg
			if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "canary") || cfg != before {
				t.Fatalf("invalid %s metadata accepted, disclosed, or mutated: %v", field, err)
			}
		}
	}
	for _, hash := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("AB", 32), strings.Repeat("z", 64)} {
		cfg := base
		cfg.ConfigHash = hash
		if err := cfg.Validate(); err == nil {
			t.Fatal("invalid configuration digest accepted")
		}
	}
}
