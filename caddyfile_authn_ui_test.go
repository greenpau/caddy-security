// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

func TestPortalUILanguage(t *testing.T) {
	for _, tc := range []struct{ name, statement, want string }{
		{"omitted", "", ""},
		{"code", "language fr", "fr"},
		{"full name", "language French", "French"},
		{"raw spelling", `language " FRENCH "`, " FRENCH "},
		{"explicit empty", `language ""`, ""},
		{"last declaration wins", "language fr\nlanguage ar", "ar"},
		{"unsupported deferred", "language fr-FR", "fr-FR"},
		{"whitespace deferred", `language " "`, " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portal := &authn.PortalConfig{UI: &ui.Parameters{Templates: make(map[string]string)}}
			d := caddyfile.NewTestDispenser("ui {\n" + tc.statement + "\n}")
			if !d.Next() {
				t.Fatal("missing UI directive")
			}
			if err := parseCaddyfileAuthPortalUI(d, portal, "security.authentication.portal.ui"); err != nil {
				t.Fatalf("parse language: %v", err)
			}
			if portal.UI.Language != tc.want {
				t.Fatal("language spelling or declaration precedence changed")
			}
		})
	}
}

func TestPortalUILanguageArity(t *testing.T) {
	for _, tc := range []struct{ name, statement string }{
		{"missing", "language"},
		{"extra token", "language fr ar"},
		{"same line language", "language fr language ar"},
		{"same line theme", "language fr theme basic"},
		{"empty then directive", `language "" language ar`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portal := &authn.PortalConfig{UI: &ui.Parameters{Templates: make(map[string]string)}}
			d := caddyfile.NewTestDispenser("ui {\n" + tc.statement + "\n}")
			if !d.Next() {
				t.Fatal("missing UI directive")
			}
			err := parseCaddyfileAuthPortalUI(d, portal, "security.authentication.portal.ui")
			if err == nil {
				t.Fatal("malformed language statement was accepted")
			}
			if !strings.Contains(err.Error(), "Testfile:2") {
				t.Fatal("language diagnostic lost its source location")
			}
			want := "language subdirective requires exactly one value"
			if tc.name == "missing" {
				want = "language subdirective has no value"
			}
			if !strings.Contains(err.Error(), want) || portal.UI.Language != "" || portal.UI.Theme != "" {
				t.Fatal("malformed language statement was not rejected at its argument boundary")
			}
		})
	}
}
