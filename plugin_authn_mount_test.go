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
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func TestAuthnMountCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		name, input, matcher, mount string
		explicit                    bool
	}{
		{"legacy", "authenticate with myportal", "*", "", false},
		{"legacy matcher", "authenticate /auth/* with myportal", "/auth/*", "", false},
		{"root", "authenticate with myportal at /", "*", "/", true},
		{"nested", "authenticate with myportal at /company/auth", "*", "/company/auth", true},
		{"named matcher", "authenticate @portal with myportal at /company/auth", "@portal", "/company/auth", true},
		{"lookalike", "authenticate /saml-service/* with myportal at /saml-service", "/saml-service/*", "/saml-service", true},
		{"uppercase", "authenticate with myportal at /LOGIN", "*", "/LOGIN", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m AuthnMiddleware
			// The Caddy handler adapter resets its dispenser after extracting a
			// matcher. Direct module parsing also accepts that unadvanced form.
			if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input)); err != nil {
				t.Fatalf("parse portal mount: %v", err)
			}
			if m.PortalName != "myportal" || m.RouteMatcher != tc.matcher || (m.BasePath != nil) != tc.explicit {
				t.Fatal("portal reference, matcher or explicit mount presence changed")
			}
			if m.BasePath != nil && *m.BasePath != tc.mount {
				t.Fatal("literal mount was changed")
			}
		})
	}
}

func TestAuthnMountCaddyfileRejects(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"missing mount", "authenticate with myportal at"},
		{"missing mount with matcher", "authenticate @portal with myportal at"},
		{"empty mount", `authenticate with myportal at ""`},
		{"extra mount", "authenticate with myportal at /auth /other"},
		{"duplicate at", "authenticate with myportal at /auth at /other"},
		{"wrong keyword", "authenticate with myportal on /auth"},
		{"trailing slash", "authenticate with myportal at /auth/"},
		{"relative", "authenticate with myportal at auth"},
		{"dot segment", "authenticate with myportal at /company/../auth"},
		{"repeated separator", "authenticate with myportal at /company//auth"},
		{"encoded separator", "authenticate with myportal at /company%2Fauth"},
		{"query", `authenticate with myportal at "/auth?next=1"`},
		{"fragment", `authenticate with myportal at "/auth#fragment"`},
		{"placeholder", `authenticate with myportal at "{env.PORTAL_MOUNT}"`},
		{"secret lookup", `authenticate with myportal at "secrets:manager:mount"`},
		{"glob", `authenticate with myportal at "/auth/*"`},
		{"reserved prefix", "authenticate with myportal at /company/login-team"},
		{"reserved segment", "authenticate with myportal at /company/api/auth"},
		{"reserved discovery", "authenticate with myportal at /company/.well-known"},
		{"non ASCII cookie path", "authenticate with myportal at /équipe/auth"},
		{"cookie attribute delimiter", `authenticate with myportal at "/neutral;parameter"`},
		{"escaped URL spelling", `authenticate with myportal at "/neutral<area>"`},
		{"block", "authenticate with myportal at /auth {\n arbitrary value\n}"},
		{"empty block", "authenticate with myportal at /auth {\n}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m AuthnMiddleware
			err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if err == nil {
				t.Fatal("invalid explicit mount syntax was accepted")
			}
			if !strings.Contains(err.Error(), "Testfile:") {
				t.Fatal("mount diagnostic lost its Caddyfile source location")
			}
		})
	}
}

func TestAuthnMountNativeValidation(t *testing.T) {
	for _, tc := range []struct {
		name, field, mount string
		explicit, valid    bool
	}{
		{"omitted", "", "", false, true},
		{"null", `,"base_path":null`, "", false, true},
		{"root", `,"base_path":"/"`, "/", true, true},
		{"nested", `,"base_path":"/company/auth"`, "/company/auth", true, true},
		{"case sensitive", `,"base_path":"/PROFILE"`, "/PROFILE", true, true},
		{"lookalike", `,"base_path":"/cross-device-team"`, "/cross-device-team", true, true},
		{"empty", `,"base_path":""`, "", true, false},
		{"trailing slash", `,"base_path":"/auth/"`, "/auth/", true, false},
		{"relative", `,"base_path":"auth"`, "auth", true, false},
		{"dot segment", `,"base_path":"/auth/../other"`, "/auth/../other", true, false},
		{"repeated separator", `,"base_path":"//auth"`, "//auth", true, false},
		{"escape", `,"base_path":"/%61uth"`, "/%61uth", true, false},
		{"query", `,"base_path":"/auth?next=1"`, "/auth?next=1", true, false},
		{"fragment", `,"base_path":"/auth#part"`, "/auth#part", true, false},
		{"backslash", `,"base_path":"/auth\\other"`, "/auth\\other", true, false},
		{"space", `,"base_path":"/auth area"`, "/auth area", true, false},
		{"control", `,"base_path":"/auth\u0000"`, "/auth\x00", true, false},
		{"placeholder", `,"base_path":"/{env.PORTAL_MOUNT}"`, "/{env.PORTAL_MOUNT}", true, false},
		{"glob", `,"base_path":"/auth*"`, "/auth*", true, false},
		{"reserved prefix", `,"base_path":"/company/profile-team"`, "/company/profile-team", true, false},
		{"reserved segment", `,"base_path":"/company/provider/auth"`, "/company/provider/auth", true, false},
		{"non ASCII cookie path", `,"base_path":"/équipe/auth"`, "/équipe/auth", true, false},
		{"cookie attribute delimiter", `,"base_path":"/neutral;parameter"`, "/neutral;parameter", true, false},
		{"escaped URL spelling", `,"base_path":"/neutral<area>"`, "/neutral<area>", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m AuthnMiddleware
			if err := json.Unmarshal([]byte(`{"route_matcher":"*","portal_name":"myportal"`+tc.field+`}`), &m); err != nil {
				t.Fatal("cannot decode native mount fixture")
			}
			if (m.BasePath != nil) != tc.explicit || (m.BasePath != nil && *m.BasePath != tc.mount) {
				t.Fatal("native declaration lost explicit presence or literal spelling")
			}
			// No runtime or storage is needed to validate the route contract.
			m.portal = &authn.Portal{}
			err := m.Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("native mount validation accepted=%t, want %t", err == nil, tc.valid)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid portal mount") {
				t.Fatal("native rejection did not come from mount validation")
			}
			if m.BasePath != nil && *m.BasePath != tc.mount {
				t.Fatal("validation normalized or replaced a declared mount")
			}
		})
	}
	for _, field := range []string{`true`, `42`, `[]`, `{}`} {
		var m AuthnMiddleware
		if json.Unmarshal([]byte(`{"base_path":`+field+`}`), &m) == nil {
			t.Fatal("non-string native mount was accepted")
		}
	}
}
