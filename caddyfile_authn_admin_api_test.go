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
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func adminPortalInput(lines string) string {
	return `{
 security {
  local identity store localdb {
   realm local
   path :memory:
  }
  authentication portal portal {
   enable identity store localdb
` + lines + `
  }
 }
}
:8443 {
 route /auth/* {
  authenticate with portal
 }
}
`
}

func adaptAdminPortal(input string) (*authn.PortalConfig, error) {
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		return nil, err
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		return nil, err
	}
	if app.Config == nil || len(app.Config.AuthenticationPortals) != 1 {
		return nil, fmt.Errorf("expected one portal")
	}
	return app.Config.AuthenticationPortals[0], nil
}

func TestPortalAdminAPIDirectives(t *testing.T) {
	for _, tc := range []struct {
		name          string
		lines         []string
		admin, export bool
	}{
		{name: "defaults"},
		{name: "admin_only", lines: []string{"enable admin api"}, admin: true},
		{name: "export_only", lines: []string{"enable admin api private key export"}, export: true},
		{name: "disable_admin", lines: []string{"disable admin api"}},
		{name: "disable_export", lines: []string{"disable admin api private key export"}},
		{name: "both_off", lines: []string{"disable admin api", "disable admin api private key export"}},
		{name: "admin_on", lines: []string{"enable admin api", "disable admin api private key export"}, admin: true},
		{name: "export_on", lines: []string{"disable admin api", "enable admin api private key export"}, export: true},
		{name: "both_on", lines: []string{"enable admin api", "enable admin api private key export"}, admin: true, export: true},
		{name: "quoted_keywords", lines: []string{`"enable" "admin" "api"`, `disable "admin" api private key export`}, admin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				lines := append(slices.Clone(tc.lines), "enable source ip tracking", "ui {\n theme basic\n}")
				if reverse {
					slices.Reverse(lines)
				}
				portal, err := adaptAdminPortal(adminPortalInput(strings.Join(lines, "\n")))
				if err != nil {
					t.Fatal(err)
				}
				want := authn.APIConfig{ProfileEnabled: true, AdminEnabled: tc.admin, AdminFetchPrivateKeysEnabled: tc.export}
				if portal.API == nil || *portal.API != want {
					t.Fatalf("API = %+v, want %+v", portal.API, want)
				}
				if !portal.TokenGrantorOptions.EnableSourceAddress || portal.UI.Theme != "basic" {
					t.Fatal("admin settings changed unrelated portal settings")
				}
				data, err := json.Marshal(portal)
				if err != nil {
					t.Fatal(err)
				}
				var roundtrip authn.PortalConfig
				if err := json.Unmarshal(data, &roundtrip); err != nil {
					t.Fatal(err)
				}
				if roundtrip.API == nil || *roundtrip.API != want {
					t.Fatal("portal JSON roundtrip changed API flags")
				}
				var raw struct {
					API map[string]bool `json:"api"`
				}
				if err := json.Unmarshal(data, &raw); err != nil {
					t.Fatal(err)
				}
				expected := map[string]bool{"profile_enabled": true}
				if tc.admin {
					expected["admin_enabled"] = true
				}
				if tc.export {
					expected["admin_fetch_private_keys_enabled"] = true
				}
				if len(raw.API) != len(expected) {
					t.Fatal("unexpected aggregate API serialization")
				}
				for field, value := range expected {
					if got, ok := raw.API[field]; !ok || got != value {
						t.Fatalf("missing established API field %s", field)
					}
				}
			}
		})
	}
}

func TestPortalAdminAPIProfilePreservation(t *testing.T) {
	for _, profile := range []bool{false, true} {
		for _, before := range []bool{false, true} {
			for _, statements := range [][]string{nil, {}, {"enable admin api"}, {"enable admin api private key export"}, {"enable admin api", "enable admin api private key export"}} {
				portal := &authn.PortalConfig{API: &authn.APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}}
				if before {
					portal.API.ProfileEnabled = profile
				}
				if err := configurePortalAdminAPI(portal, statements); err != nil {
					t.Fatal(err)
				}
				if !before {
					portal.API.ProfileEnabled = profile
				}
				if portal.API.ProfileEnabled != profile {
					t.Fatal("admin parser changed profile setting")
				}
				if portal.API.AdminEnabled != slices.Contains(statements, "enable admin api") || portal.API.AdminFetchPrivateKeysEnabled != slices.Contains(statements, "enable admin api private key export") {
					t.Fatal("admin snapshot inherited flags or coupled independent settings")
				}
			}
		}
	}
	portal := &authn.PortalConfig{API: &authn.APIConfig{ProfileEnabled: true}}
	original := portal.API
	if err := configurePortalAdminAPI(portal, []string{"enable admin api", "disable admin api"}); err == nil || portal.API != original || *portal.API != (authn.APIConfig{ProfileEnabled: true}) {
		t.Fatal("failed parse applied partial configuration")
	}
}

func TestPortalAdminAPIMalformedDirectives(t *testing.T) {
	cases := []string{
		`enable admin`, `disable admin`, `enable admin api private key`,
		`enable admin api true`, `disable admin api false`,
		`enable admin api private key export true`, `disable admin api private key export false`,
		`enable admin api 1`, `enable admin api private key export on`,
		`enable admin api extra`, `enable admin api private key export extra`,
		`enable "admin api"`, `enable admin "api private key export"`,
		`enable admin api "private key export"`, `"enable admin api"`,
		`enable admin api ""`, `enable admin api private key export ""`,
		`enable admin "" api`, `enable admin api " "`,
		"enable admin api \"private\nkey export\"",
		`enable admin_api`, `enable admin api public key export`,
		`enable admin api private certificate export`, `enable admin api private key import`,
		`disable source ip tracking`, `enable admin API`,
		"enable admin api {\n}", "enable admin api {\n disable admin api\n}",
	}
	for i, input := range cases {
		t.Run(fmt.Sprintf("case_%02d", i), func(t *testing.T) {
			if _, err := adaptAdminPortal(adminPortalInput(input)); err == nil {
				t.Fatal("accepted malformed admin directive")
			}
		})
	}
	for _, setting := range []string{"admin api", "admin api private key export"} {
		for _, first := range []string{"enable", "disable"} {
			for _, second := range []string{"enable", "disable"} {
				t.Run(setting+"/"+first+"/"+second, func(t *testing.T) {
					input := first + " " + setting + "\nui {\n theme basic\n}\nenable source ip tracking\n" + second + " " + setting
					_, err := adaptAdminPortal(adminPortalInput(input))
					if err == nil || !strings.Contains(err.Error(), "duplicate admin API setting "+setting+" at line 2") {
						t.Fatalf("expected portal-wide duplicate error, got %v", err)
					}
				})
			}
		}
	}
}

func TestPortalAdminAPIErrorRedaction(t *testing.T) {
	const secret = "synthetic-sensitive-admin-value"
	for _, input := range []string{
		"enable admin api " + secret,
		"disable admin api private key export " + secret,
		"enable admin api private " + secret + " export",
		"enable admin api \"" + secret + "\nmore\"",
		"disable " + secret + " api",
		"enable Admin api " + secret,
		"enable \" admin\" api " + secret,
		"enable \" admin api\" " + secret,
		"enable " + secret + " api",
	} {
		_, err := adaptAdminPortal(adminPortalInput(input))
		if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "security.authentication.portal") {
			t.Fatal("malformed admin setting did not produce a redacted contextual error")
		}
	}
}

func TestPortalAdminAPIIndependentPortals(t *testing.T) {
	app := &App{}
	// Use full adaptation to verify collection is scoped to each portal.
	input := strings.Replace(adminPortalInput("enable admin api\nenable admin api private key export"), "\n }\n}", "\n  authentication portal other {\n   disable admin api\n   enable identity store localdb\n  }\n }\n}", 1)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt(caddyfile.Format([]byte(input)), nil)
	if err != nil {
		t.Fatal(err)
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(config.AppsRaw["security"], app); err != nil {
		t.Fatal(err)
	}
	if len(app.Config.AuthenticationPortals) != 2 {
		t.Fatal("expected two portals")
	}
	for _, portal := range app.Config.AuthenticationPortals {
		enabled := portal.Name == "portal"
		if portal.API == nil || portal.API.AdminEnabled != enabled || portal.API.AdminFetchPrivateKeysEnabled != enabled || !portal.API.ProfileEnabled {
			t.Fatal("admin flags leaked across portals")
		}
	}
}
