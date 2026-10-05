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
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	crossdeviceparser "github.com/greenpau/go-authcrunch/pkg/authn/cross_device/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func crossDevicePortalInput(lines string) string {
	return strings.NewReplacer("portal portal", "portal myportal", "authenticate with portal", "authenticate with myportal").Replace(adminPortalInput(lines))
}

func TestPortalCrossDeviceDirectives(t *testing.T) {
	for _, mode := range []string{"", "enable", "disable"} {
		t.Run(mode, func(t *testing.T) {
			directive := ""
			var want *authn.CrossDeviceLoginConfig
			if mode != "" {
				directive = mode + " cross-device login"
				var err error
				want, err = crossdeviceparser.NewCrossDeviceLoginConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{mode, "cross-device", "login"})})
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, quote := range []bool{false, true} {
				line := directive
				if quote && mode != "" {
					line = fmt.Sprintf("%q %q %q", mode, "cross-device", "login")
				}
				input := crossDevicePortalInput(line + "\nenable source ip tracking\ndisable admin api")
				portal, err := adaptAdminPortal(input)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(want, portal.CrossDeviceLogin); diff != "" {
					t.Fatal(diff)
				}
				if !portal.TokenGrantorOptions.EnableSourceAddress || portal.API.AdminEnabled {
					t.Fatal("unrelated directives changed")
				}
				data, err := json.Marshal(portal)
				if err != nil {
					t.Fatal(err)
				}
				var restored authn.PortalConfig
				if err := json.Unmarshal(data, &restored); err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(want, restored.CrossDeviceLogin); diff != "" {
					t.Fatal(diff)
				}
				if mode == "" && strings.Contains(string(data), "cross_device_login") {
					t.Fatal("omission gained an explicit setting")
				}
			}
		})
	}
}

func TestPortalCrossDeviceRejects(t *testing.T) {
	const secret = "synthetic-must-not-appear"
	cases := []string{
		"enable cross-device", "disable cross-device", "enable cross-device signin",
		"enable cross-device login " + secret, "disable cross-device login " + secret,
		`enable "cross-device login" ` + secret, `"enable cross-device" login ` + secret,
		`"enable cross-device login ` + secret + `"`, `disable "cross-device login"`,
		`enable cross-device "" login`, `enable cross-device login ""`,
		`enable cross-device login " "`, "enable cross-device \"log\nin\"",
		`enable "" cross-device login ` + secret, `disable "" cross-device login ` + secret,
		`enable cross-device "login ` + secret + `"`, `disable cross-device "login ` + secret + `"`,
		"enable cross-device\nlogin " + secret,
		"enable cross-device login {\n}\n", "disable cross-device login {\n" + secret + "\n}",
		"enable cross-device login\nenable cross-device login",
		"enable cross-device login\ndisable cross-device login",
		"disable cross-device login\nenable cross-device login",
		"disable cross-device login\ndisable cross-device login",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(crossDevicePortalInput(input)), nil)
			if err == nil || len(data) != 0 {
				t.Fatal("malformed setting returned configuration")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error disclosed argument")
			}
		})
	}
	for _, second := range []string{"enable", "disable"} {
		input := "(device_login) {\nenable cross-device login\n}\n" + crossDevicePortalInput("import device_login\n"+second+" cross-device login")
		if _, err := adaptAdminPortal(input); err == nil || !strings.Contains(err.Error(), "duplicate cross-device login") {
			t.Fatalf("import escaped aggregate validation: %v", err)
		}
	}
}
