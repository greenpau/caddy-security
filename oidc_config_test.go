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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func TestOIDCProviderMounts(t *testing.T) {
	for _, tc := range []struct {
		name, issuer    string
		disabled, valid bool
	}{
		{"disjoint", "https://auth.example.test/other", false, true},
		{"path boundary", "https://auth.example.test/authentication", false, true},
		{"different host", "https://second.example.test/auth", false, true},
		{"largest port", "https://second.example.test:65535/auth", false, true},
		{"identical", "https://auth.example.test/auth", false, false},
		{"nested", "https://auth.example.test/auth/nested", false, false},
		{"root", "https://auth.example.test", false, false},
		{"different port same cookie scope", "https://auth.example.test:8443/auth", false, false},
		{"trailing dot same cookie scope", "https://auth.example.test./auth", false, false},
		{"trailing dot disjoint mount", "https://auth.example.test./other", false, true},
		{"disabled", "https://auth.example.test/auth", true, true},
		{"disabled port opt-out", "https://auth.example.test:65536/auth", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, err := parseOIDCTestPortal(t, oidcTestBlock(oidcTestBody))
			if err != nil {
				t.Fatal(err)
			}
			provider := *app.Config.AuthenticationPortals[0].OIDCProvider
			provider.Issuer = tc.issuer
			provider.Enabled = !tc.disabled
			app.Config.AuthenticationPortals = append(app.Config.AuthenticationPortals, &authn.PortalConfig{Name: "second", OIDCProvider: &provider})
			for range 2 {
				err := validateOIDCProviderMounts(app.Config)
				if (err == nil) != tc.valid || err != nil && !strings.Contains(err.Error(), "non-overlapping issuer mounts") {
					t.Fatalf("mount validation = %v, valid = %v", err, tc.valid)
				}
				app.Config.AuthenticationPortals[0], app.Config.AuthenticationPortals[1] = app.Config.AuthenticationPortals[1], app.Config.AuthenticationPortals[0]
			}
			secondBody := strings.Replace(oidcTestBody, "https://auth.example.test/auth", tc.issuer, 1)
			if tc.disabled {
				secondBody = "disabled\n" + secondBody
			}
			second := strings.Replace(oidcTestPortal(oidcTestBlock(secondBody)), "portal myportal", "portal second", 1)
			input := "{\nsecurity {\n" + oidcTestPortal(oidcTestBlock(oidcTestBody)) + second + applicationTestBlock("website", "") + "}\n}\n"
			_, _, err = caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
			if (err == nil) != tc.valid || err != nil && !strings.Contains(err.Error(), "non-overlapping issuer mounts") {
				t.Fatalf("adapted mount validation = %v, valid = %v", err, tc.valid)
			}
		})
	}
}

func TestOIDCProviderCookieHostAliases(t *testing.T) {
	for _, tc := range []struct{ name, first, second, want, disjointWant string }{
		{"trailing DNS dot", "auth.example.test", "auth.example.test.", "non-overlapping issuer mounts", ""},
		{"internationalized hostname", "bücher.example.test", "xn--bcher-kva.example.test", "canonical ASCII hostname", "canonical ASCII hostname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := url.Parse("https://" + tc.first + "/auth")
			if err != nil {
				t.Fatal(err)
			}
			second, err := url.Parse("https://" + tc.second + "/auth")
			if err != nil {
				t.Fatal(err)
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(first, []*http.Cookie{{Name: "AUTHP_OIDC_SESSION_ID", Value: "first-provider", Path: "/auth", Secure: true}})
			if cookies := jar.Cookies(second); len(cookies) != 1 || cookies[0].Value != "first-provider" {
				t.Fatal("test hosts do not share the client's cookie scope")
			}
			app, err := parseOIDCTestPortal(t, oidcTestBlock(oidcTestBody))
			if err != nil {
				t.Fatal(err)
			}
			app.Config.AuthenticationPortals[0].OIDCProvider.Issuer = "https://" + tc.first + "/auth"
			provider := *app.Config.AuthenticationPortals[0].OIDCProvider
			provider.Issuer = "https://" + tc.second + "/auth"
			app.Config.AuthenticationPortals = append(app.Config.AuthenticationPortals, &authn.PortalConfig{Name: "second", OIDCProvider: &provider})
			if err := validateOIDCProviderMounts(app.Config); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("providers sharing cookie scope were accepted: %v", err)
			}
			provider.Issuer = "https://" + tc.second + "/other"
			err = validateOIDCProviderMounts(app.Config)
			if (err == nil) != (tc.disjointWant == "") || err != nil && !strings.Contains(err.Error(), tc.disjointWant) {
				t.Fatalf("distinct paths on equivalent cookie hosts: %v, want %q", err, tc.disjointWant)
			}
		})
	}
}

func TestOIDCIssuerCookieHost(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"auth.example.test", "auth.example.test"},
		{"auth.example.test.", "auth.example.test"},
		{"bücher.example.test", "xn--bcher-kva.example.test"},
		{"bücher。example.test", "xn--bcher-kva.example.test"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1.", "127.0.0.1"},
		{"0:0:0:0:0:0:0:1", "::1"},
		{"2001:0db8::1", "2001:db8::1"},
		{"::ffff:127.0.0.1", "::ffff:7f00:1"},
		{"::ffff:7f00:1", "::ffff:7f00:1"},
		{"2130706433", ""},
		{"127.1", ""},
		{"0177.0.0.1", ""},
		{"0x7f000001", ""},
		{"127.0.0.01", ""},
		{"127.0.0.0x1", ""},
		{"127.0.0.0x", ""},
		{"127.0.0.999", ""},
		{"bad:host", ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			host, err := oidcIssuerCookieHost(tc.host)
			if tc.want == "" {
				if err == nil {
					t.Fatal("ambiguous or invalid cookie hostname was accepted")
				}
				return
			}
			if err != nil || host != tc.want {
				t.Fatalf("cookie host = %q, %v; want %q", host, err, tc.want)
			}
		})
	}
}

func TestOIDCProviderCanonicalOrigins(t *testing.T) {
	for _, tc := range []struct {
		issuer string
		valid  bool
	}{
		{"https://auth.example.test/auth", true},
		{"https://auth.example.test./auth", true},
		{"https://xn--bcher-kva.example.test/auth", true},
		{"https://127.0.0.1:8443/auth", true},
		{"https://[::1]:8443/auth", true},
		{"https://[::ffff:7f00:1]:8443/auth", true},
		{"https://auth.example.test:443/auth", false},
		{"https://auth.example.test:08443/auth", false},
		{"https://bücher.example.test/auth", false},
		{"https://auth。example.test/auth", false},
		{"https://127.0.0.1./auth", false},
		{"https://[0:0:0:0:0:0:0:1]/auth", false},
		{"https://[::ffff:127.0.0.1]/auth", false},
		{"https://auth..example.test/auth", false},
		{"https://auth.example.test../auth", false},
		{"https://./auth", false},
		{"https://\u00ad/auth", false},
		{"https://" + strings.Repeat("a", 64) + ".example.test/auth", false},
		{"https://" + strings.Repeat(strings.Repeat("a", 63)+".", 4) + "test/auth", false},
	} {
		t.Run(tc.issuer, func(t *testing.T) {
			body := strings.Replace(oidcTestBody, "https://auth.example.test/auth", tc.issuer, 1)
			app, err := parseOIDCTestPortal(t, oidcTestBlock(body))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateOIDCProviderMounts(app.Config); (err == nil) != tc.valid {
				t.Fatalf("origin validation = %v; valid = %v", err, tc.valid)
			}
			input := "{\nsecurity {\n" + oidcTestPortal(oidcTestBlock(body)) + applicationTestBlock("website", "") + "}\n}\n"
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); (err == nil) != tc.valid {
				t.Fatalf("adaptation = %v; valid = %v", err, tc.valid)
			}
		})
	}
}
