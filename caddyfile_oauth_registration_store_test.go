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
	"fmt"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestParseRegistrationStore(t *testing.T) {
	for _, input := range []string{
		"registration store {\npath /private\n}", "oauth registration {\npath /private\n}",
		"oauth registration store", "oauth registration store extra {\npath /private\n}",
		"oauth registration store {\n}", "oauth registration store {\npath\n}",
		"oauth registration store {\npath relative\n}", "oauth registration store {\npath /private extra\n}",
		"oauth registration store {\npath /private\npath /other\n}", "oauth registration store {\npath /private {\n}\n}",
		"oauth registration store {\npath /private\n} path /unexpected", "oauth registration store {\npath {env.PRIVATE}\n}",
		"oauth registration store {\npath /private/../other\n}",
	} {
		d := caddyfile.NewTestDispenser(input)
		d.Next()
		if _, err := parseCaddyfileOAuthRegistrationStore(d); err == nil {
			t.Fatalf("invalid storage config accepted: %s", input)
		}
	}
	d := caddyfile.NewTestDispenser("oauth registration store {\npath /private/registrations\n}")
	d.Next()
	if cfg, err := parseCaddyfileOAuthRegistrationStore(d); err != nil || cfg.Path != "/private/registrations" {
		t.Fatal("valid storage config rejected")
	}
}

func TestProvisioningFileParser(t *testing.T) {
	store := "oauth registration store {\npath /private/registrations\n}\n"
	app := "oauth application website {\nredirect_uri https://rp.example.test/callback\n}\n"
	for _, input := range []string{store + app, app + store} {
		parsed, err := parseProvisioningInput("private.Caddyfile", []byte(input))
		if err != nil || len(parsed.applications) != 1 {
			t.Fatal("valid provisioning file rejected", err)
		}
	}
	for _, input := range []string{app, strings.TrimPrefix(store, "oauth "), store + store, store + app + app, "import secret.Caddyfile", "{\n" + store + "}\n", store + "oauth application website {\nclient_secret " + registrationTestSecret + "\nredirect_uri }\n"} {
		_, err := parseProvisioningInput("private.Caddyfile", []byte(input))
		if err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatal("invalid provisioning file accepted or secret exposed")
		}
	}
	invalidUTF8 := store + "oauth application website {\nclient_secret " + registrationTestSecret + "\xff\nredirect_uri https://rp.example.test/callback\n}\n"
	if _, err := parseProvisioningInput("private.Caddyfile", []byte(invalidUTF8)); err == nil || strings.Contains(err.Error(), registrationTestSecret) {
		t.Fatal("invalid UTF-8 provisioning input accepted or secret exposed")
	}
}

func TestOAuthRegistrationStoreDeclarationScope(t *testing.T) {
	cfg, _ := registrationTestStore(t)
	store := fmt.Sprintf("oauth registration store {\npath %s\n}\n", cfg.Path)
	for _, body := range []string{store + store, strings.TrimPrefix(store, "oauth "), "oauth registration {\npath " + cfg.Path + "\n}\n"} {
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+body+"}\n}\n"), nil); err == nil {
			t.Fatal("duplicate or incorrectly scoped OAuth store declaration was accepted")
		}
	}
	if entries := registrationSnapshot(t, cfg.Path); len(entries) != 0 {
		t.Fatal("rejected store declaration wrote registration storage")
	}
}

func TestStoredApplicationParserFailures(t *testing.T) {
	cfg, _ := registrationTestStore(t)
	registrationTestCreate(t, cfg)
	for _, body := range []string{
		"registration", "registration v1 extra", "registration v1\nregistration v1", "registration missing",
		"registration v1\nclient_secret " + registrationTestSecret, "registration v1\nclient_id changed",
	} {
		input := fmt.Sprintf("{\nsecurity {\noauth registration store {\npath %s\n}\noauth application website {\n%s\nredirect_uri https://rp.example.test/callback\n}\n}\n}\n", cfg.Path, body)
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatal("invalid stored registration accepted or secret exposed")
		}
	}
}

func TestOIDCProviderBlockParser(t *testing.T) {
	for _, body := range []string{"disabled", "enabled\nissuer https://auth.example.test/auth\nrealms local\nsigning key files /private/key.pem\napplications website"} {
		input := fmt.Sprintf("{\nsecurity {\nauthentication portal myportal {\noidc provider {\n%s\n}\n}\noauth application website {\nclient_id explicit-client\nclient_secret %s\nredirect_uri https://rp.example.test/callback\n}\n}\n}\n", body, registrationTestSecret)
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{"enabled yes", "disabled\ndisabled", "disabled\napplications missing", "issuer " + registrationTestSecret, "disabled\nmax grants nope", "disabled\nscopes openid", "disabled\napplications website website"} {
		input := "{\nsecurity {\nauthentication portal myportal {\noidc provider {\n" + body + "\n}\n}\n}\n}\n"
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatal("invalid provider accepted or secret exposed")
		}
	}
}
