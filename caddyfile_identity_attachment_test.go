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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"go.uber.org/zap"
)

const attachmentSAMLBody = `realm saml
 driver generic
 entity_id urn:caddy:attachment-test
 idp_sign_cert_location /not-opened/idp.pem
 idp_login_url https://issuer.example.test/sso
 acs_url https://portal.example.test/auth/saml/saml
`
const attachmentLDAPBody = `realm directory
 servers {
  ldaps://directory.example.test
 }
 username cn=service,dc=example,dc=test
 password synthetic-bind-password
 search_base_dn dc=example,dc=test
 enable short automatic group mapping
`

func parseIdentityAttachmentTest(kind, statement string) (*authcrunch.Config, error) {
	cfg := new(authcrunch.Config)
	body := attachmentSAMLBody
	if kind == "ldap" {
		body = attachmentLDAPBody
	}
	d := caddyfile.NewTestDispenser("backend {\n" + statement + "\n" + body + "\n}")
	d.Next()
	var err error
	if kind == "ldap" {
		err = parseCaddyfileIdentityStore(d, cfg, kind, "directory", nil)
	} else {
		err = parseCaddyfileIdentityProvider(d, &App{Config: cfg}, kind, "saml", nil)
	}
	return cfg, err
}

func identityAttachmentParams(t *testing.T, cfg *authcrunch.Config, kind string) map[string]any {
	t.Helper()
	if kind == "ldap" {
		if len(cfg.IdentityStores) != 1 {
			t.Fatal("LDAP declaration missing")
		}
		return cfg.IdentityStores[0].Params
	}
	if len(cfg.IdentityProviders) != 1 {
		t.Fatal("SAML declaration missing")
	}
	return cfg.IdentityProviders[0].Params
}

func TestIdentityAttachmentParser(t *testing.T) {
	for _, kind := range []string{"saml", "ldap"} {
		t.Run(kind, func(t *testing.T) {
			for _, target := range []string{"accounts", "accounts with spaces,comma", "}", "{", "{env.ATTACHMENT_STORE}", "secrets:oauth:store"} {
				t.Run(target, func(t *testing.T) {
					cfg, err := parseIdentityAttachmentTest(kind, "attach to local identity store "+string(mustAttachmentJSON(t, target)))
					if err != nil {
						t.Fatal(err)
					}
					params := identityAttachmentParams(t, cfg, kind)
					got, ok := params["attachment"].(*attachment.Config)
					if !ok || got.LocalIdentityStore != target {
						t.Fatal("complete shared-parser statement lost literal name")
					}
					if kind == "saml" && params["realm"] != "saml" || kind == "ldap" && (params["realm"] != "directory" || params["servers"] == nil) {
						t.Fatal("attachment consumed a following declaration")
					}
				})
			}
			for name, statement := range map[string]string{
				"missing": "attach to local identity store", "empty": `attach to local identity store ""`,
				"extra": "attach to local identity store accounts extra", "joined_keywords": `attach "to local" identity store accounts`,
				"memory_name": "attach to local identity store :memory:", "space": `attach to local identity store " accounts"`,
				"duplicate":          "attach to local identity store accounts\nattach to local identity store accounts",
				"block":              "attach to local identity store accounts {\nrealm ignored\n}",
				"empty_block":        "attach to local identity store accounts {\n}",
				"disabled_duplicate": "disabled\nattach to local identity store accounts\nattach to local identity store accounts",
			} {
				t.Run(name, func(t *testing.T) {
					if _, err := parseIdentityAttachmentTest(kind, statement); err == nil {
						t.Fatal("malformed complete attachment accepted")
					}
				})
			}
			cfg, err := parseIdentityAttachmentTest(kind, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, present := identityAttachmentParams(t, cfg, kind)["attachment"]; present {
				t.Fatal("omission became an explicit attachment")
			}
		})
	}
	d := caddyfile.NewTestDispenser("local {\nrealm local\npath :memory:\nattach to local identity store other\n}")
	d.Next()
	if err := parseCaddyfileIdentityStore(d, new(authcrunch.Config), "local", "local", nil); err == nil {
		t.Fatal("local store accepted external attachment")
	}
}

func TestIdentityAttachmentActualAdapterBoundaries(t *testing.T) {
	for _, kind := range []string{"saml", "ldap"} {
		header, body := "saml identity provider saml", attachmentSAMLBody
		if kind == "ldap" {
			header, body = "ldap identity store directory", attachmentLDAPBody
		}
		for name, statement := range map[string]string{"valid": `attach to local identity store "}"`, "empty_block": "attach to local identity store accounts {\n}", "literal_braces": "attach to local identity store accounts {}"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				input := "{\nsecurity {\n" + header + " {\n" + statement + "\n" + body + "}\n}\n}"
				raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
				if name != "valid" {
					if err == nil {
						t.Fatal("actual Caddy adapter accepted malformed attachment")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				var doc struct {
					Apps struct {
						Security App `json:"security"`
					} `json:"apps"`
				}
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatal(err)
				}
				target := identityAttachmentParams(t, doc.Apps.Security.Config, kind)["attachment"].(map[string]any)["local_identity_store"]
				if target != "}" {
					t.Fatal("actual adaptation changed quoted brace target")
				}
			})
		}
	}
}

func TestIdentityAttachmentRuntimeResolution(t *testing.T) {
	for _, kind := range []string{"saml", "ldap"} {
		for _, native := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/native=%t", kind, native), func(t *testing.T) {
				cfg, err := parseIdentityAttachmentTest(kind, "attach to local identity store secrets:oauth:store")
				if err != nil {
					t.Fatal(err)
				}
				if native {
					identityAttachmentParams(t, cfg, kind)["attachment"] = map[string]any{"local_identity_store": "secrets:oauth:store"}
				}
				// App.Provision clones through JSON before traversing Params. Exercise that
				// boundary instead of teaching the generic resolver arbitrary Go pointers.
				original := mustAttachmentJSON(t, cfg)
				var snapshot authcrunch.Config
				if err := json.Unmarshal(original, &snapshot); err != nil {
					t.Fatal(err)
				}
				target := "exact accounts, {env.ATTACHMENT_SECOND_PASS}"
				t.Setenv("ATTACHMENT_SECOND_PASS", "must-not-expand")
				if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"store": target}}}, &snapshot, zap.NewNop()); err != nil {
					t.Fatal(err)
				}
				got := identityAttachmentParams(t, &snapshot, kind)["attachment"].(map[string]any)["local_identity_store"]
				if got != target {
					t.Fatal("attachment target split or expanded twice")
				}
				if string(original) != string(mustAttachmentJSON(t, cfg)) {
					t.Fatal("resolution mutated declarative snapshot")
				}
				for _, invalid := range []string{"", ":memory:", " accounts", "accounts\nprivate-sentinel"} {
					var rejected authcrunch.Config
					if err := json.Unmarshal(original, &rejected); err != nil {
						t.Fatal(err)
					}
					err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"store": invalid}}}, &rejected, zap.NewNop())
					if err == nil || strings.Contains(err.Error(), "private-sentinel") {
						t.Fatal("resolved invalid attachment did not fail safely")
					}
					if invalid == "" && !strings.Contains(err.Error(), "attachment resolved to an empty name") {
						t.Fatal("empty secret did not reach the explicit attachment guard", err)
					}
				}
			})
		}
	}
}

func TestAppIdentityProviderAttachmentDisabledTarget(t *testing.T) {
	module := sqliteTicketTestConfig(t)
	input := fmt.Sprintf("{\nsecurity {\nlocal identity store local {\nrealm local\npath :memory:\ndisabled\n}\nidentity provider sqlite application {\nrealm application\npath %q\npublic_origin %s\nissuer_url %s\nattach to local identity store local\n}\nauthentication portal portal {\nenable identity provider application\ncrypto key sign-verify synthetic-lifecycle-signing-secret\n}\n}\n}", module.Path, module.PublicOrigin, module.IssuerURL)
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Apps.Security.Config.IdentityStores) != 0 {
		t.Fatal("disabled local declaration remained active")
	}
	if _, err := credentialTestApp(t, &doc.Apps.Security); err == nil || !strings.Contains(err.Error(), "requires one configured local identity store") {
		t.Fatal("disabled target reached runtime factory", err)
	}
}

func TestIdentityAttachmentRuntimeEmptyBoundary(t *testing.T) {
	t.Setenv("ATTACHMENT_EMPTY", "")
	for _, kind := range []string{"saml", "ldap"} {
		for _, target := range []string{"{env.ATTACHMENT_EMPTY}", "", "accounts"} {
			t.Run(kind+"/target="+target, func(t *testing.T) {
				cfg, err := parseIdentityAttachmentTest(kind, "")
				if err != nil {
					t.Fatal(err)
				}
				identityAttachmentParams(t, cfg, kind)["attachment"] = map[string]any{"local_identity_store": target}
				original := mustAttachmentJSON(t, cfg)
				var snapshot authcrunch.Config
				if err := json.Unmarshal(original, &snapshot); err != nil {
					t.Fatal(err)
				}
				err = ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, &snapshot, zap.NewNop())
				if target == "{env.ATTACHMENT_EMPTY}" {
					// The generic replacer may reject an empty environment value
					// before the attachment-specific empty-name guard runs.
					if err == nil || (!strings.Contains(err.Error(), "attachment.local_identity_store: failed to perform replacement") && !strings.Contains(err.Error(), "attachment resolved to an empty name")) {
						t.Fatal("empty reference silently selected private memory", err)
					}
				} else if err != nil {
					t.Fatal("native implicit or literal attachment rejected", err)
				}
				if string(original) != string(mustAttachmentJSON(t, cfg)) {
					t.Fatal("empty-name validation mutated original snapshot")
				}
			})
		}
	}
}
