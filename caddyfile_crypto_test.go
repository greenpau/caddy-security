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
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

func adaptCryptoSettings(t *testing.T, lines string) *App {
	t.Helper()
	input := fmt.Sprintf(`{
 security {
  local identity store localdb {
   realm local
   path :memory:
  }
  authentication portal portal {
   enable identity store localdb
   %s
  }
  authorization policy policy {
   allow roles authp/user
   %s
  }
 }
}
:8443 {
 authenticate with portal
}`, lines, lines)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	if app.Config == nil || len(app.Config.AuthenticationPortals) != 1 || len(app.Config.AuthorizationPolicies) != 1 {
		t.Fatal("expected one portal and one policy")
	}
	return &app
}

// Exercise both raw instruction adapters and the actual runtime resolver. The
// library owns algorithm validation; adaptation must preserve its exact input.
func TestCaddyfileCryptoSettings(t *testing.T) {
	for _, tc := range []struct {
		name, algorithm, want string
	}{
		{"omitted", "", "ES512"},
		{"legacy", "ES512", "ES512"},
		{"EdDSA", "EdDSA", "EdDSA"},
		{"Ed25519", "Ed25519", "Ed25519"},
		{"runtime", "{env.CADDY_TEST_SIGNING_ALGORITHM}", "Ed25519"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CADDY_TEST_SIGNING_ALGORITHM", "Ed25519")
			lines := []string{"crypto default autogenerate tag adapter-" + tc.name, "crypto default token name integration_token", "crypto default token lifetime 1234"}
			if tc.algorithm != "" {
				lines = append(lines, "crypto default autogenerate algorithm "+tc.algorithm)
			}
			app := adaptCryptoSettings(t, strings.Join(lines, "\n"))
			portal, policy := app.Config.AuthenticationPortals[0], app.Config.AuthorizationPolicies[0]
			for _, raw := range [][]string{portal.GetRawCryptoKeyStoreConfig(), policy.GetRawCryptoKeyStoreConfig()} {
				var decoded []string
				for _, line := range raw {
					args, err := cfgutil.DecodeArgs(line)
					if err != nil {
						t.Fatal(err)
					}
					decoded = append(decoded, strings.Join(args, " "))
				}
				if diff := cmp.Diff(lines, decoded); diff != "" {
					t.Fatalf("raw crypto instructions changed: %s", diff)
				}
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			for _, cfg := range []*kms.CryptoKeyStoreConfig{portal.CryptoKeyStoreConfig, policy.CryptoKeyStoreConfig} {
				if cfg.AutoGenerateAlgo != tc.want || cfg.AutoGenerateTag != "adapter-"+tc.name || cfg.TokenName != "integration_token" || cfg.TokenLifetime != 1234 {
					t.Fatalf("crypto defaults changed: %+v", cfg)
				}
			}
		})
	}
}

func TestCaddyfileCryptoValidationOwnership(t *testing.T) {
	key := newJWKSKeyFiles(t, "OKP", "imported")
	for _, tc := range []struct {
		name, line string
		wantErr    bool
	}{
		{"EdDSA", "crypto default autogenerate algorithm EdDSA", false},
		{"Ed25519", "crypto default autogenerate algorithm Ed25519", false},
		{"ES512", "crypto default autogenerate algorithm ES512", false},
		{"lowercase_label", "crypto default autogenerate algorithm ed25519", true},
		{"unsupported_generation", "crypto default autogenerate algorithm RS256", true},
		{"imported", key.signer("signing"), false},
		{"imported_autogeneration_label", "crypto default autogenerate algorithm Ed25519\n" + key.signer("signing"), false},
		{"imported_relabel", key.signer("signing") + " algorithm Ed25519", true},
		{"public_sign_only", fmt.Sprintf("crypto key signing sign from file %q", key.public), true},
		{"public_sign_verify", fmt.Sprintf("crypto key signing sign-verify from file %q", key.public), false},
		{"private_verify_only", strings.Replace(key.signer("signing"), "sign-verify", "verify", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := adaptCryptoSettings(t, "crypto default autogenerate tag validation-"+tc.name+"\n"+tc.line)
			for owner, raw := range map[string][]string{
				"portal": app.Config.AuthenticationPortals[0].GetRawCryptoKeyStoreConfig(),
				"policy": app.Config.AuthorizationPolicies[0].GetRawCryptoKeyStoreConfig(),
			} {
				t.Run(owner, func(t *testing.T) {
					cfg, err := kms.NewCryptoKeyStoreConfig(raw)
					var store *kms.CryptoKeyStore
					if err == nil {
						store, err = kms.NewCryptoKeyStore(cfg, zap.NewNop())
					}
					if (err != nil) != tc.wantErr {
						t.Fatalf("library validation error = %t, want %t", err != nil, tc.wantErr)
					}
					if tc.name == "imported" || tc.name == "imported_autogeneration_label" {
						signers := store.GetSignKeys()
						if len(signers) != 1 || signers[0].Sign.Token.DefaultMethod != "EdDSA" {
							t.Fatal("autogeneration settings relabeled an imported Ed25519 signer")
						}
					}
					if tc.name == "public_sign_verify" || tc.name == "private_verify_only" {
						if len(store.GetSignKeys()) != 0 || len(store.GetVerifyKeys()) != 1 {
							t.Fatal("verification-only Ed25519 material gained signing capability")
						}
					}
				})
			}
		})
	}
}

func TestCaddyfileCryptoLegacyKeyAttributes(t *testing.T) {
	app := adaptCryptoSettings(t, `
crypto default token name portal_token
crypto default token lifetime 1200
crypto key first sign-verify synthetic-first-key
crypto key first token name legacy_token
crypto key first token lifetime 600
crypto key second verify synthetic-second-key
`)
	for owner, raw := range map[string][]string{
		"portal": app.Config.AuthenticationPortals[0].GetRawCryptoKeyStoreConfig(),
		"policy": app.Config.AuthorizationPolicies[0].GetRawCryptoKeyStoreConfig(),
	} {
		t.Run(owner, func(t *testing.T) {
			cfg, err := kms.NewCryptoKeyStoreConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			store, err := kms.NewCryptoKeyStore(cfg, zap.NewNop())
			if err != nil {
				t.Fatal("could not load legacy crypto settings")
			}
			keys := store.GetKeys()
			if len(keys) != 2 || keys[0].Config.Usage != "sign-verify" || keys[1].Config.Usage != "verify" {
				t.Fatal("legacy key order or usage changed")
			}
			for i, want := range []struct {
				id, name string
				lifetime int
			}{{"first", "legacy_token", 600}, {"second", "portal_token", 1200}} {
				if keys[i].Config.ID != want.id || keys[i].Config.TokenName != want.name || keys[i].Config.TokenLifetime != want.lifetime {
					t.Fatal("adapter changed explicit key attributes or inherited defaults")
				}
			}
			if keys[0].Sign.Token.DefaultMethod != "HS512" {
				t.Fatal("legacy HMAC default changed")
			}
		})
	}
}
