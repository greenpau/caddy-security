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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"go.uber.org/zap"
)

const accessProfileTestBody = "issuer https://auth.example.test/auth\naudience service-a\nkey ids retiring current\nmax lifetime 900"

// Adaptation and resolution validate declarations without opening these files.
const accessProfileTestVerificationKeys = "crypto key current verify from file /private/access-current-public.pem\ncrypto key retiring verify from file /private/access-retiring-public.pem\n"

func accessProfileTestBlock(body string) string { return "access token profile {\n" + body + "\n}" }
func accessProfileTestAdapt(input string) (*App, error) {
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+input+"\n}\n}"), nil)
	if err != nil {
		return nil, err
	}
	var document struct {
		Apps struct {
			Security *App `json:"security"`
		} `json:"apps"`
	}
	if json.Unmarshal(data, &document) != nil {
		return nil, fmt.Errorf("invalid adapted fixture")
	}
	return document.Apps.Security, nil
}
func accessProfileTestWant() *kms.AccessTokenProfileConfig {
	return &kms.AccessTokenProfileConfig{Issuer: "https://auth.example.test/auth", Audience: "service-a", KeyIDs: []string{"current", "retiring"}, MaxLifetimeSeconds: 900}
}
func accessProfileTestResolve(t *testing.T, app *App, managers []SecretsManager) *authcrunch.Config {
	t.Helper()
	raw, err := json.Marshal(app.Config)
	if err != nil {
		t.Fatal("cannot snapshot profile config")
	}
	var config authcrunch.Config
	if json.Unmarshal(raw, &config) != nil {
		t.Fatal("cannot restore profile config")
	}
	if err := resolveRuntimeAppConfigWithAccessTokens(t.Context(), caddy.NewReplacer(), managers, &config, app.OAuthProviderDirectives, app.PortalTokenRefreshDirectives, app.OAuthAuthorizationDirectives, app.PortalDocumentsDirectives, app.PortalAccessTokenProfileDirectives, app.PolicyAccessTokenProfileDirectives, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	return &config
}

func TestAccessTokenProfileParsing(t *testing.T) {
	profile := accessProfileTestBlock(accessProfileTestBody)
	for _, body := range []string{"access signer primary\n" + profile, profile + "\naccess signer primary"} {
		app, err := accessProfileTestAdapt("authentication portal portal {\n" + accessProfileTestVerificationKeys + body + "\n}\nauthorization policy policy {\nallow roles authp/user\n" + accessProfileTestVerificationKeys + profile + "\n}")
		if err != nil {
			t.Fatal(err)
		}
		portal, policy := app.Config.AuthenticationPortals[0], app.Config.AuthorizationPolicies[0]
		if portal.AccessSigner != "primary" || cmp.Diff(accessProfileTestWant(), portal.AccessTokenProfile) != "" || cmp.Diff(accessProfileTestWant(), policy.AccessTokenProfile) != "" {
			t.Fatal("literal parser lost selected profile")
		}
		if cmp.Diff(portal.AccessTokenProfile, portal.CryptoKeyStoreConfig.AccessTokenProfile) != "" || cmp.Diff(policy.AccessTokenProfile, policy.CryptoKeyStoreConfig.AccessTokenProfile) != "" {
			t.Fatal("core validator did not receive profile")
		}
	}
	// Audience values retain punctuation and interior spaces.
	body := strings.ReplaceAll(accessProfileTestBody, "service-a", `"service, {literal} audience"`)
	app, err := accessProfileTestAdapt("authentication portal portal {\n" + accessProfileTestVerificationKeys + "access signer primary\n" + accessProfileTestBlock(body) + "\n}")
	if err != nil || app.Config.AuthenticationPortals[0].AccessTokenProfile != nil || len(app.PortalAccessTokenProfileDirectives["portal"]) != 4 {
		t.Fatal("complete deferred profile was not retained")
	}
}

func TestAccessTokenProfileParsingRejects(t *testing.T) {
	bodies := []string{"", "issuer a", accessProfileTestBody + "\nissuer duplicate", strings.Replace(accessProfileTestBody, "retiring current", "current current", 1), strings.Replace(accessProfileTestBody, "retiring current", "bad/id", 1), strings.Replace(accessProfileTestBody, "900", "0", 1), strings.Replace(accessProfileTestBody, "900", "86401", 1), strings.Replace(accessProfileTestBody, "900", "15m", 1), strings.Replace(accessProfileTestBody, "900", "1.5", 1), strings.Replace(accessProfileTestBody, "900", strings.Repeat("9", 40), 1), strings.Replace(accessProfileTestBody, "issuer https://auth.example.test/auth", "issuer \" padded\"", 1), accessProfileTestBody + "\nalgorithm PS256", accessProfileTestBody + "\ntoken type JWT", accessProfileTestBody + "\nissuer child {\n}", strings.Replace(accessProfileTestBody, "key ids retiring current", "key ids", 1)}
	for i, body := range bodies {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			for _, scope := range []string{"authentication portal portal {\naccess signer primary\n", "authorization policy policy {\nallow roles authp/user\n"} {
				if _, err := accessProfileTestAdapt(scope + accessProfileTestVerificationKeys + accessProfileTestBlock(body) + "\n}"); err == nil {
					t.Fatal("invalid complete profile accepted")
				}
			}
		})
	}
	for _, body := range []string{"access signer", "access signer a b", "access signer \"\"", "access signer primary {\n}", "access signer primary\naccess signer primary", accessProfileTestBlock(accessProfileTestBody), "access signer primary", "access signer primary\n" + accessProfileTestBlock(accessProfileTestBody) + "\n" + accessProfileTestBlock(accessProfileTestBody), "access token profile extra {\n" + accessProfileTestBody + "\n}", "access token profile"} {
		if _, err := accessProfileTestAdapt("authentication portal portal {\n" + accessProfileTestVerificationKeys + body + "\n}"); err == nil {
			t.Fatal("malformed or incomplete portal signer selection accepted")
		}
	}
	if _, err := accessProfileTestAdapt("authorization policy policy {\nallow roles authp/user\n" + accessProfileTestVerificationKeys + "access signer primary\n}"); err == nil {
		t.Fatal("policy accepted signing authority")
	}
}

func TestAccessTokenProfileDeferredResolution(t *testing.T) {
	for key, value := range map[string]string{"ACCESS_PROFILE_SIGNER": "primary", "ACCESS_PROFILE_ISSUER": "https://auth.example.test/auth", "ACCESS_PROFILE_AUDIENCE": "service-a", "ACCESS_PROFILE_ID": "current", "ACCESS_PROFILE_SECONDS": "900"} {
		t.Setenv(key, value)
	}
	body := "issuer {env.ACCESS_PROFILE_ISSUER}\naudience {env.ACCESS_PROFILE_AUDIENCE}\nkey ids retiring {env.ACCESS_PROFILE_ID}\nmax lifetime {env.ACCESS_PROFILE_SECONDS}"
	app, err := accessProfileTestAdapt("authentication portal portal {\n" + accessProfileTestVerificationKeys + "access signer {env.ACCESS_PROFILE_SIGNER}\n" + accessProfileTestBlock(body) + "\n}\nauthorization policy policy {\nallow roles authp/user\n" + accessProfileTestVerificationKeys + accessProfileTestBlock(body) + "\n}")
	if err != nil {
		t.Fatal(err)
	}
	if app.Config.AuthenticationPortals[0].AccessSigner != "{env.ACCESS_PROFILE_SIGNER}" || app.Config.AuthenticationPortals[0].AccessTokenProfile != nil || app.Config.AuthorizationPolicies[0].AccessTokenProfile != nil {
		t.Fatal("adapter fabricated a deferred profile")
	}
	before, _ := json.Marshal(app)
	resolved := accessProfileTestResolve(t, app, nil)
	if resolved.AuthenticationPortals[0].AccessSigner != "primary" || cmp.Diff(accessProfileTestWant(), resolved.AuthenticationPortals[0].AccessTokenProfile) != "" || cmp.Diff(accessProfileTestWant(), resolved.AuthorizationPolicies[0].AccessTokenProfile) != "" {
		t.Fatal("deferred profile did not resolve completely")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("resolution mutated declarative profile snapshots")
	}
	native := &App{Config: &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "{env.ACCESS_PROFILE_SIGNER}", AccessTokenProfile: &kms.AccessTokenProfileConfig{Issuer: "{env.ACCESS_PROFILE_ISSUER}", Audience: "{env.ACCESS_PROFILE_AUDIENCE}", KeyIDs: []string{"retiring", "{env.ACCESS_PROFILE_ID}"}, MaxLifetimeSeconds: 900}}}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", AccessTokenProfile: &kms.AccessTokenProfileConfig{Issuer: "{env.ACCESS_PROFILE_ISSUER}", Audience: "{env.ACCESS_PROFILE_AUDIENCE}", KeyIDs: []string{"retiring", "{env.ACCESS_PROFILE_ID}"}, MaxLifetimeSeconds: 900}}}}}
	// Reuse the declarative ACL and verifier declarations so the complete native
	// path reaches both consumer validators after replacement, as the deferred path did.
	native.Config.AuthorizationPolicies[0].AccessListRules = app.Config.AuthorizationPolicies[0].AccessListRules
	native.Config.AuthenticationPortals[0].RawCryptoKeyStoreConfig = slices.Clone(app.Config.AuthenticationPortals[0].RawCryptoKeyStoreConfig)
	native.Config.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = slices.Clone(app.Config.AuthorizationPolicies[0].RawCryptoKeyStoreConfig)
	nativeResolved := accessProfileTestResolve(t, native, nil)
	if nativeResolved.AuthenticationPortals[0].AccessSigner != resolved.AuthenticationPortals[0].AccessSigner || cmp.Diff(nativeResolved.AuthenticationPortals[0].AccessTokenProfile, resolved.AuthenticationPortals[0].AccessTokenProfile) != "" || cmp.Diff(nativeResolved.AuthorizationPolicies[0].AccessTokenProfile, resolved.AuthorizationPolicies[0].AccessTokenProfile) != "" {
		t.Fatal("native and deferred profile semantics diverged")
	}
	// Matching portal/policy names are separate scopes, not a global collision.
	native.Config.AuthorizationPolicies[0].Name = "portal"
	if resolveAccessTokens(t.Context(), caddy.NewReplacer(), nil, native.Config, nil, nil) != nil {
		t.Fatal("same-named portal and policy were conflated")
	}

}

func TestAccessTokenProfileResolutionExactValues(t *testing.T) {
	secrets := &oauthRuntimeSecrets{Values: map[string]string{"issuer": "https://issuer.example.test/auth", "audience": "quoted audience, {env.ACCESS_PROFILE_SECOND}", "kid": "current", "signer": "primary", "seconds": "900"}}
	t.Setenv("ACCESS_PROFILE_SECOND", "must-not-expand")
	for _, deferred := range []bool{false, true} {
		native := &kms.AccessTokenProfileConfig{Issuer: "secrets:oauth:issuer", Audience: "secrets:oauth:audience", KeyIDs: []string{"secrets:oauth:kid"}, MaxLifetimeSeconds: 900}
		var statements []string
		if deferred {
			native = nil
			statements = []string{"issuer secrets:oauth:issuer", "audience secrets:oauth:audience", "key ids secrets:oauth:kid", "max lifetime secrets:oauth:seconds"}
		}
		profile, err := resolveAccessTokenProfile(t.Context(), caddy.NewReplacer(), []SecretsManager{secrets}, native, statements, deferred)
		if err != nil || profile.Issuer != secrets.Values["issuer"] || profile.Audience != secrets.Values["audience"] || !slices.Equal(profile.KeyIDs, []string{"current"}) {
			t.Fatal("profile values were split, trimmed or expanded more than once")
		}
		if native != nil && (native.Issuer != "secrets:oauth:issuer" || native.KeyIDs[0] != "secrets:oauth:kid") {
			t.Fatal("typed source profile was mutated")
		}
	}
}

func TestAccessTokenProfileResolutionRejects(t *testing.T) {
	base := strings.Split(accessProfileTestBody, "\n")
	for _, tc := range []struct {
		name     string
		native   *kms.AccessTokenProfileConfig
		body     []string
		deferred bool
	}{
		{"empty_snapshot", nil, []string{}, true}, {"typed_conflict", accessProfileTestWant(), base, true}, {"typed_empty", &kms.AccessTokenProfileConfig{}, nil, false},
		{"newline", nil, append(slices.Clone(base), "issuer a\naudience hidden"), true}, {"bad_utf8", nil, append(slices.Clone(base), "issuer \xff"), true}, {"encoded_nul", nil, append(slices.Clone(base), "issuer a\x00b"), true},
		{"unknown_keyword", nil, []string{"{env.ACCESS_PROFILE_KEYWORD} https://auth.example.test/auth", base[1], base[2], base[3]}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ACCESS_PROFILE_KEYWORD", "issuer")
			if _, err := resolveAccessTokenProfile(t.Context(), caddy.NewReplacer(), nil, tc.native, tc.body, tc.deferred); err == nil {
				t.Fatal("invalid profile source accepted")
			}
		})
	}
	for _, value := range []string{"", "bad\xff", " padded", "a\nb", "current current"} {
		for _, field := range []string{"signer", "issuer", "audience", "kid"} {
			if value == "current current" && field != "kid" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%x", field, []byte(value)), func(t *testing.T) {
				secrets := &oauthRuntimeSecrets{Values: map[string]string{"bad": value}}
				profile := accessProfileTestWant()
				portal := &authn.PortalConfig{Name: "portal", AccessSigner: "primary", AccessTokenProfile: profile, RawCryptoKeyStoreConfig: strings.Split(strings.TrimSuffix(accessProfileTestVerificationKeys, "\n"), "\n")}
				switch field {
				case "signer":
					portal.AccessSigner = "secrets:oauth:bad"
				case "issuer":
					profile.Issuer = "secrets:oauth:bad"
				case "audience":
					profile.Audience = "secrets:oauth:bad"
				case "kid":
					profile.KeyIDs = []string{"secrets:oauth:bad"}
				}
				if err := resolveAccessTokens(t.Context(), caddy.NewReplacer(), []SecretsManager{secrets}, &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}}, nil, nil); err == nil || strings.Contains(err.Error(), "secrets:oauth") {
					t.Fatal("invalid resolved authority accepted or disclosed")
				}
			})
		}
	}
	for _, value := range []string{"", "bad\xff", "0", "15m", "1.5", "86401"} {
		t.Run(fmt.Sprintf("deferred_lifetime/%x", []byte(value)), func(t *testing.T) {
			secrets := &oauthRuntimeSecrets{Values: map[string]string{"bad": value}}
			body := slices.Clone(base)
			body[3] = "max lifetime secrets:oauth:bad"
			if _, err := resolveAccessTokenProfile(t.Context(), caddy.NewReplacer(), []SecretsManager{secrets}, nil, body, true); err == nil {
				t.Fatal("invalid deferred numeric authority accepted")
			}
		})
	}
	for _, field := range []int{0, 1, 2} {
		body := slices.Clone(base)
		prefixes := []string{"issuer ", "audience ", "key ids "}
		body[field] = prefixes[field] + "secrets:oauth:bad"
		for _, value := range []string{"", "bad\xff", " padded", "line\nbreak"} {
			if _, err := resolveAccessTokenProfile(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: map[string]string{"bad": value}}}, nil, body, true); err == nil {
				t.Fatal("invalid deferred text authority accepted")
			}
		}
	}
	for _, target := range []string{"unknown_portal", "unknown_policy", "duplicate_portal", "duplicate_policy", "nil_portal", "nil_policy"} {
		t.Run(target, func(t *testing.T) {
			config := &authcrunch.Config{}
			portals, policies := map[string][]string{}, map[string][]string{}
			switch target {
			case "unknown_portal":
				portals["missing"] = base
			case "unknown_policy":
				policies["missing"] = base
			case "duplicate_portal":
				config.AuthenticationPortals = []*authn.PortalConfig{{Name: "same"}, {Name: "same"}}
			case "duplicate_policy":
				config.AuthorizationPolicies = []*authz.PolicyConfig{{Name: "same"}, {Name: "same"}}
			case "nil_portal":
				config.AuthenticationPortals = []*authn.PortalConfig{nil}
			case "nil_policy":
				config.AuthorizationPolicies = []*authz.PolicyConfig{nil}
			}
			if resolveAccessTokens(t.Context(), caddy.NewReplacer(), nil, config, portals, policies) == nil {
				t.Fatal("invalid profile target accepted")
			}
		})
	}
	t.Setenv("ACCESS_PROFILE_EMPTY", "")
	config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "{env.ACCESS_PROFILE_EMPTY}", AccessTokenProfile: accessProfileTestWant(), RawCryptoKeyStoreConfig: strings.Split(strings.TrimSuffix(accessProfileTestVerificationKeys, "\n"), "\n")}}}
	if resolveAccessTokens(t.Context(), caddy.NewReplacer(), nil, config, nil, nil) == nil {
		t.Fatal("explicit empty selection fell back to KMS")
	}
}

func TestAccessTokenInputTextBeforeSnapshot(t *testing.T) {
	for _, field := range []string{"signer", "portal_issuer", "portal_audience", "portal_kid", "policy_issuer", "policy_audience", "policy_kid"} {
		t.Run(field, func(t *testing.T) {
			portal, policy := &authn.PortalConfig{Name: "portal", AccessSigner: "primary", AccessTokenProfile: accessProfileTestWant()}, &authz.PolicyConfig{Name: "policy", AccessTokenProfile: accessProfileTestWant()}
			bad := "private-signer-diagnostic\xff"
			switch field {
			case "signer":
				portal.AccessSigner = bad
			case "portal_issuer":
				portal.AccessTokenProfile.Issuer = bad
			case "portal_audience":
				portal.AccessTokenProfile.Audience = bad
			case "portal_kid":
				portal.AccessTokenProfile.KeyIDs[0] = bad
			case "policy_issuer":
				policy.AccessTokenProfile.Issuer = bad
			case "policy_audience":
				policy.AccessTokenProfile.Audience = bad
			case "policy_kid":
				policy.AccessTokenProfile.KeyIDs[0] = bad
			}
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}, AuthorizationPolicies: []*authz.PolicyConfig{policy}}
			if err := validateAccessTokenInputText(config); err == nil || strings.Contains(err.Error(), "private-signer") {
				t.Fatal("native malformed bytes accepted or disclosed")
			}
			if err := (&App{Config: config}).Provision(caddy.Context{}); err == nil || strings.Contains(err.Error(), "private-signer") {
				t.Fatal("App repaired malformed bytes before rejecting input")
			}
		})
	}
	profile := accessProfileTestWant()
	profile.Issuer = "{env.PROFILE}"
	profile.KeyIDs = []string{"secrets:oauth:kid"}
	if validateAccessTokenInputText(&authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{AccessSigner: "{env.SIGNER}", AccessTokenProfile: profile}}}) != nil {
		t.Fatal("text guard validated unresolved semantics")
	}
}

func TestAccessTokenProfileDirectOAuthRejected(t *testing.T) {
	oauth := "use oauth identity provider upstream\noauth public origin https://app.example.test\n"
	for _, body := range []string{accessProfileTestBody, strings.Replace(accessProfileTestBody, "900", "{env.ACCESS_PROFILE_SECONDS}", 1)} {
		t.Setenv("ACCESS_PROFILE_SECONDS", "900")
		app, err := accessProfileTestAdapt("authorization policy policy {\nallow roles authp/user\n" + oauth + accessProfileTestBlock(body) + "\n}")
		if strings.Contains(body, "{env.") {
			if err != nil {
				t.Fatal("deferred direct OAuth fixture did not reach runtime validation")
			}
			err = resolveRuntimeAppConfigWithAccessTokens(t.Context(), caddy.NewReplacer(), nil, app.Config, nil, nil, app.OAuthAuthorizationDirectives, nil, nil, app.PolicyAccessTokenProfileDirectives, zap.NewNop())
		}
		if err == nil || !strings.Contains(err.Error(), "direct OAuth") {
			t.Fatal("direct OAuth profile did not reach incompatible-authority validator")
		}
	}
}

func TestAccessTokenProfileResolutionNoIO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "key.pem")
	keys := fmt.Sprintf("crypto key current verify from file %q\ncrypto key retiring verify from file %q\n", filepath.Join(filepath.Dir(path), "current-public.pem"), filepath.Join(filepath.Dir(path), "retiring-public.pem"))
	input := "access signer rsapss primary {\nkey file " + path + "\nkey id current\nissuer https://auth.example.test/auth\naudience service-a\n}\nauthentication portal portal {\n" + keys + "access signer primary\n" + accessProfileTestBlock(accessProfileTestBody) + "\n}"
	app, err := accessProfileTestAdapt(input)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(app)
	_ = accessProfileTestResolve(t, app, nil)
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("adaptation or resolution touched key storage")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("declarative snapshot changed")
	}
}
