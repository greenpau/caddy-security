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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"golang.org/x/crypto/bcrypt"
)

const challengePolicy = `transform user {
 match realm local
 field email exists
 require auth challenges u2f
 require auth challenges totp if u2f not available
 require auth challenges password if u2f and totp not available
 add amr forged
 add label "match {claims.sub}" as string
 add nested metadata label with "literal value" as string
}
transform users {
 match realm local
 add unconditional matched as string
}`

func TestCaddyAuthenticationChallengesE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthenticationChallengesProcess$", "-test.v", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CHALLENGES_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy authentication policies: %v\n%s", err, out)
	}
}

func challengeClaims(t *testing.T, f *localIdentityFixture, token string, methods ...string) map[string]any {
	t.Helper()
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "access")
	want := make([]any, len(methods))
	for i, method := range methods {
		want[i] = method
	}
	if diff := cmp.Diff(want, claims["amr"]); diff != "" {
		t.Fatal("unverified AMR", diff)
	}
	for _, field := range []string{"auth_methods", "challenges", "auth_challenge_policy"} {
		if _, exists := claims[field]; exists {
			t.Fatalf("internal policy field %s leaked", field)
		}
	}
	return claims
}

func challengePolicyInput(input, policy string) string {
	input = strings.Replace(input, "transform user {\nmatch sub alice\nrequire mfa\n}\n", "", 1)
	return strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\n"+policy, 1)
}

func challengeFactorLogin(t *testing.T, f *localIdentityFixture, flow string) string {
	t.Helper()
	waitForFreshFixtureTOTP(t, f.database, "alice")
	f.newBrowser(t)
	if flow == "html" {
		r := f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
		r.requireStatus(t, 303)
		sandbox := r.header.Get("Location")
		f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 200)
		f.noCredentials(t)
		f.request(t, "POST", sandbox, url.Values{"passcode": {authenticationClientTOTP()}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
		f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 303)
	} else {
		req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
		r := localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
		if r.NextChallenge != "totp" || r.Authenticated {
			t.Fatal("conditional flow did not select TOTP alone")
		}
		f.noCredentials(t)
		req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = r.SandboxID, r.SandboxSecret, "totp", authenticationClientTOTP()
		r = localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
		if !r.Authenticated {
			t.Fatal("selected TOTP did not finish login")
		}
	}
	token := f.cookie("AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("factor-only login omitted cookie")
	}
	return token
}

func TestCaddyAuthenticationChallengesProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CHALLENGES_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	t.Run("System API policy", func(t *testing.T) { testCaddySystemChallengePolicy(t, cert, key, roots) })
	t.Run("LDAP fallback roles", func(t *testing.T) { testCaddyLDAPFallback(t, cert, key, roots) })
	t.Run("WebAuthn-only policy", func(t *testing.T) { testCaddyWebAuthnPolicy(t, cert, key, roots) })
	t.Run("direct API key observes explicit policy", func(t *testing.T) {
		apiKey := strings.Repeat("k", 24) + strings.Repeat("A", 40)
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth"}, cert, key, roots)
		hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), 8)
		if err != nil {
			t.Fatal("cannot hash synthetic API key")
		}
		f.input = challengePolicyInput(f.input, "")
		declaration := fmt.Sprintf("user bob {\nemail bob@example.test\napi key %s \"bcrypt:8:%s\"\n}\n", apiKey[:24], hash)
		f.input = strings.Replace(f.input, "local identity store localdb {", "local identity store localdb {\n"+declaration, 1)
		challengeRestart(t, f)
		client, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", APIKey: apiKey}, authclient.Options{HTTPClient: f.plain})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := client.Authenticate(t.Context())
		if err != nil || credentials == nil || credentials.AccessToken == "" {
			t.Fatal("valid API key failed before explicit policy")
		}
		f.assertResource(t, credentials.AccessToken)
		f.input = challengePolicyInput(f.input, "transform user {\nmatch realm local\nrequire auth challenges password\n}")
		challengeRestart(t, f)
		credentials, err = client.Authenticate(t.Context())
		if err == nil || credentials != nil {
			t.Fatal("API key bypassed explicit password policy")
		}
		f.noCredentials(t)
	})
	for _, tc := range []struct{ mount, flow, refresh, oidc string }{
		{"", "html", "", ""}, {"/auth", "json", "local", "local"},
	} {
		t.Run("conditional-"+tc.flow, func(t *testing.T) {
			f := newLocalIdentityFixture(t, localIdentityOptions{mount: tc.mount, mfa: true, refreshRealm: tc.refresh, oidcRealm: tc.oidc}, cert, key, roots)
			f.input = challengePolicyInput(f.input, challengePolicy)
			if tc.refresh == "" && tc.oidc == "" {
				f.input = strings.Replace(f.input, "match realm local\n add unconditional", "match any\n add unconditional", 1)
			}
			f.input = strings.Replace(f.input, "allow roles authp/user", "acl rule {\nmatch amr otp\nallow stop\n}", 1)
			challengeRestart(t, f)
			// An account with no enrolled factor selects the password fallback. Its
			// token cannot enter an application requiring verified OTP evidence.
			passwordToken := f.formLogin(t, "bob", localIdentityBobPassword, false)
			challengeClaims(t, f, passwordToken, "pwd")
			status, _, _ := registrationHTTP(t, f.plain, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + passwordToken}})
			if status == 200 {
				t.Fatal("password fallback bypassed AMR policy")
			}
			token := challengeFactorLogin(t, f, tc.flow)
			claims := challengeClaims(t, f, token, "otp")
			if claims["label"] != "match alice" {
				t.Fatal("action containing match was misclassified")
			}
			if claims["unconditional"] != "matched" {
				t.Fatal("match any did not apply during login")
			}
			if diff := cmp.Diff(map[string]any{"label": "literal value"}, claims["metadata"]); diff != "" {
				t.Fatal("nested claim changed in the issued token: " + diff)
			}
			f.assertResource(t, token)
			// Native JSON instructions must not lose later CSV records before
			// the shared compiler can reject the malformed policy.
			validConfig, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"actions", "matchers"} {
				for _, newline := range []string{"\n", "\r\n"} {
					candidate := challengeNativeConfig(t, validConfig, func(app *App) {
						transform := app.Config.AuthenticationPortals[0].UserTransformerConfigs[0]
						if field == "actions" {
							transform.Actions[0] += newline + "require auth challenges totp"
						} else {
							transform.Matchers[0] += newline + "match email private-sentinel"
						}
					})
					if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), "instructions must be single-line") {
						t.Fatal("multiline native JSON transform was not rejected before normalization")
					}
					f.assertResource(t, token)
				}
			}
			if tc.refresh != "" || tc.oidc != "" {
				candidate := strings.Replace(f.input, "match realm local\n add unconditional", "match any\n add unconditional", 1)
				config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(candidate), nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := caddy.Load(config, true); err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported") {
					t.Fatal("unsafe match-any refresh/OIDC replacement was not rejected at resolution")
				}
				for _, matcher := range []string{`"match any"`, "{env.CHALLENGE_NATIVE_MATCHER}"} {
					t.Setenv("CHALLENGE_NATIVE_MATCHER", "match any")
					candidate := challengeNativeMatcher(t, config, matcher)
					if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported") {
						t.Fatal("encoded native JSON matcher bypassed refresh/OIDC guard")
					}
					f.assertResource(t, token)
				}
				f.assertResource(t, token)
			}
			// Refresh and OIDC tokens retain evidence of the selected factor even
			// when the backend ordinarily requires both password and TOTP.
			if tc.refresh != "" {
				f.json(t, f.client, "/api/refresh_token", map[string]any{}, "", http.Header{"X-Authcrunch-Refresh": {"1"}}).requireStatus(t, 200)
				challengeClaims(t, f, f.cookie("AUTHP_ACCESS_TOKEN"), "otp")
			}
			if tc.oidc != "" {
				params := f.authorization("trusted")
				code := f.callback(t, f.authorize(t, params), params, "")
				tokens, _ := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
				data, err := base64.RawURLEncoding.DecodeString(strings.Split(tokens.ID, ".")[1])
				var claims map[string]any
				if err != nil || json.Unmarshal(data, &claims) != nil {
					t.Fatal("invalid verified ID token")
				}
				if diff := cmp.Diff([]any{"otp"}, claims["amr"]); diff != "" {
					t.Fatal(diff)
				}
			}
			// A valid password alone cannot satisfy the selected factor policy.
			status, _, _ = registrationHTTP(t, f.plain, "GET", f.issuer+"/basic/login/local", nil, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+lifecyclePassword))}})
			if status != 403 {
				t.Fatalf("Basic bypassed factor policy: %d", status)
			}
			invalid := strings.Replace(f.input, "require auth challenges u2f", "require auth challenges email", 1)
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil); err == nil {
				t.Fatal("invalid replacement policy adapted")
			}
			f.assertResource(t, token)
			f.input = strings.Replace(f.input, "require auth challenges totp if u2f not available", "", 1)
			f.input = strings.Replace(f.input, "require auth challenges password if u2f and totp not available", "", 1)
			challengeRestart(t, f)
			f.newBrowser(t)
			f.json(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, "").requireStatus(t, 400)
			f.noCredentials(t)
		})
	}
	t.Run("static-user-rules-and-native-client", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", mfa: true, refreshRealm: "local"}, cert, key, roots)
		f.input = challengePolicyInput(f.input, "")
		declaration := fmt.Sprintf("user alice {\nemail alice@example.test\npassword %s\nauth challenges totp\n}\nuser charlie {\nemail charlie@example.test\npassword %s\nroles authp/user\nauth challenges password\n}\n", lifecyclePassword, lifecyclePassword)
		f.input = strings.Replace(f.input, "local identity store localdb {", "local identity store localdb {\n"+declaration, 1)
		challengeRestart(t, f)
		waitForFreshFixtureTOTP(t, f.database, "alice")
		client, err := authclient.NewClient(&authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "alice", TOTPSecret: authenticationClientTOTPSecret, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: f.plain})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := client.Authenticate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		challengeClaims(t, f, credentials.AccessToken, "otp")
		f.assertResource(t, credentials.AccessToken)
		f.formLogin(t, "charlie", lifecyclePassword, false)
		// Explicit rules are reapplied to existing users on provisioning; omitting
		// them later preserves the persisted policy, as upstream provisioning defines.
		f.input = strings.Replace(f.input, "auth challenges totp", "auth challenges password", 1)
		challengeRestart(t, f)
		f.input = strings.Replace(f.input, "auth challenges password", "", 1)
		challengeRestart(t, f)
		token := f.formLogin(t, "alice", lifecyclePassword, false)
		challengeClaims(t, f, token, "pwd")
	})
	t.Run("profile-policy-management", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", mfa: true, refreshRealm: "local", oidcRealm: "local"}, cert, key, roots)
		f.input = challengePolicyInput(f.input, "")
		challengeRestart(t, f)
		f.formLogin(t, "alice", lifecyclePassword, true)
		preview := func(want string, methods []string) {
			t.Helper()
			r := f.profile(t, map[string]any{"kind": "fetch_user_auth_challenges"}, 200)
			var policy struct {
				PolicySource string   `json:"policy_source"`
				Effective    []string `json:"effective_challenges"`
				Registered   []string `json:"registered_methods"`
			}
			if json.Unmarshal(r.body, &policy) != nil || policy.PolicySource != want {
				t.Fatal("invalid policy preview")
			}
			if diff := cmp.Diff(methods, policy.Effective); diff != "" {
				t.Fatal(diff)
			}
			if len(policy.Registered) != 2 {
				t.Fatal("registered methods omitted")
			}
		}
		preview("user", []string{"password", "totp"})
		before := localIdentityRecord(t, f.database, "alice").CredentialVersion
		for _, candidate := range []any{nil, "totp", []any{"totp", 1}, []string{""}, []string{"email"}, []string{"u2f"}, []string{"totp", "totp"}} {
			f.profile(t, map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": candidate}, 400)
		}
		if localIdentityRecord(t, f.database, "alice").CredentialVersion != before {
			t.Fatal("invalid policy mutated identity")
		}
		oldRefresh := f.cookie("AUTHP_REFRESH_TOKEN")
		result := f.profile(t, map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"totp"}, "username": "bob"}, 200)
		var saved struct {
			Reauthenticate bool `json:"reauthentication_required"`
		}
		if json.Unmarshal(result.body, &saved) != nil || !saved.Reauthenticate {
			t.Fatal("policy save omitted reauthentication")
		}
		if localIdentityRecord(t, f.database, "bob").HasAuthChallengeRules() {
			t.Fatal("profile selected body-supplied identity")
		}
		f.profile(t, map[string]any{"kind": "fetch_user_auth_challenges"}, 401)
		if oldRefresh == "" {
			t.Fatal("missing refresh test credentials")
		}
		f.json(t, f.plain, "/api/refresh_token", map[string]any{}, "", http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}, "Cookie": {"AUTHP_REFRESH_TOKEN=" + oldRefresh}}).requireStatus(t, 401)
		token := challengeFactorLogin(t, f, "html")
		challengeClaims(t, f, token, "otp")
		preview("user", []string{"totp"})
		f.profile(t, map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{}}, 200)
		if localIdentityRecord(t, f.database, "alice").HasAuthChallengeRules() {
			t.Fatal("empty policy did not restore defaults")
		}
	})
}

// Exercise native JSON encodings independently of Caddyfile normalization.
func challengeNativeMatcher(t *testing.T, input []byte, matcher string) []byte {
	t.Helper()
	return challengeNativeConfig(t, input, func(app *App) {
		var replaced int
		for _, portal := range app.Config.AuthenticationPortals {
			for _, transform := range portal.UserTransformerConfigs {
				for i, condition := range transform.Matchers {
					if condition == "match any" {
						transform.Matchers[i] = matcher
						replaced++
					}
				}
			}
		}
		if replaced != 1 {
			t.Fatalf("native matcher fixture replaced %d conditions, want one", replaced)
		}
	})
}

func challengeNativeConfig(t *testing.T, input []byte, update func(*App)) []byte {
	t.Helper()
	var config caddy.Config
	if err := json.Unmarshal(input, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	update(&app)
	var err error
	config.AppsRaw["security"], err = json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(&config)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// File-backed identity stores require a drained previous runtime before reuse.
func challengeRestart(t *testing.T, f *localIdentityFixture) {
	t.Helper()
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	f.load(t)
}
