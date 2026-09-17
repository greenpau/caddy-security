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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"golang.org/x/crypto/bcrypt"
)

func (f *localIdentityFixture) nativeLogin(t *testing.T, password string, mfa bool) (*authclient.Credentials, error) {
	t.Helper()
	config := &authclient.Config{BaseURL: f.issuer, Realm: "local", Username: "alice", Password: password, RefreshTransport: authclient.RefreshTransportBody}
	if mfa {
		config.TOTPSecret = authenticationClientTOTPSecret
	}
	client, err := authclient.NewClient(config, authclient.Options{HTTPClient: f.plain})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err == nil && credentials != nil {
		f.secrets = append(f.secrets, credentials.AccessToken, credentials.RefreshToken)
	}
	return credentials, err
}

func (f *localIdentityFixture) rejectNativeLogin(t *testing.T, password string, mfa bool) {
	t.Helper()
	credentials, err := f.nativeLogin(t, password, mfa)
	var response *authclient.HTTPError
	if credentials != nil || !errors.As(err, &response) || response.StatusCode != http.StatusUnauthorized {
		t.Fatal("rejected native login did not return HTTP 401 without credentials")
	}
}

func (f *localIdentityFixture) admin(t *testing.T, bearer, operation string, fields map[string]any) map[string]any {
	t.Helper()
	user := map[string]any{"username": "alice", "email": "alice@example.test"}
	for k, v := range fields {
		user[k] = v
	}
	r := f.json(t, f.plain, "/api/server/user", map[string]any{"realm": "local", "operation": operation, "user": user}, bearer)
	r.requireStatus(t, 200)
	var body map[string]any
	if json.Unmarshal(r.body, &body) != nil || body["status"] != "success" {
		t.Fatalf("admin %s did not succeed", operation)
	}
	return body
}

func (f *localIdentityFixture) profile(t *testing.T, body map[string]any, status int) oidcRPResponse {
	t.Helper()
	r := f.json(t, f.client, "/api/profile", body, "")
	r.requireStatus(t, status)
	var result struct{ Status int }
	if json.Unmarshal(r.body, &result) != nil || result.Status != status {
		t.Fatal("profile response omitted or changed its operation status")
	}
	if status >= 400 {
		assertAdminRedacted(t, r.body, f.secrets)
	}
	return r
}

func localIdentityActivePassword(t *testing.T, user *identity.User) *identity.Password {
	t.Helper()
	if user == nil {
		t.Fatal("missing identity for password assertion")
	}
	var active *identity.Password
	for _, password := range user.Passwords {
		if password.Disabled || password.Expired {
			continue
		}
		if active != nil {
			t.Fatal("multiple active passwords remain")
		}
		active = password
	}
	if active == nil {
		t.Fatal("no active password")
	}
	return active
}

func testLocalIdentityMutations(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, protocol := range []string{"form", "json"} {
		t.Run("reset-during-"+protocol+"-MFA", func(t *testing.T) {
			f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local", oidcRealm: "local", mfa: true}, cert, key, roots)
			admin := f.formLogin(t, "admin", lifecyclePassword, false)
			f.newBrowser(t)
			var sandbox string
			var challenge apiauth.AuthResponse
			if protocol == "form" {
				sandbox = f.formPassword(t, "alice", lifecyclePassword, 303)
			} else {
				challenge = f.jsonPassword(t, f.client, "alice", lifecyclePassword, "")
				if challenge.Authenticated || challenge.NextChallenge != "totp" {
					t.Fatal("password bypassed MFA")
				}
			}
			f.noCredentials(t)
			reset := f.admin(t, admin, "reset_password", nil)
			password, _ := reset["password"].(string)
			if password == "" || password == lifecyclePassword {
				t.Fatal("checkpoint reset did not return a fresh password")
			}
			f.secrets = append(f.secrets, password)
			if protocol == "form" {
				f.request(t, "POST", sandbox, url.Values{"passcode": {authenticationClientTOTP()}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
				f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 401)
			} else {
				r := f.json(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", SandboxID: challenge.SandboxID, SandboxSecret: challenge.SandboxSecret, ChallengeKind: "totp", ChallengeResponse: authenticationClientTOTP()}, "")
				localIdentityRejectedAuth(t, r, 401)
			}
			f.noCredentials(t)
			if f.cookie("AUTHP_OIDC_SESSION_ID") != "" {
				t.Fatal("stale checkpoint issued an OIDC browser session")
			}
		})
	}
	for _, operation := range []string{"password", "same-password", "import", "same-import", "admin-reset", "mfa-add", "mfa-delete", "profile-challenges", "admin-challenges", "disable", "recreate", "reload", "restore-and-reload"} {
		t.Run(operation, func(t *testing.T) {
			mfa := operation == "mfa-delete" || operation == "profile-challenges" || operation == "admin-challenges"
			f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local", oidcRealm: "local", mfa: mfa}, cert, key, roots)
			admin := f.formLogin(t, "admin", lifecyclePassword, false)
			// This existing endpoint must propagate the library's new 404.
			f.json(t, f.plain, "/api/server/info", map[string]string{"realm": "missing"}, admin).requireStatus(t, 404)
			portalAccess := f.formLogin(t, "alice", lifecyclePassword, mfa)
			native, err := f.nativeLogin(t, lifecyclePassword, mfa)
			if err != nil || native == nil || native.RefreshToken == "" || native.SessionID == "" {
				t.Fatal("missing fresh native credentials")
			}
			params := f.authorization("trusted")
			code := f.callback(t, f.authorize(t, params), params, "")
			tokens, claims := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
			f.userinfo(t, tokens, claims, "alice@example.test")
			pending := f.callback(t, f.authorize(t, params), params, "")
			f.secrets = append(f.secrets, tokens.Access, tokens.ID, code, pending)
			before := localIdentityRecord(t, f.database, "alice")
			oldPassword := localIdentityActivePassword(t, before)
			original, err := os.ReadFile(f.database)
			if err != nil {
				t.Fatal(err)
			}
			// A failed update must not invalidate sessions or touch password data.
			for _, body := range []map[string]any{
				{"kind": "update_user_password", "old_password": localIdentityBobPassword, "new_password": "ReplacementPassword42!"},
				{"kind": "update_user_password", "old_password": lifecyclePassword, "new_password": "short"},
				{"kind": "update_user_password", "old_password": lifecyclePassword, "new_password": "bcrypt:invalid-cost:invalid"},
			} {
				f.profile(t, body, 400)
				after := localIdentityRecord(t, f.database, "alice")
				if after.CredentialVersion != before.CredentialVersion || !cmp.Equal(after.Passwords, before.Passwords) {
					t.Fatal("rejected password update mutated identity")
				}
			}
			f.userinfo(t, tokens, claims, "alice@example.test")
			rotated := localIdentityAuth(t, f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, ""))
			if rotated.SessionID != native.SessionID || rotated.RefreshToken == "" {
				t.Fatal("rejected mutation invalidated refresh proof")
			}
			native.RefreshToken = rotated.RefreshToken
			f.secrets = append(f.secrets, rotated.RefreshToken, rotated.AccessToken)
			password, freshMFA := lifecyclePassword, mfa
			switch operation {
			case "password", "same-password", "import", "same-import", "restore-and-reload":
				replacement := lifecyclePassword
				if operation == "password" || operation == "import" {
					password = "ReplacementPassword42!"
					replacement = password
				}
				if operation == "import" {
					hash, err := bcrypt.GenerateFromPassword([]byte(password), 9)
					if err != nil {
						t.Fatal(err)
					}
					replacement = "bcrypt:9:" + string(hash)
				}
				if operation == "same-import" {
					replacement = "bcrypt:8:" + oldPassword.Hash
				}
				f.secrets = append(f.secrets, password, replacement)
				f.profile(t, map[string]any{"kind": "update_user_password", "old_password": lifecyclePassword, "new_password": replacement}, 200)
				if operation == "restore-and-reload" {
					// Restore the old revision, including its credential version;
					// backend reload evidence must still prevent resurrection.
					if err := os.WriteFile(f.database, original, 0600); err != nil {
						t.Fatal(err)
					}
					f.json(t, f.plain, "/api/server/reload", map[string]string{"realm": "local"}, admin).requireStatus(t, 200)
				}
			case "admin-reset":
				body := f.admin(t, admin, "reset_password", nil)
				password, _ = body["password"].(string)
				if password == "" || password == lifecyclePassword {
					t.Fatal("admin reset did not return a fresh password")
				}
				f.secrets = append(f.secrets, password)
			case "mfa-add":
				f.profile(t, map[string]any{"kind": "add_user_app_multi_factor_authenticator", "title": "FixtureFactor", "description": "", "secret": authenticationClientTOTPSecret, "period": 30, "digits": 6}, 200)
				freshMFA = true
			case "mfa-delete":
				if len(before.MfaTokens) != 1 {
					t.Fatal("missing enrolled factor")
				}
				f.profile(t, map[string]any{"kind": "delete_user_multi_factor_authenticator", "id": before.MfaTokens[0].ID}, 200)
			case "profile-challenges":
				f.profile(t, map[string]any{"kind": "overwrite_user_auth_challenges", "challenges": []string{"password mfa"}}, 200)
			case "admin-challenges":
				f.admin(t, admin, "overwrite_auth_challenges", map[string]any{"challenges": []string{"password mfa"}})
			case "disable", "recreate":
				op := "disable"
				if operation == "recreate" {
					op = "delete"
				}
				f.admin(t, admin, op, nil)
			case "reload":
				f.json(t, f.plain, "/api/server/reload", map[string]string{"realm": "local"}, admin).requireStatus(t, 200)
			}
			after := localIdentityRecord(t, f.database, "alice")
			switch operation {
			case "recreate":
				if after != nil {
					t.Fatal("deleted identity persisted")
				}
			case "reload", "restore-and-reload":
				if after.CredentialVersion != before.CredentialVersion {
					t.Fatal("reload rewrote the stored credential version")
				}
			default:
				if after.CredentialVersion <= before.CredentialVersion || after.ID != before.ID {
					t.Fatal("security mutation did not persist its credential version")
				}
			}
			if operation == "same-password" || operation == "same-import" {
				active := localIdentityActivePassword(t, after)
				if active.Hash != oldPassword.Hash || !active.CreatedAt.Equal(oldPassword.CreatedAt) {
					t.Fatal("duplicate update rehashed the active credential")
				}
			}
			if operation == "password" || operation == "import" || operation == "admin-reset" {
				if localIdentityActivePassword(t, after).Hash == oldPassword.Hash {
					t.Fatal("replacement retained the old active hash")
				}
			}
			if operation == "mfa-add" && len(after.MfaTokens) != 1 || operation == "mfa-delete" && len(after.MfaTokens) != 0 {
				t.Fatal("profile factor mutation was not persisted")
			}
			// An unrelated legacy account stays version zero; no bulk migration.
			bob := localIdentityRecord(t, f.database, "bob")
			if bob.CredentialVersion != 0 {
				t.Fatal("mutation migrated an unrelated legacy identity")
			}
			if operation == "recreate" {
				// Recreate before the first stale-proof attempt: an earlier
				// rejection could revoke the family and hide username rebinding.
				body := f.admin(t, admin, "add", map[string]any{"name": "Alice Recreated", "roles": []string{"authp/user", "alice"}})
				password, _ = body["password"].(string)
				f.secrets = append(f.secrets, password)
				if password == "" || localIdentityRecord(t, f.database, "alice").ID == before.ID {
					t.Fatal("recreation reused the deleted identity")
				}
			}
			refresh := f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, "")
			localIdentityRejectedAuth(t, refresh, 401)
			f.exchange(t, "trusted", pending, oidcRPCallback, oidcRPVerifier).failure(t, 400, "invalid_grant")
			f.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens.Access}}).requireStatus(t, 401)
			params.Set("prompt", "none")
			f.callback(t, f.authorize(t, params), params, "login_required")
			f.assertResource(t, portalAccess)
			f.assertResource(t, native.AccessToken)
			if operation == "mfa-delete" || operation == "profile-challenges" || operation == "admin-challenges" {
				// A transform explicitly requires MFA, including enrollment
				// after deletion. Challenge rules alone select available factors.
				credentials, err := f.nativeLogin(t, password, false)
				if credentials != nil || !errors.Is(err, authclient.ErrInputRequired) {
					t.Fatal("fresh login did not stop at the required factor checkpoint")
				}
				if operation == "mfa-delete" {
					f.rejectNativeLogin(t, password, true)
					sandbox := f.formPassword(t, "alice", password, 303)
					f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 200)
					f.noCredentials(t)
					return
				}
			}
			if operation == "disable" {
				f.rejectNativeLogin(t, password, false)
				f.admin(t, admin, "enable", nil)
			}
			if password != lifecyclePassword {
				f.rejectNativeLogin(t, lifecyclePassword, false)
			}
			if operation == "import" || operation == "same-import" {
				active := localIdentityActivePassword(t, after)
				serialized := fmt.Sprintf("bcrypt:%d:%s", active.Cost, active.Hash)
				f.rejectNativeLogin(t, serialized, false)
			}
			fresh, err := f.nativeLogin(t, password, freshMFA)
			if err != nil || fresh == nil || fresh.RefreshToken == "" || fresh.SessionID == native.SessionID {
				t.Fatal("fresh login did not create independent renewable credentials")
			}
			f.formLogin(t, "alice", password, freshMFA)
			newCode := f.callback(t, f.authorize(t, params), params, "")
			newTokens, newClaims := f.tokens(t, f.exchange(t, "trusted", newCode, oidcRPCallback, oidcRPVerifier), params)
			f.secrets = append(f.secrets, newCode, newTokens.Access, newTokens.ID)
			if (newClaims.Subject != claims.Subject) != (operation == "recreate") {
				t.Fatal("OIDC subject did not follow immutable identity lifetime")
			}
			if freshMFA && !slices.Contains(newClaims.Methods, "otp") {
				t.Fatal("fresh OIDC evidence omitted completed MFA")
			}
		})
	}
}
