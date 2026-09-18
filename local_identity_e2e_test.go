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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/certmagic"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/bcrypt"
)

const localIdentityBobPassword = "SeparateBobPassword42!"

type localIdentityOptions struct {
	mount, refreshRealm, oidcRealm string
	transform, mfa                 bool
}

type localIdentityFixture struct {
	*oidcRPFixture
	plain           *http.Client
	database, input string
	keys            []map[string]string
	secrets         []string
}

// Provision only fixture data before Caddy opens the store. Runtime security
// mutations below must cross the management/profile HTTP boundary.
func seedLocalIdentity(t *testing.T, path string, mfa bool) {
	t.Helper()
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob", "admin"} {
		password, role := lifecyclePassword, "authp/user"
		if name == "bob" {
			password = localIdentityBobPassword
		}
		if name == "admin" {
			role = "authp/admin"
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), 8)
		if err != nil {
			t.Fatal("cannot hash synthetic password")
		}
		r := &requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: "bcrypt:8:" + string(hash), Roles: []string{role, name}}}
		if err := db.AddUser(r); err != nil {
			t.Fatal("cannot seed local identity")
		}
		if name == "alice" && mfa {
			r.MfaToken = requests.MfaToken{Type: "totp", Secret: authenticationClientTOTPSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
			if err := db.AddMfaToken(r); err != nil {
				t.Fatal("cannot enroll fixture factor")
			}
			r.User.Challenges = []string{"password totp"}
			if err := db.OverwriteUserAuthChallengeRules(r); err != nil {
				t.Fatal("cannot require fixture MFA")
			}
		}
	}
}

func localIdentityRecord(t *testing.T, path, username string) *identity.User {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct{ Users []*identity.User }
	if json.Unmarshal(data, &file) != nil {
		t.Fatal("invalid identity file")
	}
	for _, user := range file.Users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

func newLocalIdentityFixture(t *testing.T, options localIdentityOptions, cert, tlsKey string, roots *x509.CertPool) *localIdentityFixture {
	t.Helper()
	dir := t.TempDir()
	database := filepath.Join(dir, "users.json")
	seedLocalIdentity(t, database, options.mfa)
	excluded := filepath.Join(dir, "excluded.json")
	data, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excluded, data, 0600); err != nil {
		t.Fatal(err)
	}
	base := "https://" + lifecycleAddress(t)
	accessKey, opKey := newJWKSKeyFiles(t, "RSA", "identity-access"), newOIDCRPKey(t, "identity-op")
	refresh, provider, transform := "", "", ""
	if options.refreshRealm != "" {
		path := options.mount
		if path == "" {
			path = "/"
		}
		refresh = fmt.Sprintf("token refresh {\nrealms %s\npublic origin %s\nbase path %s\nbody transport enabled\naccess lifetime 600\n}\n", options.refreshRealm, base, path)
	}
	if options.oidcRealm != "" {
		provider = fmt.Sprintf("oidc provider {\nissuer %s%s\nrealms %s\nsigning key files %q\napplications trusted\n}\n", base, options.mount, options.oidcRealm, opKey.private)
	}
	if options.transform {
		transform = "transform user {\nmatch sub alice\naction overwrite sub bob\naction overwrite email alias@example.test\n}\n"
	}
	if options.mfa {
		transform = "transform user {\nmatch sub alice\nrequire mfa\n}\n" + transform
	}
	logFile, accessLog := filepath.Join(dir, "runtime.jsonl"), filepath.Join(dir, "access.jsonl")
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 storage file_system %q
 log {
  level DEBUG
  output file %q
  format json
 }
 security {
  local identity store localdb {
   realm local
   path %q
  }
  local identity store excludeddb {
   realm excluded
   path %q
  }
  oauth application trusted {
   client_id trusted
   client_secret %s
   redirect_uri %s
   skip_consent true
  }
  authentication portal myportal {
   enable identity stores localdb excludeddb
   enable admin api
   %s
   crypto default token lifetime 600
   %s
   %s
   %s
  }
  authorization policy app_policy {
   %s
   set auth url %s%s/login
   validate bearer header
   allow roles authp/user
  }
 }
}
%s {
 tls %q %q
 log {
  output file %q
  format filter {
   wrap json
   fields {
    resp_headers>Location delete
   }
  }
 }
 route {
  route /resource {
   authorize with app_policy
   respond "identity resource"
  }
  route %s/* {
   authenticate with myportal
  }
  respond unmatched 404
 }
}`, filepath.Join(dir, "caddy-storage"), logFile, database, excluded, applicationTestSecret, oidcRPCallback, accessKey.signer("access"), refresh, provider, transform, accessKey.verifier("access"), base, options.mount, base, cert, tlsKey, accessLog, options.mount)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := &localIdentityFixture{oidcRPFixture: &oidcRPFixture{client: client, base: base, mount: options.mount, issuer: base + options.mount}, database: database, input: input, secrets: []string{lifecyclePassword, localIdentityBobPassword, authenticationClientTOTPSecret, applicationTestSecret}}
	plain := *client
	f.plain = &plain
	loaded := false
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
		if !loaded {
			return
		}
		for _, path := range []string{logFile, accessLog} {
			data, err := os.ReadFile(path)
			if err != nil || len(data) == 0 {
				t.Error("missing identity HTTP/log evidence")
				continue
			}
			assertAdminRedacted(t, data, f.secrets)
		}
	})
	f.newBrowser(t)
	f.load(t)
	loaded = true
	if options.oidcRealm != "" {
		f.discover(t)
	}
	r := f.request(t, "GET", "/.well-known/jwks.json", nil, nil)
	r.requireStatus(t, 200)
	var doc struct{ Keys []map[string]string }
	if json.Unmarshal(r.body, &doc) != nil || len(doc.Keys) != 1 {
		t.Fatal("missing access verification key")
	}
	f.keys = doc.Keys
	return f
}

func (f *localIdentityFixture) load(t *testing.T) {
	t.Helper()
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(config, true); err != nil {
		t.Fatal(err)
	}
	// DefaultStorage captures its path during package initialization; Setenv
	// inside a test cannot redirect it. Verify the running host uses our store.
	storage, ok := caddy.ActiveContext().Storage().(*certmagic.FileStorage)
	if !ok || storage.Path != filepath.Join(filepath.Dir(f.database), "caddy-storage") {
		t.Fatal("Caddy fixture did not isolate its runtime storage")
	}
}

func (f *localIdentityFixture) json(t *testing.T, client *http.Client, path string, body any, bearer string, headers ...http.Header) oidcRPResponse {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if client.Jar != nil {
		req.Header.Set("Origin", f.base)
	}
	for _, header := range headers {
		maps.Copy(req.Header, header)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("identity TLS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		t.Fatal("invalid identity HTTP response")
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("identity request did not use verified TLS")
	}
	r := oidcRPResponse{response.StatusCode, response.Header, data}
	r.noStore(t)
	return r
}

func localIdentityAuth(t *testing.T, r oidcRPResponse) apiauth.AuthResponse {
	t.Helper()
	r.requireStatus(t, 200)
	var response apiauth.AuthResponse
	if json.Unmarshal(r.body, &response) != nil {
		t.Fatal("invalid login response")
	}
	return response
}

func localIdentityRejectedAuth(t *testing.T, r oidcRPResponse, status int) apiauth.AuthResponse {
	t.Helper()
	r.requireStatus(t, status)
	var response apiauth.AuthResponse
	if json.Unmarshal(r.body, &response) != nil || response.Authenticated || response.AccessToken != "" || response.RefreshToken != "" || response.SessionID != "" {
		t.Fatal("rejected authentication returned invalid data or credentials")
	}
	return response
}

func (f *localIdentityFixture) cookie(name string) string {
	u, _ := url.Parse(f.issuer + "/portal")
	for _, cookie := range f.client.Jar.Cookies(u) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

func (f *localIdentityFixture) noCredentials(t *testing.T) {
	t.Helper()
	if f.cookie("AUTHP_ACCESS_TOKEN") != "" || f.cookie("AUTHP_REFRESH_TOKEN") != "" {
		t.Fatal("unfinished login issued credentials")
	}
	if f.discovery != nil {
		params := f.authorization("trusted")
		params.Set("prompt", "none")
		f.callback(t, f.authorize(t, params), params, "login_required")
	}
}

func (f *localIdentityFixture) formPassword(t *testing.T, username, password string, status int) string {
	t.Helper()
	f.newBrowser(t)
	r := f.request(t, "POST", "/login", url.Values{"username": {username}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
	r.requireStatus(t, 303)
	sandbox := r.header.Get("Location")
	location, err := url.Parse(sandbox)
	if err != nil || location.Scheme != "https" || location.Host != strings.TrimPrefix(f.base, "https://") || location.User != nil || !strings.HasPrefix(location.Path, f.mount+"/sandbox/") {
		t.Fatal("password sandbox left the mounted TLS portal")
	}
	f.request(t, "POST", sandbox, url.Values{"secret": {password}}, http.Header{"Origin": {f.base}}).requireStatus(t, status)
	return sandbox
}

func (f *localIdentityFixture) formLogin(t *testing.T, username, password string, mfa bool) string {
	t.Helper()
	sandbox := f.formPassword(t, username, password, 303)
	f.noCredentials(t)
	if mfa {
		waitForFreshFixtureTOTP(t, f.database, "alice")
		f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 200)
		f.request(t, "POST", sandbox, url.Values{"passcode": {authenticationClientTOTP()}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
	}
	f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 303)
	access := f.cookie("AUTHP_ACCESS_TOKEN")
	if access == "" {
		t.Fatal("completed form login omitted access token")
	}
	f.secrets = append(f.secrets, access, f.cookie("AUTHP_REFRESH_TOKEN"))
	return access
}

func (f *localIdentityFixture) jsonPassword(t *testing.T, client *http.Client, username, password, transport string, status ...int) apiauth.AuthResponse {
	t.Helper()
	request := apiauth.AuthRequest{Username: username, Realm: "local", RefreshTransport: transport}
	start := localIdentityAuth(t, f.json(t, client, "/login", request, ""))
	if start.Authenticated || start.NextChallenge != "password" || start.SandboxID == "" || start.SandboxSecret == "" {
		t.Fatal("missing initial password checkpoint")
	}
	request.Username = "ALICE@EXAMPLE.TEST"
	request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "password", password
	r := f.json(t, client, "/login", request, "")
	if len(status) == 0 {
		return localIdentityAuth(t, r)
	}
	return localIdentityRejectedAuth(t, r, status[0])
}

func (f *localIdentityFixture) completeJSON(t *testing.T, response apiauth.AuthResponse, mfa bool) apiauth.AuthResponse {
	t.Helper()
	if mfa {
		if response.Authenticated || response.NextChallenge != "totp" || response.AccessToken != "" || response.RefreshToken != "" || response.SessionID != "" {
			t.Fatal("password substituted for required MFA")
		}
		f.noCredentials(t)
		response = localIdentityAuth(t, f.json(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", SandboxID: response.SandboxID, SandboxSecret: response.SandboxSecret, ChallengeKind: "totp", ChallengeResponse: authenticationClientTOTP()}, ""))
	}
	if !response.Authenticated {
		t.Fatal("completed JSON login failed")
	}
	f.secrets = append(f.secrets, response.AccessToken, f.cookie("AUTHP_ACCESS_TOKEN"), f.cookie("AUTHP_REFRESH_TOKEN"))
	return response
}

func (f *localIdentityFixture) assertResource(t *testing.T, token string) {
	t.Helper()
	status, _, body := registrationHTTP(t, f.plain, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}})
	if status != 200 || string(body) != "identity resource" {
		t.Fatalf("stateless access authorization: HTTP %d", status)
	}
}

func TestCaddyLocalIdentityE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLocalIdentityProcess$", "-test.v", "-test.timeout=7m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_LOCAL_IDENTITY_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy local identity journeys: %v\n%s", err, output)
	}
}

func TestCaddyLocalIdentityProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_LOCAL_IDENTITY_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct{ name, refresh, oidc string }{
		{"legacy", "", ""}, {"refresh", "local", ""}, {"oidc", "", "local"},
		{"both", "local", "local"}, {"unselected", "excluded", "excluded"},
		{"only-refresh-selected", "local", "excluded"}, {"only-oidc-selected", "excluded", "local"},
	} {
		for _, mfa := range []bool{false, true} {
			t.Run(fmt.Sprintf("login/%s/mfa=%v", tc.name, mfa), func(t *testing.T) {
				mount := "/tenant/auth"
				if mfa {
					mount = ""
				}
				for _, protocol := range []string{"form", "json"} {
					t.Run(protocol, func(t *testing.T) {
						// Independent journeys need independent factors: successful
						// authentication persists the consumed TOTP counter.
						f := newLocalIdentityFixture(t, localIdentityOptions{mount: mount, refreshRealm: tc.refresh, oidcRealm: tc.oidc, transform: true, mfa: mfa}, cert, key, roots)
						f.newBrowser(t)
						// Bob's password cannot authenticate Alice even though a
						// configured transform sets her access subject to Bob.
						if protocol == "form" {
							f.formPassword(t, "ALICE@EXAMPLE.TEST", localIdentityBobPassword, 401)
						} else {
							f.jsonPassword(t, f.client, "ALICE", localIdentityBobPassword, "", 401)
						}
						f.noCredentials(t)
						var access string
						if protocol == "form" {
							access = f.formLogin(t, "ALICE@EXAMPLE.TEST", lifecyclePassword, mfa)
						} else {
							f.newBrowser(t)
							result := f.completeJSON(t, f.jsonPassword(t, f.client, "ALICE", lifecyclePassword, ""), mfa)
							access = f.cookie("AUTHP_ACCESS_TOKEN")
							if tc.refresh == "local" {
								if result.AccessToken != "" || result.RefreshToken != "" || result.SessionID == "" {
									t.Fatal("cookie refresh login exposed credentials or omitted session")
								}
							} else {
								access = result.AccessToken
								if access == "" || result.SessionID != "" || result.RefreshToken != "" {
									t.Fatal("legacy access-only JSON contract changed")
								}
							}
						}
						claims := verifyCaddyJWKSSignature(t, f.keys, access, "RS512", "access")
						wantSubject := "bob"
						if tc.refresh == "local" {
							wantSubject = "alice"
						}
						roles, _ := claims["roles"].([]any)
						if claims["sub"] != wantSubject || claims["email"] != "alias@example.test" || claims["origin"] != "local" || !slices.Contains(roles, any("alice")) || slices.Contains(roles, any("bob")) {
							t.Fatal("login lost canonical identity or transformed claim contract")
						}
						if (f.cookie("AUTHP_REFRESH_TOKEN") != "") != (tc.refresh == "local") {
							t.Fatal("refresh realm selection changed")
						}
						if tc.refresh == "local" {
							result := localIdentityAuth(t, f.json(t, f.client, "/api/refresh_token", struct{}{}, "", http.Header{"X-Authcrunch-Refresh": {"1"}, "Sec-Fetch-Site": {"same-origin"}}))
							renewed := verifyCaddyJWKSSignature(t, f.keys, f.cookie("AUTHP_ACCESS_TOKEN"), "RS512", "access")
							if result.SessionID != claims["sid"] || renewed["sub"] != "alice" || renewed["email"] != "alias@example.test" || renewed["sid"] != claims["sid"] {
								t.Fatal("refresh rebound the transformed login to another account")
							}
							f.secrets = append(f.secrets, f.cookie("AUTHP_ACCESS_TOKEN"), f.cookie("AUTHP_REFRESH_TOKEN"))
						}
						f.assertResource(t, access)
						if tc.oidc != "" {
							params := f.authorization("trusted")
							params.Set("prompt", "none")
							if tc.oidc != "local" {
								f.callback(t, f.authorize(t, params), params, "login_required")
							} else {
								code := f.callback(t, f.authorize(t, params), params, "")
								tokens, id := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
								f.userinfo(t, tokens, id, "alice@example.test")
								want := []string{"pwd"}
								if mfa {
									want = append(want, "otp")
								}
								if !slices.Equal(id.Methods, want) {
									t.Fatal("OIDC authentication evidence lost required checkpoints")
								}
								f.secrets = append(f.secrets, code, tokens.Access, tokens.ID)
							}
						}
					})
				}
			})
		}
	}
	t.Run("mutations", func(t *testing.T) { testLocalIdentityMutations(t, cert, key, roots) })
	t.Run("public-keys", func(t *testing.T) { testLocalIdentityPublicKeys(t, cert, key, roots) })
}
