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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

// These journeys run cmd/authcrunch itself, including CLI dispatch and Caddyfile
// loading. The HTTP helpers are shared with the in-process identity suite.
type passwordCaddyFixture struct {
	*localIdentityFixture
	binary, configPath, admin, logPath, dir string
	command                                 *exec.Cmd
	done                                    chan error
	cancel                                  context.CancelFunc
}

func passwordBinaryCommand(t *testing.T, binary, input string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.WaitDelay = 3 * time.Second
	return cmd.CombinedOutput()
}

func newPasswordCaddyFixture(t *testing.T, binary, imported, cert, key string, roots *x509.CertPool) *passwordCaddyFixture {
	t.Helper()
	dir := t.TempDir()
	base := "https://" + lifecycleAddress(t)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	plain := *client
	f := &passwordCaddyFixture{
		localIdentityFixture: &localIdentityFixture{
			oidcRPFixture: &oidcRPFixture{client: client, base: base, mount: "/auth", issuer: base + "/auth"},
			plain:         &plain, database: filepath.Join(dir, "users.json"),
			secrets: []string{argon2FixturePlaintext, bcryptFixturePlaintext, imported, strings.TrimPrefix(imported, "argon2:"), bcryptFixtureHash, strings.TrimPrefix(bcryptFixtureHash, "bcrypt:8:")},
		},
		binary: binary, dir: dir, configPath: filepath.Join(dir, "Caddyfile"), admin: lifecycleAddress(t), logPath: filepath.Join(dir, "caddy.log"),
	}
	signing := newJWKSKeyFiles(t, "RSA", "password-access")
	f.input = fmt.Sprintf(`{
 admin %s
 persist_config off
 auto_https off
 storage file_system %q
 security {
  local identity store localdb {
   realm local
   path %q
   user alice {
    email alice@example.test
    password %q overwrite
    roles authp/user
   }
   user bob {
    email bob@example.test
    password %q
    roles authp/user
   }
  }
  messaging file provider notifications {
   root_dir %q
   sender registration@example.test
  }
  user registration signup {
   dropbox %q
   email provider notifications
   admin email admin@example.test
   identity store localdb
  }
  authentication portal myportal {
   enable identity store localdb
   %s
   token refresh {
    realms local
    public origin %s
    base path /auth
    body transport enabled
    access lifetime 600
   }
  }
  authorization policy app_policy {
   %s
   set auth url %s/auth/login
   validate bearer header
   allow roles authp/user
  }
 }
}
%s {
 tls %q %q
 route /resource {
  authorize with app_policy
  respond "identity resource"
 }
 route /auth/* {
  authenticate with myportal
 }
 respond unmatched 404
}
`, f.admin, filepath.Join(dir, "storage"), f.database, imported, bcryptFixtureHash, filepath.Join(dir, "mail"), filepath.Join(dir, "registrations.json"), signing.signer("access"), base, signing.verifier("access"), base, base, cert, key)
	t.Cleanup(func() {
		f.stop(t)
		transport.CloseIdleConnections()
		data, err := os.ReadFile(f.logPath)
		if err != nil {
			t.Error("missing executable diagnostic evidence")
			return
		}
		assertAdminRedacted(t, data, f.secrets)
	})
	f.start(t)
	response := f.request(t, "GET", "/.well-known/jwks.json", nil, nil)
	response.requireStatus(t, 200)
	var jwks struct{ Keys []map[string]string }
	if json.Unmarshal(response.body, &jwks) != nil || len(jwks.Keys) != 1 {
		t.Fatal("missing executable signing key")
	}
	f.keys = jwks.Keys
	return f
}

func (f *passwordCaddyFixture) start(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.configPath, []byte(f.input), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(f.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	f.cancel = cancel
	f.command = exec.CommandContext(ctx, f.binary, "run", "--adapter", "caddyfile", "--config", f.configPath)
	f.command.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(f.dir, "data"), "XDG_CONFIG_HOME="+filepath.Join(f.dir, "config"))
	f.command.Stdout, f.command.Stderr = log, log
	f.command.WaitDelay = 3 * time.Second
	if err := f.command.Start(); err != nil {
		log.Close()
		cancel()
		t.Fatal("cannot start Caddy executable", err)
	}
	// Capture this run's command/channel so even late process completion cannot
	// race with cleanup or a restart replacing the fixture fields.
	command, done := f.command, make(chan error, 1)
	f.done = done
	go func() { err := command.Wait(); log.Close(); done <- err }()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-f.done:
			f.done = nil
			cancel()
			t.Fatalf("Caddy executable exited before readiness: %v", err)
		case <-deadline.C:
			t.Fatal("Caddy executable did not become ready")
		case <-ticker.C:
			response, err := f.plain.Get(f.issuer + "/login")
			if err != nil {
				continue
			}
			response.Body.Close()
			if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("fixture TLS was not verified")
			}
			if response.StatusCode == 200 {
				f.newBrowser(t)
				return
			}
		}
	}
}

func (f *passwordCaddyFixture) stop(t *testing.T) {
	t.Helper()
	if f.done == nil {
		return
	}
	// Use Caddy's bounded shutdown endpoint so cleanup works on Windows too.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.binary, "stop", "--address", f.admin)
	cmd.WaitDelay = 3 * time.Second
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Error("Caddy graceful shutdown failed", err)
		f.cancel()
	}
	select {
	case err := <-f.done:
		if err != nil {
			t.Error("Caddy executable did not exit cleanly", err)
		}
	case <-ctx.Done():
		t.Error("Caddy executable exceeded the graceful shutdown deadline")
		f.cancel()
		select {
		case <-f.done:
		case <-time.After(5 * time.Second):
			t.Error("Caddy process did not stop")
		}
	}
	f.done = nil
	f.cancel()
}

func (f *passwordCaddyFixture) verifyAccess(t *testing.T, token, username string) {
	t.Helper()
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "access")
	if claims["sub"] != username || claims["origin"] != "local" {
		t.Fatal("password login changed token identity")
	}
	f.assertResource(t, token)
}

func (f *passwordCaddyFixture) nativePassword(t *testing.T, username, password string, allowed bool) apiauth.AuthResponse {
	t.Helper()
	f.secrets = append(f.secrets, password)
	req := apiauth.AuthRequest{Username: username, Realm: "local", RefreshTransport: "body"}
	start := f.json(t, f.plain, "/login", req, "")
	if !allowed && start.status == 401 {
		return localIdentityRejectedAuth(t, start, 401)
	}
	challenge := localIdentityAuth(t, start)
	if challenge.Authenticated || challenge.NextChallenge != "password" || challenge.SandboxID == "" || challenge.SandboxSecret == "" {
		t.Fatal("native password challenge missing")
	}
	f.secrets = append(f.secrets, challenge.SandboxSecret)
	req.SandboxID, req.SandboxSecret = challenge.SandboxID, challenge.SandboxSecret
	req.ChallengeKind, req.ChallengeResponse = "password", password
	result := f.json(t, f.plain, "/login", req, "")
	if !allowed {
		return localIdentityRejectedAuth(t, result, 401)
	}
	auth := localIdentityAuth(t, result)
	if !auth.Authenticated || auth.AccessToken == "" || auth.RefreshToken == "" || auth.SessionID == "" {
		t.Fatal("native login did not issue complete credentials")
	}
	if len(result.header.Values("Set-Cookie")) != 0 {
		t.Fatal("native login set browser cookies")
	}
	f.secrets = append(f.secrets, auth.AccessToken, auth.RefreshToken)
	f.verifyAccess(t, auth.AccessToken, username)
	return auth
}

func (f *passwordCaddyFixture) basicPassword(t *testing.T, username, password string, allowed bool) {
	t.Helper()
	credential := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	f.secrets = append(f.secrets, password, credential)
	f.newBrowser(t)
	result := f.request(t, "GET", "/basic/login/local", nil, http.Header{"Authorization": {"Basic " + credential}})
	result.noStore(t)
	if !allowed {
		result.requireStatus(t, 401)
		f.noCredentials(t)
		assertAdminRedacted(t, result.body, append(f.secrets, password))
		return
	}
	result.requireStatus(t, 303)
	token := f.cookie("AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("portal Basic login omitted access cookie")
	}
	f.secrets = append(f.secrets, token, f.cookie("AUTHP_REFRESH_TOKEN"))
	f.verifyAccess(t, token, username)
}

func TestCaddyPasswordArgon2E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "authcrunch")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy: %v\n%s", err, output)
	}
	for _, adapter := range []string{"adapt", "validate"} {
		output, err := passwordBinaryCommand(t, binary, "", adapter, "--adapter", "caddyfile", "--config", "testdata/caddyfile_adapt/testcase_authenticate_with_argon2_malformed.Caddyfile")
		if err == nil || !bytes.Contains(output, []byte("password only supports the overwrite option")) || bytes.Contains(output, []byte("synthetic-import")) || bytes.Contains(output, []byte("synthetic-misplaced-import")) {
			t.Fatal("Caddy password directive error accepted or disclosed an import")
		}
	}

	version, err := passwordBinaryCommand(t, binary, "", "security", "version")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.TrimSpace(string(version)))
	output, err := passwordBinaryCommand(t, binary, argon2FixturePlaintext+"\n", "security", "local", "generate", "password", "hash", "--algorithm", "argon2", "--memory", "1024", "--iterations", "2", "--parallelism", "2", "--password-file", "-")
	if err != nil {
		t.Fatal("executable Argon2 generation failed", err)
	}
	generated := generatedArgon2Password(t, output, argon2FixturePlaintext)
	for _, flags := range [][]string{
		{"--cost", "10"}, {"--memory", "262145"}, {"--parallelism", "17"},
		{"--algorithm", "argon2\t"}, {"--algorithm", "argon2\u2003"},
		{"--algorithm", "bcrypt\t"}, {"--algorithm", "bcrypt\u2003"},
	} {
		args := append([]string{"security", "local", "generate", "password", "hash", "--algorithm", "argon2", "--password-file", "-"}, flags...)
		out, err := passwordBinaryCommand(t, binary, argon2FixturePlaintext, args...)
		if err == nil || bytes.Contains(out, []byte(argon2FixturePlaintext)) || bytes.Contains(out, []byte("password \"")) {
			t.Fatal("Caddy generator accepted invalid options or disclosed plaintext")
		}
	}
	// Raw login passwords retain plaintext semantics, including reserved prefixes.
	const literalPassword = "argon2:LiteralPassword42!"
	literal, err := passwordBinaryCommand(t, binary, literalPassword, "security", "local", "generate", "password", "hash", "--cost", "8", "--password-file", "-")
	if err != nil {
		t.Fatal("literal bcrypt compatibility generation failed")
	}
	passwordDirective(t, literal, literalPassword)

	cert, key, roots := cookieTLSCertificate(t)
	for _, protocol := range []string{"html", "native", "basic"} {
		t.Run(protocol, func(t *testing.T) {
			f := newPasswordCaddyFixture(t, binary, generated.EncodedHash(), cert, key, roots)
			f.stop(t)
			f.secrets = append(f.secrets, literalPassword)
			f.input = strings.Replace(f.input, "   user alice {", fmt.Sprintf("   user literal {\n email literal@example.test\n %s roles authp/user\n }\n   user alice {", literal), 1)
			f.start(t)

			login := func(username, password string, allowed bool) {
				t.Helper()
				f.secrets = append(f.secrets, password)
				switch protocol {
				case "native":
					f.nativePassword(t, username, password, allowed)
				case "basic":
					f.basicPassword(t, username, password, allowed)
				case "html":
					if allowed {
						f.verifyAccess(t, f.formLogin(t, username, password, false), username)
						return
					}
					f.formPassword(t, username, password, 401)
					f.noCredentials(t)
				}
			}
			login("alice", argon2FixturePlaintext, true)
			login("bob", bcryptFixturePlaintext, true)
			login("literal", literalPassword, true)
			for _, attempt := range []struct{ username, password string }{
				{"alice", "IncorrectPassword42!"}, {"missing", "IncorrectPassword42!"}, {"alice", generated.EncodedHash()}, {"bob", bcryptFixtureHash},
			} {
				login(attempt.username, attempt.password, false)
			}
			// Four failures stay below the enabled limiter's threshold. A successful
			// control proves none of the rejections were a blanket transport block.
			login("alice", argon2FixturePlaintext, true)
		})
	}
	t.Run("persistence-and-overwrite", func(t *testing.T) {
		f := newPasswordCaddyFixture(t, binary, generated.EncodedHash(), cert, key, roots)
		f.nativePassword(t, "alice", argon2FixturePlaintext, true)
		before := localIdentityRecord(t, f.database, "alice")
		original := localIdentityActivePassword(t, before)
		if original.Algorithm != "argon2" || original.Cost != 0 || original.Hash != generated.Hash {
			t.Fatal("import changed at provisioning")
		}
		data, err := os.ReadFile(f.database)
		if err != nil {
			t.Fatal(err)
		}
		var persistedFile struct {
			Users []struct {
				Username  string
				Passwords []map[string]json.RawMessage
			}
		}
		if json.Unmarshal(data, &persistedFile) != nil {
			t.Fatal("invalid persisted database")
		}
		for _, user := range persistedFile.Users {
			if user.Username == "alice" {
				if len(user.Passwords) != 1 || string(user.Passwords[0]["algorithm"]) != `"argon2"` || user.Passwords[0]["cost"] != nil {
					t.Fatal("Argon2 persistence included a bcrypt cost or lost algorithm")
				}
			}
		}

		f.stop(t)
		f.start(t)
		after := localIdentityRecord(t, f.database, "alice")
		same := localIdentityActivePassword(t, after)
		if same.Hash != original.Hash || !same.CreatedAt.Equal(original.CreatedAt) || len(after.Passwords) != len(before.Passwords) || after.CredentialVersion != before.CredentialVersion+1 {
			t.Fatal("identical overwrite duplicated hash history or lost revocation version")
		}
		f.nativePassword(t, "alice", argon2FixturePlaintext, true)
		f.nativePassword(t, "bob", bcryptFixturePlaintext, true)
		f.stop(t)
		const replacement = "ReplacementArgon2Password42!"
		f.secrets = append(f.secrets, replacement)
		f.input = strings.Replace(f.input, fmt.Sprintf("password %q overwrite", generated.EncodedHash()), fmt.Sprintf("password %q overwrite", replacement), 1)
		f.start(t)
		f.nativePassword(t, "alice", argon2FixturePlaintext, false)
		f.nativePassword(t, "alice", replacement, true)
		replaced := localIdentityRecord(t, f.database, "alice")
		active := localIdentityActivePassword(t, replaced)
		if active.Algorithm != "argon2" || active.Cost != 0 || !strings.HasPrefix(active.Hash, "$argon2id$v=19$m=65536,t=3,p=4$") || replaced.CredentialVersion != after.CredentialVersion+1 {
			t.Fatal("plaintext overwrite did not preserve Argon2 at library defaults")
		}
		// Remove the old configured import before restart; deliberate overwrite is
		// authoritative even when an identity database already exists.
		f.stop(t)
		f.input = strings.Replace(f.input, fmt.Sprintf("password %q overwrite", replacement), fmt.Sprintf("password %q", generated.EncodedHash()), 1)
		f.start(t)
		f.nativePassword(t, "alice", replacement, true)
		persisted := localIdentityRecord(t, f.database, "alice")
		if localIdentityActivePassword(t, persisted).Hash != active.Hash || len(persisted.Passwords) != len(replaced.Passwords) {
			t.Fatal("restart did not preserve replacement and history")
		}
		f.stop(t)
		f.input = strings.Replace(f.input, fmt.Sprintf("password %q", generated.EncodedHash()), fmt.Sprintf("password %q overwrite", bcryptFixtureHash), 1)
		f.start(t)
		f.nativePassword(t, "alice", replacement, false)
		f.nativePassword(t, "alice", bcryptFixturePlaintext, true)
		if localIdentityActivePassword(t, localIdentityRecord(t, f.database, "alice")).Algorithm != "bcrypt" {
			t.Fatal("explicit bcrypt overwrite did not switch algorithms")
		}
	})
	t.Run("public-profile", func(t *testing.T) { testPasswordProfileImports(t, binary, generated.EncodedHash(), cert, key, roots) })
	t.Run("public-registration", func(t *testing.T) {
		testPasswordRegistrationImports(t, binary, generated.EncodedHash(), cert, key, roots)
	})
}

func testPasswordProfileImports(t *testing.T, binary, imported, cert, key string, roots *x509.CertPool) {
	f := newPasswordCaddyFixture(t, binary, imported, cert, key, roots)
	f.formLogin(t, "alice", argon2FixturePlaintext, false)
	before := localIdentityRecord(t, f.database, "alice")
	original := localIdentityActivePassword(t, before)
	for _, candidate := range []string{imported, bcryptFixtureHash, "argon2:malformed", "bcrypt:malformed", " \targon2:malformed\n", " \tbcrypt:malformed\n"} {
		f.secrets = append(f.secrets, candidate)
		f.profile(t, map[string]any{"kind": "update_user_password", "old_password": argon2FixturePlaintext, "new_password": candidate}, 400)
		after := localIdentityRecord(t, f.database, "alice")
		if after.CredentialVersion != before.CredentialVersion || len(after.Passwords) != len(before.Passwords) || localIdentityActivePassword(t, after).Hash != original.Hash {
			t.Fatal("rejected public import changed credentials")
		}
	}
	f.nativePassword(t, "alice", argon2FixturePlaintext, true)
	refreshed := f.json(t, f.client, "/api/refresh_token", struct{}{}, "", http.Header{"X-Authcrunch-Refresh": {"1"}, "Sec-Fetch-Site": {"same-origin"}})
	auth := localIdentityAuth(t, refreshed)
	if !auth.Authenticated || f.cookie("AUTHP_REFRESH_TOKEN") == "" {
		t.Fatal("rejected imports invalidated refresh eligibility")
	}
	f.secrets = append(f.secrets, f.cookie("AUTHP_ACCESS_TOKEN"), f.cookie("AUTHP_REFRESH_TOKEN"))
	const replacement = "ProfileArgon2Password42!"
	f.secrets = append(f.secrets, replacement)
	// Also retain separate native evidence to verify revocation across transports.
	native := f.nativePassword(t, "alice", argon2FixturePlaintext, true)
	f.profile(t, map[string]any{"kind": "update_user_password", "old_password": argon2FixturePlaintext, "new_password": replacement}, 200)
	changed := localIdentityRecord(t, f.database, "alice")
	if changed.CredentialVersion != before.CredentialVersion+1 || localIdentityActivePassword(t, changed).Algorithm != "argon2" {
		t.Fatal("public plaintext change lost Argon2 or revocation")
	}
	f.nativePassword(t, "alice", argon2FixturePlaintext, false)
	f.nativePassword(t, "alice", replacement, true)
	localIdentityRejectedAuth(t, f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, ""), 401)
	localIdentityRejectedAuth(t, f.json(t, f.client, "/api/refresh_token", struct{}{}, "", http.Header{"X-Authcrunch-Refresh": {"1"}, "Sec-Fetch-Site": {"same-origin"}}), 401)
}

func testPasswordRegistrationImports(t *testing.T, binary, imported, cert, key string, roots *x509.CertPool) {
	f := newPasswordCaddyFixture(t, binary, imported, cert, key, roots)
	f.request(t, "GET", "/register/local", nil, nil).requireStatus(t, 200)
	submit := func(password string) oidcRPResponse {
		t.Helper()
		f.secrets = append(f.secrets, password)
		return f.request(t, "POST", "/register/local", url.Values{"registrant": {"newuser"}, "registrant_email": {"newuser@example.test"}, "registrant_password": {password}}, http.Header{"Origin": {f.base}})
	}
	for _, candidate := range []string{imported, bcryptFixtureHash, "argon2:malformed", "bcrypt:malformed", " \targon2:malformed\n", " \tbcrypt:malformed\n"} {
		result := submit(candidate)
		result.requireStatus(t, 200) // The public HTML form reports validation inline.
		if !strings.Contains(string(result.body), "the password value is invalid") {
			t.Fatal("registration did not report reserved password rejection")
		}
		assertAdminRedacted(t, result.body, append(f.secrets, candidate))
		matches, err := filepath.Glob(filepath.Join(f.dir, "mail", "*.eml"))
		if err != nil || len(matches) != 0 {
			t.Fatal("rejected import sent a registration message")
		}
		if localIdentityRecord(t, f.database, "newuser") != nil {
			t.Fatal("rejected registration persisted a login user")
		}
		data, err := os.ReadFile(filepath.Join(f.dir, "registrations.json"))
		if err == nil {
			var db struct{ Users []json.RawMessage }
			if json.Unmarshal(data, &db) != nil || len(db.Users) != 0 {
				t.Fatal("rejected registration persisted a dropbox user")
			}
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	// Positive control reaches the local file sender; no live SMTP/DNS is used.
	result := submit("RegistrationPlaintext42!")
	result.requireStatus(t, 200)
	matches, err := filepath.Glob(filepath.Join(f.dir, "mail", "*.eml"))
	if err != nil || len(matches) != 1 {
		t.Fatal("plaintext registration did not send confirmation")
	}
}
