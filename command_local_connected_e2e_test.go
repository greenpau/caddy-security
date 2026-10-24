// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	identities "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

// The CLI is the production binary. Only the isolated Caddy server fixture
// runs in the instrumented test executable; this is not an OS server restart.
func TestCaddyConnectedAccountsAdministrationE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "authcrunch")
	buildCtx, buildCancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer buildCancel()
	build := exec.CommandContext(buildCtx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath -p=1")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production administration command: %v\n%s", err, output)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyConnectedAccountsAdministrationProcess$", "-test.v", "-test.timeout=220s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CONNECTED_ADMIN_BINARY="+binary,
		"XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		// Child assertions report fixed stages, never command output or records.
		t.Fatalf("built CLI administration through TLS Caddy: %v\n%s", err, output)
	}
}

type connectedAdminCLI struct {
	binary, config, tokenPath, ca string
	f                             *caddyConnectedAccountsFixture
}

type connectedAdminCLIResult struct {
	stdout, stderr []byte
	err            error
}

// Workers may execute commands concurrently; only the test goroutine decodes
// responses, asserts outcomes and appends credentials to the private inventory.
func (c *connectedAdminCLI) execute(ctx context.Context, action string, flags ...string) connectedAdminCLIResult {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := append([]string{"security", "local"}, strings.Fields(action)...)
	args = append(args, "--config", c.config, "--ca-file", c.ca, "--timeout", "25s")
	cmd := exec.CommandContext(ctx, c.binary, append(args, flags...)...)
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return connectedAdminCLIResult{stdout.Bytes(), stderr.Bytes(), err}
}

func connectedAdminCapture(f *caddyConnectedAccountsFixture, body []byte) {
	var response struct {
		Password  string               `json:"password"`
		Passwords []*identity.Password `json:"passwords"`
	}
	if json.Unmarshal(body, &response) != nil {
		return
	}
	f.secrets = append(f.secrets, response.Password)
	for _, password := range response.Passwords {
		if password != nil {
			f.secrets = append(f.secrets, password.Hash)
		}
	}
}

func (c *connectedAdminCLI) result(t *testing.T, action string, result connectedAdminCLIResult, success bool) []byte {
	t.Helper()
	connectedAdminCapture(c.f, result.stdout)
	assertAdminRedacted(t, result.stderr, c.f.secrets)
	if len(result.stdout) > securityLocalMaxResponse*2 || len(result.stderr) > 64*1024 {
		t.Fatal("administration command output exceeded its fixture bound")
	}
	if (result.err == nil) != success {
		t.Fatalf("administration command %s success=%v (output withheld)", action, success)
	}
	if !success {
		if len(result.stdout) != 0 {
			t.Fatal("rejected administration command printed a result")
		}
		return nil
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(result.stdout, &response) != nil || response == nil || len(result.stderr) != 0 {
		t.Fatal("administration command omitted clean JSON output")
	}
	if action == "update user" || action == "delete user" {
		var status string
		if json.Unmarshal(response["status"], &status) != nil || status != "success" {
			t.Fatal("administration mutation was not confirmed")
		}
		c.f.contracts.AssertComponent(t, "AdminUserMutation", result.stdout)
	}
	return result.stdout
}

func (c *connectedAdminCLI) call(t *testing.T, action string, success bool, flags ...string) []byte {
	t.Helper()
	return c.result(t, action, c.execute(t.Context(), action, flags...), success)
}

func newConnectedAdminCLI(t *testing.T, binary string, f *caddyConnectedAccountsFixture, username, password string) *connectedAdminCLI {
	t.Helper()
	dir := t.TempDir()
	c := &connectedAdminCLI{binary: binary, config: filepath.Join(dir, "client.yaml"), tokenPath: filepath.Join(dir, "token.json"), ca: f.cert, f: f}
	input := fmt.Sprintf("base_url: %q\nrealm: local\nusername: %q\npassword: %q\ntoken_path: %q\n", f.issuer, username, password, c.tokenPath)
	if err := os.WriteFile(c.config, []byte(input), 0600); err != nil {
		t.Fatal("cannot create private administration client config")
	}
	body := c.call(t, "connect", true)
	// Capture the newly written credentials before checking response metadata.
	// The CLI resolves ancestor links, including macOS /var -> /private/var;
	// compare its canonical result and actual file identity, not lexical spelling.
	credentials := c.credentials(t)
	var connected struct {
		Status    string `json:"status"`
		TokenPath string `json:"token_path"`
	}
	expected, pathErr := filepath.EvalSymlinks(c.tokenPath)
	if json.Unmarshal(body, &connected) != nil || connected.Status != "success" || pathErr != nil || len(connected.TokenPath) > 8192 || !filepath.IsAbs(connected.TokenPath) || connected.TokenPath != expected {
		t.Fatal("native CLI connection did not select its private credential file")
	}
	wanted, wantedErr := os.Lstat(c.tokenPath)
	reported, reportedErr := os.Lstat(connected.TokenPath)
	if wantedErr != nil || reportedErr != nil || !wanted.Mode().IsRegular() || !reported.Mode().IsRegular() || !os.SameFile(wanted, reported) || reported.Mode().Perm() != 0600 || reported.Size() <= 0 || reported.Size() > 1<<20 {
		t.Fatal("native CLI reported a different or nonprivate credential file")
	}
	c.tokenPath = connected.TokenPath
	claims := verifyCaddyJWKSSignature(t, f.keys, credentials.AccessToken, "RS512", "access")
	account := localIdentityRecord(t, f.database, username)
	roles, ok := claims["roles"].([]any)
	if account == nil || claims["id"] != account.ID || !ok || slices.Contains(roles, any("authp/admin")) != (username == "admin") {
		t.Fatal("native CLI login did not authenticate the intended local authority")
	}
	return c
}

func (c *connectedAdminCLI) credentials(t *testing.T) *authclient.Credentials {
	t.Helper()
	info, err := os.Lstat(c.tokenPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 1<<20 {
		t.Fatal("CLI credentials were missing, oversized or not private")
	}
	store, err := authclient.NewFileTokenStore(c.tokenPath)
	if err != nil {
		t.Fatal("cannot select CLI credential storage")
	}
	credentials, err := store.Load()
	if err != nil {
		t.Fatal("cannot read CLI credential storage")
	}
	c.f.secrets = append(c.f.secrets, credentials.AccessToken, credentials.RefreshToken)
	return credentials
}

func (c *connectedAdminCLI) info(t *testing.T, username string, extra ...string) *identity.User {
	t.Helper()
	flags := append([]string{"--realm", "local", "--username", username}, extra...)
	body := c.call(t, "info user", true, flags...)
	c.f.contracts.AssertComponent(t, "AdminUserRecord", body)
	var user identity.User
	if json.Unmarshal(body, &user) != nil || user.ID == "" || user.Username != username {
		t.Fatal("CLI info did not return the selected account")
	}
	return &user
}

func (c *connectedAdminCLI) users(t *testing.T) []identity.UserMetadata {
	t.Helper()
	body := c.call(t, "list users", true, "--realm", "local")
	var response struct {
		Users []identity.UserMetadata `json:"users"`
	}
	if json.Unmarshal(body, &response) != nil || response.Users == nil {
		t.Fatal("CLI listing did not return account metadata")
	}
	return response.Users
}

func connectedAdminSelect(t *testing.T, users []identity.UserMetadata, id string) identity.UserMetadata {
	t.Helper()
	var matches []identity.UserMetadata
	for _, user := range users {
		if user.ID == id {
			matches = append(matches, user)
		}
	}
	if len(matches) != 1 || matches[0].Username == "" {
		t.Fatal("CLI listing did not uniquely identify the verified local account")
	}
	return matches[0]
}

func connectedAdminUnchanged(t *testing.T, before, after *identity.User) {
	t.Helper()
	a, errA := json.Marshal(before)
	b, errB := json.Marshal(after)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		t.Fatal("rejected selector changed account state")
	}
}

func connectedAdminRoles(t *testing.T, user *identity.User, want []string) {
	t.Helper()
	var got []string
	for _, role := range user.Roles {
		got = append(got, role.String())
	}
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatal("stored administrative roles differ from the accepted mutations")
	}
}

func connectedAdminClaims(t *testing.T, f *caddyConnectedAccountsFixture, wantID string, wantRoles []string) map[string]any {
	t.Helper()
	browser := f.browser(t)
	f.login(t, browser, "upstream", 303)
	claims := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, browser, "AUTHP_ACCESS_TOKEN"))
	roles, ok := claims["roles"].([]any)
	if claims["id"] != wantID || !ok {
		t.Fatal("fresh verified provider login lost its managed local identity")
	}
	for _, role := range wantRoles {
		if !slices.Contains(roles, any(role)) {
			t.Fatal("fresh verified provider login omitted a current managed role")
		}
	}
	return claims
}

func connectedAdminHTTP(t *testing.T, c *connectedAdminCLI, realm, operation string, fields map[string]any, status int, validRequest bool) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"realm": realm, "operation": operation, "user": fields})
	if err != nil {
		t.Fatal("cannot encode administration request")
	}
	authorization, err := c.credentials(t).Authorization()
	if err != nil {
		t.Fatal("CLI credentials cannot authorize administration")
	}
	headers := http.Header{"Authorization": {authorization}, "Accept": {"application/json"}, "Content-Type": {"application/json"}}
	if validRequest {
		c.f.contracts.AssertRequest(t, "POST", "/api/server/user", headers, body)
	}
	r := connectedAccountsSend(t, c.f.localIdentityFixture, c.f.plain, "POST", "/api/server/user", bytes.NewReader(body), headers)
	connectedAdminCapture(c.f, r.body)
	r.requireStatus(t, status)
	r.noStore(t)
	c.f.contracts.AssertResponse(t, "POST", "/api/server/user", r.status, r.header, r.body)
	return r.body
}

func TestCaddyConnectedAccountsAdministrationProcess(t *testing.T) {
	binary := os.Getenv("CADDY_SECURITY_CONNECTED_ADMIN_BINARY")
	if binary == "" {
		t.Skip("subprocess helper")
	}
	if info, err := os.Stat(binary); err != nil || !filepath.IsAbs(binary) || !info.Mode().IsRegular() {
		t.Fatal("production administration binary is unavailable")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("cannot load fixture TLS key pair")
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal("cannot initialize TLS trust fixture")
	}
	oauthE2ESystemRoots = roots
	// SQLite is a concrete non-local-store control. Its existing paired selector
	// remains required even when the same portal admits automatic local records.
	sqliteConfig := sqliteIdentityCLIConfig(t)
	sqlite, err := identities.New(t.Context(), sqliteConfig)
	if err != nil {
		t.Fatal("cannot open nonlocal selector control")
	}
	sqliteAccount, createErr := sqlite.Create(t.Context(), &identities.Account{Username: "sqlitecontrol", Email: "sqlite@example.test", Name: "SQLite Control", Roles: []string{"authp/user"}}, lifecyclePassword)
	closeErr := sqlite.Close()
	if createErr != nil || closeErr != nil {
		t.Fatal("cannot provision and close nonlocal selector control")
	}
	sqliteID, ok := sqliteAccount["id"].(string)
	if !ok || sqliteID == "" {
		t.Fatal("nonlocal selector control has no account identity")
	}
	f := newCaddyConnectedAccountsFixture(t, connectedAccountsOptions{mount: "/tenant/auth", seed: func(t *testing.T, path string) {
		db, err := identity.NewDatabase(path)
		if err != nil {
			t.Fatal("cannot seed aliased automatic-account control")
		}
		if err := db.AddUser(&requests.Request{User: requests.User{Username: "aliased", Email: "aliased@example.test", Password: lifecyclePassword, Roles: []string{"authp/user"}}}); err != nil {
			t.Fatal("cannot create aliased selector control")
		}
		for _, user := range db.Users {
			if user.Username == "aliased" {
				user.ExternallyProvisioned = true
			}
		}
		if err := db.Save(); err != nil {
			t.Fatal("cannot save offline automatic-record control")
		}
	}, configure: func(input string) string {
		declaration := fmt.Sprintf("identity store sqlite %s {\nrealm %s\npath %q\ntimeout 5s\n}\n", sqliteConfig.Name, sqliteConfig.Realm, sqliteConfig.Path)
		input = strings.Replace(input, "authentication portal myportal {", declaration+"authentication portal myportal {", 1)
		return strings.Replace(input, "enable identity store localdb", "enable identity stores localdb "+sqliteConfig.Name, 1)
	}}, cert, key, roots, pair)
	browser := f.browser(t)
	f.login(t, browser, "upstream", 303)
	initial := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, browser, "AUTHP_ACCESS_TOKEN"))
	id := initial["id"].(string)
	ordinary := localIdentityRecord(t, f.database, "alice")
	if id == ordinary.ID || id == f.upstream.fixedSubject {
		t.Fatal("provider display email selected an existing local account")
	}
	admin := newConnectedAdminCLI(t, binary, f, "admin", lifecyclePassword)
	member := newConnectedAdminCLI(t, binary, f, "bob", localIdentityBobPassword)
	metadata := connectedAdminSelect(t, admin.users(t), id)
	username := metadata.Username
	before := admin.info(t, username)
	if !before.ExternallyProvisioned || before.ID != id || before.Disabled || len(before.EmailAddresses) != 0 || len(before.Passwords) != 0 || len(before.MfaTokens) != 0 || len(before.APIKeys) != 0 || len(before.ExternalAccounts) != 1 || before.ExternalAccounts[0].Email != "alice@example.test" {
		t.Fatal("CLI info did not expose the passwordless automatic identity")
	}
	selector := []string{"--realm", "local", "--username", username}
	update := func(flags ...string) []byte {
		return admin.call(t, "update user", true, append(slices.Clone(selector), flags...)...)
	}

	t.Run("selector_boundaries", func(t *testing.T) {
		member.call(t, "info user", false, selector...)
		member.call(t, "update user", false, append(slices.Clone(selector), "--disable")...)
		connectedAdminHTTP(t, member, "local", "disable", map[string]any{"username": username}, 403, true)
		for _, email := range []string{"alice@example.test", "wrong@example.test"} {
			flags := append(slices.Clone(selector), "--email", email)
			admin.call(t, "info user", false, flags...)
			admin.call(t, "update user", false, append(flags, "--disable")...)
		}
		for _, value := range []any{nil, false, []string{}} {
			connectedAdminHTTP(t, admin, "local", "info", map[string]any{"username": username, "email": value}, 400, false)
		}
		for _, fields := range []map[string]any{{"username": username}, {"username": username, "email": ""}} {
			data := connectedAdminHTTP(t, admin, "local", "info", fields, 200, true)
			var got identity.User
			if json.Unmarshal(data, &got) != nil || got.ID != id {
				t.Fatal("omitted and empty HTTP selectors selected different accounts")
			}
		}
		admin.call(t, "add user", false, "--realm", "local", "--username", "missingemail", "--name", "Missing Email", "--roles", "authp/user")
		connectedAdminHTTP(t, admin, "local", "add", map[string]any{"username": "missingemail", "name": "Missing Email", "roles": []string{"authp/user"}}, 400, false)
		connectedAdminUnchanged(t, before, admin.info(t, username, "--email="))
		for _, target := range []string{"alice", "aliased"} {
			prior := admin.info(t, target, "--email", target+"@example.test")
			for _, operation := range []struct {
				action string
				flags  []string
			}{
				{"info user", nil}, {"delete user", nil},
				{"update user", []string{"--disable"}}, {"update user", []string{"--enable"}},
				{"update user", []string{"--reset-password"}}, {"update user", []string{"--overwrite-roles", "rejected-role"}},
				{"update user", []string{"--add-roles", "rejected-role"}}, {"update user", []string{"--overwrite-auth-challenges", "password"}},
			} {
				flags := append([]string{"--realm", "local", "--username", target}, operation.flags...)
				admin.call(t, operation.action, false, flags...)
			}
			admin.call(t, "info user", false, "--realm", "local", "--username", target, "--email", "wrong@example.test")
			connectedAdminHTTP(t, admin, "local", "info", map[string]any{"username": target}, 500, true)
			failure := connectedAdminHTTP(t, admin, "local", "disable", map[string]any{"username": target}, 200, true)
			var mutation struct{ Status string }
			if json.Unmarshal(failure, &mutation) != nil || mutation.Status != "failure" {
				t.Fatal("HTTP-200 selector rejection did not report operation failure")
			}
			connectedAdminUnchanged(t, prior, admin.info(t, target, "--email", target+"@example.test"))
		}
		// Enable searches disabled records, so qualify the aliased exception at
		// that distinct operation boundary with a real disabled positive control.
		aliased := admin.info(t, "aliased", "--email", "aliased@example.test")
		admin.call(t, "update user", true, "--realm", "local", "--username", "aliased", "--email", "aliased@example.test", "--disable")
		for _, extra := range [][]string{nil, {"--email", "wrong@example.test"}} {
			flags := append([]string{"--realm", "local", "--username", "aliased", "--enable"}, extra...)
			admin.call(t, "update user", false, flags...)
			if !connectedAdminSelect(t, admin.users(t), aliased.ID).Disabled {
				t.Fatal("invalid email re-enabled the aliased automatic control")
			}
		}
		admin.call(t, "update user", true, "--realm", "local", "--username", "aliased", "--email", "aliased@example.test", "--enable")
		current := admin.info(t, "aliased", "--email", "aliased@example.test")
		if current.ID != aliased.ID || current.Disabled || current.CredentialVersion != aliased.CredentialVersion+2 || !current.ExternallyProvisioned || len(current.EmailAddresses) != 1 {
			t.Fatal("paired selectors changed the aliased automatic identity")
		}
		sqliteFlags := []string{"--realm", sqliteConfig.Realm, "--username", "sqlitecontrol"}
		pairedFlags := append(slices.Clone(sqliteFlags), "--email", "sqlite@example.test")
		sqliteBefore := admin.call(t, "info user", true, pairedFlags...)
		// SQLite's detached public accountMap uses name/role strings rather
		// than the full local-record schema validated by admin.info above.
		var nonlocal struct {
			ID, Username, Email, Name string
			Roles                     []string
			Disabled                  bool
		}
		if json.Unmarshal(sqliteBefore, &nonlocal) != nil || nonlocal.ID != sqliteID || nonlocal.Username != "sqlitecontrol" || nonlocal.Email != "sqlite@example.test" || nonlocal.Name != "SQLite Control" || nonlocal.Disabled || !slices.Equal(nonlocal.Roles, []string{"authp/user"}) {
			t.Fatal("paired nonlocal selector did not reach the configured store")
		}
		admin.call(t, "info user", false, sqliteFlags...)
		admin.call(t, "update user", false, append(slices.Clone(sqliteFlags), "--disable")...)
		for _, fields := range []map[string]any{{"username": "sqlitecontrol"}, {"username": "sqlitecontrol", "email": ""}} {
			connectedAdminHTTP(t, admin, sqliteConfig.Realm, "info", fields, 400, true)
			connectedAdminHTTP(t, admin, sqliteConfig.Realm, "disable", fields, 400, true)
		}
		if !bytes.Equal(sqliteBefore, admin.call(t, "info user", true, pairedFlags...)) {
			t.Fatal("rejected empty selectors changed the nonlocal control")
		}
	})
	if t.Failed() {
		return
	}
	t.Log("selector and authority boundaries completed")

	managedRoles := []string{"managed/first", "managed/second", "managed/concurrent-a", "managed/concurrent-b"}
	update("--overwrite-roles", managedRoles[0])
	connectedAdminRoles(t, admin.info(t, username), managedRoles[:1])
	update("--add-roles", managedRoles[1])
	parallel := newConnectedAdminCLI(t, binary, f, "admin", lifecyclePassword)
	var results [2]connectedAdminCLIResult
	var workers sync.WaitGroup
	start := make(chan struct{})
	for i, client := range []*connectedAdminCLI{admin, parallel} {
		workers.Go(func() {
			<-start
			results[i] = client.execute(t.Context(), "update user", append(slices.Clone(selector), "--add-roles", managedRoles[i+2])...)
		})
	}
	close(start)
	workers.Wait()
	for _, result := range results {
		admin.result(t, "update user", result, true)
	}
	connectedAdminRoles(t, admin.info(t, username), managedRoles)
	connectedAdminClaims(t, f, id, managedRoles)
	t.Log("current roles and concurrent CLI mutations completed")
	active := admin.info(t, username)
	update("--disable")
	if !connectedAdminSelect(t, admin.users(t), id).Disabled {
		t.Fatal("disabled automatic account disappeared from CLI listing")
	}
	rejected := f.browser(t)
	r := f.login(t, rejected, "upstream", 401)
	providerDestinationNoIssuance(t, r)
	if connectedAccountsCookie(t, f.localIdentityFixture, rejected, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("disabled automatic identity retained fresh provider access")
	}
	admin.call(t, "update user", false, append(slices.Clone(selector), "--email", "alice@example.test", "--enable")...)
	if !connectedAdminSelect(t, admin.users(t), id).Disabled {
		t.Fatal("provider display email re-enabled the disabled identity")
	}
	update("--email=", "--enable")
	enabled := admin.info(t, username)
	if enabled.ID != id || enabled.Disabled || enabled.CredentialVersion != active.CredentialVersion+2 || !slices.Equal(enabled.ExternalAccounts, active.ExternalAccounts) {
		t.Fatal("disable/enable lost identity, connections or credential generation")
	}
	connectedAdminClaims(t, f, id, managedRoles)
	t.Log("disable and exact-selector enable completed")
	reset := update("--reset-password")
	var generated struct{ Password string }
	if json.Unmarshal(reset, &generated) != nil || generated.Password == "" {
		t.Fatal("password reset did not return a captured credential")
	}
	resetUser := admin.info(t, username)
	if !resetUser.ExternallyProvisioned || len(resetUser.EmailAddresses) != 0 || len(resetUser.Passwords) == 0 {
		t.Fatal("password reset changed no-email selector eligibility")
	}
	update("--overwrite-auth-challenges", "password")
	policy := admin.info(t, username)
	if !slices.Equal(policy.AuthChallengeRules, []string{"password"}) {
		t.Fatal("CLI did not apply the explicit local password requirement")
	}
	factorBrowser := f.browser(t)
	r = f.login(t, factorBrowser, "upstream", 303)
	providerDestinationNoIssuance(t, r)
	location, err := url.Parse(r.header.Get("Location"))
	base, _ := url.Parse(f.base)
	if err != nil {
		t.Fatal("provider local-factor callback omitted a sandbox")
	}
	sandbox := base.ResolveReference(location)
	if sandbox.Scheme+"://"+sandbox.Host != f.base || !strings.HasPrefix(sandbox.Path, f.mount+"/sandbox/") || sandbox.User != nil || sandbox.RawQuery != "" || sandbox.Fragment != "" || connectedAccountsCookie(t, f.localIdentityFixture, factorBrowser, "AUTHP_ACCESS_TOKEN") != "" {
		t.Fatal("explicit local factor was bypassed or escaped the mounted portal")
	}
	connectedAccountsSend(t, f.localIdentityFixture, factorBrowser, "GET", sandbox.String(), nil, nil).requireStatus(t, 200)
	connectedAccountsForm(t, f.localIdentityFixture, factorBrowser, sandbox.String(), url.Values{"secret": {generated.Password}}).requireStatus(t, 303)
	connectedAccountsSend(t, f.localIdentityFixture, factorBrowser, "GET", sandbox.String(), nil, nil).requireStatus(t, 303)
	proved := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, factorBrowser, "AUTHP_ACCESS_TOKEN"))
	methods, ok := proved["amr"].([]any)
	if proved["id"] != id || !ok || !slices.Contains(methods, any("pwd")) || !slices.Contains(methods, any("federated")) {
		t.Fatal("generated password did not complete actual external/local authentication")
	}
	t.Log("generated password and explicit local-factor login completed")
	admin.call(t, "delete user", true, selector...)
	for _, entry := range admin.users(t) {
		if entry.ID == id || entry.Username == "missingemail" {
			t.Fatal("deleted or rejected-created identity remained in CLI listing")
		}
	}
	recreatedBrowser := f.browser(t)
	f.login(t, recreatedBrowser, "upstream", 303)
	recreated := f.verifyAccess(t, connectedAccountsCookie(t, f.localIdentityFixture, recreatedBrowser, "AUTHP_ACCESS_TOKEN"))
	newID := recreated["id"].(string)
	newMetadata := connectedAdminSelect(t, admin.users(t), newID)
	newUser := admin.info(t, newMetadata.Username)
	if newID == id || newUser.ID != newID || !newUser.ExternallyProvisioned || len(newUser.EmailAddresses) != 0 || len(newUser.Passwords) != 0 || len(newUser.AuthChallengeRules) != 0 || len(newUser.ExternalAccounts) != 1 {
		t.Fatal("deletion did not reprovision a distinct passwordless local identity")
	}
	roles, ok := recreated["roles"].([]any)
	if !ok {
		t.Fatal("recreated identity omitted signed roles")
	}
	for _, role := range managedRoles {
		if slices.Contains(roles, any(role)) {
			t.Fatal("deleted identity's managed roles survived reprovisioning")
		}
	}
	connectedAdminRoles(t, newUser, nil)
	connectedAdminUnchanged(t, ordinary, admin.info(t, "alice", "--email", "alice@example.test"))
	t.Log("delete and distinct-identity provider reprovisioning completed")
}
