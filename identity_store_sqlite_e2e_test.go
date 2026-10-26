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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

const sqliteIdentitySigningKey = "synthetic-sqlite-identity-signing-secret-0123456789"
const sqliteIdentityPassword = "Synthetic-identity-password-2026!"

// The production binary consumes the Caddyfile and the real SQLite backend.
// A separate management handle mutates durable records while Caddy is serving.
func TestCaddySQLiteIdentityE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/companion_caddy")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free Caddy: %v\n%s", err, output)
	}
	cert, key, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &accounts.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(dir, "identities.db"), Timeout: "2s"}
	management, err := accounts.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = management.Close() })
	account := &accounts.Account{Username: "alice", Email: "alice@example.test", Name: "Alice Example", Roles: []string{"authp/user"}}
	if _, err := management.Create(t.Context(), account, sqliteIdentityPassword); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf(`{
 admin %s
 auto_https off
 security {
  identity store sqlite accounts {
   realm staff
   path %q
   timeout 2s
  }
  authentication portal myportal {
   enable identity store accounts
   crypto key sign-verify %s
   token refresh {
    realms staff
    public origin %s
    base path /auth
    body transport enabled
   }
  }
  authorization policy app_policy {
   crypto key verify %s
   validate bearer header
   allow roles authp/user
   disable auth redirect
  }
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /auth/* {
  authenticate with myportal
 }
 route /resource {
  authorize with app_policy
  respond "identity resource"
 }
}`, f.admin, cfg.Path, sqliteIdentitySigningKey, f.base, sqliteIdentitySigningKey, f.base, cert, key)
	baseline := f.write(t, source)
	f.start(t)
	verify := func(raw string) jwt.MapClaims {
		t.Helper()
		token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(sqliteIdentitySigningKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
		if err != nil || !token.Valid {
			t.Fatal("invalid signed SQLite credential")
		}
		claims := token.Claims.(jwt.MapClaims)
		if claims["sub"] != "alice" || claims["origin"] != "staff" {
			t.Fatal("wrong SQLite subject/realm")
		}
		methods, ok := claims["amr"].([]any)
		if !ok || len(methods) != 1 || methods[0] != "pwd" {
			t.Fatal("incorrect password evidence")
		}
		return claims
	}
	basic := func(realm, secret string, status int) string {
		t.Helper()
		auth := base64.StdEncoding.EncodeToString([]byte("alice:" + secret))
		r := persistentRequest(t, f.client, "GET", f.base+"/auth/basic/login/"+realm, nil, http.Header{"Authorization": {"Basic " + auth}}, status)
		token := strings.TrimPrefix(r.header.Get("Authorization"), "Bearer ")
		if status != 303 && token != "" {
			t.Fatal("denied Basic request issued a token")
		}
		return token
	}
	resource := func(token string, status int) {
		t.Helper()
		persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}}, status)
	}
	native := func(secret string) *authclient.Credentials {
		t.Helper()
		client, err := authclient.NewClient(&authclient.Config{BaseURL: f.base + "/auth", Realm: "staff", Username: "ALICE@EXAMPLE.TEST", Password: secret, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: f.client})
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.Authenticate(t.Context())
		if err != nil {
			t.Fatal("native SQLite authentication failed", err)
		}
		verify(result.AccessToken)
		if result.RefreshToken == "" || result.SessionID == "" {
			t.Fatal("missing native session credentials")
		}
		return result
	}
	initial := basic("staff", sqliteIdentityPassword, 303)
	verify(initial)
	resource(initial, 200)
	basic("staff", "incorrect-password", 401)
	basic("unknown", sqliteIdentityPassword, 400)
	login := native(sqliteIdentityPassword)
	resource(login.AccessToken, 200)
	runSQLiteIdentityBrowser(t, f.base, cert, sqliteIdentityPassword)
	refresh := &caddyTokenRefreshFixture{base: f.base, mount: "/auth", client: f.client}
	renewed, _ := refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, nil, 200)
	verify(renewed.AccessToken)
	// Form/sandbox/cookie protocol coverage complements the real Chrome journey.
	browser := f.browser(t)
	form := func(target string, values url.Values) oidcRPResponse {
		t.Helper()
		return persistentRequest(t, browser, "POST", target, values, http.Header{"Origin": {f.base}}, 303)
	}
	start := form(f.base+"/auth/login", url.Values{"username": {"ALICE@EXAMPLE.TEST"}, "realm": {"staff"}})
	sandbox := start.header.Get("Location")
	form(sandbox, url.Values{"secret": {sqliteIdentityPassword}})
	persistentRequest(t, browser, "GET", sandbox, nil, nil, 303)
	cookieURL, _ := url.Parse(f.base + "/auth/portal")
	browserToken := ""
	for _, cookie := range browser.Jar.Cookies(cookieURL) {
		if cookie.Name == "AUTHP_ACCESS_TOKEN" {
			browserToken = cookie.Value
		}
	}
	verify(browserToken)
	resource(browserToken, 200)
	// SQLite credentials never enter the local file store's profile API.
	for _, kind := range []string{"fetch_user_info", "update_user_password"} {
		body, _ := json.Marshal(map[string]string{"kind": kind, "password": "Must-not-replace-password!"})
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.base+"/auth/api/profile", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", f.base)
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("SQLite profile %s returned %d", kind, resp.StatusCode)
		}
	}
	verify(basic("staff", sqliteIdentityPassword, 303))
	// Current account data governs new credentials and refresh. Already signed
	// access JWTs retain their bounded lifetime after a password/account change.
	if _, err := management.OverwriteUserRoles("alice", "alice@example.test", []string{"unprivileged"}); err != nil {
		t.Fatal(err)
	}
	denied := basic("staff", sqliteIdentityPassword, 303)
	verify(denied)
	resource(denied, 403)
	if _, err := management.OverwriteUserRoles("alice", "alice@example.test", account.Roles); err != nil {
		t.Fatal(err)
	}
	if err := management.DisableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	basic("staff", sqliteIdentityPassword, 401)
	refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": renewed.RefreshToken}, nil, 401)
	resource(initial, 200)
	if err := management.EnableUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	replacement := "Replacement-identity-password-2026!"
	if err := management.SetPassword(t.Context(), "alice", "alice@example.test", replacement); err != nil {
		t.Fatal(err)
	}
	basic("staff", sqliteIdentityPassword, 401)
	verify(basic("staff", replacement, 303))
	beforeDelete := native(replacement)
	if err := management.DeleteUser("alice", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	basic("staff", replacement, 401)
	if _, err := management.Create(t.Context(), account, replacement); err != nil {
		t.Fatal(err)
	}
	verify(basic("staff", replacement, 303))
	refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": beforeDelete.RefreshToken}, nil, 401)
	reload := func(data []byte, success bool) []byte {
		t.Helper()
		if err := os.WriteFile(f.config, data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "reload", "--force", "--config", f.config, "--address", f.admin)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		assertAdminRedacted(t, output, []string{sqliteIdentityPassword, replacement, initial, login.RefreshToken})
		if (err == nil) != success {
			t.Fatalf("identity reload success=%v: %v", success, err)
		}
		return output
	}
	// Invalid replacement cannot dispose the serving store.
	var candidate map[string]any
	if err := json.Unmarshal(baseline, &candidate); err != nil {
		t.Fatal(err)
	}
	app := candidate["apps"].(map[string]any)["security"].(map[string]any)
	app["identity_stores"].([]any)[0].(map[string]any)["path"] = filepath.Join(dir, "missing.db")
	bad, _ := json.Marshal(candidate)
	reload(bad, false)
	verify(basic("staff", replacement, 303))
	// A fully specified OP candidate must reject this non-local realm before
	// publication, without interrupting the current password login runtime.
	if err := json.Unmarshal(baseline, &candidate); err != nil {
		t.Fatal(err)
	}
	opKey := newOIDCRPKey(t, "sqlite-rejected-op")
	portal := candidate["apps"].(map[string]any)["security"].(map[string]any)["config"].(map[string]any)["authentication_portals"].([]any)[0].(map[string]any)
	portal["oidc_provider"] = &oidc.Config{Enabled: true, Issuer: f.base + "/auth", Realms: []string{"staff"}, SigningKeyFiles: []string{opKey.private}, Clients: []*oidc.ClientConfig{{ClientID: "native", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://client.example.test/callback"}}}}
	bad, _ = json.Marshal(candidate)
	if output := reload(bad, false); !bytes.Contains(output, []byte("local identity store")) {
		t.Fatal("OP candidate did not identify the SQLite realm restriction")
	}
	verify(basic("staff", replacement, 303))
	if err := os.Chmod(cfg.Path, 0644); err != nil {
		t.Fatal(err)
	}
	basic("staff", replacement, 401)
	reload(baseline, false)
	if err := os.Chmod(cfg.Path, 0600); err != nil {
		t.Fatal(err)
	}
	verify(basic("staff", replacement, 303))
	old := native(replacement)
	begin, _ := refresh.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "staff", RefreshTransport: "body"}, nil, 200)
	reload(baseline, true)
	refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": old.RefreshToken}, nil, 401)
	refresh.post(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "staff", RefreshTransport: "body", SandboxID: begin.SandboxID, SandboxSecret: begin.SandboxSecret, ChallengeKind: "password", ChallengeResponse: replacement}, nil, 400)
	verify(basic("staff", replacement, 303))
	// Stronger policy remains authoritative for this password-only backend.
	factor := strings.Replace(source, "enable identity store accounts", "enable identity store accounts\n   transform user {\n    match realm staff\n    require totp\n   }", 1)
	strict := f.write(t, factor)
	reload(strict, true)
	basic("staff", replacement, 403)
	reload(baseline, true)
	f.restart(t)
	verify(basic("staff", replacement, 303))
	// Persist portal families across process termination: the new SQLite instance
	// still rejects old identity evidence even though its refresh family survives.
	f.kill(t)
	durableSource := strings.Replace(source, "security {", "security {\n  state {\n   directory "+fmt.Sprintf("%q", f.directory)+"\n  }", 1)
	f.write(t, durableSource)
	f.start(t)
	beforeRestart := native(replacement)
	f.restart(t)
	refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": beforeRestart.RefreshToken}, nil, 401)
	resource(beforeRestart.AccessToken, 200)
	afterRestart := native(replacement)
	renewed, _ = refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": afterRestart.RefreshToken}, nil, 200)
	verify(renewed.AccessToken)
	f.kill(t)
	log, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	assertAdminRedacted(t, log, []string{sqliteIdentityPassword, replacement, initial, login.RefreshToken})
}
