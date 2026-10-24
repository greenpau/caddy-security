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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

type sqliteRefreshOptions struct {
	mount                                       string
	capacity, rotations, access, idle, absolute int
	other                                       bool
}
type sqliteRefreshFixture struct {
	*accessSignerFixture
	options  sqliteRefreshOptions
	database string
}

type sqliteRefreshGrant struct {
	access, refresh string
	metadata        apiauth.AuthResponse
	claims          map[string]any
}

func newSQLiteRefreshFixture(t *testing.T, options sqliteRefreshOptions, cert, key string, roots *x509.CertPool) *sqliteRefreshFixture {
	t.Helper()
	if options.capacity == 0 {
		options.capacity = 8
	}
	if options.rotations == 0 {
		options.rotations = 32
	}
	if options.access == 0 {
		options.access = 45
	}
	if options.idle == 0 {
		options.idle = 120
	}
	if options.absolute == 0 {
		options.absolute = 240
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("cannot prepare private SQLite refresh directory")
	}
	f := &sqliteRefreshFixture{options: options, database: filepath.Join(dir, "refresh.sqlite")}
	var peerKey jwksKeyFiles
	if options.other {
		peerKey = newJWKSKeyFiles(t, "RSA", "peer-selected")
	}
	signerOptions := accessSignerOptions{mount: options.mount, refresh: true, maximum: 180, lifetime: 120}
	signerOptions.configure = func(input string) string {
		declaration := fmt.Sprintf("state {\ndirectory %q\n}\ntoken refresh store sqlite selected {\npath %q\nmax sessions %d\nmax rotations %d\ntimeout 2s\n}\n", filepath.Join(dir, "root-state"), f.database, options.capacity, options.rotations)
		input = strings.Replace(input, "security {", "security {\n"+declaration, 1)
		input = strings.Replace(input, "token refresh {", fmt.Sprintf("token refresh {\nstore selected\nmax sessions %d\nmax rotations %d\n", options.capacity, options.rotations), 1)
		input = strings.Replace(input, "access lifetime 600", fmt.Sprintf("access lifetime %d\nidle timeout %d\nabsolute timeout %d", options.access, options.idle, options.absolute), 1)
		if options.other {
			if options.mount == "" {
				t.Fatal("peer portal requires a bounded nested primary mount")
			}
			base := accessSignerOrigin(t, input)
			// Each renewable portal pins its own origin+mount issuer. Sharing the
			// durable refresh backend does not share access-token authority.
			peerSigner := fmt.Sprintf("access signer rsapss peer_selected {\nkey file %q\nkey id peer-selected\nalgorithm PS256\nissuer %s/peer\naudience %s\nmax lifetime 180s\n}\n", peerKey.private, base, accessSignerAudience)
			input = strings.Replace(input, "security {", "security {\n"+peerSigner, 1)
			peer := fmt.Sprintf(`authentication portal peer {
 enable identity store localdb
 access signer peer_selected
 access token profile {
  issuer %s/peer
  audience %s
  key ids peer-selected
  max lifetime 180
 }
 %s
 crypto default token lifetime 120
 cookie prefix PEER
 cookie path /
 transform user {
  match any
  action overwrite aud %s
 }
 token refresh {
  store selected
  realms local
  public origin %s
  base path /peer
  body transport enabled
  access lifetime %d
  idle timeout %d
  absolute timeout %d
  max sessions %d
  max rotations %d
 }
}
`, base, accessSignerAudience, peerKey.verifier("peer-selected"), accessSignerAudience, base, options.access, options.idle, options.absolute, options.capacity, options.rotations)
			peerPolicy := fmt.Sprintf("authorization policy peer_policy {\naccess token profile {\nissuer %s/peer\naudience %s\nkey ids peer-selected\nmax lifetime 180\n}\n%s\nvalidate bearer header\nset auth url %s/peer/login\nallow roles authp/user\n}\n", base, accessSignerAudience, peerKey.verifier("peer-selected"), base)
			input = strings.Replace(input, "authentication portal myportal {", peer+peerPolicy+"authentication portal myportal {", 1)
			input = strings.Replace(input, " route {", " route {\n  route /peer-resource {\n   authorize with peer_policy\n   respond \"peer identity resource\"\n  }\n  route /peer/* {\n   authenticate with peer at /peer\n  }", 1)
		}
		return input
	}
	f.accessSignerFixture = newAccessSignerFixture(t, signerOptions, cert, key, roots)
	if options.other {
		private, err := os.ReadFile(peerKey.private)
		if err != nil {
			t.Fatal("cannot inventory peer private signing key")
		}
		f.secrets = append(f.secrets, string(private))
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error("cannot drain selected SQLite runtime")
		}
		sqliteRefreshScanClosed(t, f.database, f.secrets)
	})
	return f
}

// This transport helper returns errors to its caller so concurrent workers never
// call Fatal or mutate a shared secret inventory. Every request uses real TLS.
func sqliteRefreshWire(ctx context.Context, client *http.Client, method, target string, body any, headers http.Header, host string) (oidcRPResponse, error) {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return oidcRPResponse{}, fmt.Errorf("encode refresh fixture request")
		}
		input = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, input)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("construct refresh fixture request")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
	}
	maps.Copy(request.Header, headers)
	if host != "" {
		request.Host = host
	}
	response, err := client.Do(request)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("verified refresh TLS request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return oidcRPResponse{}, fmt.Errorf("refresh response lacks bounded verified TLS")
	}
	return oidcRPResponse{status: response.StatusCode, header: response.Header.Clone(), body: data}, nil
}
func sqliteRefreshRequest(t *testing.T, f *localIdentityFixture, client *http.Client, target string, body any, headers http.Header, status int) oidcRPResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.issuer + target
	}
	response, err := sqliteRefreshWire(t.Context(), client, "POST", target, body, headers, "")
	if err != nil {
		t.Fatal(err)
	}
	accessSignerCapture(f, response)
	response.requireStatus(t, status)
	response.noStore(t)
	if status != 200 {
		localIdentityRejectedAuth(t, response, status)
		providerDestinationNoIssuance(t, response)
	}
	return response
}
func sqliteRefreshLogin(t *testing.T, f *localIdentityFixture, client *http.Client, user, transport string, status int) (apiauth.AuthResponse, oidcRPResponse) {
	t.Helper()
	request := apiauth.AuthRequest{Username: user, Realm: "local", RefreshTransport: transport}
	first := f.json(t, client, "/login", request, "")
	accessSignerCapture(f, first)
	proof := localIdentityAuth(t, first)
	if proof.Authenticated || proof.NextChallenge != "password" || proof.SandboxID == "" || proof.SandboxSecret == "" {
		t.Fatal("selected store login bypassed its real password challenge")
	}
	request.SandboxID, request.SandboxSecret = proof.SandboxID, proof.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "password", lifecyclePassword
	if user == "bob" {
		request.ChallengeResponse = localIdentityBobPassword
	}
	response := f.json(t, client, "/login", request, "")
	accessSignerCapture(f, response)
	if status != 200 {
		return localIdentityRejectedAuth(t, response, status), response
	}
	return localIdentityAuth(t, response), response
}
func (f *sqliteRefreshFixture) grant(t *testing.T, response oidcRPResponse, cookie bool) sqliteRefreshGrant {
	t.Helper()
	accessSignerCapture(f.localIdentityFixture, response)
	metadata := localIdentityAuth(t, response)
	result := sqliteRefreshGrant{metadata: metadata, access: metadata.AccessToken, refresh: metadata.RefreshToken}
	if cookie {
		if metadata.AccessToken != "" || metadata.RefreshToken != "" {
			t.Fatal("cookie transport exposed credentials in JSON")
		}
		access := tokenRefreshActiveCookie(t, (&http.Response{Header: response.header}).Cookies(), f.cookie)
		refresh := tokenRefreshActiveCookie(t, (&http.Response{Header: response.header}).Cookies(), "AUTHP_REFRESH_TOKEN")
		if !access.Secure || !access.HttpOnly || !refresh.Secure || !refresh.HttpOnly || access.Domain != "" || refresh.Domain != "" {
			t.Fatal("selected refresh weakened cookie privacy")
		}
		result.access, result.refresh = access.Value, refresh.Value
	} else if len(response.header.Values("Set-Cookie")) != 0 {
		t.Fatal("native selected refresh issued browser cookies")
	}
	result.claims = f.verify(t, result.access)
	if !metadata.Authenticated || result.refresh == "" || metadata.SessionID == "" || result.claims["sid"] != metadata.SessionID || accessSignerNumber(t, result.claims, "exp") != metadata.AccessExpiresAt || metadata.RefreshExpiresAt > metadata.SessionExpiresAt || metadata.AccessExpiresAt > metadata.SessionExpiresAt {
		t.Fatal("selected store renewal metadata disagrees with signed authority")
	}
	iat := accessSignerNumber(t, result.claims, "iat")
	if metadata.AccessExpiresAt != min(iat+int64(f.options.access), metadata.SessionExpiresAt) {
		t.Fatal("selected SQLite grant ignored its configured access lifetime")
	}
	if !cookie && (metadata.AccessTokenName != f.cookie || metadata.RefreshTokenName != "AUTHP_REFRESH_TOKEN") {
		t.Fatal("native selected refresh changed its wire credential names")
	}
	f.assertResource(t, result.access)
	return result
}
func (f *sqliteRefreshFixture) body(t *testing.T, token string, status int) oidcRPResponse {
	t.Helper()
	return sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", map[string]string{"refresh_token": token}, nil, status)
}
func (f *sqliteRefreshFixture) cookieHeaders(refresh, sid string) http.Header {
	headers := http.Header{"Origin": {f.base}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"}}
	if refresh != "" {
		headers.Set("Cookie", "AUTHP_REFRESH_TOKEN="+refresh)
	}
	if sid != "" {
		headers.Set("X-Authcrunch-Refresh-Session", sid)
	}
	return headers
}
func sqliteRefreshSameFamily(t *testing.T, before, after sqliteRefreshGrant) {
	t.Helper()
	if before.refresh == after.refresh || before.access == after.access || before.metadata.SessionID != after.metadata.SessionID || before.metadata.SessionExpiresAt != after.metadata.SessionExpiresAt || before.claims["id"] != after.claims["id"] || before.claims["auth_time"] != after.claims["auth_time"] || before.claims["jti"] == after.claims["jti"] {
		t.Fatal("selected SQLite rotation changed identity/family or reused authority")
	}
}
func sqliteRefreshLogout(t *testing.T, f *localIdentityFixture, token string) {
	t.Helper()
	response := sqliteRefreshRequest(t, f, f.plain, "/api/logout", map[string]string{"refresh_token": token}, nil, 200)
	var result map[string]any
	if json.Unmarshal(response.body, &result) != nil || result["logged_out"] != true {
		t.Fatal("selected SQLite logout was not acknowledged")
	}
	providerDestinationNoIssuance(t, response)
}
func sqliteRefreshScanClosed(t *testing.T, path string, secrets []string) {
	t.Helper()
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		info, err := os.Lstat(path + suffix)
		if os.IsNotExist(err) && suffix != "" {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 32<<20 {
			t.Error("closed SQLite refresh evidence is missing, oversized or not private")
			continue
		}
		data, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Error("cannot read closed SQLite refresh evidence")
			continue
		}
		assertAdminRedacted(t, data, secrets)
	}
}

func TestCaddySQLiteRefreshE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private SQLite refresh backend requires POSIX ownership")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddySQLiteRefreshProcess$", "-test.v", "-test.timeout=220s")
	child.Env = append(os.Environ(), "CADDY_SQLITE_REFRESH_CHILD=1", "XDG_CONFIG_HOME="+t.TempDir(), "XDG_DATA_HOME="+t.TempDir())
	collectSubprocessCoverage(t, child)
	child.WaitDelay = 5 * time.Second
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("selected SQLite refresh through Caddy: %v\n%s", err, output)
	}
}
func TestCaddySQLiteRefreshProcess(t *testing.T) {
	if os.Getenv("CADDY_SQLITE_REFRESH_CHILD") != "1" {
		t.Skip("isolated Caddy helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	t.Run("oauth_snapshot_connected_identity", func(t *testing.T) {
		testSQLiteRefreshProvider(t, cert, key, roots)
	})
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run("transports"+strings.ReplaceAll(mount, "/", "_"), func(t *testing.T) {
			f := newSQLiteRefreshFixture(t, sqliteRefreshOptions{mount: mount}, cert, key, roots)
			untrusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}, Timeout: 3 * time.Second}
			defer untrusted.CloseIdleConnections()
			if response, err := untrusted.Get(f.issuer + adminJWKSPath); err == nil {
				response.Body.Close()
				t.Fatal("selected store fixture accepted untrusted TLS")
			}
			_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			native := f.grant(t, raw, false)
			next := f.grant(t, f.body(t, native.refresh, 200), false)
			sqliteRefreshSameFamily(t, native, next)
			f.body(t, native.refresh, 401)
			f.body(t, next.refresh, 401)
			browser := accessSignerBrowser(t, f.plain)
			_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, browser, "alice", "", 200)
			first := f.grant(t, raw, true)
			// Transport/origin/SID mistakes must not consume the correct family's proof.
			f.body(t, first.refresh, 401)
			for _, headers := range []http.Header{
				{"Origin": {"https://attacker.invalid"}, "X-Authcrunch-Refresh": {"1"}, "Cookie": {"AUTHP_REFRESH_TOKEN=" + first.refresh}},
				{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}, "Sec-Fetch-Site": {"cross-site"}, "Cookie": {"AUTHP_REFRESH_TOKEN=" + first.refresh}},
			} {
				sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", struct{}{}, headers, 403)
			}
			sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", struct{}{}, f.cookieHeaders(first.refresh, "wrong-family"), 401)
			response, err := sqliteRefreshWire(t.Context(), f.plain, "POST", f.issuer+"/api/refresh_token", struct{}{}, f.cookieHeaders(first.refresh, first.metadata.SessionID), "attacker.invalid")
			if err != nil {
				t.Fatal(err)
			}
			accessSignerCapture(f.localIdentityFixture, response)
			// The site Host matcher excludes this request before portal dispatch.
			// Caddy ends an unmatched server route with its empty default response.
			response.requireStatus(t, 200)
			if len(response.body) != 0 {
				t.Fatal("wrong Host reached a response-producing route")
			}
			providerDestinationNoIssuance(t, response)
			if response.header.Get("Location") != "" {
				t.Fatal("wrong Host redirected outside the pinned portal")
			}
			rotated := f.grant(t, sqliteRefreshRequest(t, f.localIdentityFixture, browser, "/api/refresh_token", struct{}{}, f.cookieHeaders("", first.metadata.SessionID), 200), true)
			sqliteRefreshSameFamily(t, first, rotated)
			sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", struct{}{}, f.cookieHeaders(first.refresh, ""), 401)
			sqliteRefreshRequest(t, f.localIdentityFixture, browser, "/api/refresh_token", struct{}{}, f.cookieHeaders("", ""), 401)
			_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			fresh := f.grant(t, raw, false)
			sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", struct{}{}, f.cookieHeaders(fresh.refresh, ""), 401)
			freshNext := f.grant(t, f.body(t, fresh.refresh, 200), false)
			sqliteRefreshLogout(t, f.localIdentityFixture, fresh.refresh) // Spent logout retires its descendant.
			f.body(t, freshNext.refresh, 401)
			_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			current := f.grant(t, raw, false)
			sqliteRefreshLogout(t, f.localIdentityFixture, current.refresh)
			f.body(t, current.refresh, 401)
		})
	}
	t.Run("concurrent_rotation", func(t *testing.T) {
		f := newSQLiteRefreshFixture(t, sqliteRefreshOptions{mount: "/tenant/auth"}, cert, key, roots)
		_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
		first := f.grant(t, raw, false)
		type outcome struct {
			response oidcRPResponse
			err      error
		}
		start := make(chan struct{})
		results := make(chan outcome, 2)
		for range 2 {
			go func() {
				<-start
				response, err := sqliteRefreshWire(t.Context(), f.plain, "POST", f.issuer+"/api/refresh_token", map[string]string{"refresh_token": first.refresh}, nil, "")
				results <- outcome{response, err}
			}()
		}
		close(start)
		completed := []outcome{<-results, <-results} // Join both requests before any assertion exits.
		winners := 0
		var winner sqliteRefreshGrant
		for _, result := range completed {
			if result.err != nil {
				t.Fatal(result.err)
			}
			accessSignerCapture(f.localIdentityFixture, result.response)
			switch result.response.status {
			case 200:
				winners++
				winner = f.grant(t, result.response, false)
			case 401:
				localIdentityRejectedAuth(t, result.response, 401)
			default:
				t.Fatalf("same-handle concurrent refresh returned HTTP %d", result.response.status)
			}
		}
		if winners != 1 {
			t.Fatal("same-handle rotation did not admit exactly one result")
		}
		f.body(t, winner.refresh, 401) // The losing matching replay revokes the winner's family.
		_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
		f.grant(t, f.body(t, f.grant(t, raw, false).refresh, 200), false)
	})
	t.Run("capacity_replacement_and_rotation_limit", func(t *testing.T) {
		f := newSQLiteRefreshFixture(t, sqliteRefreshOptions{mount: "/tenant/auth", capacity: 1, rotations: 2}, cert, key, roots)
		browser := accessSignerBrowser(t, f.plain)
		_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, browser, "alice", "", 200)
		first := f.grant(t, raw, true)
		sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "bob", "body", 503)
		_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, browser, "bob", "", 200)
		fresh := f.grant(t, raw, true)
		if fresh.metadata.SessionID == first.metadata.SessionID || fresh.claims["sub"] != "bob" {
			t.Fatal("capacity-one replacement did not use fresh identity proof")
		}
		sqliteRefreshRequest(t, f.localIdentityFixture, f.plain, "/api/refresh_token", struct{}{}, f.cookieHeaders(first.refresh, ""), 401)
		for range 2 {
			fresh = f.grant(t, sqliteRefreshRequest(t, f.localIdentityFixture, browser, "/api/refresh_token", struct{}{}, f.cookieHeaders("", ""), 200), true)
		}
		sqliteRefreshRequest(t, f.localIdentityFixture, browser, "/api/refresh_token", struct{}{}, f.cookieHeaders("", ""), 401)
		_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
		f.grant(t, raw, false)
	})
	for _, kind := range []string{"roles", "disable", "factor"} {
		t.Run("current_"+kind, func(t *testing.T) {
			f := newSQLiteRefreshFixture(t, sqliteRefreshOptions{mount: "/tenant/auth"}, cert, key, roots)
			admin, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "admin", "body", false)
			_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			first := f.grant(t, raw, false)
			switch kind {
			case "roles":
				f.admin(t, admin.AccessToken, "overwrite_roles", map[string]any{"roles": []string{"authp/user", "current/role"}})
			case "disable":
				f.admin(t, admin.AccessToken, "disable", nil)
			case "factor":
				f.admin(t, admin.AccessToken, "overwrite_auth_challenges", map[string]any{"challenges": []string{"password totp"}})
			}
			f.body(t, first.refresh, 401)
			// These remain stateless access grants until their signed deadlines.
			f.assertResource(t, first.access)
			switch kind {
			case "disable":
				f.rejectNativeLogin(t, lifecyclePassword, false)
				f.admin(t, admin.AccessToken, "enable", nil)
			case "factor":
				// Alice has no enrolled TOTP. Identification rejects the unavailable
				// required method before issuing even a password sandbox.
				response := f.json(t, f.plain, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", RefreshTransport: "body"}, "")
				accessSignerCapture(f.localIdentityFixture, response)
				localIdentityRejectedAuth(t, response, http.StatusBadRequest)
				providerDestinationNoIssuance(t, response)
				f.admin(t, admin.AccessToken, "overwrite_auth_challenges", map[string]any{"challenges": []string{"password"}})
			}
			_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			fresh := f.grant(t, raw, false)
			if fresh.claims["id"] != first.claims["id"] || fresh.metadata.SessionID == first.metadata.SessionID {
				t.Fatal("current-identity recovery changed UUID or reused retired family")
			}
			if kind == "roles" {
				roles, ok := fresh.claims["roles"].([]any)
				if !ok || !slices.Contains(roles, any("current/role")) {
					t.Fatal("fresh selected grant omitted current local roles")
				}
			}
			f.body(t, first.refresh, 401)
			f.grant(t, f.body(t, fresh.refresh, 200), false)
		})
	}
	t.Run("shared_handle_portal_binding_and_file_capacity", func(t *testing.T) {
		f := newSQLiteRefreshFixture(t, sqliteRefreshOptions{mount: "/tenant/auth", capacity: 2, other: true}, cert, key, roots)
		_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
		first := f.grant(t, raw, false)
		peer := &localIdentityFixture{oidcRPFixture: &oidcRPFixture{client: f.plain, base: f.base, mount: "/peer", issuer: f.base + "/peer"}, plain: f.plain}
		t.Cleanup(func() { f.secrets = append(f.secrets, peer.secrets...) })
		second, peerRaw := sqliteRefreshLogin(t, peer, f.plain, "bob", "body", 200)
		accessSignerCapture(f.localIdentityFixture, peerRaw)
		discovery, err := sqliteRefreshWire(t.Context(), f.plain, "GET", peer.issuer+adminJWKSPath, nil, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		discovery.requireStatus(t, 200)
		discovery.noStore(t)
		var peerKeys struct {
			Keys []map[string]string `json:"keys"`
		}
		if json.Unmarshal(discovery.body, &peerKeys) != nil || len(peerKeys.Keys) != 1 {
			t.Fatal("peer portal did not publish its exact selected verification key")
		}
		verifyPeer := func(token string) map[string]any {
			t.Helper()
			f.secrets = append(f.secrets, token)
			claims := accessSignerVerify(t, token, peer.issuer, accessSignerAudience, "peer-selected", 180, peerKeys.Keys)
			status, _, body := registrationHTTP(t, f.plain, "GET", f.base+"/peer-resource", nil, http.Header{"Authorization": {"Bearer " + token}})
			if status != 200 || string(body) != "peer identity resource" {
				t.Fatal("peer selected grant did not authorize its own protected resource")
			}
			return claims
		}
		peerClaims := verifyPeer(second.AccessToken)
		if second.SessionID == "" || second.SessionID == first.metadata.SessionID || peerClaims["sid"] != second.SessionID {
			t.Fatal("peer portal omitted its own renewable family")
		}
		sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 503)
		sqliteRefreshRequest(t, peer, f.plain, "/api/refresh_token", map[string]string{"refresh_token": first.refresh}, nil, 401)
		f.body(t, second.RefreshToken, 401)
		next := f.grant(t, f.body(t, first.refresh, 200), false)
		peerRaw = sqliteRefreshRequest(t, peer, f.plain, "/api/refresh_token", map[string]string{"refresh_token": second.RefreshToken}, nil, 200)
		oldPeer := second
		second = localIdentityAuth(t, peerRaw)
		if second.SessionID != oldPeer.SessionID || second.RefreshToken == oldPeer.RefreshToken {
			t.Fatal("peer portal rotation changed family ownership")
		}
		verifyPeer(second.AccessToken)
		sqliteRefreshLogout(t, peer, second.RefreshToken)
		_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "bob", "body", 200)
		f.grant(t, raw, false)
		f.grant(t, f.body(t, next.refresh, 200), false)
	})
	for _, kind := range []string{"idle", "absolute"} {
		t.Run(kind+"_deadline", func(t *testing.T) {
			options := sqliteRefreshOptions{mount: "/tenant/auth", capacity: 1, access: 2, idle: 2, absolute: 7}
			if kind == "absolute" {
				options.idle = 4
				options.absolute = 6
			}
			f := newSQLiteRefreshFixture(t, options, cert, key, roots)
			_, raw := sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			first := f.grant(t, raw, false)
			deadline := first.metadata.RefreshExpiresAt
			if kind == "absolute" {
				accessSignerWait(t, time.Unix(first.metadata.AccessExpiresAt, 0).Add(50*time.Millisecond))
				next := f.grant(t, f.body(t, first.refresh, 200), false)
				sqliteRefreshSameFamily(t, first, next)
				first = next
				deadline = first.metadata.SessionExpiresAt
			}
			accessSignerWait(t, time.Unix(deadline, 0).Add(100*time.Millisecond))
			f.body(t, first.refresh, 401)
			_, raw = sqliteRefreshLogin(t, f.localIdentityFixture, f.plain, "alice", "body", 200)
			f.grant(t, raw, false)
		})
	}
}
