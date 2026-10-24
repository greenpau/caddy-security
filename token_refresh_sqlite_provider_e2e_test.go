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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/go-cmp/cmp"
)

type sqliteRefreshProviderGrant struct {
	access, refresh string
	claims          map[string]any
}

// The fixture follows the real issuer redirect/code exchange and signed claims,
// then the actual connected-account forms. Only the storage/signer selection is
// overlaid; no provider response, account link or browser credential is invented.
func testSQLiteRefreshProvider(t *testing.T, cert, tlsKey string, roots *x509.CertPool) {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(cert, tlsKey)
	if err != nil {
		t.Fatal("cannot load provider refresh fixture TLS key")
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal("cannot initialize provider TLS roots")
	}
	previousRoots := oauthE2ESystemRoots
	oauthE2ESystemRoots = roots
	t.Cleanup(func() { oauthE2ESystemRoots = previousRoots })
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("cannot prepare private provider refresh directory")
	}
	storePath := filepath.Join(dir, "provider-refresh.sqlite")
	key := newJWKSKeyFiles(t, "RSA", "selected-provider")
	options := accessSignerOptions{mount: "/tenant/auth", maximum: 180, lifetime: 90}
	options.configure = func(input string) string {
		declarations := fmt.Sprintf("state {\ndirectory %q\n}\ntoken refresh store sqlite selected {\npath %q\nmax sessions 8\nmax rotations 32\ntimeout 2s\n}\n", filepath.Join(dir, "root-state"), storePath)
		input = strings.Replace(input, "security {", "security {\n"+declarations, 1)
		// The connected fixture already declares max sessions 8 for these realms.
		input = strings.Replace(input, "token refresh {", "token refresh {\nstore selected\nmax rotations 32\n", 1)
		input = strings.Replace(input, "access lifetime 600", "access lifetime 90\nidle timeout 180\nabsolute timeout 300", 1)
		return strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\ntransform user {\nmatch realm upstream\nadd captured_provider_name {claims.name} as string\nadd current_request_issuer {claims.iss} as string\n}\n", 1)
	}
	f := newCaddyConnectedAccountsFixture(t, connectedAccountsOptions{mount: options.mount, providerRefresh: true, configure: func(input string) string {
		return accessSignerConfigure(t, options, key, "selected", input)
	}}, cert, tlsKey, roots, pair)
	private, err := os.ReadFile(key.private)
	if err != nil {
		t.Fatal("cannot inventory provider private signer")
	}
	f.secrets = append(f.secrets, string(private))
	accessSignerCaptureCookies(f.localIdentityFixture)
	captureIssuer := func() {
		for _, issuer := range []*oauthE2EUpstream{f.upstream, f.secondUpstream} {
			issuer.mu.Lock()
			f.secrets = append(f.secrets, issuer.issuedSecrets...)
			issuer.mu.Unlock()
		}
	}
	t.Cleanup(func() {
		if caddy.Stop() != nil {
			t.Error("cannot drain selected provider refresh runtime")
		}
		captureIssuer()
		sqliteRefreshScanClosed(t, storePath, f.secrets)
	})
	counts := func() [2]int {
		f.upstream.mu.Lock()
		defer f.upstream.mu.Unlock()
		return [2]int{f.upstream.exchanges, f.upstream.userInfos}
	}
	verify := func(token string) map[string]any {
		t.Helper()
		f.secrets = append(f.secrets, token)
		return accessSignerVerify(t, token, f.issuer, accessSignerAudience, "selected", 180, f.keys)
	}
	grant := func(response oidcRPResponse) sqliteRefreshProviderGrant {
		t.Helper()
		accessSignerCapture(f.localIdentityFixture, response)
		access := tokenRefreshActiveCookie(t, (&http.Response{Header: response.header}).Cookies(), "AUTHP_ACCESS_TOKEN")
		refresh := tokenRefreshActiveCookie(t, (&http.Response{Header: response.header}).Cookies(), "AUTHP_REFRESH_TOKEN")
		if !access.Secure || !access.HttpOnly || !refresh.Secure || !refresh.HttpOnly || access.Domain != "" || refresh.Domain != "" || refresh.Path != f.mount {
			t.Fatal("selected provider refresh weakened its browser cookie contract")
		}
		claims := verify(access.Value)
		f.assertResource(t, access.Value)
		sid, validSID := claims["sid"].(string)
		id, validID := claims["id"].(string)
		if !validSID || sid == "" || !validID || id == "" || claims["sub"] != f.upstream.fixedSubject || claims["origin"] != "upstream" || !cmp.Equal(claims["amr"], []any{"federated"}) {
			t.Fatal("selected provider grant lost its genuine federated proof")
		}
		proofTime := accessSignerNumber(t, claims, "auth_time")
		if proofTime <= 0 || proofTime > accessSignerNumber(t, claims, "iat") {
			t.Fatal("selected provider grant supplied an invalid proof time")
		}
		if response.status == 200 {
			metadata := localIdentityAuth(t, response)
			if !metadata.Authenticated || metadata.AccessToken != "" || metadata.RefreshToken != "" || metadata.SessionID != claims["sid"] || metadata.AccessExpiresAt != accessSignerNumber(t, claims, "exp") {
				t.Fatal("selected provider renewal metadata disagrees with signed authority")
			}
		}
		return sqliteRefreshProviderGrant{access.Value, refresh.Value, claims}
	}
	client := f.browser(t)
	renew := func(status int) oidcRPResponse {
		t.Helper()
		before := counts()
		response := f.send(t, client, "POST", "/api/refresh_token", strings.NewReader(`{}`), http.Header{"Content-Type": {"application/json"}, "Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}})
		response.requireStatus(t, status)
		response.noStore(t)
		if counts() != before {
			t.Fatal("selected provider renewal contacted token or UserInfo endpoints")
		}
		if status != 200 {
			localIdentityRejectedAuth(t, response, status)
			providerDestinationNoIssuance(t, response)
		}
		return response
	}
	same := func(before, after sqliteRefreshProviderGrant) {
		t.Helper()
		for _, field := range []string{"id", "sub", "sid", "auth_time", "amr"} {
			if before.claims[field] == nil || !cmp.Equal(before.claims[field], after.claims[field]) {
				t.Fatalf("selected provider renewal changed signed %s", field)
			}
		}
		if before.access == after.access || before.refresh == after.refresh || before.claims["jti"] == after.claims["jti"] {
			t.Fatal("selected provider renewal reused a credential")
		}
	}
	started := time.Now().Unix()
	initial := grant(f.login(t, client, "upstream", 303))
	alice := localIdentityRecord(t, f.database, "alice")
	if alice == nil {
		t.Fatal("ordinary local connection target is missing")
	}
	if initial.claims["id"] == alice.ID || initial.claims["id"] == initial.claims["sub"] || accessSignerNumber(t, initial.claims, "auth_time") < started {
		t.Fatal("provider display email matched an ordinary local identity or supplied proof time")
	}
	f.upstream.mu.Lock()
	f.upstream.deactivated = true
	if f.upstream.identityClaims == nil {
		f.upstream.identityClaims = make(map[string]any)
	}
	// The top-level name is ID-token authority. UserInfo profile fields stay
	// nested; changing those alone must not overwrite the signed name.
	f.upstream.identityClaims["name"] = "Changed provider display name"
	f.upstream.userInfoClaims["name"] = "Changed provider display name"
	f.upstream.userInfoClaims["roles"] = []string{"changed/provider"}
	f.upstream.mu.Unlock()
	rotated := grant(renew(200))
	same(initial, rotated)
	rotatedRoles, validRoles := rotated.claims["roles"].([]any)
	if !validRoles || slices.Contains(rotatedRoles, any("changed/provider")) {
		t.Fatal("selected renewal adopted provider roles changed after captured proof")
	}
	if rotated.claims["captured_provider_name"] != initial.claims["captured_provider_name"] || rotated.claims["current_request_issuer"] != f.issuer+"/api/refresh_token" || rotated.claims["current_request_issuer"] == initial.claims["current_request_issuer"] {
		t.Fatal("selected provider renewal replaced its snapshot or skipped current request transforms")
	}
	f.upstream.mu.Lock()
	f.upstream.deactivated = false
	f.upstream.mu.Unlock()
	changed := grant(f.login(t, client, "upstream", 303))
	changedRoles, validRoles := changed.claims["roles"].([]any)
	if !validRoles || !slices.Contains(changedRoles, any("changed/provider")) {
		t.Fatal("fresh provider proof omitted current upstream roles")
	}
	if changed.claims["id"] != initial.claims["id"] {
		t.Fatal("fresh provider callback changed its durable identity")
	}
	if changed.claims["sid"] == initial.claims["sid"] {
		t.Fatal("fresh provider callback reused its original family")
	}
	if changed.claims["captured_provider_name"] != "Changed provider display name" {
		t.Fatal("fresh provider callback missed current upstream display name")
	}
	// Establish the real local link using fresh native HTML proof and confirmation.
	operation := connectedAccountsBegin(t, f.localIdentityFixture, client)
	sandbox := connectedAccountsStartLocal(t, f.localIdentityFixture, client, operation.loginURL, "alice")
	finish := connectedAccountsFinishLocal(t, f.localIdentityFixture, client, sandbox, "alice")
	if finish.header.Get("Location") != operation.endpoint {
		t.Fatal("selected local proof lost its connection operation")
	}
	localClaims := verify(connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
	if localClaims["id"] != alice.ID {
		t.Fatal("connection did not authenticate the ordinary local account")
	}
	review := connectedAccountsOperationForm(t, f.localIdentityFixture, connectedAccountsSend(t, f.localIdentityFixture, client, "GET", operation.endpoint, nil, nil))
	if review.endpoint != operation.endpoint || review.csrf != operation.csrf {
		t.Fatal("selected connection review changed operation")
	}
	connectedAccountsPage(t, connectedAccountsForm(t, f.localIdentityFixture, client, review.endpoint, url.Values{"csrf": {review.csrf}, "action": {"connect"}}))
	linked := grant(f.login(t, client, "upstream", 303))
	if linked.claims["id"] != alice.ID || linked.claims["id"] == initial.claims["id"] {
		t.Fatal("selected provider grant did not adopt its explicitly connected local identity")
	}
	f.upstream.mu.Lock()
	f.upstream.deactivated = true
	f.upstream.mu.Unlock()
	beforeRestart := counts()
	if caddy.Stop() != nil {
		t.Fatal("cannot drain selected provider store before replacement")
	}
	captureIssuer()
	// This is bounded read-only evidence after every handle has closed, with no
	// schema dependency or live SQLite file descriptor. It proves this actual
	// provider family was persisted in the selected file, not a memory fallback.
	info, err := os.Lstat(storePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 32<<20 {
		t.Fatal("selected provider refresh file lacks private bounded evidence")
	}
	data, err := os.ReadFile(storePath)
	if err != nil || !bytes.Contains(data, []byte(linked.claims["sid"].(string))) || !bytes.Contains(data, []byte(f.upstream.fixedSubject)) {
		t.Fatal("selected SQLite file did not persist the genuine provider family")
	}
	sqliteRefreshScanClosed(t, storePath, f.secrets)
	f.localIdentityFixture.load(t)
	f.request(t, "GET", adminJWKSPath, nil, nil).requireStatus(t, 200)
	continued := grant(renew(200))
	same(linked, continued)
	if counts() != beforeRestart {
		t.Fatal("root replacement re-authenticated captured provider proof")
	}
	// Actual admin API mutation invalidates linked evidence, without consulting
	// the unavailable provider or immediately revoking the existing access JWT.
	admin, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "admin", "body", false)
	verify(admin.AccessToken)
	f.admin(t, admin.AccessToken, "overwrite_roles", map[string]any{"roles": []string{"authp/user", "sqlite/current"}})
	renew(401)
	f.assertResource(t, continued.access)
	f.upstream.mu.Lock()
	f.upstream.deactivated = false
	f.upstream.mu.Unlock()
	fresh := grant(f.login(t, client, "upstream", 303))
	roles, ok := fresh.claims["roles"].([]any)
	if !ok || !slices.Contains(roles, any("sqlite/current")) || fresh.claims["id"] != alice.ID || fresh.claims["sid"] == continued.claims["sid"] {
		t.Fatal("fresh provider proof missed current connected local policy")
	}
	same(fresh, grant(renew(200)))
}
