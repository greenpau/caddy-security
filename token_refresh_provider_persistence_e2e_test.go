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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

const persistentProviderSubject = "persistent-provider-subject"

// This case shares the real Caddy command build with the runtime-state suite.
// Every restart replaces the OS process, including the provider and attachment.
func testPersistentProviderSnapshot(t *testing.T, binary string) {
	t.Run("file_attachment", func(t *testing.T) {
		f := newPersistentProviderFixture(t, binary, true)
		first := f.login(t)
		f.upstream.mu.Lock()
		f.upstream.deactivated = true
		f.upstream.mu.Unlock()
		f.restart(t)
		next := f.refresh(t, first.refresh, http.StatusOK)
		for _, name := range []string{"id", "sub", "sid", "auth_time", "amr"} {
			if fmt.Sprint(first.claims[name]) != fmt.Sprint(next.claims[name]) {
				t.Fatalf("fresh-process renewal changed %s", name)
			}
		}
		if first.refresh == next.refresh || first.access == next.access || first.claims["jti"] == next.claims["jti"] {
			t.Fatal("fresh-process renewal did not rotate credentials")
		}
		f.authorize(t, next.access)

		// The spent credential remains spent after a process replacement. Its
		// replay revokes the descendant, and that revocation also survives.
		f.restart(t)
		f.refresh(t, first.refresh, http.StatusUnauthorized)
		f.restart(t)
		f.refresh(t, next.refresh, http.StatusUnauthorized)
		f.upstream.mu.Lock()
		f.upstream.deactivated = false
		f.upstream.mu.Unlock()

		loggedOut := f.login(t)
		if loggedOut.claims["id"] != first.claims["id"] || loggedOut.claims["sid"] == first.claims["sid"] {
			t.Fatal("fresh login did not retain the stored identity with a new family")
		}
		f.logout(t, loggedOut.refresh)
		f.restart(t)
		f.refresh(t, loggedOut.refresh, http.StatusUnauthorized)

		// Rotate actual provider client credentials, then prove the changed
		// configuration can authenticate. This reaches a valid root epoch change,
		// not an invalid-provider startup or failed discovery shortcut.
		oldTrust := f.login(t)
		const replacementSecret = "synthetic-replacement-provider-client-secret"
		f.secrets = append(f.secrets, replacementSecret)
		f.kill(t)
		f.upstream.mu.Lock()
		f.upstream.clientSecret = replacementSecret
		f.upstream.mu.Unlock()
		changed := strings.Replace(f.input, "client_secret "+oauthE2ESecret, "client_secret "+replacementSecret, 1)
		if changed == f.input {
			t.Fatal("fixture did not change provider trust configuration")
		}
		f.write(t, changed)
		f.start(t)
		f.refresh(t, oldTrust.refresh, http.StatusUnauthorized)
		changedTrust := f.login(t)
		changedTrust = f.refresh(t, changedTrust.refresh, http.StatusOK)
		f.kill(t)
		f.upstream.mu.Lock()
		f.upstream.clientSecret = oauthE2ESecret
		f.upstream.mu.Unlock()
		f.write(t, f.input)
		f.start(t)
		f.refresh(t, oldTrust.refresh, http.StatusUnauthorized)
		f.refresh(t, changedTrust.refresh, http.StatusUnauthorized)
		restored := f.login(t)
		if restored.claims["id"] != first.claims["id"] {
			t.Fatal("configuration retirement replaced the durable attached UUID")
		}
		f.refresh(t, restored.refresh, http.StatusOK)
	})
	t.Run("implicit_attachment_is_volatile", func(t *testing.T) {
		f := newPersistentProviderFixture(t, binary, false)
		first := f.login(t)
		current := f.refresh(t, first.refresh, http.StatusOK)
		f.restart(t)
		// Root refresh storage is still persistent. The missing authority is the
		// provider's old private identity, which was never file-backed.
		f.refresh(t, current.refresh, http.StatusUnauthorized)
		fresh := f.login(t)
		if fresh.claims["id"] == first.claims["id"] || fresh.claims["sid"] == first.claims["sid"] {
			t.Fatal("fresh provider reused private identity or old family authority")
		}
		f.refresh(t, fresh.refresh, http.StatusOK)
	})
}

type persistentProviderTokens struct {
	access, refresh string
	claims          jwt.MapClaims
}

type persistentProviderFixture struct {
	*persistentCaddy
	upstream *oauthE2EUpstream
	input    string
	secrets  []string
}

func newPersistentProviderFixture(t *testing.T, binary string, fileAttachment bool) *persistentProviderFixture {
	t.Helper()
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("load provider persistence fixture certificate")
	}
	f := &persistentProviderFixture{persistentCaddy: newPersistentCaddy(t, binary, cert, key, roots), upstream: newOAuthE2EUpstream(t, pair, "EdDSA"), secrets: []string{oauthE2ESecret, oauthE2EPortalKey}}
	f.upstream.mu.Lock()
	f.upstream.callback = f.base + "/auth/oauth2/upstream/authorization-code-callback"
	f.upstream.fixedSubject = persistentProviderSubject
	f.upstream.accessMode = "userinfo"
	f.upstream.mu.Unlock()
	store, attachment := "", ""
	if fileAttachment {
		store = fmt.Sprintf("local identity store external_accounts {\n realm external_accounts\n path %q\n}\n", filepath.Join(f.workspace, "external-accounts.json"))
		attachment = "attach to local identity store external_accounts"
	}
	security := fmt.Sprintf(`%s
oauth identity provider upstream {
 driver generic
 realm upstream
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 issuer %s
 scopes openid profile email
 extract email roles from userinfo
 %s
}
authentication portal provider_portal {
 enable identity provider upstream
 crypto key sign-verify %s
 cookie prefix PERSIST
 token refresh {
  realms upstream
  provider revalidation upstream snapshot
  public origin %s
  base path /auth
  access lifetime 600
  idle timeout 1800
  absolute timeout 3600
 }
 transform user {
  match realm upstream
  action add role authp/user
 }
}
authorization policy provider_resource {
 crypto key verify %s
 validate bearer header
 allow roles authp/user
}`, store, oauthE2EClient, oauthE2ESecret, f.upstream.server.URL, f.upstream.server.URL, f.upstream.server.URL, attachment, oauthE2EPortalKey, f.base, oauthE2EPortalKey)
	f.input = f.persistentCaddy.input(security, `route /auth/* {
 authenticate with provider_portal at /auth
}
route /protected {
 authorize with provider_resource
 respond "persistent provider resource"
}`, cert, key)
	t.Cleanup(func() {
		f.kill(t)
		f.upstream.mu.Lock()
		secrets := append(append([]string{}, f.secrets...), f.upstream.issuedSecrets...)
		f.upstream.mu.Unlock()
		logs, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
		if err != nil {
			t.Error("read provider persistence diagnostics")
			return
		}
		for _, secret := range secrets {
			if secret != "" && bytes.Contains(logs, []byte(secret)) {
				t.Error("provider persistence diagnostics exposed a captured credential")
				break
			}
		}
	})
	f.write(t, f.input)
	f.start(t)
	return f
}

func (f *persistentProviderFixture) exchangeCounts() [2]int {
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	return [2]int{f.upstream.exchanges, f.upstream.userInfos}
}

func (f *persistentProviderFixture) restart(t *testing.T) {
	t.Helper()
	counts, pid := f.exchangeCounts(), f.cmd.Process.Pid
	f.persistentCaddy.restart(t)
	if f.cmd.Process.Pid == pid || f.exchangeCounts() != counts {
		t.Fatal("restart reused a process or fetched upstream authentication evidence")
	}
}

func (f *persistentProviderFixture) request(t *testing.T, client *http.Client, method, target, refresh string) oidcRPResponse {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal("construct provider persistence request")
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Origin", f.base)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("X-Authcrunch-Refresh", "1")
		req.AddCookie(&http.Cookie{Name: "PERSIST_REFRESH_TOKEN", Value: refresh})
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("provider persistence TLS request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("provider persistence response lacked a bounded body or verified TLS")
	}
	for _, c := range resp.Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			f.secrets = append(f.secrets, c.Value)
		}
	}
	if location, err := url.Parse(resp.Header.Get("Location")); err == nil {
		for _, name := range []string{"code", "state", "nonce", "code_challenge"} {
			if value := location.Query().Get(name); value != "" {
				f.secrets = append(f.secrets, value)
			}
		}
	}
	return oidcRPResponse{resp.StatusCode, resp.Header, raw}
}

func (f *persistentProviderFixture) login(t *testing.T) persistentProviderTokens {
	t.Helper()
	counts := f.exchangeCounts()
	browser := f.browser(t)
	begin := f.request(t, browser, http.MethodGet, f.base+"/auth/oauth2/upstream?redirect_url=", "")
	begin.requireStatus(t, http.StatusFound)
	if !strings.HasPrefix(begin.header.Get("Location"), f.upstream.server.URL+"/authorize?") {
		t.Fatal("provider persistence login left the controlled issuer")
	}
	authorized := f.request(t, browser, http.MethodGet, begin.header.Get("Location"), "")
	authorized.requireStatus(t, http.StatusFound)
	if !strings.HasPrefix(authorized.header.Get("Location"), f.base+"/auth/oauth2/upstream/authorization-code-callback?") {
		t.Fatal("provider persistence login left the exact callback")
	}
	completed := f.request(t, browser, http.MethodGet, authorized.header.Get("Location"), "")
	completed.requireStatus(t, http.StatusSeeOther)
	if f.exchangeCounts() != [2]int{counts[0] + 1, counts[1] + 1} {
		t.Fatal("fresh login did not use the real token and userinfo endpoints exactly once")
	}
	tokens := f.tokens(t, completed)
	f.authorize(t, tokens.access)
	return tokens
}

func (f *persistentProviderFixture) refresh(t *testing.T, token string, status int) persistentProviderTokens {
	t.Helper()
	counts := f.exchangeCounts()
	r := f.request(t, f.client, http.MethodPost, f.base+"/auth/api/refresh_token", token)
	r.requireStatus(t, status)
	if f.exchangeCounts() != counts {
		t.Fatal("provider snapshot renewal contacted the token or userinfo endpoint")
	}
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Content-Type") != "application/json" || r.header.Get("Authorization") != "" || r.header.Get("Location") != "" {
		t.Fatal("provider renewal changed the JSON or cache/redirect contract")
	}
	var result apiauth.AuthResponse
	if json.Unmarshal(r.body, &result) != nil || result.AccessToken != "" || result.RefreshToken != "" {
		t.Fatal("browser renewal exposed bearer credentials or invalid JSON")
	}
	if status != http.StatusOK {
		if result.Authenticated {
			t.Fatal("rejected provider renewal reported success")
		}
		for _, c := range (&http.Response{Header: r.header}).Cookies() {
			if (c.Name == "PERSIST_ACCESS_TOKEN" || c.Name == "PERSIST_REFRESH_TOKEN" || c.Name == "PERSIST_ID_TOKEN") && c.Value != "" && c.MaxAge >= 0 {
				t.Fatal("rejected provider renewal delivered a credential")
			}
		}
		return persistentProviderTokens{}
	}
	tokens := f.tokens(t, r)
	if !result.Authenticated || result.SessionID != tokens.claims["sid"] || result.AccessExpiresAt != int64(tokens.claims["exp"].(float64)) {
		t.Fatal("renewal metadata did not match the independently signed credential")
	}
	return tokens
}

func (f *persistentProviderFixture) tokens(t *testing.T, r oidcRPResponse) persistentProviderTokens {
	t.Helper()
	cookies := (&http.Response{Header: r.header}).Cookies()
	access := tokenRefreshActiveCookie(t, cookies, "PERSIST_ACCESS_TOKEN")
	refresh := tokenRefreshActiveCookie(t, cookies, "PERSIST_REFRESH_TOKEN")
	if refresh.Path != "/auth" || refresh.Domain != "" || !refresh.Secure || !refresh.HttpOnly || refresh.SameSite != http.SameSiteLaxMode {
		t.Fatal("persisted provider family has unsafe cookie attributes")
	}
	parsed, err := jwt.Parse(access.Value, func(*jwt.Token) (any, error) { return []byte(oauthE2EPortalKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid {
		t.Fatal("independent persisted provider access signature verification failed")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	id, idOK := claims["id"].(string)
	sid, sidOK := claims["sid"].(string)
	authTime, timeOK := claims["auth_time"].(float64)
	if _, err := uuid.Parse(id); err != nil || !idOK || !sidOK || sid == "" || !timeOK || authTime <= 0 || authTime > float64(time.Now().Unix()) || claims["sub"] != persistentProviderSubject || fmt.Sprint(claims["amr"]) != "[federated]" || claims["jti"] == nil {
		t.Fatal("provider family omitted its immutable identity or original authentication evidence")
	}
	return persistentProviderTokens{access.Value, refresh.Value, claims}
}

func (f *persistentProviderFixture) logout(t *testing.T, refresh string) {
	t.Helper()
	counts := f.exchangeCounts()
	r := f.request(t, f.client, http.MethodPost, f.base+"/auth/api/logout", refresh)
	r.requireStatus(t, http.StatusOK)
	var result struct {
		LoggedOut bool `json:"logged_out"`
	}
	if f.exchangeCounts() != counts || json.Unmarshal(r.body, &result) != nil || !result.LoggedOut || r.header.Get("Cache-Control") != "no-store" {
		t.Fatal("provider logout did not acknowledge a bounded local revocation")
	}
}

func (f *persistentProviderFixture) authorize(t *testing.T, token string) {
	t.Helper()
	r := persistentRequest(t, f.client, http.MethodGet, f.base+"/protected", nil, http.Header{"Authorization": {"Bearer " + token}}, http.StatusOK)
	if string(r.body) != "persistent provider resource" {
		t.Fatal("persisted provider access did not reach the protected application")
	}
}
