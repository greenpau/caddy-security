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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func testCompositionRoles(t *testing.T, f *compositionFixture) {
	browser, admin := f.browser(t), f.browser(t)
	f.browserLogin(t, browser, "employees", 200)
	req := apiauth.AuthRequest{Username: "admin", Realm: "employees"}
	begin, _ := f.post(t, admin, "/login", req, f.headers(), 200)
	req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = begin.SandboxID, begin.SandboxSecret, begin.NextChallenge, lifecyclePassword
	f.post(t, admin, "/login", req, f.headers(), 200)
	operation := map[string]any{"realm": "employees", "operation": "overwrite_roles", "user": map[string]any{"username": "alice", "email": "alice@example.test", "roles": []string{"changed/viewer"}}}
	body, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), "POST", f.base+"/auth/api/server/user", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header = f.headers()
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	resp, err := admin.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	err = json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || result["status"] != "success" {
		t.Fatalf("role mutation failed: status=%d", resp.StatusCode)
	}
	// Role mutations now revoke the earlier authentication evidence. Require
	// a fresh password login before current roles can authorize another family.
	f.post(t, browser, "/api/refresh_token", struct{}{}, f.headers(), 401)
	current := f.browser(t)
	login, cookies := f.browserLogin(t, current, "employees", 200)
	access := tokenRefreshActiveCookie(t, cookies, f.accessName()).Value
	f.secrets = append(f.secrets, access)
	claims := verifyCaddyJWKSSignature(t, f.keys, access, "RS512", "refresh")
	roles, ok := claims["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "changed/viewer" {
		t.Fatal("fresh login retained roles from before the mutation")
	}
	f.resourceStatus(t, access, "/protected", 403)
	rotated, cookies := f.post(t, current, "/api/refresh_token", struct{}{}, f.headers(), 200)
	if rotated.SessionID != login.SessionID {
		t.Fatal("current-role refresh changed family")
	}
	renewed := tokenRefreshActiveCookie(t, cookies, f.accessName()).Value
	claims = verifyCaddyJWKSSignature(t, f.keys, renewed, "RS512", "refresh")
	roles, ok = claims["roles"].([]any)
	if !ok || len(roles) != 1 || roles[0] != "changed/viewer" {
		t.Fatal("renewal restored a removed role")
	}
	f.resourceStatus(t, renewed, "/protected", 403)
}

// The probe only holds the response writer around the real security plugins.
// AuthCrunch has already entered (and may have committed a refresh) when the
// hold fires. Blocking a handler before admission would not test disposal.
func compositionLifecycleConfig(t *testing.T, data []byte, label string) []byte {
	t.Helper()
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	count := 0
	walk = func(value any) {
		switch node := value.(type) {
		case map[string]any:
			for k, child := range node {
				if k == "handle" {
					if handlers, ok := child.([]any); ok {
						for _, handler := range handlers {
							if h, ok := handler.(map[string]any); ok && (h["handler"] == "authenticator" || h["handler"] == "authentication" || h["handler"] == "authorization") {
								node[k] = append([]any{map[string]any{"handler": "security_lifecycle_probe", "label": label}}, handlers...)
								count++
								break
							}
						}
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(config)
	if count == 0 {
		t.Fatal("composition lifecycle probe did not wrap security")
	}
	out, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testCompositionDisposal(t *testing.T, f *compositionFixture) {
	initial := compositionLifecycleConfig(t, f.adapt(t, f.input), "composed-initial")
	if err := caddy.Load(initial, true); err != nil {
		t.Fatal(err)
	}
	old := f.active(t)
	browser := f.browser(t)
	login, _ := f.browserLogin(t, browser, "employees", 200)
	tokens := f.exchange(t, browser)
	// Keep an unredeemed authorization code as well as a live grant/session.
	query := url.Values{"client_id": {f.registration.ClientID}, "response_type": {"code"}, "redirect_uri": {f.registration.RedirectURIs[0]}, "scope": {"openid"}, "state": {"pending"}, "nonce": {"pending"}, "code_challenge_method": {"S256"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}}
	status, headers, raw := registrationHTTP(t, browser, "GET", f.base+"/auth/oidc/authorize?"+query.Encode(), nil, nil)
	code, err := verifyOIDCRPCallback(oidcRPResponse{status: status, header: headers, body: raw}, query, f.base+"/auth", "")
	if err != nil {
		t.Fatal(err)
	}

	type response struct {
		status  int
		cookies []*http.Cookie
		err     error
	}
	results := make(chan response, 2)
	var holds []*lifecycleHold
	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, h := range holds {
				close(h.release)
			}
		})
	}
	defer release()
	for _, path := range []string{"/auth/.well-known/openid-configuration", "/auth/api/refresh_token"} {
		hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
		holds = append(holds, hold)
		lifecycleHolds.Store(path, hold)
		t.Cleanup(func() { lifecycleHolds.Delete(path) })
		go func() {
			method := "GET"
			var body io.Reader
			if strings.HasSuffix(path, "refresh_token") {
				method, body = "POST", strings.NewReader("{}")
			}
			req, err := http.NewRequestWithContext(t.Context(), method, f.base+path, body)
			if err != nil {
				results <- response{err: err}
				return
			}
			req.Header = f.headers()
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Lifecycle-Hold", path)
			resp, err := browser.Do(req)
			if err != nil {
				results <- response{err: err}
				return
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results <- response{status: resp.StatusCode, cookies: resp.Cookies(), err: err}
		}()
	}
	for _, h := range holds {
		awaitLifecycle(t, h.entered, "composed request inside AuthCrunch")
	}
	replacement := compositionLifecycleConfig(t, f.adapt(t, f.input), "composed-replacement")
	done := make(chan struct{})
	var loadErr error
	go func() { loadErr = caddy.Load(replacement, true); close(done) }()
	waitDisposing(t, old)
	select {
	case <-done:
		t.Fatal("reload completed before admitted requests drained")
	default:
	}
	if _, err := old.server.GetPortalByName("myportal"); err != nil {
		t.Fatal("runtime disposed under pending request")
	}
	status, responseHeaders, _ := registrationHTTP(t, f.client, "GET", f.base+"/auth/.well-known/openid-configuration", nil, nil)
	if status != 200 || responseHeaders.Get("X-Lifecycle") != "composed-replacement" {
		t.Fatal("new deployment not serving during old drain")
	}
	release()
	awaitLifecycle(t, done, "composed replacement")
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil || result.status != 200 {
				t.Fatalf("pending response failed: status=%d error=%v", result.status, result.err)
			}
			for _, cookie := range result.cookies {
				if cookie.Name == f.refreshName() && cookie.MaxAge >= 0 {
					f.replay(t, cookie.Value, login.SessionID)
				}
			}
		case <-time.After(10 * time.Second):
			t.Fatal("pending HTTP request survived disposal")
		}
	}
	assertServerClosed(t, old)
	f.userinfoStatus(t, tokens.accessToken, 401)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.registration.RedirectURIs[0]}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}}
	auth := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(f.registration.ClientID)+":"+url.QueryEscape(f.registration.ClientSecret)))}}
	status, headers, raw = registrationHTTP(t, f.client, "POST", f.base+"/auth/oidc/token", form, auth)
	if status != 400 || headers.Get("Cache-Control") != "no-store" || !bytes.Contains(raw, []byte("invalid_grant")) {
		t.Fatal("pending authorization code survived replacement")
	}
	assertAdminRedacted(t, raw, append(f.secrets, code))
	f.browserLogin(t, f.browser(t), "employees", 200)
	// Retained plugin references fail closed after their owning app retires.
	gate, err := old.server.GetGatekeeperByName("app_policy")
	if err == nil || gate != nil {
		t.Fatal("retired runtime still lends gatekeepers")
	}
}
