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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func (f *oidcRPFixture) testRouting(t *testing.T) {
	f.newBrowser(t)
	for _, accept := range []string{"text/html", "application/json"} {
		for _, tc := range []struct {
			method, path, allow string
			status              int
		}{
			{"GET", "/.well-known/openid-configuration", "", 200},
			{"HEAD", "/.well-known/openid-configuration", "", 200},
			{"POST", "/.well-known/openid-configuration", "GET, HEAD", 405},
			{"GET", "/oidc/jwks", "", 200},
			{"HEAD", "/oidc/jwks", "", 200},
			{"POST", "/oidc/jwks", "GET, HEAD", 405},
			{"GET", "/oidc/authorize", "", 400},
			{"GET", "/oidc/token", "POST", 405},
			{"GET", "/oidc/userinfo", "", 401},
			{"GET", "/oidc/revoke", "POST", 405},
			{"GET", "/oidc/token/", "", 404},
			{"GET", "/oidc/%74oken", "", 400},
			{"GET", "/oidc/logout", "", 404},
			{"POST", "/oidc/register", "", 404},
		} {
			r := f.request(t, tc.method, tc.path, nil, http.Header{"Accept": {accept}, "Authorization": {"Bearer invalid-portal-token"}})
			r.requireStatus(t, tc.status)
			r.noStore(t)
			if r.header.Get("Allow") != tc.allow || !strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
				t.Fatalf("library headers changed for %s %s", tc.method, tc.path)
			}
			if tc.method == "HEAD" && len(r.body) != 0 {
				t.Fatal("HEAD returned a body")
			}
			if tc.path == "/oidc/userinfo" && r.header.Get("WWW-Authenticate") == "" {
				t.Fatal("UserInfo lost bearer challenge")
			}
		}
	}
	if f.mount != "" {
		for _, prefix := range []string{"", "/other", f.mount + "entication"} {
			for _, endpoint := range []string{"/.well-known/openid-configuration", "/oidc/jwks", "/oidc/token"} {
				r := f.request(t, "GET", f.base+prefix+endpoint, nil, http.Header{"Accept": {"application/json"}})
				if r.status == 200 || bytes.Contains(r.body, []byte(`"issuer"`)) || bytes.Contains(r.body, []byte(`"keys"`)) {
					t.Fatal("OP endpoint leaked beyond the issuer mount")
				}
			}
		}
	}
	// The Caddy edge strips origin hints from an untrusted connection.
	f.request(t, "GET", "/.well-known/openid-configuration", nil, http.Header{"X-Forwarded-Host": {"attacker.example"}}).requireStatus(t, 200)
	f.request(t, "POST", "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, http.Header{"Origin": {"https://attacker.example"}}).requireStatus(t, 403)
}

func (f *oidcRPFixture) testClients(t *testing.T) {
	for _, client := range []string{"basic", "post", "public"} {
		for _, mode := range []string{"query", "form_post"} {
			t.Run(client+"/"+mode, func(t *testing.T) {
				f.newBrowser(t)
				params := f.authorization(client)
				params.Set("response_mode", mode)
				params.Set("state", `<script>alert("x")</script>&state=+`)
				var start oidcRPResponse
				if mode == "form_post" {
					start = f.request(t, "POST", f.endpoint(t, "authorization_endpoint"), params, nil)
				} else {
					start = f.authorize(t, params)
				}
				start.requireStatus(t, 303)
				location, err := url.Parse(start.header.Get("Location"))
				if err != nil || (location.Host != "" && location.Host != strings.TrimPrefix(f.base, "https://")) || location.Path != f.mount+"/login" {
					t.Fatal("authorization did not enter the canonical portal login")
				}
				f.request(t, "GET", start.header.Get("Location"), nil, nil).requireStatus(t, 200)
				f.login(t)
				response := f.request(t, "GET", "/oidc/continue", nil, nil)
				if client == "basic" {
					response = f.approve(t, response, "allow")
				}
				if mode == "form_post" && bytes.Contains(response.body, []byte(`<script>alert("x")`)) {
					t.Fatal("form-post state was not HTML escaped")
				}
				code := f.callback(t, response, params, "")
				tokens, claims := f.tokens(t, f.exchange(t, client, code, params.Get("redirect_uri"), oidcRPVerifier), params)
				if !slices.Equal(claims.Methods, []string{"pwd"}) {
					t.Fatal("password authentication method missing")
				}
				f.userinfo(t, tokens, claims, "alice@example.test")
				f.exchange(t, client, code, params.Get("redirect_uri"), oidcRPVerifier).failure(t, 400, "invalid_grant")
			})
		}
	}
}

func (f *oidcRPFixture) testConsent(t *testing.T) {
	for _, mode := range []string{"query", "form_post"} {
		t.Run(mode, func(t *testing.T) {
			f.newBrowser(t)
			params := f.authorization("basic")
			params.Set("response_mode", mode)
			params.Set("prompt", "none")
			f.callback(t, f.authorize(t, params), params, "login_required")
			f.login(t)
			f.callback(t, f.authorize(t, params), params, "consent_required")
			params.Del("prompt")
			f.callback(t, f.approve(t, f.authorize(t, params), "deny"), params, "access_denied")
		})
	}
	params := f.authorization("basic")
	consent := f.authorize(t, params)
	consent.requireStatus(t, 200)
	fields := oidcRPForm(t, consent.body).values
	for _, form := range []url.Values{{"decision": {"allow"}}, {"csrf": {"forged"}, "decision": {"allow"}}} {
		f.request(t, "POST", "/oidc/continue", form, http.Header{"Origin": {f.base}}).requireStatus(t, 403)
	}
	f.request(t, "POST", "/oidc/continue", url.Values{"csrf": {fields.Get("csrf")}, "decision": {"allow"}}, http.Header{"Origin": {"https://attacker.example"}}).requireStatus(t, 403)
	code := f.callback(t, f.approve(t, consent, "allow"), params, "")
	f.tokens(t, f.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier), params)
	params.Set("prompt", "none")
	f.callback(t, f.authorize(t, params), params, "")
	params.Set("prompt", "consent")
	f.callback(t, f.approve(t, f.authorize(t, params), "allow"), params, "")
	// Even a trusted registration must honor an explicit consent prompt.
	params.Set("client_id", "trusted")
	f.callback(t, f.approve(t, f.authorize(t, params), "deny"), params, "access_denied")

	f.newBrowser(t)
	f.login(t)
	params = f.authorization("basic")
	params.Set("scope", "openid")
	code = f.callback(t, f.approve(t, f.authorize(t, params), "allow"), params, "")
	tokens, claims := f.tokens(t, f.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier), params)
	r := f.request(t, "POST", f.endpoint(t, "userinfo_endpoint"), url.Values{"access_token": {tokens.Access}}, nil)
	r.requireStatus(t, 200)
	var info map[string]any
	if json.Unmarshal(r.body, &info) != nil || len(info) != 1 || info["sub"] != claims.Subject {
		t.Fatal("openid-only UserInfo released extra identity data")
	}
	params.Set("scope", "openid email")
	params.Set("prompt", "none")
	f.callback(t, f.authorize(t, params), params, "consent_required")
}

func (f *oidcRPFixture) testFreshAuthentication(t *testing.T) {
	for _, parameter := range []string{"prompt", "max_age"} {
		t.Run(parameter, func(t *testing.T) {
			f.newBrowser(t)
			f.login(t)
			params := f.authorization("trusted")
			// A completed password checkpoint predating the request must not
			// become fresh evidence when its sandbox is subsequently redeemed.
			f.request(t, "GET", "/login?fresh=1", nil, nil).requireStatus(t, 200)
			sandbox := f.loginStart(t)
			time.Sleep(1100 * time.Millisecond)
			if parameter == "prompt" {
				params.Set("prompt", "login")
			} else {
				params.Set("max_age", "0")
			}
			requestedAt := time.Now().Unix()
			start := f.authorize(t, params)
			start.requireStatus(t, 303)
			page := f.request(t, "GET", start.header.Get("Location"), nil, nil)
			page.requireStatus(t, 200)
			if !bytes.Contains(page.body, []byte("username")) {
				t.Fatal("fresh authentication reused the portal access token")
			}
			f.request(t, "GET", sandbox, nil, nil).requireStatus(t, 303)
			f.callback(t, f.request(t, "GET", "/oidc/continue", nil, nil), params, "login_required")
			f.login(t)
			code := f.callback(t, f.request(t, "GET", "/oidc/continue", nil, nil), params, "")
			_, claims := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
			if claims.AuthTime < requestedAt {
				t.Fatal("ID token retained stale authentication time")
			}
			params.Del("max_age")
			params.Set("prompt", "none")
			params.Set("max_age", "3600")
			f.callback(t, f.authorize(t, params), params, "")
			params.Set("max_age", "0")
			f.callback(t, f.authorize(t, params), params, "login_required")
		})
	}
	// A positive max_age must stop silent SSO after the actual authentication
	// timestamp ages out; this does not use a fabricated server clock/evidence.
	f.newBrowser(t)
	f.login(t)
	params := f.authorization("trusted")
	params.Set("prompt", "none")
	params.Set("max_age", "3600")
	f.callback(t, f.authorize(t, params), params, "")
	time.Sleep(2100 * time.Millisecond)
	params.Set("max_age", "1")
	f.callback(t, f.authorize(t, params), params, "login_required")
}

func (f *oidcRPFixture) testMFA(t *testing.T) {
	f.newBrowser(t)
	start := f.jsonLogin(t, map[string]any{"username": "mfauser", "realm": "local"})
	if start["sandbox_id"] == nil || start["sandbox_secret"] == nil {
		t.Fatal("MFA login did not create a sandbox")
	}
	checkpoint := map[string]any{"username": "mfauser", "realm": "local", "sandbox_id": start["sandbox_id"], "sandbox_secret": start["sandbox_secret"], "challenge_kind": "password", "challenge_response": lifecyclePassword}
	password := f.jsonLogin(t, checkpoint)
	if password["authenticated"] == true || password["access_token"] != nil {
		t.Fatal("password bypassed enrolled MFA")
	}
	params := f.authorization("trusted")
	params.Set("prompt", "none")
	f.callback(t, f.authorize(t, params), params, "login_required")
	if jarCookie(t, f.client.Jar, f.issuer+"/", "RP_OIDC_SESSION_ID") != "" {
		t.Fatal("incomplete MFA created an OP session")
	}
	// Independent RFC 6238 calculation from the fixture's enrolled raw secret.
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, []byte(oidcRPMFASecret))
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	checkpoint["sandbox_id"] = password["sandbox_id"]
	checkpoint["sandbox_secret"] = password["sandbox_secret"]
	checkpoint["challenge_kind"] = password["next_challenge"]
	checkpoint["challenge_response"] = fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
	completed := f.jsonLogin(t, checkpoint)
	if completed["authenticated"] != true {
		t.Fatal("real password/TOTP login did not complete")
	}
	code := f.callback(t, f.authorize(t, params), params, "")
	tokens, claims := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
	if !slices.Equal(claims.Methods, []string{"pwd", "otp"}) {
		t.Fatal("ID token did not preserve verified MFA methods")
	}
	f.userinfo(t, tokens, claims, "mfauser@example.test")
}

func (f *oidcRPFixture) testBindings(t *testing.T) {
	f.newBrowser(t)
	f.login(t)
	for _, tc := range []struct {
		name, parameter, value, failure string
		local                           bool
	}{
		{"unknown client", "client_id", "unknown", "invalid_request", true},
		{"wrong callback", "redirect_uri", "https://attacker.example/callback", "invalid_request", true},
		{"callback fragment", "redirect_uri", oidcRPCallback + "#fragment", "invalid_request", true},
		{"plain PKCE", "code_challenge_method", "plain", "invalid_request", false},
		{"missing PKCE", "code_challenge", "", "invalid_request", false},
		{"implicit", "response_type", "id_token", "unsupported_response_type", false},
		{"mixed prompt", "prompt", "none login", "invalid_request", false},
		{"dynamic registration", "registration", "{}", "registration_not_supported", false},
		{"request URI", "request_uri", "https://attacker.example/request.jwt", "request_uri_not_supported", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := f.authorization("trusted")
			params.Set(tc.parameter, tc.value)
			r := f.authorize(t, params)
			if tc.local {
				r.failure(t, 400, tc.failure)
				if r.header.Get("Location") != "" {
					t.Fatal("untrusted client/callback received a redirect")
				}
			} else {
				f.callback(t, r, params, tc.failure)
			}
		})
	}
	for _, tc := range []string{"wrong client", "wrong redirect", "wrong PKCE", "missing secret", "wrong method", "assertion"} {
		t.Run(tc, func(t *testing.T) {
			params := f.authorization("trusted")
			code := f.callback(t, f.authorize(t, params), params, "")
			form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oidcRPCallback}, "code_verifier": {oidcRPVerifier}}
			headers := oidcRPAuth("trusted", form)
			status, failure := 400, "invalid_grant"
			switch tc {
			case "wrong client":
				headers = oidcRPAuth("post", form)
			case "wrong redirect":
				form.Set("redirect_uri", oidcRPCallback+"&extra=1")
			case "wrong PKCE":
				form.Set("code_verifier", strings.Repeat("z", 43))
			case "missing secret":
				headers = nil
				form.Set("client_id", "trusted")
				status, failure = 401, "invalid_client"
			case "wrong method":
				headers = nil
				form.Set("client_id", "trusted")
				form.Set("client_secret", applicationTestSecret)
				status, failure = 401, "invalid_client"
			case "assertion":
				headers = nil
				form.Set("client_id", "trusted")
				form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
				form.Set("client_assertion", "unsigned")
				status, failure = 401, "invalid_client"
			}
			f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, headers).failure(t, status, failure)
			// Invalid redemption must not consume the correctly bound code.
			f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
		})
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unsupported"}}
	f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth("trusted", form)).failure(t, 400, "unsupported_grant_type")
	// Unsupported scopes are ignored by the OP; requesting offline_access
	// must never enable a refresh grant or cause it to appear in granted scope.
	params := f.authorization("trusted")
	params.Set("scope", "openid offline_access")
	code := f.callback(t, f.authorize(t, params), params, "")
	r := f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier)
	f.tokens(t, r, params)
	var fields map[string]any
	if json.Unmarshal(r.body, &fields) != nil || fields["scope"] != "openid" {
		t.Fatal("unsupported refresh scope granted")
	}
}

func (f *oidcRPFixture) testLogoutRevocation(t *testing.T) {
	for _, client := range []string{"trusted", "post", "public"} {
		t.Run(client, func(t *testing.T) {
			f.newBrowser(t)
			f.login(t)
			params := f.authorization(client)
			code := f.callback(t, f.authorize(t, params), params, "")
			tokens, claims := f.tokens(t, f.exchange(t, client, code, oidcRPCallback, oidcRPVerifier), params)
			f.userinfo(t, tokens, claims, "alice@example.test")
			wrong := url.Values{"token": {tokens.Access}}
			wrongClient := "trusted"
			if client == "trusted" {
				wrongClient = "post"
			}
			f.request(t, "POST", f.endpoint(t, "revocation_endpoint"), wrong, oidcRPAuth(wrongClient, wrong)).requireStatus(t, 200)
			f.userinfo(t, tokens, claims, "alice@example.test")
			for _, token := range []string{tokens.Access, tokens.Access, "unknown"} {
				form := url.Values{"token": {token}}
				r := f.request(t, "POST", f.endpoint(t, "revocation_endpoint"), form, oidcRPAuth(client, form))
				r.requireStatus(t, 200)
				r.noStore(t)
			}
			f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + tokens.Access}}).failure(t, 401, "invalid_token")
			code = f.callback(t, f.authorize(t, params), params, "")
			tokens, _ = f.tokens(t, f.exchange(t, client, code, oidcRPCallback, oidcRPVerifier), params)
			pendingCode := f.callback(t, f.authorize(t, params), params, "")
			oldSession := jarCookie(t, f.client.Jar, f.issuer+"/", "RP_OIDC_SESSION_ID")
			if oldSession == "" {
				t.Fatal("missing OP browser session")
			}
			f.request(t, "GET", "/logout", nil, nil).requireStatus(t, 302)
			f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + tokens.Access}}).failure(t, 401, "invalid_token")
			f.exchange(t, client, pendingCode, oidcRPCallback, oidcRPVerifier).failure(t, 400, "invalid_grant")
			params.Set("prompt", "none")
			f.callback(t, f.authorize(t, params), params, "login_required")
			f.newBrowser(t)
			r := f.request(t, "GET", f.endpoint(t, "authorization_endpoint")+"?"+params.Encode(), nil, http.Header{"Cookie": {"RP_OIDC_SESSION_ID=" + oldSession}})
			f.callback(t, r, params, "login_required")
		})
	}
}

func (f *oidcRPFixture) testTokenPurposes(t *testing.T) {
	f.newBrowser(t)
	f.login(t)
	params := f.authorization("trusted")
	code := f.callback(t, f.authorize(t, params), params, "")
	tokens, _ := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
	portalToken := jarCookie(t, f.client.Jar, f.issuer+"/", "RP_ACCESS_TOKEN")
	if portalToken == "" {
		t.Fatal("missing portal access token")
	}
	public := f.request(t, "GET", "/.well-known/jwks.json", nil, nil)
	public.requireStatus(t, 200)
	var accessKeys oidcRPKeys
	if json.Unmarshal(public.body, &accessKeys) != nil || len(accessKeys.Keys) == 0 {
		t.Fatal("missing portal JWKS")
	}
	for _, op := range f.keys(t).Keys {
		for _, access := range accessKeys.Keys {
			if op["kid"] == access["kid"] || op["n"] == access["n"] {
				t.Fatal("OP and portal access-token keys overlap")
			}
		}
	}
	if _, _, err := verifyOIDCRPToken(tokens.ID, tokens.Access, f.issuer, "trusted", params.Get("nonce"), accessKeys, time.Now()); err == nil {
		t.Fatal("portal keys verified the OP ID token")
	}
	f.newBrowser(t)
	for _, token := range []string{tokens.ID, portalToken} {
		f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + token}}).failure(t, 401, "invalid_token")
	}
	params.Set("prompt", "none")
	for _, token := range []string{tokens.ID, tokens.Access, portalToken} {
		r := f.request(t, "GET", f.endpoint(t, "authorization_endpoint")+"?"+params.Encode(), nil, http.Header{"Authorization": {"Bearer " + token}})
		f.callback(t, r, params, "login_required")
	}
	if f.mount != "" {
		f.request(t, "GET", f.base+"/app/protected", nil, http.Header{"Authorization": {"Bearer " + portalToken}}).requireStatus(t, 200)
		for _, token := range []string{tokens.ID, tokens.Access} {
			r := f.request(t, "GET", f.base+"/app/protected", nil, http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}})
			if r.status == 200 || bytes.Contains(r.body, []byte("protected application")) {
				t.Fatal("OP token passed the ordinary Caddy gatekeeper")
			}
		}
	}
}

func (f *oidcRPFixture) testCORS(t *testing.T) {
	f.newBrowser(t)
	f.login(t)
	const origin = "https://rp.example.test"
	preflight := f.request(t, "OPTIONS", f.endpoint(t, "token_endpoint"), nil, http.Header{"Origin": {origin}, "Access-Control-Request-Method": {"POST"}, "Access-Control-Request-Headers": {"content-type"}})
	preflight.requireStatus(t, 204)
	if preflight.header.Get("Access-Control-Allow-Origin") != origin || preflight.header.Get("Access-Control-Allow-Credentials") != "" || !strings.Contains(strings.Join(preflight.header.Values("Vary"), ","), "Origin") {
		t.Fatal("public-client CORS headers changed")
	}
	for _, origin := range []string{"https://attacker.example", "null", "https://rp.example.test.attacker.example", "https://rp.example.test:8443", "http://localhost:43112", "http://127.0.0.1:43112", "http://[::1]:43112"} {
		r := f.request(t, "OPTIONS", f.endpoint(t, "token_endpoint"), nil, http.Header{"Origin": {origin}, "Access-Control-Request-Method": {"POST"}})
		r.requireStatus(t, 403)
		if r.header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unregistered CORS origin admitted")
		}
	}
	params := f.authorization("public")
	code := f.callback(t, f.authorize(t, params), params, "")
	form := url.Values{"client_id": {"public"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oidcRPCallback}, "code_verifier": {oidcRPVerifier}}
	r := f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, http.Header{"Origin": {origin}})
	tokens, _ := f.tokens(t, r, params)
	if r.header.Get("Access-Control-Allow-Origin") != origin || r.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("token response CORS changed")
	}
	r = f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Origin": {origin}, "Authorization": {"Bearer " + tokens.Access}})
	r.requireStatus(t, 200)
	if r.header.Get("Access-Control-Allow-Origin") != origin || r.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("UserInfo CORS changed")
	}
}

func (f *oidcRPFixture) testRequestObjects(t *testing.T) {
	f.newBrowser(t)
	params := f.authorization("trusted")
	inner := map[string]any{"prompt": "none", "sub": "administrator", "authenticated": true, "roles": []string{"authp/admin"}}
	object := func() string {
		body, err := json.Marshal(inner)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	}
	params.Set("request", object())
	f.callback(t, f.authorize(t, params), params, "login_required")
	f.login(t)
	code := f.callback(t, f.authorize(t, params), params, "")
	// Parameter encoding cannot replace confidential client authentication.
	form := url.Values{"client_id": {"trusted"}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {oidcRPCallback}, "code_verifier": {oidcRPVerifier}, "request": {object()}}
	f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, nil).failure(t, 401, "invalid_client")
	tokens, claims := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
	if claims.Subject == "administrator" {
		t.Fatal("request object fabricated identity")
	}
	f.userinfo(t, tokens, claims, "alice@example.test")
	inner["client_id"] = "public"
	params.Set("request", object())
	f.callback(t, f.authorize(t, params), params, "invalid_request_object")
	// A signed ID token is not a supported signed authorization request object.
	params.Set("request", tokens.ID)
	f.callback(t, f.authorize(t, params), params, "invalid_request_object")
}
