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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Exercise v1.2.6 capabilities through the Caddy-adapted registration, local
// password login, consent, and independently verified public HTTP artifacts.
func (f *oidcRPFixture) testCapabilities(t *testing.T) {
	f.newBrowser(t)
	params := f.authorization("capabilities")
	params.Set("scope", "openid address phone offline_access")
	params.Set("prompt", "consent")
	params.Set("acr_values", "urn:example:password")
	inner := map[string]any{}
	for name := range params {
		inner[name] = params.Get(name)
	}
	inner["iss"], inner["aud"] = "capabilities", f.issuer
	inner["exp"] = time.Now().Add(time.Minute).Unix()
	inner["claims"] = map[string]any{"id_token": map[string]any{"given_name": map[string]any{"essential": true}}}
	body, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"rp-key"}`)) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.requestKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	params.Set("request", unsigned+"."+base64.RawURLEncoding.EncodeToString(signature))
	f.authorize(t, params).requireStatus(t, 303)
	f.login(t)
	code := f.callback(t, f.approve(t, f.request(t, "GET", "/oidc/continue", nil, nil), "allow"), params, "")
	r := f.exchange(t, "capabilities", code, oidcRPCallback, oidcRPVerifier)
	verify := func(r oidcRPResponse) (oidcRPTokens, string) {
		t.Helper()
		r.requireStatus(t, 200)
		r.noStore(t)
		var tokens oidcRPTokens
		var fields map[string]any
		if json.Unmarshal(r.body, &tokens) != nil || json.Unmarshal(r.body, &fields) != nil {
			t.Fatal("invalid capability token response")
		}
		refresh, ok := fields["refresh_token"].(string)
		if !ok || refresh == "" || tokens.Type != "Bearer" || tokens.Expires <= 0 {
			t.Fatal("missing rotating refresh credential")
		}
		if _, _, err := verifyOIDCRPToken(tokens.ID, tokens.Access, f.issuer, "capabilities", params.Get("nonce"), f.keys(t), time.Now()); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tokens.ID, ".")[1])
		var claims map[string]any
		if err != nil || json.Unmarshal(payload, &claims) != nil || claims["given_name"] != "Alice" || claims["acr"] != "urn:example:password" {
			t.Fatal("consented essential claim or verified authentication context missing")
		}
		info := f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + tokens.Access}})
		info.requireStatus(t, 200)
		var user map[string]any
		if json.Unmarshal(info.body, &user) != nil || user["sub"] != claims["sub"] || user["phone_number"] != "+1 202-555-0100" || user["phone_number_verified"] != false || user["email"] != nil || user["given_name"] != nil {
			t.Fatal("UserInfo lost scope/location filtering or explicit phone data")
		}
		address, ok := user["address"].(map[string]any)
		if !ok || address["country"] != "US" {
			t.Fatal("explicit address data missing")
		}
		return tokens, refresh
	}
	_, refresh := verify(r)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth("trusted", form)).failure(t, 400, "invalid_grant")
	rotated, next := verify(f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth("capabilities", form)))
	if next == refresh {
		t.Fatal("refresh credential did not rotate")
	}
	f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth("capabilities", form)).failure(t, 400, "invalid_grant")
	form.Set("refresh_token", next)
	f.request(t, "POST", f.endpoint(t, "token_endpoint"), form, oidcRPAuth("capabilities", form)).failure(t, 400, "invalid_grant")
	f.request(t, "GET", f.endpoint(t, "userinfo_endpoint"), nil, http.Header{"Authorization": {"Bearer " + rotated.Access}}).requireStatus(t, 401)
	// A tampered signature and an unsigned downgrade both fail at authorization.
	signature[0] ^= 1
	params.Set("request", unsigned+"."+base64.RawURLEncoding.EncodeToString(signature))
	f.callback(t, f.authorize(t, params), params, "invalid_request_object")
	params.Set("request", base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))+"."+base64.RawURLEncoding.EncodeToString(body)+".")
	f.callback(t, f.authorize(t, params), params, "invalid_request_object")
}
