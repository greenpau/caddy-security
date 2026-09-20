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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func challengeWebAuthnRegistration(t *testing.T, rpID string) (requests.WebAuthn, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	registration := identity.WebAuthnRegisterRequest{
		ID: "portal-origin-credential", Type: "public-key", Transports: []string{"internal"},
		AttestationObject: &identity.AttestationObject{AuthData: &identity.AuthData{
			RelyingPartyID: fmt.Sprintf("%x", rpIDHash), Flags: map[string]bool{"UP": true},
			CredentialData: &identity.CredentialData{PublicKey: map[string]any{
				"key_type": 2, "algorithm": -7, "curve_type": 1,
				"curve_x": base64.StdEncoding.EncodeToString(public[1:33]),
				"curve_y": base64.StdEncoding.EncodeToString(public[33:65]),
			}},
		}},
	}
	data, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	return requests.WebAuthn{Register: base64.StdEncoding.EncodeToString(data), Challenge: "fixture-registration-challenge"}, key, registration.ID
}

func challengeWebAuthnAssertion(t *testing.T, key *ecdsa.PrivateKey, credentialID, rpID, challenge, origin string) string {
	t.Helper()
	clientData, err := json.Marshal(identity.ClientData{Type: "webauthn.get", Challenge: challenge, Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 37)
	copy(authData, rpIDHash[:])
	authData[32] = 0x01
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	signedDataHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, key, signedDataHash[:])
	if err != nil {
		t.Fatal(err)
	}
	request := identity.WebAuthnAuthenticateRequest{
		ID: credentialID, Type: "public-key",
		AuthDataEncoded:   base64.StdEncoding.EncodeToString(authData),
		ClientDataEncoded: base64.StdEncoding.EncodeToString(clientData),
		SignatureEncoded:  base64.StdEncoding.EncodeToString(signature),
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func testCaddyWebAuthnPolicy(t *testing.T, cert, tlsKey string, roots *x509.CertPool) {
	registration, key, credentialID := challengeWebAuthnRegistration(t, "127.0.0.1")
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/tenant/auth", mfa: true, refreshRealm: "local", oidcRealm: "local", seed: func(t *testing.T, path string) {
		db, err := identity.NewDatabase(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "synthetic Caddy assertion credential"}, WebAuthn: registration}); err != nil {
			t.Fatal(err)
		}
	}}, cert, tlsKey, roots)
	f.input = challengePolicyInput(f.input, challengePolicy)
	f.input = strings.Replace(f.input, "allow roles authp/user", "allow amr hwk", 1)
	challengeRestart(t, f)
	for _, scenario := range []string{"wrong origin", "wrong signature", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			f.newBrowser(t)
			req := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			result := localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
			if result.NextChallenge != "u2f" || result.Authenticated {
				t.Fatal("WebAuthn policy retained password/TOTP checkpoint")
			}
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeKind, req.ChallengeResponse = "u2f", "webauthn"
			result = localIdentityAuth(t, f.json(t, f.client, "/login", req, ""))
			data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(result.NextChallenge, "mfa:u2f:"))
			var challenge struct{ Challenge string }
			if err != nil || json.Unmarshal(data, &challenge) != nil || challenge.Challenge == "" {
				t.Fatal("missing WebAuthn server challenge")
			}
			f.noCredentials(t)
			origin, signingKey := f.base, key
			if scenario == "wrong origin" {
				origin = "https://attacker.example.test"
			}
			if scenario == "wrong signature" {
				signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			req.SandboxID, req.SandboxSecret = result.SandboxID, result.SandboxSecret
			req.ChallengeResponse = challengeWebAuthnAssertion(t, signingKey, credentialID, "127.0.0.1", challenge.Challenge, origin)
			response := f.json(t, f.client, "/login", req, "")
			if scenario != "valid" {
				localIdentityRejectedAuth(t, response, 401)
				f.noCredentials(t)
				return
			}
			if !localIdentityAuth(t, response).Authenticated {
				t.Fatal("valid WebAuthn assertion rejected")
			}
			token := f.cookie("AUTHP_ACCESS_TOKEN")
			challengeClaims(t, f, token, "hwk")
			f.assertResource(t, token)
			f.json(t, f.client, "/api/refresh_token", map[string]any{}, "", http.Header{"X-Authcrunch-Refresh": {"1"}}).requireStatus(t, 200)
			challengeClaims(t, f, f.cookie("AUTHP_ACCESS_TOKEN"), "hwk")
			params := f.authorization("trusted")
			code := f.callback(t, f.authorize(t, params), params, "")
			tokens, _ := f.tokens(t, f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
			data, err = base64.RawURLEncoding.DecodeString(strings.Split(tokens.ID, ".")[1])
			var claims struct {
				AMR []string `json:"amr"`
			}
			if err != nil || json.Unmarshal(data, &claims) != nil || len(claims.AMR) != 1 || claims.AMR[0] != "hwk" {
				t.Fatal("OIDC lost verified WebAuthn-only methods")
			}
		})
	}
}
