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
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	jwt "github.com/golang-jwt/jwt/v5"
)

// This qualifies inherited RSA-PSS verification through the actual Caddy host.
// PS256 credentials are minted by the test issuer, not by the portal: its KMS
// still issues RS512 and exposes no reference-signer selection API.
func TestCaddyRSAPSSVerificationE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyRSAPSSVerificationProcess$", "-test.v", "-test.timeout=105s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_RSAPSS_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS Caddy RSA-PSS verification: %v\n%s", err, output)
	}
}

// Construct fixtures with the standard library, independently of AuthCrunch
// and jwt's process-global PSS methods. Nonstandard salts remain mathematically
// valid signatures, so their rejection establishes the verifier's JOSE boundary.
func caddyRSAPSSFixtureToken(t *testing.T, key jwksKeyFiles, kid, alg string, hash crypto.Hash, saltLength int, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"typ": "authcrunch-access+jwt", "alg": alg, "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := hash.New()
	_, _ = digest.Write([]byte(input))
	private := key.key.(*rsa.PrivateKey)
	signature, err := rsa.SignPSS(rand.Reader, private, hash, digest.Sum(nil), &rsa.PSSOptions{SaltLength: saltLength, Hash: hash})
	if err != nil {
		t.Fatal("could not sign RSA-PSS fixture")
	}
	if err := rsa.VerifyPSS(&private.PublicKey, hash, digest.Sum(nil), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: hash}); err != nil {
		t.Fatal("RSA-PSS fixture is not a valid signature")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestCaddyRSAPSSVerificationProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_RSAPSS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, certKey, roots := cookieTLSCertificate(t)
	current := newJWKSKeyFiles(t, "RSA", "current")
	next := newJWKSKeyFiles(t, "RSA", "next")
	f := newCaddyJWKSFixture(t, "/tenant/auth", current.signer("current"), current.verifier("current"), certFile, certKey, roots)
	portalToken := f.login(t, "keyadmin")
	// Public discovery describes the actual portal signer. Verifier support
	// must not relabel the advertised algorithm or change password issuance.
	claims := verifyCaddyJWKSToken(t, fetchCaddyJWKS(t, f, 1), portalToken, "RS512", "current")
	assertCaddyGatekeeper(t, f, portalToken, true)
	sign := func(key jwksKeyFiles, kid string, claims map[string]any) string {
		return caddyRSAPSSFixtureToken(t, key, kid, "PS256", crypto.SHA256, 32, claims)
	}
	currentToken := sign(current, "current", claims)
	nextToken := sign(next, "next", claims)
	assertCaddyGatekeeper(t, f, currentToken, true)
	assertCaddyGatekeeper(t, f, nextToken, false)

	t.Run("algorithms_and_salts", func(t *testing.T) {
		for _, tc := range []struct {
			name, alg string
			hash      crypto.Hash
			salt      int
			allowed   bool
		}{
			{"PS256_exact_salt", "PS256", crypto.SHA256, 32, true},
			{"PS256_short_salt", "PS256", crypto.SHA256, 1, false},
			{"PS256_salt_31", "PS256", crypto.SHA256, 31, false},
			{"PS256_salt_33", "PS256", crypto.SHA256, 33, false},
			{"PS256_maximum_salt", "PS256", crypto.SHA256, rsa.PSSSaltLengthAuto, false},
			{"PS256_wrong_hash", "PS256", crypto.SHA384, 32, false},
			{"PS384", "PS384", crypto.SHA384, 48, false},
			{"PS512", "PS512", crypto.SHA512, 64, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				token := caddyRSAPSSFixtureToken(t, current, "current", tc.alg, tc.hash, tc.salt, claims)
				assertCaddyGatekeeper(t, f, token, tc.allowed)
			})
		}
	})
	t.Run("trust_and_tampering", func(t *testing.T) {
		assertCaddyGatekeeper(t, f, sign(next, "current", claims), false)
		public, err := os.ReadFile(current.public)
		if err != nil {
			t.Fatal(err)
		}
		confused := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		confused.Header["kid"] = "current"
		confusedToken, err := confused.SignedString(public)
		if err != nil {
			t.Fatal("could not create algorithm-confusion fixture")
		}
		assertCaddyGatekeeper(t, f, confusedToken, false)
		parts := strings.Split(currentToken, ".")
		header, _ := json.Marshal(map[string]string{"typ": "authcrunch-access+jwt", "alg": "RS256", "kid": "current"})
		assertCaddyGatekeeper(t, f, base64.RawURLEncoding.EncodeToString(header)+"."+parts[1]+"."+parts[2], false)
		altered := maps.Clone(claims)
		altered["sub"] = "altered"
		payload, err := json.Marshal(altered)
		if err != nil {
			t.Fatal(err)
		}
		assertCaddyGatekeeper(t, f, parts[0]+"."+base64.RawURLEncoding.EncodeToString(payload)+"."+parts[2], false)
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || len(signature) == 0 {
			t.Fatal("invalid fixture signature encoding")
		}
		signature[0] ^= 1
		assertCaddyGatekeeper(t, f, parts[0]+"."+parts[1]+"."+base64.RawURLEncoding.EncodeToString(signature), false)
		assertCaddyGatekeeper(t, f, parts[0]+"."+parts[1]+".", false)
	})
	t.Run("signed_claims_still_require_authorization", func(t *testing.T) {
		for _, name := range []string{"expired", "future", "wrong_role"} {
			t.Run(name, func(t *testing.T) {
				modified := maps.Clone(claims)
				switch name {
				case "expired":
					modified["exp"] = time.Now().Add(-time.Hour).Unix()
				case "future":
					modified["nbf"] = time.Now().Add(time.Hour).Unix()
				case "wrong_role":
					modified["roles"] = []string{"untrusted/user"}
				}
				assertCaddyGatekeeper(t, f, sign(current, "current", modified), false)
			})
		}
	})
	t.Run("verifier_rotation", func(t *testing.T) {
		original := f.input
		load := func(portal, policy string) error {
			f.input = strings.Replace(original, current.signer("current"), portal, 1)
			f.input = strings.Replace(f.input, current.verifier("current"), policy, 1)
			err := f.reload("")
			// Probes must reach the replacement server, not retiring keep-alives.
			f.client.CloseIdleConnections()
			return err
		}
		if err := load(next.signer("next"), current.verifier("current")+"\n"+next.verifier("next")); err != nil {
			t.Fatal("could not publish overlapping RSA verifiers")
		}
		assertCaddyGatekeeper(t, f, currentToken, true)
		assertCaddyGatekeeper(t, f, nextToken, true)
		verifyCaddyJWKSToken(t, fetchCaddyJWKS(t, f, 1), f.login(t, "keyadmin"), "RS512", "next")
		missing := strings.Replace(next.verifier("next"), next.public, next.public+".missing.pem", 1)
		if err := load(next.signer("next"), missing); err == nil {
			t.Fatal("missing verification key unexpectedly provisioned")
		}
		assertCaddyGatekeeper(t, f, currentToken, true)
		assertCaddyGatekeeper(t, f, nextToken, true)
		verifyCaddyJWKSToken(t, fetchCaddyJWKS(t, f, 1), f.login(t, "keyadmin"), "RS512", "next")
		if err := load(next.signer("next"), next.verifier("next")); err != nil {
			t.Fatal("could not retire old RSA verifier")
		}
		assertCaddyGatekeeper(t, f, currentToken, false)
		assertCaddyGatekeeper(t, f, nextToken, true)
		if err := caddy.Stop(); err != nil {
			t.Fatal("could not stop Caddy")
		}
		f.client.CloseIdleConnections()
		if err := f.reload(""); err != nil {
			t.Fatal("could not restart Caddy with explicit RSA keys")
		}
		assertCaddyGatekeeper(t, f, currentToken, false)
		assertCaddyGatekeeper(t, f, nextToken, true)
		verifyCaddyJWKSToken(t, fetchCaddyJWKS(t, f, 1), f.login(t, "keyadmin"), "RS512", "next")
	})
}
