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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	jwt "github.com/golang-jwt/jwt/v5"
)

func TestCaddyJWKSE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyJWKSProcess$", "-test.v", "-test.timeout=165s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_JWKS_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS Caddy JWKS: %v\n%s", err, output)
	}
}

type jwksKeyFiles struct {
	private, public string
	key             crypto.Signer
}

func newJWKSKeyFiles(t *testing.T, family, kid string) jwksKeyFiles {
	t.Helper()
	var key crypto.Signer
	var err error
	switch family {
	case "RSA":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "EC":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "OKP":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatal("unknown test key family")
	}
	if err != nil {
		t.Fatal("could not generate signing key")
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("could not encode private key")
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal("could not encode public key")
	}
	f := jwksKeyFiles{private: filepath.Join(t.TempDir(), kid+".pem"), public: filepath.Join(t.TempDir(), kid+".pem"), key: key}
	for _, entry := range []struct {
		path, kind string
		der        []byte
	}{{f.private, "PRIVATE KEY", private}, {f.public, "PUBLIC KEY", public}} {
		if err := os.WriteFile(entry.path, pem.EncodeToMemory(&pem.Block{Type: entry.kind, Bytes: entry.der}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (k jwksKeyFiles) signer(kid string) string {
	return fmt.Sprintf("crypto key %s sign-verify from file %q", kid, k.private)
}

func (k jwksKeyFiles) verifier(kid string) string {
	return fmt.Sprintf("crypto key %s verify from file %q", kid, k.public)
}

// Reuse the admin API suite's browser login and private-export request helpers.
// This fixture adds an ordinary gatekeeper and exact Caddy mount matchers.
func newCaddyJWKSFixture(t *testing.T, mount, portalCrypto, policyCrypto, certFile, certKey string, roots *x509.CertPool) *caddyAdminFixture {
	t.Helper()
	addr := lifecycleAddress(t)
	authURL := mount
	if authURL == "" {
		authURL = "/"
	}
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  local identity store localdb {
   realm local
   path :memory:
   user keyadmin {
    email keyadmin@example.test
    password %s
    roles authp/admin authp/user
   }
  }
  authentication portal portal {
   enable identity store localdb
   %s
   %s
  }
  authorization policy policy {
   %s
   allow roles authp/user
   validate bearer header
   set auth url %s
  }
 }
}
https://%s {
 tls %s %s
 @portal path %s %s/*
 route {
  route /protected {
   authorize with policy
   respond allowed 200
  }
  route @portal {
   authenticate with portal
  }
  route {
   authorize with policy
   respond allowed 200
  }
 }
}`, lifecyclePassword, portalCrypto, adminDirectivesMarker, policyCrypto, authURL, addr, certFile, certKey, authURL, mount)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	f := &caddyAdminFixture{
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:   "https://" + addr, mount: mount, input: input, profile: true,
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		if err := caddy.Stop(); err != nil {
			t.Error("could not stop Caddy JWKS fixture")
		}
	})
	if err := f.reload(""); err != nil {
		t.Fatalf("could not provision Caddy JWKS fixture: %v", err)
	}
	return f
}

func jwksHTTPRequest(t *testing.T, f *caddyAdminFixture, method, target string, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.base+target, nil)
	if err != nil {
		t.Fatal("could not construct JWKS request")
	}
	req.Header = headers.Clone()
	resp, err := f.client.Do(req)
	if err != nil {
		// Keep transport diagnostics without echoing request URLs or headers.
		if requestErr, ok := err.(*url.Error); ok {
			err = requestErr.Err
		}
		t.Fatalf("JWKS %s transport failed: %v", method, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		t.Fatal("invalid or oversized JWKS response")
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("JWKS request did not use verified TLS")
	}
	return resp.StatusCode, resp.Header, body
}

func fetchCaddyJWKS(t *testing.T, f *caddyAdminFixture, count int) []map[string]string {
	t.Helper()
	want := http.StatusOK
	if count == 0 {
		want = http.StatusNotFound
	}
	// HEAD must work before any GET could initialize a cache or discovery state.
	firstStatus, firstHeaders, firstBody := jwksHTTPRequest(t, f, "HEAD", f.mount+adminJWKSPath, nil)
	if firstStatus != want || len(firstBody) != 0 || firstHeaders.Get("Cache-Control") != "no-store" || firstHeaders.Get("X-Content-Type-Options") != "nosniff" || len(firstHeaders.Values("Set-Cookie")) != 0 || firstHeaders.Get("Location") != "" {
		t.Fatal("initial HEAD changed the public discovery contract")
	}
	var baseline []byte
	// Deliberately invalid credentials must neither obstruct discovery nor cause
	// cookie deletion. API/JSON negotiation must not consume the public route.
	for _, negotiation := range []http.Header{
		{},
		{"Accept": {"application/json"}, "Content-Type": {"application/json"}},
		{"Accept": {"text/html"}, "Authorization": {"Bearer invalid"}, "Cookie": {"AUTHP_ACCESS_TOKEN=invalid; AUTHP_SESSION_ID=invalid"}},
	} {
		for _, query := range []string{"", "?format=json"} {
			for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
				status := want
				if method != "GET" && method != "HEAD" {
					status = 405
				}
				got, headers, body := jwksHTTPRequest(t, f, method, f.mount+adminJWKSPath+query, negotiation)
				if got != status {
					t.Fatalf("%s discovery: HTTP %d, want %d", method, got, status)
				}
				if headers.Get("Cache-Control") != "no-store" || headers.Get("X-Content-Type-Options") != "nosniff" || len(headers.Values("Set-Cookie")) != 0 || headers.Get("Location") != "" {
					t.Fatal("discovery changed cache, cookie, redirect, or nosniff contract")
				}
				assertAdminRedacted(t, body, f.secrets)
				if status == 405 && headers.Get("Allow") != "GET, HEAD" {
					t.Fatal("discovery lost allowed methods")
				}
				if status == 200 {
					if headers.Get("Content-Type") != "application/jwk-set+json" {
						t.Fatal("discovery changed media type")
					}
					if method == "GET" {
						if baseline == nil {
							baseline = body
						}
						if !bytes.Equal(body, baseline) {
							t.Fatal("discovery changed with negotiation or credentials")
						}
					}
					if headers.Get("Content-Length") != strconv.Itoa(len(baseline)) {
						t.Fatal("GET/HEAD content length mismatch")
					}
				}
				if (method == "HEAD" || status != 200) && len(body) != 0 {
					t.Fatal("HEAD or error discovery response had a body")
				}
			}
		}
	}
	if count == 0 {
		return nil
	}
	if firstHeaders.Get("Content-Type") != "application/jwk-set+json" || firstHeaders.Get("Content-Length") != strconv.Itoa(len(baseline)) {
		t.Fatal("initial HEAD headers differ from GET")
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(baseline, &document); err != nil || len(document) != 1 {
		t.Fatal("JWKS must be an object containing only keys")
	}
	var keys []map[string]string
	if err := json.Unmarshal(document["keys"], &keys); err != nil || len(keys) != count {
		t.Fatalf("JWKS keys array has %d entries, want %d", len(keys), count)
	}
	for _, key := range keys {
		allowed := map[string]bool{"kty": true, "kid": true, "alg": true, "use": true}
		switch key["kty"] {
		case "OKP":
			allowed["crv"], allowed["x"] = true, true
		case "EC":
			allowed["crv"], allowed["x"], allowed["y"] = true, true, true
		case "RSA":
			allowed["n"], allowed["e"] = true, true
		default:
			t.Fatal("JWKS published an unexpected key family")
		}
		for field := range key {
			if !allowed[field] {
				t.Fatal("JWKS published a non-public or unexpected field")
			}
		}
		if key["use"] != "sig" {
			t.Fatal("JWKS did not describe a signing key")
		}
	}
	return keys
}

func assertNoCaddyJWKS(t *testing.T, headers http.Header, body []byte, keys []map[string]string) {
	t.Helper()
	var document map[string]json.RawMessage
	_ = json.Unmarshal(body, &document)
	if strings.HasPrefix(headers.Get("Content-Type"), "application/jwk-set+json") || document["keys"] != nil {
		t.Fatal("non-discovery path published a key set")
	}
	// An incorrect media type, singleton response, or HTML wrapper must not
	// conceal publication. Check the actual public parameters too.
	for _, key := range keys {
		for _, field := range []string{"x", "n"} {
			if value := key[field]; value != "" && bytes.Contains(body, []byte(value)) {
				t.Fatal("non-discovery path published signing material")
			}
		}
	}
}

// Reconstruct the verifier solely from the fetched JWKS and verify the original
// compact signing input with the standard library, without KMS or JWT methods.
func verifyCaddyJWKSSignature(t *testing.T, keys []map[string]string, signed, alg, kid string) map[string]any {
	t.Helper()
	decode := func(value string) []byte {
		data, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil {
			t.Fatal("invalid base64url in token or JWKS")
		}
		return data
	}
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		t.Fatal("invalid compact JWT")
	}
	var header map[string]string
	var claims map[string]any
	if json.Unmarshal(decode(parts[0]), &header) != nil || json.Unmarshal(decode(parts[1]), &claims) != nil {
		t.Fatal("invalid JWT header or claims")
	}
	if header["alg"] != alg || header["kid"] != kid {
		t.Fatalf("JWT changed exact alg/kid: %q/%q, want %q/%q", header["alg"], header["kid"], alg, kid)
	}
	if _, exists := header["kid"]; kid == "" && exists {
		t.Fatal("default JWT key ID must be omitted")
	}
	var key map[string]string
	for _, candidate := range keys {
		if candidate["kid"] == kid && candidate["alg"] == alg {
			key = candidate
			break
		}
	}
	if key == nil {
		t.Fatal("no JWKS key matches the exact JWT alg/kid")
	}
	if _, exists := key["kid"]; kid == "" && exists {
		t.Fatal("default JWKS key ID must be omitted")
	}
	input, signature := []byte(parts[0]+"."+parts[1]), decode(parts[2])
	valid := false
	switch alg {
	case "EdDSA", "Ed25519":
		public := decode(key["x"])
		if key["kty"] != "OKP" || key["crv"] != "Ed25519" || len(public) != ed25519.PublicKeySize {
			t.Fatal("invalid OKP public key")
		}
		valid = ed25519.Verify(ed25519.PublicKey(public), input, signature)
	case "RS512":
		n, e := decode(key["n"]), decode(key["e"])
		if key["kty"] != "RSA" || len(n) == 0 || len(e) == 0 || n[0] == 0 || e[0] == 0 {
			t.Fatal("invalid RSA public key")
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		hash := sha512.Sum512(input)
		valid = rsa.VerifyPKCS1v15(public, crypto.SHA512, hash[:], signature) == nil
	case "ES256", "ES512":
		curve, size, crv := elliptic.P256(), 32, "P-256"
		hash := sha256.Sum256(input)
		digest := hash[:]
		if alg == "ES512" {
			curve, size, crv = elliptic.P521(), 66, "P-521"
			hash := sha512.Sum512(input)
			digest = hash[:]
		}
		x, y := decode(key["x"]), decode(key["y"])
		if key["kty"] != "EC" || key["crv"] != crv || len(x) != size || len(y) != size || len(signature) != 2*size {
			t.Fatal("invalid EC key or signature")
		}
		public, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			t.Fatal("invalid EC public point")
		}
		valid = ecdsa.Verify(public, digest, new(big.Int).SetBytes(signature[:size]), new(big.Int).SetBytes(signature[size:]))
	default:
		t.Fatal("unexpected signing algorithm")
	}
	if !valid {
		t.Fatal("independent JWT signature verification failed")
	}
	return claims
}

func verifyCaddyJWKSToken(t *testing.T, keys []map[string]string, signed, alg, kid string) map[string]any {
	t.Helper()
	claims := verifyCaddyJWKSSignature(t, keys, signed, alg, kid)
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if claims["sub"] != "keyadmin" || !expOK || !iatOK || exp <= float64(time.Now().Unix()) || exp-iat != 900 {
		t.Fatal("portal JWT identity or default lifetime changed")
	}
	return claims
}

func assertCaddyGatekeeper(t *testing.T, f *caddyAdminFixture, token string, allowed bool) {
	t.Helper()
	for _, headers := range []http.Header{{"Authorization": {"Bearer " + token}}, {"Cookie": {"AUTHP_ACCESS_TOKEN=" + token}}} {
		status, _, body := jwksHTTPRequest(t, f, "GET", "/protected", headers)
		if allowed && (status != 200 || string(body) != "allowed") {
			t.Fatalf("ordinary gatekeeper rejected portal token: HTTP %d", status)
		}
		if !allowed && status != 302 && status != 401 && status != 403 {
			t.Fatalf("ordinary gatekeeper accepted unintended token: HTTP %d", status)
		}
	}
}

func TestCaddyJWKSProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_JWKS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, certKey, roots := cookieTLSCertificate(t)
	ed := newJWKSKeyFiles(t, "OKP", "ed-current")
	rsaKey := newJWKSKeyFiles(t, "RSA", "rsa")
	ec := newJWKSKeyFiles(t, "EC", "ec")
	for _, tc := range []struct {
		name, alg, kid, portal, policy string
	}{
		{name: "omitted", alg: "ES512", portal: "crypto default autogenerate tag jwks-default", policy: "crypto default autogenerate tag jwks-default"},
		{name: "generated_EdDSA", alg: "EdDSA", portal: "crypto default autogenerate tag jwks-ed\ncrypto default autogenerate algorithm EdDSA", policy: "crypto default autogenerate tag jwks-ed\ncrypto default autogenerate algorithm EdDSA"},
		{name: "generated_Ed25519", alg: "Ed25519", portal: "crypto default autogenerate tag jwks-ed\ncrypto default autogenerate algorithm Ed25519", policy: "crypto default autogenerate tag jwks-ed\ncrypto default autogenerate algorithm EdDSA"},
		{name: "persisted_Ed25519", alg: "EdDSA", kid: "ed-current", portal: ed.signer("ed-current"), policy: ed.verifier("ed-current")},
		{name: "persisted_with_autogeneration_label", alg: "EdDSA", kid: "ed-current", portal: "crypto default autogenerate algorithm Ed25519\n" + ed.signer("ed-current"), policy: "crypto default autogenerate algorithm Ed25519\n" + ed.verifier("ed-current")},
		{name: "legacy_RSA", alg: "RS512", kid: "rsa", portal: rsaKey.signer("rsa"), policy: rsaKey.verifier("rsa")},
		{name: "legacy_EC", alg: "ES256", kid: "ec", portal: ec.signer("ec"), policy: ec.verifier("ec")},
	} {
		for _, mount := range []string{"", "/tenant/auth"} {
			t.Run(tc.name+mount, func(t *testing.T) {
				f := newCaddyJWKSFixture(t, mount, tc.portal, tc.policy, certFile, certKey, roots)
				keys := fetchCaddyJWKS(t, f, 1)
				token := f.login(t, "keyadmin")
				verifyCaddyJWKSToken(t, keys, token, tc.alg, tc.kid)
				assertCaddyGatekeeper(t, f, token, true)
				f.request(t, "GET", adminExportPath, token, "", 404)
				// Discovery must also remain public after an authenticated session.
				status, headers, _ := jwksHTTPRequest(t, f, "GET", mount+adminJWKSPath, http.Header{"Cookie": {"AUTHP_ACCESS_TOKEN=" + token}})
				if status != 200 || len(headers.Values("Set-Cookie")) != 0 {
					t.Fatal("public discovery changed the logged-in session")
				}
				if mount != "" {
					for _, target := range []string{adminJWKSPath, mount + "evil" + adminJWKSPath, "/other" + mount + adminJWKSPath} {
						status, headers, body := jwksHTTPRequest(t, f, "GET", target, nil)
						if status != 302 || headers.Get("Location") == "" {
							t.Fatal("JWKS escaped the exact Caddy mount boundary")
						}
						assertNoCaddyJWKS(t, headers, body, keys)
					}
				}
				for _, target := range []string{mount + adminJWKSPath + "/", mount + adminJWKSPath + "%2f", mount + adminJWKSPath + ".extra", mount + "/?path=" + adminJWKSPath, mount + "/oidc/jwks"} {
					for _, accept := range []string{"text/html", "application/json"} {
						_, headers, body := jwksHTTPRequest(t, f, "GET", target, http.Header{"Accept": {accept}})
						assertNoCaddyJWKS(t, headers, body, keys)
					}
				}
			})
		}
	}
	t.Run("key_sources", func(t *testing.T) {
		private, err := os.ReadFile(ed.private)
		if err != nil {
			t.Fatal(err)
		}
		public, err := os.ReadFile(ed.public)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("CADDY_JWKS_PRIVATE", string(private))
		t.Setenv("CADDY_JWKS_PUBLIC", string(public))
		t.Setenv("CADDY_JWKS_PRIVATE_FILE", ed.private)
		t.Setenv("CADDY_JWKS_PUBLIC_DIR", filepath.Dir(ed.public))
		for _, tc := range []struct{ name, portal, policy string }{
			{"directory", fmt.Sprintf("crypto key ignored sign-verify from directory %q", filepath.Dir(ed.private)), fmt.Sprintf("crypto key ignored verify from directory %q", filepath.Dir(ed.public))},
			{"env_pem", "crypto key ed-current sign-verify from env CADDY_JWKS_PRIVATE as key", "crypto key ed-current verify from env CADDY_JWKS_PUBLIC"},
			{"env_paths", "crypto key ed-current sign-verify from env CADDY_JWKS_PRIVATE_FILE as file", "crypto key ignored verify from env CADDY_JWKS_PUBLIC_DIR as directory"},
			{"replacer", "crypto key ed-current sign-verify from file {env.CADDY_JWKS_PRIVATE_FILE}", ed.verifier("ed-current")},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newCaddyJWKSFixture(t, "/auth", tc.portal, tc.policy, certFile, certKey, roots)
				keys := fetchCaddyJWKS(t, f, 1)
				token := f.login(t, "keyadmin")
				verifyCaddyJWKSToken(t, keys, token, "EdDSA", "ed-current")
				assertCaddyGatekeeper(t, f, token, true)
			})
		}
	})
	const hmacKey = "synthetic-jwks-hmac-key"
	const system = "crypto key system-key system 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Run("selection", func(t *testing.T) {
		for _, tc := range []struct {
			name, portal string
			count        int
		}{
			{"HMAC_first", "crypto key shared sign-verify " + hmacKey + "\n" + ed.signer("ed-current") + "\n" + rsaKey.signer("rsa"), 0},
			{"verification_public_only", ed.verifier("ed-current"), 0},
			{"public_sign_verify", strings.Replace(ed.verifier("ed-current"), " verify ", " sign-verify ", 1), 0},
			{"verification_private_only", strings.Replace(ed.signer("ed-current"), "sign-verify", "verify", 1), 0},
			{"system_and_verifier", system + "\n" + ed.verifier("ed-current"), 0},
			{"mixed", system + "\n" + ed.verifier("excluded") + "\n" + ed.signer("ed-current") + "\ncrypto key shared sign-verify " + hmacKey + "\n" + rsaKey.signer("rsa") + "\n" + ec.signer("ec"), 3},
			{"sign_only", strings.Replace(ed.signer("ed-current"), "sign-verify", "sign", 1) + "\n" + ed.verifier("verifier"), 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newCaddyJWKSFixture(t, "/auth", tc.portal, "crypto key shared verify "+hmacKey+"\n"+ed.verifier("ed-current"), certFile, certKey, roots)
				keys := fetchCaddyJWKS(t, f, tc.count)
				if tc.count > 0 {
					token := f.login(t, "keyadmin")
					claims := verifyCaddyJWKSToken(t, keys, token, "EdDSA", "ed-current")
					assertCaddyGatekeeper(t, f, token, true)
					if tc.count == 3 && (keys[0]["kid"] != "ed-current" || keys[1]["kid"] != "rsa" || keys[2]["kid"] != "ec") {
						t.Fatal("mixed JWKS lost signing order or leaked an excluded key")
					}
					if tc.name == "mixed" {
						// Later entries must be usable too. Publication does not add
						// these keys to the policy's explicitly configured verifiers.
						for _, signer := range []struct {
							kid    string
							method jwt.SigningMethod
							key    crypto.Signer
						}{
							{"rsa", jwt.SigningMethodRS512, rsaKey.key},
							{"ec", jwt.SigningMethodES256, ec.key},
						} {
							signed := jwt.NewWithClaims(signer.method, jwt.MapClaims(claims))
							signed.Header["kid"] = signer.kid
							compact, err := signed.SignedString(signer.key)
							if err != nil {
								t.Fatal("could not sign with later JWKS key")
							}
							verifyCaddyJWKSToken(t, keys, compact, signer.method.Alg(), signer.kid)
							assertCaddyGatekeeper(t, f, compact, false)
						}
					}
				} else if tc.name == "HMAC_first" {
					token := f.login(t, "keyadmin")
					parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(hmacKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
					if err != nil || !parsed.Valid || parsed.Header["kid"] != "shared" {
						t.Fatal("HMAC-first portal changed signer")
					}
					assertCaddyGatekeeper(t, f, token, true)
				}
			})
		}
	})
	t.Run("negotiation_precedence_at_reserved_segments", func(t *testing.T) {
		// These deliberately awkward mounts test discovery dispatch only, not
		// browser login; ordinary portal mounts must avoid reserved segments.
		for _, mount := range []string{"/tenant/api/auth", "/tenant/qrcode/auth"} {
			t.Run(mount, func(t *testing.T) {
				f := newCaddyJWKSFixture(t, mount, ed.signer("ed-current"), ed.verifier("ed-current"), certFile, certKey, roots)
				fetchCaddyJWKS(t, f, 1)
			})
		}
	})
	t.Run("reload_discovery_availability", func(t *testing.T) {
		f := newCaddyJWKSFixture(t, "/auth", ed.signer("ed-current"), ed.verifier("ed-current"), certFile, certKey, roots)
		original := f.input
		fetchCaddyJWKS(t, f, 1)
		for _, settings := range []string{
			"crypto key shared sign-verify " + hmacKey + "\n" + ed.signer("ed-current"),
			ed.verifier("ed-current"),
		} {
			f.input = strings.Replace(original, ed.signer("ed-current"), settings, 1)
			if err := f.reload(""); err != nil {
				t.Fatal("could not reload discovery configuration")
			}
			fetchCaddyJWKS(t, f, 0)
		}
		f.input = original
		if err := f.reload(""); err != nil {
			t.Fatal("could not restore asymmetric signer")
		}
		keys := fetchCaddyJWKS(t, f, 1)
		verifyCaddyJWKSToken(t, keys, f.login(t, "keyadmin"), "EdDSA", "ed-current")
	})
	// Exercise the gatekeeper with valid signatures as well as malformed tokens.
	t.Run("gatekeeper_trust", func(t *testing.T) {
		f := newCaddyJWKSFixture(t, "/auth", ed.signer("ed-current"), ed.verifier("ed-current"), certFile, certKey, roots)
		token := f.login(t, "keyadmin")
		claims := verifyCaddyJWKSToken(t, fetchCaddyJWKS(t, f, 1), token, "EdDSA", "ed-current")
		assertCaddyGatekeeper(t, f, token, true)
		for _, alg := range []string{"EdDSA", "Ed25519"} {
			key := oauthE2EKey{id: "ed-current", alg: alg, private: ed.key}
			signed, err := key.sign(claims, "")
			if err != nil {
				t.Fatal(err)
			}
			assertCaddyGatekeeper(t, f, signed, true)
			rogue := newOAuthE2EKey(t, "ed-current", alg)
			signed, err = rogue.sign(claims, "")
			if err != nil {
				t.Fatal(err)
			}
			assertCaddyGatekeeper(t, f, signed, false)
		}
		// Dedicated OP/ID-token RS256 material is a different trust domain.
		foreign := oauthE2EKey{id: "ed-current", alg: "RS256", private: rsaKey.key}
		foreignToken, err := foreign.sign(claims, "")
		if err != nil {
			t.Fatal(err)
		}
		assertCaddyGatekeeper(t, f, foreignToken, false)
		confused := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
		confused.Header["kid"] = "ed-current"
		confusedToken, err := confused.SignedString([]byte(ed.key.Public().(ed25519.PublicKey)))
		if err != nil {
			t.Fatal(err)
		}
		assertCaddyGatekeeper(t, f, confusedToken, false)
		parts := strings.Split(token, ".")
		header, _ := json.Marshal(map[string]string{"alg": "Ed25519", "kid": "ed-current"})
		assertCaddyGatekeeper(t, f, base64.RawURLEncoding.EncodeToString(header)+"."+parts[1]+"."+parts[2], false)
		assertCaddyGatekeeper(t, f, parts[0]+"."+parts[1]+".", false)
		for _, failure := range []string{"expired", "wrong_role"} {
			t.Run(failure, func(t *testing.T) {
				modified := make(map[string]any, len(claims))
				for name, value := range claims {
					modified[name] = value
				}
				if failure == "expired" {
					modified["exp"] = time.Now().Add(-time.Hour).Unix()
				} else {
					modified["roles"] = []string{"untrusted/user"}
				}
				key := oauthE2EKey{id: "ed-current", alg: "EdDSA", private: ed.key}
				signed, err := key.sign(modified, "")
				if err != nil {
					t.Fatal(err)
				}
				assertCaddyGatekeeper(t, f, signed, false)
			})
		}
	})
	for _, algorithm := range []string{"EdDSA", "Ed25519"} {
		t.Run("export_and_reimport_"+algorithm, func(t *testing.T) {
			dir := t.TempDir()
			privateFile, publicFile := filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem")
			settings := "crypto default autogenerate tag export-" + algorithm + "\ncrypto default autogenerate algorithm " + algorithm
			f := newCaddyJWKSFixture(t, "/auth", settings, settings, certFile, certKey, roots)
			originalToken := f.login(t, "keyadmin")
			originalKeys := fetchCaddyJWKS(t, f, 1)
			verifyCaddyJWKSToken(t, originalKeys, originalToken, algorithm, "")
			f.request(t, "GET", adminExportPath, originalToken, "", 404)
			if err := f.reload("enable admin api\nenable admin api private key export"); err != nil {
				t.Fatal("could not enable private export")
			}
			_, data := f.request(t, "GET", adminExportPath, originalToken, "", 200)
			var exported struct {
				Keys []struct {
					Public  map[string]string `json:"public_key"`
					Private string            `json:"private_key"`
				} `json:"keys"`
			}
			if json.Unmarshal(data, &exported) != nil || len(exported.Keys) != 1 {
				t.Fatal("private export lost keys array")
			}
			entry := exported.Keys[0]
			block, rest := pem.Decode([]byte(entry.Private))
			if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
				t.Fatal("private export is not PKCS#8 PEM")
			}
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal("private export did not parse")
			}
			private, ok := parsed.(ed25519.PrivateKey)
			if !ok || entry.Public["x"] != originalKeys[0]["x"] || entry.Public["alg"] != algorithm || base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) != entry.Public["x"] {
				t.Fatal("private export changed signing material or exact label")
			}
			publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
			if err != nil {
				t.Fatal("could not marshal exported public key")
			}
			// These files outlive both Caddy instances.
			if err := os.WriteFile(privateFile, []byte(entry.Private), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(publicFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0600); err != nil {
				t.Fatal(err)
			}
			// Keep export and reimport in one test: filtering a later phase must
			// still create the persisted material that it needs.
			f.client.CloseIdleConnections()
			if err := caddy.Stop(); err != nil {
				t.Fatal("could not stop Caddy before reimport")
			}
			f = newCaddyJWKSFixture(t, "/auth", fmt.Sprintf("crypto key sign-verify from file %q", privateFile), fmt.Sprintf("crypto key verify from file %q", publicFile), certFile, certKey, roots)
			keys := fetchCaddyJWKS(t, f, 1)
			if keys[0]["x"] != originalKeys[0]["x"] {
				t.Fatal("persisted key material changed")
			}
			// PEM retains material, not a JOSE preference: both exported labels
			// reimport with EdDSA, while old Ed25519 tokens remain valid.
			newToken := f.login(t, "keyadmin")
			verifyCaddyJWKSToken(t, keys, newToken, "EdDSA", "")
			assertCaddyGatekeeper(t, f, originalToken, true)
			assertCaddyGatekeeper(t, f, newToken, true)
			f.request(t, "GET", adminExportPath, newToken, "", 404)
		})
	}
}
