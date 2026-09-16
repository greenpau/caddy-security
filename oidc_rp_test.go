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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"strings"
	"testing"
	"time"
)

type oidcRPKeys struct {
	Keys []map[string]string `json:"keys"`
}

type oidcRPClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	Nonce     string   `json:"nonce"`
	AtHash    string   `json:"at_hash"`
	Issued    int64    `json:"iat"`
	Expires   int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	AuthTime  int64    `json:"auth_time"`
	Methods   []string `json:"amr"`
}

// JWT member names are case-sensitive. A map avoids encoding/json's struct
// field folding; token-by-token decoding also rejects duplicate decoded names.
func decodeOIDCRPObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return nil, fmt.Errorf("expected JWT JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || fields[name] != nil {
			return nil, fmt.Errorf("invalid or duplicate JWT member")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid JWT member value")
		}
		fields[name] = value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, fmt.Errorf("incomplete JWT object")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JWT JSON data")
	}
	return fields, nil
}

// This RP intentionally uses only public HTTP artifacts and crypto/rsa. It
// neither calls the OP's token parser nor reads its signing key or runtime.
// The audience is a single string for this provider's single-client grants.
func verifyOIDCRPToken(raw, access, issuer, audience, nonce string, keys oidcRPKeys, now time.Time) (oidcRPClaims, string, error) {
	var claims oidcRPClaims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return claims, "", fmt.Errorf("malformed ID token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, "", fmt.Errorf("invalid ID token header encoding")
	}
	header, err := decodeOIDCRPObject(headerJSON)
	var algorithm, kid string
	if err != nil || json.Unmarshal(header["alg"], &algorithm) != nil || json.Unmarshal(header["kid"], &kid) != nil || algorithm != "RS256" || kid == "" || header["crit"] != nil || header["b64"] != nil {
		return claims, "", fmt.Errorf("invalid ID token header")
	}
	var public *rsa.PublicKey
	seen := make(map[string]bool)
	for _, key := range keys.Keys {
		for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, exists := key[secret]; exists {
				return claims, "", fmt.Errorf("private material in public JWKS")
			}
		}
		if key["kid"] == "" || seen[key["kid"]] {
			return claims, "", fmt.Errorf("ambiguous JWKS key ID")
		}
		seen[key["kid"]] = true
		if key["kid"] != kid {
			continue
		}
		if key["kty"] != "RSA" || key["alg"] != "RS256" || key["use"] != "sig" {
			return claims, "", fmt.Errorf("unexpected key purpose")
		}
		n, nerr := base64.RawURLEncoding.DecodeString(key["n"])
		e, eerr := base64.RawURLEncoding.DecodeString(key["e"])
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e)
		if nerr != nil || eerr != nil || modulus.BitLen() < 2048 || n[0] == 0 || len(e) == 0 || e[0] == 0 || exponent.BitLen() > 31 || exponent.Int64() < 3 || exponent.Bit(0) == 0 {
			return claims, "", fmt.Errorf("invalid RSA public key")
		}
		public = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	}
	if public == nil {
		return claims, "", fmt.Errorf("ID signing key missing")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) != nil {
		return claims, "", fmt.Errorf("invalid ID signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, "", fmt.Errorf("invalid ID claims encoding")
	}
	fields, err := decodeOIDCRPObject(payload)
	if err != nil {
		return claims, "", fmt.Errorf("invalid ID claims")
	}
	for name, destination := range map[string]any{
		"iss": &claims.Issuer, "sub": &claims.Subject, "aud": &claims.Audience,
		"nonce": &claims.Nonce, "at_hash": &claims.AtHash, "iat": &claims.Issued,
		"exp": &claims.Expires, "nbf": &claims.NotBefore, "auth_time": &claims.AuthTime, "amr": &claims.Methods,
	} {
		if value, exists := fields[name]; exists {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, destination) != nil {
				return claims, "", fmt.Errorf("invalid ID claim type")
			}
		}
	}
	if claims.Issuer != issuer || claims.Audience != audience || claims.Nonce != nonce || claims.Subject == "" {
		return claims, "", fmt.Errorf("invalid ID binding")
	}
	if claims.Issued <= 0 || claims.AuthTime <= 0 || claims.AuthTime > claims.Issued || claims.Issued > now.Unix() || claims.Expires <= now.Unix() || claims.Expires <= claims.Issued || claims.NotBefore > now.Unix() {
		return claims, "", fmt.Errorf("invalid ID time")
	}
	accessHash := sha256.Sum256([]byte(access))
	if access == "" || claims.AtHash != base64.RawURLEncoding.EncodeToString(accessHash[:16]) {
		return claims, "", fmt.Errorf("invalid access-token hash")
	}
	return claims, kid, nil
}

func TestOIDCRPVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	access := "synthetic-access-token"
	digest := sha256.Sum256([]byte(access))
	valid := oidcRPClaims{Issuer: "https://issuer.example/auth", Subject: "subject", Audience: "rp", Nonce: "nonce", AtHash: base64.RawURLEncoding.EncodeToString(digest[:16]), Issued: now.Unix(), Expires: now.Add(time.Minute).Unix(), AuthTime: now.Add(-time.Minute).Unix(), Methods: []string{"pwd"}}
	jwk := map[string]string{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "first", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
	keys := oidcRPKeys{Keys: []map[string]string{jwk}}
	signRaw := func(header, body string) string {
		t.Helper()
		unsigned := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body))
		digest := sha256.Sum256([]byte(unsigned))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	sign := func(claims oidcRPClaims) string {
		t.Helper()
		body, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		return signRaw(`{"alg":"RS256","kid":"first"}`, string(body))
	}
	verify := func(raw string, keys oidcRPKeys) error {
		_, _, err := verifyOIDCRPToken(raw, access, valid.Issuer, valid.Audience, valid.Nonce, keys, now)
		return err
	}
	if err := verify(sign(valid), keys); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []string{
		strings.Replace(string(body), `"iss":`, `"i\u0073s":`, 1),
		fmt.Sprintf(`{"nbf":%d,`, now.Unix()) + string(body[1:]),
	} {
		if err := verify(signRaw(`{"alg":"RS256","kid":"first","typ":"JWT"}`, payload), keys); err != nil {
			t.Fatalf("valid signed JWT rejected: %v", err)
		}
	}
	for _, header := range []struct{ name, value string }{
		{"algorithm case", `{"ALG":"RS256","kid":"first"}`},
		{"key ID case", `{"alg":"RS256","KID":"first"}`},
		{"duplicate algorithm", `{"alg":"none","alg":"RS256","kid":"first"}`},
		{"critical extension", `{"alg":"RS256","kid":"first","crit":["extension"],"extension":true}`},
		{"payload encoding", `{"alg":"RS256","kid":"first","b64":false}`},
	} {
		t.Run(header.name, func(t *testing.T) {
			if verify(signRaw(header.value, string(body)), keys) == nil {
				t.Fatal("accepted invalid signed JOSE header")
			}
		})
	}
	for _, field := range []string{"iss", "sub", "aud", "nonce", "at_hash", "iat", "exp", "auth_time"} {
		t.Run("claim case/"+field, func(t *testing.T) {
			payload := strings.Replace(string(body), `"`+field+`":`, `"`+strings.ToUpper(field)+`":`, 1)
			if verify(signRaw(`{"alg":"RS256","kid":"first"}`, payload), keys) == nil {
				t.Fatal("accepted incorrectly capitalized JWT claim")
			}
		})
	}
	for _, tc := range []struct{ name, payload string }{
		{"duplicate issuer", `{"iss":"https://attacker.example",` + string(body[1:])},
		{"escaped duplicate issuer", `{"i\u0073s":"https://attacker.example",` + string(body[1:])},
		{"not yet valid", fmt.Sprintf(`{"nbf":%d,`, now.Add(time.Minute).Unix()) + string(body[1:])},
		{"null time", `{"nbf":null,` + string(body[1:])},
		{"trailing object", string(body) + " {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if verify(signRaw(`{"alg":"RS256","kid":"first"}`, tc.payload), keys) == nil {
				t.Fatal("accepted ambiguous or premature signed claims")
			}
		})
	}
	for i, tc := range []struct{ field, value string }{
		{"kty", "EC"}, {"alg", "RS512"}, {"use", "enc"},
		{"n", ""}, {"n", "!"}, {"n", base64.RawURLEncoding.EncodeToString(append([]byte{0}, key.N.Bytes()...))},
		{"e", ""}, {"e", "!"}, {"e", "AAEAAQ"}, {"e", "Ag"},
	} {
		t.Run(fmt.Sprintf("key/%s/%d", tc.field, i), func(t *testing.T) {
			invalid := maps.Clone(jwk)
			invalid[tc.field] = tc.value
			if verify(sign(valid), oidcRPKeys{Keys: []map[string]string{invalid}}) == nil {
				t.Fatal("accepted invalid RSA key encoding or purpose")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*oidcRPClaims)
	}{
		{"issuer", func(c *oidcRPClaims) { c.Issuer += "/other" }},
		{"audience", func(c *oidcRPClaims) { c.Audience = "other" }},
		{"nonce", func(c *oidcRPClaims) { c.Nonce = "other" }},
		{"subject", func(c *oidcRPClaims) { c.Subject = "" }},
		{"at_hash", func(c *oidcRPClaims) { c.AtHash = "wrong" }},
		{"expired", func(c *oidcRPClaims) { c.Expires = now.Unix() }},
		{"future issuance", func(c *oidcRPClaims) { c.Issued++ }},
		{"future authentication", func(c *oidcRPClaims) { c.AuthTime = c.Issued + 1 }},
		{"missing issuance", func(c *oidcRPClaims) { c.Issued = 0 }},
		{"missing authentication", func(c *oidcRPClaims) { c.AuthTime = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.change(&claims)
			if verify(sign(claims), keys) == nil {
				t.Fatal("accepted invalid signed claims")
			}
		})
	}
	parts := strings.Split(sign(valid), ".")
	if verify(parts[0]+"."+parts[1]+".AAAA", keys) == nil || verify(sign(valid), oidcRPKeys{}) == nil {
		t.Fatal("accepted invalid signature or unknown key")
	}
	if verify(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"first"}`))+"."+parts[1]+".", keys) == nil {
		t.Fatal("accepted unsigned token")
	}
	keys.Keys = append(keys.Keys, jwk)
	if verify(sign(valid), keys) == nil {
		t.Fatal("accepted ambiguous signing key")
	}
	keys.Keys = keys.Keys[:1]
	jwk["d"] = "private"
	if verify(sign(valid), keys) == nil {
		t.Fatal("accepted private JWKS")
	}
}
