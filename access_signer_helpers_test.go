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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

const accessSignerAudience = "signer-resource"

type accessSignerOptions struct {
	mount, cookie, tokenLabel, transform string
	maximum, lifetime, cookieLifetime    int
	mfa, refresh, oidc                   bool
	configure                            func(string) string
	seed                                 func(*testing.T, string)
}

type accessSignerFixture struct {
	*localIdentityFixture
	key     jwksKeyFiles
	kid     string
	maximum int64
	cookie  string
}

func accessSignerOrigin(t *testing.T, input string) string {
	t.Helper()
	for line := range strings.SplitSeq(input, "\n") {
		if strings.HasPrefix(line, "https://") {
			return strings.Fields(line)[0]
		}
	}
	t.Fatal("signer fixture has no HTTPS origin")
	return ""
}

// Overlay only the existing fixture's access-key entries. OP/system keys retain
// their separate producers, and there is no ordinary signing key left as fallback.
func accessSignerConfigure(t *testing.T, options accessSignerOptions, key jwksKeyFiles, kid string, input string) string {
	t.Helper()
	origin := accessSignerOrigin(t, input)
	issuer := origin + options.mount
	maximum := options.maximum
	if maximum == 0 {
		maximum = 60
	}
	lifetime := options.lifetime
	if lifetime == 0 {
		lifetime = 45
	}
	profile := fmt.Sprintf("access token profile {\nissuer %s\naudience %s\nkey ids %s\nmax lifetime %d\n}\n", issuer, accessSignerAudience, kid, maximum)
	declaration := fmt.Sprintf("access signer rsapss selected {\nkey file %q\nkey id %s\nalgorithm PS256\nissuer %s\naudience %s\nmax lifetime %ds\n}\n", key.private, kid, issuer, accessSignerAudience, maximum)
	var lines []string
	for line := range strings.SplitSeq(input, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "crypto" && fields[1] == "key" && fields[2] == "access" {
			line = key.verifier(kid)
		}
		lines = append(lines, line)
	}
	input = strings.Join(lines, "\n")
	input = strings.Replace(input, "security {", "security {\n"+declaration, 1)
	portal := "access signer selected\n" + profile + "transform user {\nmatch any\naction overwrite aud " + accessSignerAudience + "\n}\n" + options.transform
	if !strings.Contains(input, "cookie path /") {
		portal += "cookie path /\n"
	}
	if options.tokenLabel != "" {
		portal += "crypto default token name " + options.tokenLabel + "\n"
	}
	if options.cookie != "" {
		portal += "cookie access token name " + options.cookie + "\n"
	}
	if options.cookieLifetime > 0 {
		portal += fmt.Sprintf("cookie lifetime %d\n", options.cookieLifetime)
	}
	input = strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\n"+portal, 1)
	input = strings.Replace(input, "authorization policy app_policy {", "authorization policy app_policy {\n"+profile, 1)
	input = strings.ReplaceAll(input, "crypto default token lifetime 600", fmt.Sprintf("crypto default token lifetime %d", lifetime))
	if options.cookie != "" {
		input = strings.Replace(input, "validate bearer header", "validate bearer header\nset token sources cookie header\nset access_token cookie name "+options.cookie, 1)
	}
	mount := options.mount
	if mount == "" {
		mount = "/"
	}
	if !strings.Contains(input, "authenticate with myportal at ") {
		input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at "+mount, 1)
	}
	input = strings.Replace(input, "level DEBUG", "level INFO", 1)
	input = strings.Replace(input, "format json", "format filter {\nwrap json\nfields {\nresp_headers>Location delete\n}\n}", 1)
	if !strings.Contains(input, "request>uri delete") {
		input = strings.ReplaceAll(input, "resp_headers>Location delete", "resp_headers>Location delete\nrequest>uri delete\nrequest>headers>Referer delete")
	}
	if options.configure != nil {
		input = options.configure(input)
	}
	return input
}

func newAccessSignerFixture(t *testing.T, options accessSignerOptions, cert, tlsKey string, roots *x509.CertPool) *accessSignerFixture {
	t.Helper()
	key := newJWKSKeyFiles(t, "RSA", "selected")
	local := localIdentityOptions{mount: options.mount, mfa: options.mfa, seed: options.seed}
	if options.refresh {
		local.refreshRealm = "local"
	}
	if options.oidc {
		local.oidcRealm = "local"
	}
	local.configure = func(input string) string { return accessSignerConfigure(t, options, key, "selected", input) }
	f := &accessSignerFixture{localIdentityFixture: newLocalIdentityFixture(t, local, cert, tlsKey, roots), key: key, kid: "selected", maximum: int64(options.maximum), cookie: options.cookie}
	if f.maximum == 0 {
		f.maximum = 60
	}
	if f.cookie == "" {
		f.cookie = "AUTHP_ACCESS_TOKEN"
	}
	private, err := os.ReadFile(key.private)
	if err != nil {
		t.Fatal("cannot inventory private signing key")
	}
	f.secrets = append(f.secrets, string(private))
	accessSignerCaptureCookies(f.localIdentityFixture)
	return f
}

func accessSignerNumber(t *testing.T, claims map[string]any, name string) int64 {
	t.Helper()
	n, ok := claims[name].(json.Number)
	if !ok {
		t.Fatalf("signed claim %s is not an exact number", name)
	}
	v, err := n.Int64()
	if err != nil {
		t.Fatalf("signed claim %s is not an integer", name)
	}
	return v
}

// Independent verification: standard-library RSA-PSS, exact salt length and
// UseNumber. Never call the signer/profile implementation to verify its output.
func accessSignerVerify(t *testing.T, token, issuer, audience, kid string, maximum int64, keys []map[string]string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 100<<10 {
		t.Fatal("invalid selected access-token envelope")
	}
	var header map[string]string
	encoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || json.Unmarshal(encoded, &header) != nil || len(header) != 3 || header["alg"] != "PS256" || header["typ"] != "authcrunch-access+jwt" || header["kid"] != kid {
		t.Fatal("selected access header changed algorithm, purpose or key")
	}
	var public *rsa.PublicKey
	for _, key := range keys {
		if key["kid"] != kid {
			continue
		}
		if public != nil || key["kty"] != "RSA" || key["alg"] != "PS256" || key["use"] != "sig" {
			t.Fatal("selected discovery key has ambiguous metadata")
		}
		n, e1 := base64.RawURLEncoding.Strict().DecodeString(key["n"])
		e, e2 := base64.RawURLEncoding.Strict().DecodeString(key["e"])
		exponent := new(big.Int).SetBytes(e)
		if e1 != nil || e2 != nil || len(e) > 4 || !exponent.IsInt64() || exponent.Int64() < 3 {
			t.Fatal("selected discovery RSA key is malformed")
		}
		public = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}
	}
	if public == nil {
		t.Fatal("selected discovery key missing")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPSS(public, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}) != nil {
		t.Fatal("selected access signature failed independent verification")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		t.Fatal("invalid selected claim encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var claims map[string]any
	if decoder.Decode(&claims) != nil || decoder.Decode(new(any)) != io.EOF || claims["iss"] != issuer {
		t.Fatal("selected access claims changed issuer or encoding")
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		t.Fatal("selected access token lost its subject")
	}
	aud := claims["aud"]
	if values, ok := aud.([]any); ok && len(values) == 1 {
		aud = values[0]
	}
	if aud != audience {
		t.Fatal("selected access token broadened its audience")
	}
	iat, nbf, exp := accessSignerNumber(t, claims, "iat"), accessSignerNumber(t, claims, "nbf"), accessSignerNumber(t, claims, "exp")
	now := time.Now().Unix()
	if iat <= 0 || iat > nbf || nbf > now || exp <= now || exp-iat > maximum {
		t.Fatal("selected access token violated its strict lifetime")
	}
	return claims
}

func (f *accessSignerFixture) verify(t *testing.T, token string) map[string]any {
	t.Helper()
	f.secrets = append(f.secrets, token)
	return accessSignerVerify(t, token, f.issuer, accessSignerAudience, f.kid, f.maximum, f.keys)
}

func accessSignerRawToken(t *testing.T, key jwksKeyFiles, header, payload []byte, algorithm string, hash crypto.Hash, salt int) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := hash.New()
	_, _ = digest.Write([]byte(input))
	private := key.key.(*rsa.PrivateKey)
	var signature []byte
	var err error
	if algorithm == "RS256" {
		signature, err = rsa.SignPKCS1v15(rand.Reader, private, hash, digest.Sum(nil))
	} else {
		signature, err = rsa.SignPSS(rand.Reader, private, hash, digest.Sum(nil), &rsa.PSSOptions{SaltLength: salt, Hash: hash})
	}
	if err != nil {
		t.Fatal("could not sign independent negative fixture")
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func accessSignerJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal("could not encode signer fixture data")
	}
	return b
}

func accessSignerBrowser(t *testing.T, client *http.Client) *http.Client {
	t.Helper()
	copy := *client
	var err error
	copy.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal("cannot create signer browser")
	}
	return &copy
}

type accessSignerCaptureRoundTripper struct {
	delegate http.RoundTripper
	fixture  *localIdentityFixture
}

func (c *accessSignerCaptureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := c.delegate.RoundTrip(r)
	if response != nil {
		accessSignerCapture(c.fixture, oidcRPResponse{header: response.Header})
	}
	return response, err
}

// Collect actual returned browser proofs before shared form helpers assert.
// These fixtures make client calls sequentially; no server transport is wrapped.
func accessSignerCaptureCookies(f *localIdentityFixture) {
	f.client.Transport = &accessSignerCaptureRoundTripper{delegate: f.client.Transport, fixture: f}
	f.plain.Transport = f.client.Transport
}

func accessSignerCapture(f *localIdentityFixture, r oidcRPResponse) {
	for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
		// Preserve the existing AUTHP_SESSION_ID diagnostic-correlation exception.
		if cookie.Name != "AUTHP_SESSION_ID" && authenticationEventLiveCookie(cookie) {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	if value := r.header.Get("Authorization"); value != "" {
		f.secrets = append(f.secrets, strings.TrimPrefix(value, "Bearer "))
	}
	var response apiauth.AuthResponse
	if json.Unmarshal(r.body, &response) == nil {
		f.secrets = append(f.secrets, response.AccessToken, response.RefreshToken, response.SandboxID, response.SandboxSecret)
	}
}

func accessSignerNative(t *testing.T, f *localIdentityFixture, client *http.Client, name, transport string, mfa bool) (apiauth.AuthResponse, oidcRPResponse) {
	t.Helper()
	return accessSignerNativeRealm(t, f, client, "local", name, transport, mfa)
}

func accessSignerNativeRealm(t *testing.T, f *localIdentityFixture, client *http.Client, realm, name, transport string, mfa bool) (apiauth.AuthResponse, oidcRPResponse) {
	t.Helper()
	post := func(stage string, input apiauth.AuthRequest) (apiauth.AuthResponse, oidcRPResponse) {
		t.Helper()
		r := f.json(t, client, "/login", input, "")
		accessSignerCapture(f, r)
		if r.status != http.StatusOK {
			t.Fatalf("selected %s checkpoint returned HTTP %d, want 200", stage, r.status)
		}
		return localIdentityAuth(t, r), r
	}
	request := apiauth.AuthRequest{Username: name, Realm: realm, RefreshTransport: transport}
	response, raw := post("identification", request)
	if response.Authenticated || response.AccessToken != "" || response.NextChallenge != "password" || response.SandboxID == "" || response.SandboxSecret == "" {
		t.Fatal("signer login skipped its real password checkpoint")
	}
	request.SandboxID, request.SandboxSecret = response.SandboxID, response.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "password", lifecyclePassword
	response, raw = post("password", request)
	if mfa {
		if response.Authenticated || response.AccessToken != "" || response.RefreshToken != "" || response.NextChallenge != "totp" {
			t.Fatal("selected signing bypassed required MFA")
		}
		// A successful unfinished checkpoint rotates its continuation secret.
		if response.SandboxID != request.SandboxID || response.SandboxSecret == "" || response.SandboxSecret == request.SandboxSecret {
			t.Fatal("password checkpoint did not rotate its bound continuation")
		}
		request.SandboxSecret = response.SandboxSecret
		waitForFreshFixtureTOTP(t, f.database, name)
		request.ChallengeKind, request.ChallengeResponse = "totp", authenticationClientTOTP()
		f.secrets = append(f.secrets, request.ChallengeResponse)
		response, raw = post("TOTP", request)
	}
	if !response.Authenticated {
		t.Fatal("selected signer did not complete the real credential flow")
	}
	return response, raw
}

func accessSignerLoad(input string) error {
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		return err
	}
	return caddy.Load(config, true)
}

func (f *accessSignerFixture) consumers(t *testing.T, token string, allowed bool) {
	t.Helper()
	f.secrets = append(f.secrets, token)
	for _, transport := range []string{"bearer", "cookie"} {
		headers := http.Header{"Accept": {"application/json"}}
		if transport == "bearer" {
			headers.Set("Authorization", "Bearer "+token)
		} else {
			headers.Set("Cookie", f.cookie+"="+token)
		}
		for _, target := range []string{f.issuer + "/whoami", f.base + "/resource"} {
			status, header, body := registrationHTTP(t, f.plain, "GET", target, nil, headers)
			accessSignerCapture(f.localIdentityFixture, oidcRPResponse{status, header, body})
			if allowed && status != 200 || !allowed && status == 200 {
				t.Fatalf("strict %s consumer acceptance mismatch: HTTP %d", transport, status)
			}
			if !allowed && !slices.Contains([]int{401, 403, 302, 303}, status) {
				t.Fatalf("strict consumer unexpected rejection: HTTP %d", status)
			}
		}
	}
}

// This deliberately oversized header reaches Caddy's transport limit before
// the strict JWT decoder. Decoder byte limits have separate upstream coverage;
// do not count HTTP431 as an authentication-handler rejection.
func (f *accessSignerFixture) oversizedHeaders(t *testing.T, token string) {
	t.Helper()
	f.secrets = append(f.secrets, token)
	for _, transport := range []string{"bearer", "cookie"} {
		headers := http.Header{"Accept": {"application/json"}}
		if transport == "bearer" {
			headers.Set("Authorization", "Bearer "+token)
		} else {
			headers.Set("Cookie", f.cookie+"="+token)
		}
		for _, target := range []string{f.issuer + "/whoami", f.base + "/resource"} {
			status, header, body := registrationHTTP(t, f.plain, "GET", target, nil, headers)
			accessSignerCapture(f.localIdentityFixture, oidcRPResponse{status, header, body})
			if status != http.StatusRequestHeaderFieldsTooLarge || header.Get("Location") != "" || header.Get("Authorization") != "" || len(header.Values("Set-Cookie")) != 0 {
				t.Fatalf("oversized %s header lost transport rejection without issuance: HTTP %d", transport, status)
			}
		}
	}
}

func accessSignerCookie(t *testing.T, raw oidcRPResponse, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range (&http.Response{Header: raw.header}).Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatal("selected access cookie missing")
	return nil
}

func accessSignerWait(t *testing.T, deadline time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Until(deadline)+2*time.Second)
	defer cancel()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("selected token expiry wait exceeded deadline")
	case <-timer.C:
	}
}
