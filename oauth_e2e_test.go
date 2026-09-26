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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	_ "unsafe" // Required by the test-only system-root hook below.

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/golang-jwt/jwt/v5"
)

const oauthE2EClient = "caddy-oauth-client"
const oauthE2ESecret = "synthetic-upstream-client-secret"
const oauthE2EPortalKey = "synthetic-independent-portal-signing-key"

// oauthE2ESystemRoots uses the root-pool hook retained by crypto/x509 for
// github.com/breml/rootcerts (Go issue 67401). Caddy has already called
// SetFallbackRoots during init, so that public API cannot install fixture roots.
// Only the isolated child replaces this pointer, after SystemCertPool initializes
// it and before starting any TLS clients. No OS trust store is changed.
//
//go:linkname oauthE2ESystemRoots crypto/x509.systemRoots
var oauthE2ESystemRoots *x509.CertPool

// A child isolates Caddy globals and the fixture's trusted root pool. Verification
// remains enabled on every TLS connection, including authcrunch's HTTP client.
func TestCaddyOAuthE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyOAuthProcess$", "-test.v", "-test.timeout=150s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_OAUTH_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS Caddy OAuth: %v\n%s", err, output)
	}
}

type oauthE2EKey struct {
	id, alg string
	private crypto.Signer
	public  map[string]string
}

func newOAuthE2EKey(t *testing.T, id, alg string) oauthE2EKey {
	t.Helper()
	key := oauthE2EKey{id: id, alg: alg, public: map[string]string{"kid": id, "alg": alg, "use": "sig"}}
	encode := base64.RawURLEncoding.EncodeToString
	switch alg {
	case "RS256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key.private = k
		key.public["kty"] = "RSA"
		key.public["n"] = encode(k.N.Bytes())
		key.public["e"] = "AQAB"
	case "ES256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key.private = k
		key.public["kty"] = "EC"
		key.public["crv"] = "P-256"
		key.public["x"] = encode(k.X.FillBytes(make([]byte, 32)))
		key.public["y"] = encode(k.Y.FillBytes(make([]byte, 32)))
	default:
		pub, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key.private = k
		key.public["kty"] = "OKP"
		key.public["crv"] = "Ed25519"
		key.public["x"] = encode(pub)
	}
	return key
}

// Sign with Go's crypto primitives, independently of the upstream JWT parser.
func (k oauthE2EKey) sign(claims map[string]any, failure string) (string, error) {
	header := map[string]string{"alg": k.alg, "kid": k.id, "typ": "JWT"}
	if failure == "unknown kid" {
		header["kid"] = "unknown"
	}
	if failure == "missing kid" {
		delete(header, "kid")
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	var signature []byte
	switch key := k.private.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, []byte(input))
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		var r, s []byte
		rr, ss, e := ecdsa.Sign(rand.Reader, key, hash[:])
		err = e
		if err == nil {
			r = rr.FillBytes(make([]byte, 32))
			s = ss.FillBytes(make([]byte, 32))
			signature = append(r, s...)
		}
	}
	if err != nil {
		return "", err
	}
	if failure == "signature" {
		signature[0] ^= 1
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (k oauthE2EKey) pem(t *testing.T, pkcs1 bool) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.private.Public())
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	if pkcs1 {
		block.Type = "RSA PUBLIC KEY"
		block.Bytes = x509.MarshalPKCS1PublicKey(k.private.Public().(*rsa.PublicKey))
	}
	path := filepath.Join(t.TempDir(), "upstream public.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type oauthE2ECode struct{ state, nonce, challenge, redirect, subject string }
type oauthE2EUpstream struct {
	mu                                                           sync.Mutex
	server                                                       *httptest.Server
	identity, access                                             oauthE2EKey
	keys                                                         []map[string]string
	callback, discoveredIssuer, tokenIssuer, accessMode, failure string
	clientID, clientSecret, accessAudience                       string
	// Optional persistent-state fixtures: large verified identities exercise
	// the real snapshot bound; holds exercise reload with an admitted callback.
	identityName                                                      string
	exchangeEntered                                                   chan struct{}
	exchangeRelease                                                   <-chan struct{}
	codes                                                             map[string]oauthE2ECode
	subjects                                                          map[string]string
	issuedSecrets                                                     []string
	metadataFetches, keyFetches, exchanges, authorizations, userInfos int
}

func newOAuthE2EUpstream(t *testing.T, cert tls.Certificate, alg string) *oauthE2EUpstream {
	t.Helper()
	f := &oauthE2EUpstream{identity: newOAuthE2EKey(t, "identity", alg), access: newOAuthE2EKey(t, "access", "Ed25519"), codes: make(map[string]oauthE2ECode), subjects: make(map[string]string), accessMode: "jwt"}
	f.clientID, f.clientSecret, f.accessAudience = oauthE2EClient, oauthE2ESecret, "resource-api"
	if alg == "EdDSA" {
		f.access = newOAuthE2EKey(t, "access", "EdDSA")
	}
	f.keys = []map[string]string{f.identity.public, f.access.public}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(t, w, r) }))
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.server.StartTLS()
	f.discoveredIssuer = f.server.URL
	f.tokenIssuer = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *oauthE2EUpstream) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.TLS == nil {
		t.Error("upstream request lacked TLS")
		w.WriteHeader(400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/metadata":
		f.metadataFetches++
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.discoveredIssuer, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "userinfo_endpoint": f.server.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"EdDSA", "Ed25519", "RS256", "ES256", "unknown"}})
	case "/jwks":
		f.keyFetches++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": f.keys})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != f.clientID || q.Get("redirect_uri") != f.callback || q.Get("response_type") != "code" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			t.Error("authorization request violated client, redirect, state, nonce, or PKCE contract")
			w.WriteHeader(400)
			return
		}
		f.authorizations++
		code := fmt.Sprintf("one-use-code-%d", f.authorizations)
		f.issuedSecrets = append(f.issuedSecrets, code)
		record := oauthE2ECode{q.Get("state"), q.Get("nonce"), q.Get("code_challenge"), f.callback, fmt.Sprintf("external-user-%d", f.authorizations)}
		if f.failure == "pkce" {
			record.challenge = "mismatched-challenge"
		}
		f.codes[code] = record
		params := url.Values{"code": {code}, "state": {q.Get("state")}}
		if f.failure == "state" {
			params.Set("state", "wrong-state")
		}
		http.Redirect(w, r, f.callback+"?"+params.Encode(), 302)
	case "/token":
		if f.exchangeEntered != nil {
			close(f.exchangeEntered)
			<-f.exchangeRelease
			f.exchangeEntered = nil
		}
		if r.Method != "POST" || r.ParseForm() != nil {
			t.Error("invalid code exchange method")
			w.WriteHeader(400)
			return
		}
		record, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		verifier := r.Form.Get("code_verifier")
		challenge := sha256.Sum256([]byte(verifier))
		bound := ok && r.Form.Get("client_id") == f.clientID && r.Form.Get("client_secret") == f.clientSecret && r.Form.Get("redirect_uri") == record.redirect && r.Form.Get("grant_type") == "authorization_code" && r.Form.Get("state") == record.state
		if !bound || len(verifier) < 43 || base64.RawURLEncoding.EncodeToString(challenge[:]) != record.challenge {
			if f.failure != "pkce" {
				t.Error("code exchange violated client, redirect, state, or PKCE binding")
			}
			w.WriteHeader(400)
			return
		}
		f.exchanges++
		id := map[string]any{"iss": f.tokenIssuer, "aud": f.clientID, "sub": record.subject, "email": record.subject + "@example.test", "name": "External User", "nonce": record.nonce, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"authp/user"}}
		if f.identityName != "" {
			id["name"] = f.identityName
		}
		access := map[string]any{"iss": f.tokenIssuer, "aud": f.accessAudience, "azp": f.clientID, "exp": time.Now().Add(time.Hour).Unix(), "roles": []string{"resource/editor"}}
		switch f.failure {
		case "identity issuer":
			id["iss"] = "https://wrong.example"
		case "identity audience":
			id["aud"] = "resource-api"
		case "identity nonce":
			id["nonce"] = "wrong-nonce"
		case "identity expired":
			id["exp"] = time.Now().Add(-time.Hour).Unix()
		case "access issuer":
			access["iss"] = "https://wrong.example"
		case "access audience":
			access["aud"] = "wrong-api"
		case "access azp":
			access["azp"] = "wrong-client"
		case "access expired":
			access["exp"] = time.Now().Add(-time.Hour).Unix()
		}
		identityFailure := strings.TrimPrefix(f.failure, "identity ")
		signedID, err := f.identity.sign(id, identityFailure)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		signedAccess := "opaque-" + record.subject
		if f.accessMode == "jwt" {
			signedAccess, err = f.access.sign(access, strings.TrimPrefix(f.failure, "access "))
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
		}
		if f.accessMode == "identity" || f.accessMode == "identity wrong audience" {
			if f.accessMode == "identity wrong audience" {
				id["aud"] = "resource-api"
			}
			signedAccess, err = f.identity.sign(id, "")
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
		}
		f.subjects[signedAccess] = record.subject
		f.issuedSecrets = append(f.issuedSecrets, signedID, signedAccess)
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": signedID, "access_token": signedAccess, "token_type": "Bearer", "expires_in": 3600})
	case "/userinfo":
		subject, ok := f.subjects[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			t.Error("userinfo did not receive original access token")
			w.WriteHeader(401)
			return
		}
		f.userInfos++
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": subject, "email": subject + "@example.test", "roles": []string{"userinfo/user"}})
	default:
		http.NotFound(w, r)
	}
}

type caddyOAuthFixture struct {
	upstream    *oauthE2EUpstream
	client      *http.Client
	base, input string
	secrets     map[string]string
}

func newCaddyOAuthFixture(t *testing.T, upstream *oauthE2EUpstream, mode, issuer, audience, certFile, keyFile string, roots *x509.CertPool, options ...func(*caddyOAuthFixture)) *caddyOAuthFixture {
	t.Helper()
	provider := fmt.Sprintf("realm upstream\ndriver generic\nclient_id %s\nclient_secret \"%s\"\nbase_auth_url %s/unrelated-base-path\n", upstream.clientID, upstream.clientSecret, upstream.server.URL)
	provider += `icon "Company Login" "custom company" blue white priority 20 text black gray` + "\n"
	if mode != "static" && mode != "static-pkcs1" {
		provider += "metadata_url " + upstream.server.URL + "/metadata\n"
	}
	if mode != "discovery" {
		provider += fmt.Sprintf("authorization_url %s/authorize\ntoken_url %s/token\njwks key identity %q\n", upstream.server.URL, upstream.server.URL, upstream.identity.pem(t, mode == "static-pkcs1"))
		// combined keeps the access key remote; combined-pins pins both keys.
		if mode != "combined" {
			provider += fmt.Sprintf("jwks key access %q\n", upstream.access.pem(t, false))
		}
	}
	if issuer != "" {
		provider += fmt.Sprintf("issuer \"%s\"\n", issuer)
	}
	if audience != "" {
		provider += fmt.Sprintf("access token audience \"%s\"\n", audience)
	}
	if upstream.accessMode == "userinfo" {
		provider += "extract email roles from userinfo\n"
	}
	if strings.HasPrefix(upstream.accessMode, "identity") {
		provider += "identity_token_field_name access_token\n"
	}
	addr := lifecycleAddress(t)
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 servers {
  protocols h1 h2
 }
 log {
  level ERROR
 }
 security {
  oauth identity provider upstream {
   %s
  }
  authentication portal portal {
   enable identity provider upstream
   crypto key sign-verify %s
  }
  authorization policy policy {
   crypto key verify %s
   set token sources cookie
   allow roles authp/user resource/editor userinfo/user
  }
  authorization policy editor {
   crypto key verify %s
   set token sources cookie
   allow roles resource/editor
  }
 }
}
https://%s {
 tls %s %s
 route /auth/* {
  authenticate with portal
 }
 route /protected {
  authorize with policy
  respond allowed 200
 }
 route /editor {
  authorize with editor
  respond allowed 200
 }
}`, provider, oauthE2EPortalKey, oauthE2EPortalKey, oauthE2EPortalKey, addr, certFile, keyFile)
	f := &caddyOAuthFixture{upstream: upstream, base: "https://" + addr, input: input}
	for _, option := range options {
		option(f)
	}
	upstream.mu.Lock()
	upstream.callback = f.base + "/auth/oauth2/upstream/authorization-code-callback"
	upstream.mu.Unlock()
	data := f.adapt(t)
	upstream.mu.Lock()
	fetches := upstream.metadataFetches + upstream.keyFetches
	upstream.mu.Unlock()
	if fetches != 0 {
		t.Fatal("adaptation fetched discovery or started provider")
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(tr.CloseIdleConnections)
	f.client = &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, body := f.request(t, f.client, f.base+"/auth/login")
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Company Login") || !strings.Contains(string(body), "custom company") {
		t.Fatal("translated upstream login icon was not rendered")
	}
	return f
}

func (f *caddyOAuthFixture) adapt(t *testing.T) []byte {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.secrets != nil {
		var document map[string]any
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		app := document["apps"].(map[string]any)["security"].(map[string]any)
		app["secrets_managers"] = []any{map[string]any{"driver": "oauth_test", "values": f.secrets}}
		data, err = json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
	}
	return data
}

func (f *caddyOAuthFixture) request(t *testing.T, client *http.Client, target string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "GET", target, nil)
	if err != nil {
		t.Fatal("construct OAuth journey request")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("verified TLS OAuth request failed", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("OAuth request did not verify TLS")
	}
	return resp, body
}

func (f *caddyOAuthFixture) login(t *testing.T, valid, editor bool) string {
	t.Helper()
	client := *f.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	location := f.base + "/auth/oauth2/upstream"
	var response *http.Response
	for step := 0; step < 3; step++ {
		response, _ = f.request(t, &client, location)
		if step < 2 {
			if response.StatusCode != 302 {
				t.Fatalf("OAuth redirect %d: HTTP %d", step, response.StatusCode)
			}
			location = response.Header.Get("Location")
		}
	}
	token := jarCookie(t, client.Jar, f.base+"/protected", "AUTHP_ACCESS_TOKEN")
	want := 401
	if valid {
		want = 303
	}
	if response.StatusCode != want {
		t.Fatalf("OAuth callback: HTTP %d, want %d", response.StatusCode, want)
	}
	if !valid {
		if token != "" || response.Header.Get("Authorization") != "" {
			t.Fatal("invalid identity issued portal credentials")
		}
		for _, c := range response.Cookies() {
			if c.Name == "AUTHP_ACCESS_TOKEN" && c.Value != "" && c.MaxAge >= 0 {
				t.Fatal("invalid identity issued a cookie")
			}
		}
	} else {
		parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(oauthE2EPortalKey), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
		if err != nil || !parsed.Valid {
			t.Fatal("independent portal signature verification failed")
		}
		claims := parsed.Claims.(jwt.MapClaims)
		roles, ok := claims["roles"].([]any)
		if !ok {
			t.Fatal("portal roles missing")
		}
		if slices.Contains(roles, any("resource/editor")) != editor {
			t.Fatal("supplemental token contributed incorrect roles")
		}
		if !strings.HasPrefix(fmt.Sprint(claims["sub"]), "external-user-") {
			t.Fatal("upstream subject not preserved")
		}
	}
	protected, _ := f.request(t, &client, f.base+"/protected")
	wantProtected, wantEditor := http.StatusFound, http.StatusFound
	if valid {
		wantProtected, wantEditor = http.StatusOK, http.StatusForbidden
		if editor {
			wantEditor = http.StatusOK
		}
	}
	if protected.StatusCode != wantProtected {
		t.Fatalf("protected route: HTTP %d, want %d", protected.StatusCode, wantProtected)
	}
	resource, _ := f.request(t, &client, f.base+"/editor")
	if resource.StatusCode != wantEditor {
		t.Fatalf("resource role enforcement: HTTP %d, want %d", resource.StatusCode, wantEditor)
	}
	return token
}

func TestCaddyOAuthProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_OAUTH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, keyFile, roots := cookieTLSCertificate(t)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Initialize the cached system roots before installing the child-only pool.
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	for _, alg := range []string{"EdDSA", "Ed25519", "RS256", "ES256"} {
		modes := []string{"discovery", "static", "combined"}
		if alg == "ES256" {
			modes = []string{"discovery"}
		} // The upstream static PEM loader supports RSA and Ed25519.
		for _, mode := range modes {
			t.Run(alg+"/"+mode, func(t *testing.T) {
				u := newOAuthE2EUpstream(t, cert, alg)
				expected := ""
				if mode != "discovery" {
					expected = u.server.URL
				}
				f := newCaddyOAuthFixture(t, u, mode, expected, "resource-api", certFile, keyFile, roots)
				f.login(t, true, true)
				u.mu.Lock()
				defer u.mu.Unlock()
				want := 1
				if mode == "static" {
					want = 0
				}
				if u.metadataFetches != want || u.keyFetches != want || u.exchanges != 1 {
					t.Fatalf("unexpected discovery/exchange counts: %d/%d/%d", u.metadataFetches, u.keyFetches, u.exchanges)
				}
			})
		}
	}
	t.Run("RSA PKCS1 static", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, cert, "RS256")
		f := newCaddyOAuthFixture(t, u, "static-pkcs1", u.server.URL, "resource-api", certFile, keyFile, roots)
		f.login(t, true, true)
	})
	t.Run("Google runtime secrets retain exact values", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, cert, "EdDSA")
		u.clientID += ".apps.googleusercontent.com"
		// A substituted secret is data, even if it resembles a Caddy placeholder.
		u.clientSecret = "literal-{env.DO_NOT_EXPAND_OAUTH_SECRET}\u2003"
		u.tokenIssuer += "\t"
		u.accessAudience += "\u00a0"
		f := newCaddyOAuthFixture(t, u, "discovery", u.tokenIssuer, u.accessAudience, certFile, keyFile, roots, func(f *caddyOAuthFixture) {
			f.input = strings.Replace(f.input, "driver generic", "driver google", 1)
			f.input = strings.Replace(f.input, "client_id "+u.clientID, "client_id secrets:oauth:client", 1)
			f.input = strings.Replace(f.input, `client_secret "`+u.clientSecret+`"`, "client_secret secrets:oauth:secret", 1)
			f.input = strings.Replace(f.input, `issuer "`+u.tokenIssuer+`"`, "issuer secrets:oauth:issuer", 1)
			f.input = strings.Replace(f.input, `audience "`+u.accessAudience+`"`, "audience secrets:oauth:audience", 1)
			f.secrets = map[string]string{"client": u.clientID, "secret": u.clientSecret, "issuer": u.tokenIssuer, "audience": u.accessAudience}
		})
		f.login(t, true, true)
		for _, failure := range []string{"missing secret", "duplicate audience", "logout URL", "unsupported target parameter", "unknown provider"} {
			var document map[string]any
			if err := json.Unmarshal(f.adapt(t), &document); err != nil {
				t.Fatal(err)
			}
			app := document["apps"].(map[string]any)["security"].(map[string]any)
			snapshots := app["oauth_provider_directives"].(map[string]any)
			switch failure {
			case "missing secret":
				manager := app["secrets_managers"].([]any)[0].(map[string]any)
				delete(manager["values"].(map[string]any), "client")
			case "duplicate audience":
				snapshots["upstream"] = append(snapshots["upstream"].([]any), "access_token_audience wrong")
			case "logout URL":
				snapshots["upstream"] = append(snapshots["upstream"].([]any), "logout_url https://example.test/logout")
			case "unsupported target parameter":
				config := app["config"].(map[string]any)
				provider := config["identity_providers"].([]any)[0].(map[string]any)
				provider["params"].(map[string]any)["logout_url"] = "https://example.test/logout"
			case "unknown provider":
				snapshots["missing"] = snapshots["upstream"]
			}
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := caddy.Load(data, true); err == nil {
				t.Fatalf("invalid OAuth runtime configuration accepted: %s", failure)
			}
			f.login(t, true, true)
		}
		// Resolved issuer and audience are still authoritative and exact.
		u.mu.Lock()
		u.tokenIssuer = u.server.URL
		u.mu.Unlock()
		f.login(t, false, false)
		u.mu.Lock()
		u.tokenIssuer += "\t"
		u.accessAudience = "resource-api"
		u.mu.Unlock()
		f.login(t, true, false)
	})
	for _, suffix := range []string{"\t", "\u00a0", "\u2003"} {
		t.Run(fmt.Sprintf("quoted values U+%04X", []rune(suffix)[0]), func(t *testing.T) {
			u := newOAuthE2EUpstream(t, cert, "EdDSA")
			u.clientSecret += suffix
			u.tokenIssuer += suffix
			u.accessAudience += suffix
			f := newCaddyOAuthFixture(t, u, "discovery", u.tokenIssuer, u.accessAudience, certFile, keyFile, roots)
			f.login(t, true, true)
			// Trimming either claim must fail its own trust check. An invalid
			// supplemental audience still permits the verified identity to log in.
			u.mu.Lock()
			u.tokenIssuer = u.server.URL
			u.mu.Unlock()
			f.login(t, false, false)
			u.mu.Lock()
			u.tokenIssuer += suffix
			u.accessAudience = "resource-api"
			u.mu.Unlock()
			f.login(t, true, false)
		})
	}
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, failure := range []string{"identity issuer", "identity audience", "identity nonce", "identity expired", "identity signature", "identity unknown kid", "state", "pkce", "access issuer", "access audience", "access azp", "access expired", "access signature", "access unknown kid"} {
			t.Run(alg+"/"+failure, func(t *testing.T) {
				u := newOAuthE2EUpstream(t, cert, alg)
				u.failure = failure
				f := newCaddyOAuthFixture(t, u, "discovery", "", "resource-api", certFile, keyFile, roots)
				optional := strings.HasPrefix(failure, "access ")
				f.login(t, optional, false)
				u.mu.Lock()
				u.failure = ""
				u.mu.Unlock()
				f.login(t, true, true)
			})
		}
	}
	// Missing kid retains upstream candidate-key verification; it is distinct
	// from an explicitly unknown or malformed key ID.
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		for _, token := range []string{"identity", "access"} {
			t.Run(alg+"/"+token+" without kid", func(t *testing.T) {
				u := newOAuthE2EUpstream(t, cert, alg)
				u.failure = token + " missing kid"
				f := newCaddyOAuthFixture(t, u, "discovery", "", "resource-api", certFile, keyFile, roots)
				f.login(t, true, true)
			})
		}
	}
	for _, tc := range []struct {
		name, mode, explicit, discovered, token, audience, access string
		valid, editor                                             bool
	}{
		{name: "explicit overrides discovery", mode: "discovery", explicit: "https://Issuer.example/Exact/", discovered: "https://untrusted.example", token: "https://Issuer.example/Exact/", valid: true, editor: true},
		{name: "explicit cannot fall back to discovery", mode: "discovery", explicit: "https://explicit.example", discovered: "https://discovered.example", token: "https://discovered.example"},
		{name: "discovered issuer mismatch", mode: "discovery", discovered: "https://wrong.example"},
		{name: "issuer trailing slash exact", mode: "static", explicit: "https://Issuer.example/", token: "https://Issuer.example"},
		{name: "issuer case exact", mode: "static", explicit: "https://Issuer.example", token: "https://issuer.example"},
		{name: "base URL does not infer issuer", mode: "static", token: "https://unrelated-issuer.example", valid: true, editor: true},
		{name: "access azp fallback", mode: "discovery", audience: "omit", valid: true, editor: true},
		{name: "explicit access audience cannot use azp fallback", mode: "discovery", audience: "another-api", valid: true},
		{name: "opaque access token", mode: "discovery", access: "opaque", valid: true},
		{name: "userinfo access token", mode: "discovery", access: "userinfo", valid: true},
		{name: "access selected as identity uses client ID", mode: "discovery", access: "identity", valid: true},
		{name: "access selected as identity rejects resource audience", mode: "discovery", access: "identity wrong audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newOAuthE2EUpstream(t, cert, "EdDSA")
			if tc.discovered != "" {
				u.discoveredIssuer = tc.discovered
			}
			if tc.token != "" {
				u.tokenIssuer = tc.token
			}
			if tc.access != "" {
				u.accessMode = tc.access
			}
			audience := tc.audience
			if audience == "" {
				audience = "resource-api"
			}
			if audience == "omit" {
				audience = ""
			}
			f := newCaddyOAuthFixture(t, u, tc.mode, tc.explicit, audience, certFile, keyFile, roots)
			f.login(t, tc.valid, tc.editor)
			if tc.access == "userinfo" {
				u.mu.Lock()
				defer u.mu.Unlock()
				if u.userInfos != 1 {
					t.Fatal("userinfo was not fetched")
				}
			}
		})
	}
	t.Run("mixed JWKS and same kid rollover", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, cert, "EdDSA")
		rsaKey, ecKey := newOAuthE2EKey(t, "rsa", "RS256"), newOAuthE2EKey(t, "ec", "ES256")
		u.keys = append([]map[string]string{
			{"kty": "OKP", "crv": "X25519", "kid": "unknown-curve", "x": u.identity.public["x"]},
			{"kty": "OKP", "crv": "Ed25519", "kid": "invalid-point", "x": "bad"},
			{"kty": "future", "kid": "unknown-type"},
			{"kty": "OKP", "crv": "Ed25519", "kid": "identity", "x": "bad"},
			{"kty": "RSA", "kid": "invalid-rsa", "n": "!", "e": "!"},
			rsaKey.public, ecKey.public,
		}, u.keys...)
		f := newCaddyOAuthFixture(t, u, "discovery", "", "resource-api", certFile, keyFile, roots)
		first := f.login(t, true, true)
		// Keep both kid and algorithm unchanged: the cached key must be selected,
		// fail signature verification, and trigger a refresh with new material.
		rotated := newOAuthE2EKey(t, "identity", "EdDSA")
		u.mu.Lock()
		u.identity = rotated
		u.keys[len(u.keys)-2] = rotated.public
		u.mu.Unlock()
		f.login(t, true, true)
		// Other supported signing families remain usable in the same mixed set.
		for _, key := range []oauthE2EKey{rsaKey, ecKey} {
			u.mu.Lock()
			u.identity = key
			u.mu.Unlock()
			f.login(t, true, true)
		}
		u.mu.Lock()
		fetches := u.keyFetches
		u.mu.Unlock()
		if fetches != 2 {
			t.Fatalf("same-kid rollover fetched JWKS %d times, want 2", fetches)
		}
		client := *f.client
		client.Jar, _ = cookiejar.New(nil)
		base, _ := url.Parse(f.base)
		client.Jar.SetCookies(base, []*http.Cookie{{Name: "AUTHP_ACCESS_TOKEN", Value: first, Path: "/", Secure: true}})
		resp, _ := f.request(t, &client, f.base+"/protected")
		if resp.StatusCode != 200 {
			t.Fatal("upstream rollover invalidated portal credentials")
		}
	})
	for _, alg := range []string{"EdDSA", "Ed25519"} {
		t.Run(alg+"/supplemental same kid rollover", func(t *testing.T) {
			u := newOAuthE2EUpstream(t, cert, alg)
			f := newCaddyOAuthFixture(t, u, "discovery", "", "resource-api", certFile, keyFile, roots)
			f.login(t, true, true)
			rotated := newOAuthE2EKey(t, u.access.id, alg)
			u.mu.Lock()
			u.access = rotated
			u.keys[1] = rotated.public
			u.mu.Unlock()
			// A valid identity must not conceal failed access-key refresh by
			// logging in without the supplemental resource role.
			f.login(t, true, true)
			u.mu.Lock()
			defer u.mu.Unlock()
			if u.keyFetches != 2 {
				t.Fatalf("supplemental rollover fetched JWKS %d times, want 2", u.keyFetches)
			}
		})
	}
	for _, token := range []string{"identity", "access"} {
		t.Run("static "+token+" pin wins over remote collision", func(t *testing.T) {
			u := newOAuthE2EUpstream(t, cert, "Ed25519")
			selected, index, mode := &u.identity, 0, "combined"
			if token == "access" {
				selected, index, mode = &u.access, 1, "combined-pins"
			}
			pinned := *selected
			rogue := newOAuthE2EKey(t, pinned.id, "Ed25519")
			u.keys[index] = rogue.public
			f := newCaddyOAuthFixture(t, u, mode, u.server.URL, "resource-api", certFile, keyFile, roots)
			f.login(t, true, true)
			u.mu.Lock()
			*selected = rogue
			before := u.keyFetches
			u.mu.Unlock()
			f.login(t, token == "access", false)
			u.mu.Lock()
			*selected = pinned
			after := u.keyFetches
			u.mu.Unlock()
			if after != before {
				t.Fatal("static pin failure fetched remote replacement")
			}
			f.login(t, true, true)
		})
	}
	t.Run("redirect trust scope and malformed reload", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, cert, "EdDSA")
		f := newCaddyOAuthFixture(t, u, "discovery", u.server.URL, "resource-api", certFile, keyFile, roots)
		const rules = `trust login redirect uri domain example.test path "/logout redirect uri"
   trust logout redirect uri domain example.test path "/login redirect uri"`
		input := strings.Replace(f.input, "enable identity provider upstream", "enable identity provider upstream\n"+rules, 1)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := caddy.Load(data, true); err != nil {
			t.Fatal(err)
		}
		loginURL := "https://example.test/logout%20redirect%20uri"
		logoutURL := "https://example.test/login%20redirect%20uri"
		for _, target := range []string{loginURL, logoutURL} {
			response, _ := f.request(t, f.client, f.base+"/auth/login?redirect_url="+url.QueryEscape(target))
			if response.StatusCode != http.StatusOK {
				t.Fatal("login page did not serve redirect trust request")
			}
			var referer string
			for _, cookie := range response.Cookies() {
				if cookie.Name == "AUTHP_REDIRECT_URL" && cookie.MaxAge >= 0 {
					referer = cookie.Value
				}
			}
			want := ""
			if target == loginURL {
				want = target
			}
			if referer != want {
				t.Fatal("login redirect did not enforce its configured trust scope")
			}
			response, _ = f.request(t, f.client, f.base+"/auth/logout?redirect_uri="+url.QueryEscape(target))
			want = f.base + "/auth/login"
			if target == logoutURL {
				want = target
			}
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != want {
				t.Fatal("logout redirect did not enforce its configured trust scope")
			}
		}
		for _, invalid := range []string{
			"trust login redirect uri domain", "trust logout redirect uri path",
			"trust login redirect uri domain example.test path", "trust logout redirect uri path / domain",
			"trust notlogin redirect uri domain example.test path /",
		} {
			bad := strings.Replace(input, rules, invalid, 1)
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(bad), nil); err == nil {
				t.Fatal("malformed redirect trust accepted on reconfiguration")
			}
			f.login(t, true, true)
		}
	})
	t.Run("reload rejects duplicate without replacing trust", func(t *testing.T) {
		u := newOAuthE2EUpstream(t, cert, "EdDSA")
		f := newCaddyOAuthFixture(t, u, "discovery", u.server.URL, "resource-api", certFile, keyFile, roots)
		f.login(t, true, true)
		bad := strings.Replace(f.input, "access token audience", "access_token_audience wrong\naccess token audience", 1)
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(bad), nil); err == nil {
			t.Fatal("duplicate trust alias accepted")
		}
		f.login(t, true, true)
		for _, badIcon := range []string{
			"text black gray text red",
			"text black gray ignored",
			"text black gray\nlogin icon text color red",
		} {
			bad := strings.Replace(f.input, "text black gray", badIcon, 1)
			if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(bad), nil); err == nil {
				t.Fatal("invalid legacy icon accepted on reconfiguration")
			}
			f.login(t, true, true)
		}
		// Outbound provider discovery must still reject an untrusted TLS peer.
		untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS peer was contacted over HTTP") }))
		defer untrusted.Close()
		untrustedConfig := strings.Replace(f.input, u.server.URL+"/metadata", untrusted.URL, 1)
		rejected, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(untrustedConfig), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := caddy.Load(rejected, true); err == nil {
			t.Fatal("provider accepted untrusted discovery TLS")
		}
		f.login(t, true, true)
		// A valid reload must change trust enforcement immediately.
		good := strings.Replace(f.input, `audience "resource-api"`, `audience "different-api"`, 1)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(good), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := caddy.Load(data, true); err != nil {
			t.Fatal(err)
		}
		f.login(t, true, false)
	})
}
