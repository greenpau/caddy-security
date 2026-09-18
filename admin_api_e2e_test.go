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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	adminExportPath       = "/api/server/private_keys"
	adminJWKSPath         = "/.well-known/jwks.json"
	adminDirectivesMarker = "ADMIN_API_TEST_DIRECTIVES"
)

// Isolate Caddy's process-global listeners and logging from the other E2E suites.
func TestCaddyAdminAPIE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAdminAPIProcess$", "-test.v", "-test.timeout=135s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_ADMIN_API_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		// Fixtures and assertions never print credentials, response bodies, or keys.
		t.Fatalf("TLS Caddy admin API: %v\n%s", err, output)
	}
}

type caddyAdminFixture struct {
	client      *http.Client
	base, mount string
	input       string
	profile     bool
	key         *ecdsa.PrivateKey
	secrets     []string
	logs        []string
}

func newCaddyAdminFixture(t *testing.T, mount, directives string, profile bool, certFile, certKey string, roots *x509.CertPool) *caddyAdminFixture {
	t.Helper()
	dir := t.TempDir()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate signing key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(signingKey)
	if err != nil {
		t.Fatal("could not marshal signing key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signingFile := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(signingFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	addr := lifecycleAddress(t)
	logFile, accessFile := filepath.Join(dir, "runtime.jsonl"), filepath.Join(dir, "access.jsonl")
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level DEBUG
  output file %s
  format json
 }
 security {
  local identity store localdb {
   realm local
   path :memory:
   user keyadmin {
    email keyadmin@example.test
    password %s
    roles authp/admin
   }
   user keymember {
    email keymember@example.test
    password %s
    roles authp/user
   }
  }
  authentication portal portal {
   %s
   enable identity store localdb
   crypto key signing sign-verify from file %s
   ui {
    theme basic
   }
  }
 }
}
https://%s {
 tls %s %s
 log {
  output file %s
  format json
 }
 route %s/* {
  authenticate with portal
 }
 respond unmatched 404
}
`, logFile, lifecyclePassword, lifecyclePassword, adminDirectivesMarker, signingFile, addr, certFile, certKey, accessFile, mount)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	f := &caddyAdminFixture{
		client: &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		base:   "https://" + addr, mount: mount, key: signingKey,
		input: input, profile: profile,
		secrets: []string{lifecyclePassword, string(keyPEM), base64.StdEncoding.EncodeToString(der), base64.RawURLEncoding.EncodeToString(signingKey.D.FillBytes(make([]byte, 32)))},
		logs:    []string{logFile, accessFile},
	}
	if err := f.reload(directives); err != nil {
		t.Fatal("could not provision TLS Caddy admin API fixture")
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		if err := caddy.Stop(); err != nil {
			t.Error("could not stop Caddy fixture")
		}
		for _, path := range f.logs {
			data, err := os.ReadFile(path)
			if err != nil || len(data) == 0 {
				t.Error("missing Caddy logging evidence")
				continue
			}
			assertAdminRedacted(t, data, f.secrets)
		}
	})
	return f
}

func (f *caddyAdminFixture) reload(directives string) error {
	input := strings.Replace(f.input, adminDirectivesMarker, directives, 1)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		return err
	}
	var config caddy.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		return err
	}
	portal := app.Config.AuthenticationPortals[0]
	if portal.API == nil || !portal.API.ProfileEnabled {
		return fmt.Errorf("adaptation lost default profile API")
	}
	// Profile access also has an independent JSON configuration surface.
	portal.API.ProfileEnabled = f.profile
	config.AppsRaw["security"], err = json.Marshal(&app)
	if err != nil {
		return err
	}
	data, err = json.Marshal(config)
	if err != nil {
		return err
	}
	return caddy.Load(data, true)
}

func (f *caddyAdminFixture) login(t *testing.T, username string) string {
	t.Helper()
	// Profile operations require the portal session created by browser login.
	// Give each identity its own jar; API probes use the jar-free fixture client.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := *f.client
	browser.Jar = jar
	request := func(method, target string, form url.Values, status int) *http.Response {
		if !strings.HasPrefix(target, "https://") {
			target = f.base + target
		}
		req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal("could not construct browser login")
		}
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", f.base)
		}
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal("browser login TLS request failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != status {
			t.Fatalf("browser login %s: HTTP %d, want %d", method, resp.StatusCode, status)
		}
		return resp
	}
	request("GET", f.mount+"/login", nil, 200)
	start := request("POST", f.mount+"/login", url.Values{"username": {username}, "realm": {"local"}}, 303)
	sandbox := start.Header.Get("Location")
	if !strings.Contains(sandbox, "/sandbox/") {
		t.Fatal("missing sandbox login redirect")
	}
	request("POST", sandbox, url.Values{"secret": {lifecyclePassword}}, 303)
	request("GET", sandbox, nil, 303)
	token := jarCookie(t, jar, f.base+f.mount+adminExportPath, "AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("real password login did not issue credentials")
	}
	f.secrets = append(f.secrets, token)
	return token
}

func assertAdminRedacted(t *testing.T, data []byte, secrets []string) {
	t.Helper()
	for _, marker := range []string{"PRIVATE KEY", `"private_key"`, `\"private_key\"`} {
		if bytes.Contains(data, []byte(marker)) {
			t.Fatal("private material appeared in a public response, error, or log")
		}
	}
	for _, secret := range secrets {
		if secret != "" && bytes.Contains(data, []byte(secret)) {
			t.Fatal("sensitive value appeared in a response or log")
		}
	}
}

func (f *caddyAdminFixture) request(t *testing.T, method, path, token, body string, status int, extra ...http.Header) (http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.base+f.mount+path, strings.NewReader(body))
	if err != nil {
		t.Fatal("could not construct request")
	}
	req.Header.Set("Accept", "application/json")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, headers := range extra {
		maps.Copy(req.Header, headers)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal("TLS request failed")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		t.Fatal("invalid or oversized HTTP response")
	}
	if resp.StatusCode != status {
		t.Fatalf("%s %s: HTTP %d, want %d", method, req.URL.EscapedPath(), resp.StatusCode, status)
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("request did not use verified TLS")
	}
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Pragma") != "no-cache" || resp.Header.Get("Location") != "" {
		t.Fatal("API response allowed caching or redirected")
	}
	headers, err := json.Marshal(resp.Header)
	if err != nil {
		t.Fatal("could not inspect response headers")
	}
	assertAdminRedacted(t, headers, f.secrets)
	if status != 200 || path == adminJWKSPath {
		assertAdminRedacted(t, data, f.secrets)
	}
	return resp.Header, data
}

func (f *caddyAdminFixture) publicKey(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 {
		t.Fatal("expected one public signing key")
	}
	key := set.Keys[0]
	for field := range key {
		switch field {
		case "kty", "kid", "alg", "use", "crv", "x", "y":
		default:
			t.Fatal("public JWKS contained an unexpected field")
		}
	}
	if key["kty"] != "EC" || key["crv"] != "P-256" || key["alg"] != "ES256" || key["use"] != "sig" || key["kid"] == "" {
		t.Fatal("unexpected public signing metadata")
	}
	x, xerr := base64.RawURLEncoding.DecodeString(key["x"])
	y, yerr := base64.RawURLEncoding.DecodeString(key["y"])
	if xerr != nil || yerr != nil || len(x) != 32 || len(y) != 32 {
		t.Fatal("invalid public coordinates")
	}
	public, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil || !public.Equal(&f.key.PublicKey) {
		t.Fatal("public JWKS did not match the configured signing key")
	}
	return key
}

func (f *caddyAdminFixture) validateExport(t *testing.T, data []byte, public map[string]string, format, encoding string) {
	t.Helper()
	var set struct {
		Keys []struct {
			Public  map[string]string `json:"public_key"`
			Private json.RawMessage   `json:"private_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 || !maps.Equal(set.Keys[0].Public, public) {
		t.Fatal("export did not match published JWKS")
	}
	if format == "jwk" {
		var private map[string]string
		if err := json.Unmarshal(set.Keys[0].Private, &private); err != nil {
			t.Fatal("invalid private JWK")
		}
		if private["d"] != base64.RawURLEncoding.EncodeToString(f.key.D.FillBytes(make([]byte, 32))) {
			t.Fatal("private JWK scalar does not match signing key")
		}
		for field, value := range public {
			if private[field] != value {
				t.Fatal("private JWK public parameters changed")
			}
		}
		return
	}
	var encoded string
	if err := json.Unmarshal(set.Keys[0].Private, &encoded); err != nil {
		t.Fatal("private export was not a string")
	}
	var der []byte
	if encoding == "der" {
		var err error
		der, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal("invalid DER export encoding")
		}
	} else {
		block, rest := pem.Decode([]byte(encoded))
		label := "PRIVATE KEY"
		if format == "sec1" {
			label = "EC PRIVATE KEY"
		}
		if block == nil || block.Type != label || len(rest) != 0 {
			t.Fatal("invalid private PEM export")
		}
		der = block.Bytes
	}
	var private *ecdsa.PrivateKey
	if format == "sec1" {
		var err error
		private, err = x509.ParseECPrivateKey(der)
		if err != nil {
			t.Fatal("invalid SEC1 export")
		}
	} else {
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			t.Fatal("invalid PKCS8 export")
		}
		var ok bool
		private, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("unexpected exported key type")
		}
	}
	if !private.Equal(f.key) {
		t.Fatal("exported private key does not match the public signing key")
	}
}

func (f *caddyAdminFixture) invalidTokens(t *testing.T, admin string) []string {
	t.Helper()
	valid, err := jwt.Parse(admin, func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil }, jwt.WithValidMethods([]string{"ES256"}), jwt.WithExpirationRequired())
	if err != nil || !valid.Valid {
		t.Fatal("could not verify real login token")
	}
	claims, ok := valid.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("invalid login claims")
	}
	expired := maps.Clone(claims)
	expired["exp"], expired["iat"], expired["nbf"] = time.Now().Add(-time.Hour).Unix(), time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-2*time.Hour).Unix()
	expired["jti"] = "expired-admin-e2e"
	token := jwt.NewWithClaims(jwt.SigningMethodES256, expired)
	token.Header = maps.Clone(valid.Header)
	signed, err := token.SignedString(f.key)
	if err != nil {
		t.Fatal("could not sign expired fixture")
	}
	parts := strings.Split(admin, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) == 0 {
		t.Fatal("missing login signature")
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	invalid := []string{"synthetic-invalid-admin-token", strings.Join(parts, "."), signed}
	f.secrets = append(f.secrets, invalid...)
	return invalid
}

func TestCaddyAdminAPIProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_ADMIN_API_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	certFile, certKey, roots := cookieTLSCertificate(t)
	for _, profile := range []bool{true, false} {
		for _, tc := range []struct {
			name, directives string
			admin, export    bool
		}{
			{name: "defaults"},
			{name: "both_off", directives: "disable admin api\ndisable admin api private key export"},
			{name: "admin_only", directives: "enable admin api\ndisable admin api private key export", admin: true},
			{name: "export_only", directives: "enable admin api private key export\ndisable admin api", export: true},
			{name: "both_on", directives: "enable admin api private key export\nenable source ip tracking\nenable admin api", admin: true, export: true},
		} {
			t.Run(fmt.Sprintf("%s/profile_%t", tc.name, profile), func(t *testing.T) {
				mount := "/tenant/auth"
				if !profile {
					mount = ""
				}
				f := newCaddyAdminFixture(t, mount, tc.directives, profile, certFile, certKey, roots)
				if mount != "" {
					req, err := http.NewRequestWithContext(t.Context(), "GET", f.base+adminExportPath, nil)
					if err != nil {
						t.Fatal("could not construct unmounted export request")
					}
					resp, err := f.client.Do(req)
					if err != nil {
						t.Fatal("unmounted export request failed")
					}
					body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
					resp.Body.Close()
					if err != nil || resp.StatusCode != 404 || string(body) != "unmatched" {
						t.Fatal("export was exposed outside the portal mount")
					}
				}
				admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
				invalid := f.invalidTokens(t, admin)
				tokens := []struct {
					name, token    string
					invalid, admin bool
				}{
					{name: "admin", token: admin, admin: true}, {name: "member", token: member}, {name: "anonymous"},
					{name: "malformed", token: invalid[0], invalid: true}, {name: "bad_signature", token: invalid[1], invalid: true}, {name: "expired", token: invalid[2], invalid: true},
				}
				_, data := f.request(t, "GET", adminJWKSPath, "", "", 200)
				public := f.publicKey(t, data)
				for _, identity := range tokens {
					t.Run(identity.name, func(t *testing.T) {
						metadataStatus := 400
						if identity.invalid {
							metadataStatus = 401
						} else if tc.admin {
							metadataStatus = 403
							if identity.admin {
								metadataStatus = 200
							}
						}
						f.request(t, "GET", "/api/server/metadata", identity.token, "", metadataStatus)
						// Discovery precedes authentication and ignores private-export selectors.
						for _, query := range []string{"", "?format=jwk", "?format=pkcs8&encoding=der", "?admin_fetch_private_keys_enabled=true"} {
							h, body := f.request(t, "GET", adminJWKSPath+query, identity.token, "", 200)
							if h.Get("Content-Type") != "application/jwk-set+json" || h.Get("X-Content-Type-Options") != "nosniff" {
								t.Fatal("incorrect discovery headers")
							}
							if !maps.Equal(f.publicKey(t, body), public) {
								t.Fatal("credentials or selectors changed public discovery")
							}
							assertAdminRedacted(t, body, f.secrets)
						}
						for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
							// API authentication errors precede the private-export flag checks.
							status := 404
							if identity.invalid {
								status = 401
							} else if tc.admin && tc.export {
								status = 403
								if identity.admin {
									status = 405
									if method == "GET" {
										status = 200
									}
								}
							}
							h, body := f.request(t, method, adminExportPath, identity.token, "", status)
							if status == 405 && h.Get("Allow") != "GET" {
								t.Fatal("private export did not advertise GET")
							}
							if status == 200 {
								if h.Get("Content-Type") != "application/json" || h.Get("X-Content-Type-Options") != "nosniff" {
									t.Fatal("incorrect private export headers")
								}
								f.validateExport(t, body, public, "pkcs8", "pem")
							}
						}
					})
				}
				// A valid browser admin cookie crosses the same boundary as bearer tokens.
				exportStatus := 404
				if tc.admin && tc.export {
					exportStatus = 200
				}
				_, exported := f.request(t, "GET", adminExportPath, "", "", exportStatus, http.Header{"Cookie": {"AUTHP_ACCESS_TOKEN=" + admin}})
				if exportStatus == 200 {
					f.validateExport(t, exported, public, "pkcs8", "pem")
				}
				for _, token := range []string{admin, member} {
					status := 400
					if profile {
						status = 200
					}
					_, body := f.request(t, "POST", "/api/profile", token, `{"kind":"fetch_user_info"}`, status)
					if profile {
						var result struct {
							Status int            `json:"status"`
							Entry  map[string]any `json:"entry"`
						}
						if err := json.Unmarshal(body, &result); err != nil || result.Status != 200 || result.Entry["metadata"] == nil {
							t.Fatal("profile API did not retain user access")
						}
					}
				}
				for _, method := range []string{"HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
					status := 405
					if method == "HEAD" {
						status = 200
					}
					h, body := f.request(t, method, adminJWKSPath, invalid[0], "", status)
					if len(body) != 0 || (status == 405 && h.Get("Allow") != "GET, HEAD") {
						t.Fatal("incorrect discovery method handling")
					}
				}
				for _, selector := range []struct{ query, format, encoding string }{
					{"?format=pkcs8", "pkcs8", "pem"}, {"?format=pkcs8&encoding=der", "pkcs8", "der"},
					{"?format=jwk", "jwk", ""}, {"?format=sec1", "sec1", "pem"}, {"?format=sec1&encoding=der", "sec1", "der"},
					{"?admin_fetch_private_keys_enabled=true", "pkcs8", "pem"},
				} {
					_, body := f.request(t, "GET", adminExportPath+selector.query, admin, "", exportStatus)
					if exportStatus == 200 {
						f.validateExport(t, body, public, selector.format, selector.encoding)
					}
				}
				for _, query := range []string{
					"?format=synthetic-selector-secret", "?encoding=synthetic-selector-secret", "?format=", "?encoding=",
					"?format=pkcs1", "?format=jwk&encoding=pem", "?format=jwk&format=pkcs8", "?%66ormat=jwk&format=pkcs8",
					"?encoding=pem&encoding=der", "?format=%ZZ", "?format=pkcs8;encoding=der",
				} {
					status := 404
					if tc.admin && tc.export {
						status = 400
					}
					_, body := f.request(t, "GET", adminExportPath+query, admin, "", status)
					assertAdminRedacted(t, body, []string{"synthetic-selector-secret"})
				}
				for _, suffix := range []string{"/", ".json", "%2fextra"} {
					f.request(t, "GET", adminExportPath+suffix, admin, "", 400)
				}
			})
		}
	}
	t.Run("reload", func(t *testing.T) {
		f := newCaddyAdminFixture(t, "/auth", "enable admin api\nenable admin api private key export", true, certFile, certKey, roots)
		admin, member := f.login(t, "keyadmin"), f.login(t, "keymember")
		_, body := f.request(t, "GET", adminJWKSPath, "", "", 200)
		public := f.publicKey(t, body)
		_, body = f.request(t, "GET", adminExportPath, admin, "", 200)
		f.validateExport(t, body, public, "pkcs8", "pem")
		for _, tc := range []struct {
			name, directives string
			admin, export    bool
		}{
			{name: "disable_export", directives: "enable admin api\ndisable admin api private key export", admin: true},
			{name: "disable_admin", directives: "disable admin api\nenable admin api private key export", export: true},
			{name: "disable_both", directives: "disable admin api\ndisable admin api private key export"},
			{name: "reenable_both", directives: "enable admin api\nenable admin api private key export", admin: true, export: true},
			{name: "remove_directives"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := f.reload(tc.directives); err != nil {
					t.Fatal("valid admin API reload failed")
				}
				// Existing signed credentials must obey the new flags immediately.
				status, memberStatus, metadataStatus := 404, 404, 400
				if tc.admin {
					metadataStatus = 200
				}
				if tc.admin && tc.export {
					status, memberStatus = 200, 403
				}
				_, body := f.request(t, "GET", adminExportPath, admin, "", status)
				if status == 200 {
					f.validateExport(t, body, public, "pkcs8", "pem")
				}
				f.request(t, "GET", adminExportPath, member, "", memberStatus)
				f.request(t, "GET", "/api/server/metadata", admin, "", metadataStatus)
				_, body = f.request(t, "GET", adminJWKSPath, "", "", 200)
				if !maps.Equal(f.publicKey(t, body), public) {
					t.Fatal("admin reload changed public discovery")
				}
				// Rejected statements cannot partially change the live portal's flags.
				for _, bad := range []string{
					"enable admin api\ndisable admin api",
					"enable admin api\nenable admin api private key export\nenable Admin api synthetic-admin-reload-secret",
					"enable admin api\nenable admin api private key export\nenable \" admin\" api synthetic-admin-reload-secret",
				} {
					err := f.reload(bad)
					if err == nil || strings.Contains(err.Error(), "synthetic-admin-reload-secret") {
						t.Fatal("invalid admin reload was accepted or disclosed an argument")
					}
					_, body = f.request(t, "GET", adminExportPath, admin, "", status)
					if status == 200 {
						f.validateExport(t, body, public, "pkcs8", "pem")
					}
				}
				// A fresh session confirms that the profile flag survived provisioning.
				fresh := f.login(t, "keymember")
				f.request(t, "POST", "/api/profile", fresh, `{"kind":"fetch_user_info"}`, 200)
			})
		}
	})
}
