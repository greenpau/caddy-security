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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

func TestCaddyDocumentsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 9*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyDocumentsProcess$", "-test.v", "-test.timeout=8m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_DOCUMENTS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy Documents journeys: %v\n%s", err, output)
	}
}

type caddyDocumentsOptions struct {
	mount                 string
	transform, refresh    bool
	disabled, storageOnly bool
	legacyMount           bool
	limits                documents.Config
}

type caddyDocumentsFixture struct {
	*localIdentityFixture
	documentsDB, privateDir, publicDir string
	fixtureURL, cryptoURL, cert        string
	logs                               []string
	expectedUsers                      map[string]string
	roots                              *x509.CertPool
	contracts                          *openAPIContracts
	running                            bool
}

func newCaddyDocumentsFixture(t *testing.T, options caddyDocumentsOptions, cert, tlsKey string, roots *x509.CertPool) *caddyDocumentsFixture {
	t.Helper()
	workspace := t.TempDir()
	private, public := filepath.Join(workspace, "private"), filepath.Join(workspace, "public")
	for _, path := range []string{private, public} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal("cannot create private Documents fixture directory")
		}
	}
	database := filepath.Join(private, "users.json")
	seedLocalIdentity(t, database, false)
	base := "https://" + lifecycleAddress(t)
	mount := strings.TrimSuffix(options.mount, "/")
	declaredMount := mount
	if declaredMount == "" {
		declaredMount = "/"
	}
	settings := options.limits
	settings.Database, settings.PublicOrigin, settings.BasePath, settings.Realms = filepath.Join(private, "documents.db"), base, declaredMount, []string{"local"}
	if err := settings.Validate(); err != nil {
		t.Fatal("invalid Documents fixture limits")
	}
	api := "enable documents api\n"
	if options.disabled {
		api = "disable documents api\n"
	} else if options.storageOnly {
		api = ""
	}
	api += fmt.Sprintf(`documents api database %q
documents api public origin %s
documents api base path %s
documents api realms local
documents api max file bytes %d
documents api max user bytes %d
documents api max total bytes %d
documents api max user files %d
documents api max total files %d
documents api max keys %d
documents api max recipients %d
documents api upload ttl seconds %d
`, settings.Database, base, declaredMount, settings.MaxFileBytes, settings.MaxUserBytes, settings.MaxTotalBytes, settings.MaxUserFiles, settings.MaxTotalFiles, settings.MaxKeys, settings.MaxRecipients, settings.UploadTTLSeconds)
	refresh, transform, handler := "", "", "authenticate with myportal at "+declaredMount
	if options.refresh {
		refresh = fmt.Sprintf("token refresh {\nrealms local\npublic origin %s\nbase path %s\nbody transport enabled\naccess lifetime 600\n}\n", base, declaredMount)
	}
	if options.transform {
		transform = "transform user {\nmatch sub alice\naction overwrite sub bob\naction overwrite email alias@example.test\n}\n"
	}
	if options.legacyMount {
		handler = "authenticate with myportal"
	}
	keys := newJWKSKeyFiles(t, "RSA", "documents-access")
	logs := []string{filepath.Join(private, "runtime.jsonl"), filepath.Join(private, "access.jsonl")}
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 storage file_system %q
 log {
  level INFO
  output file %q
  format json
 }
 security {
  local identity store localdb {
   realm local
   path %q
  }
  authentication portal myportal {
   enable identity stores localdb
   enable admin api
   crypto default token lifetime 600
   %s
   %s
   %s
   %s
  }
  authorization policy app_policy {
   %s
   set auth url %s%s/login
   validate bearer header
   allow roles authp/user authp/admin
  }
 }
}
%s {
 tls %q %q
 log {
  output file %q
  format filter {
   wrap json
   fields {
    request>uri delete
    request>headers>Referer delete
    resp_headers>Location delete
   }
  }
 }
 route {
  handle_path /_documents_test/* {
   root * %q
   file_server
  }
  route /resource {
   authorize with app_policy
   respond "identity resource"
  }
  route %s/* {
   %s
  }
  respond unmatched 404
 }
}`, filepath.Join(private, "caddy-storage"), logs[0], database, keys.signer("access"), api, refresh, transform, keys.verifier("access"), base, mount, base, cert, tlsKey, logs[1], public, mount, handler)
	contracts := newOpenAPIContracts(t)
	module, err := os.OpenRoot(contracts.module.Dir)
	if err != nil {
		t.Fatal("cannot open selected Documents client module")
	}
	clientSource, err := module.Open("pkg/authn/documents/client/crypto.mjs")
	if err != nil {
		module.Close()
		t.Fatal("selected module has no Documents crypto client")
	}
	clientBytes, readErr := io.ReadAll(io.LimitReader(clientSource, (128<<10)+1))
	clientSource.Close()
	module.Close()
	if readErr != nil || len(clientBytes) == 0 || len(clientBytes) > 128<<10 {
		t.Fatal("invalid selected Documents client size")
	}
	t.Logf("Documents selected client sha256=%x", sha256.Sum256(clientBytes))
	for name, data := range map[string][]byte{"crypto.mjs": clientBytes, "index.html": []byte("<!doctype html><meta charset=utf-8><title>Documents integration fixture</title><main id=documents-fixture>Documents integration fixture</main>")} {
		if err := os.WriteFile(filepath.Join(public, name), data, 0600); err != nil {
			t.Fatal("cannot write public Documents fixture asset")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f := &caddyDocumentsFixture{
		localIdentityFixture: &localIdentityFixture{oidcRPFixture: &oidcRPFixture{base: base, mount: mount, issuer: base + mount, client: client}, database: database, input: input, secrets: []string{lifecyclePassword, localIdentityBobPassword}},
		documentsDB:          settings.Database, privateDir: private, publicDir: public, fixtureURL: base + "/_documents_test/", cryptoURL: base + "/_documents_test/crypto.mjs", cert: cert, roots: roots, logs: logs, expectedUsers: make(map[string]string), contracts: contracts,
	}
	plain := *client
	f.plain = &plain
	for _, username := range []string{"alice", "bob", "admin"} {
		f.expectedUsers[username] = localIdentityRecord(t, database, username).ID
	}
	t.Cleanup(func() {
		f.stop(t)
		transport.CloseIdleConnections()
		f.scan(t, nil)
	})
	f.newBrowser(t)
	f.start(t)
	r := f.request(t, "GET", "/.well-known/jwks.json", nil, nil)
	r.requireStatus(t, http.StatusOK)
	var jwks struct{ Keys []map[string]string }
	if json.Unmarshal(r.body, &jwks) != nil || len(jwks.Keys) != 1 {
		t.Fatal("Documents fixture omitted the access verification key")
	}
	f.keys = jwks.Keys
	return f
}

func (f *caddyDocumentsFixture) start(t *testing.T) {
	t.Helper()
	if f.running {
		t.Fatal("Documents fixture already running")
	}
	f.load(t)
	f.running = true
}

func (f *caddyDocumentsFixture) stop(t *testing.T) {
	t.Helper()
	if !f.running {
		return
	}
	if err := caddy.Stop(); err != nil {
		t.Error("cannot drain Documents fixture")
	}
	f.running = false
}

func (f *caddyDocumentsFixture) scan(t *testing.T, extra [][]byte) {
	t.Helper()
	if f.running {
		t.Error("Documents confidentiality scan requires a drained root")
		return
	}
	secrets := append([][]byte(nil), extra...)
	for _, secret := range f.secrets {
		if secret != "" {
			secrets = append(secrets, []byte(secret))
		}
	}
	paths := append([]string(nil), f.logs...)
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		paths = append(paths, f.documentsDB+suffix)
	}
	for i, path := range paths {
		file, err := os.Open(path)
		if os.IsNotExist(err) && i >= len(f.logs) {
			continue
		}
		if err != nil {
			t.Error("cannot inspect Documents private artifact")
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, (32<<20)+1))
		file.Close()
		if err != nil || len(data) > 32<<20 || (i < len(f.logs) && len(data) == 0) {
			t.Error("Documents private artifact is missing or exceeds fixture bound")
			continue
		}
		for _, secret := range secrets {
			if len(secret) > 0 && bytes.Contains(data, secret) {
				t.Error("Documents store or diagnostics exposed captured secret material")
				break
			}
		}
	}
}

func (f *caddyDocumentsFixture) verifyAccess(t *testing.T, token string) map[string]any {
	t.Helper()
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "access")
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || !iatOK || exp <= float64(time.Now().Unix()) || iat > float64(time.Now().Add(time.Second).Unix()) {
		t.Fatal("Documents login token has invalid timestamps")
	}
	return claims
}

func (f *caddyDocumentsFixture) login(t *testing.T, username string) string {
	t.Helper()
	password := lifecyclePassword
	if username == "bob" {
		password = localIdentityBobPassword
	}
	f.newBrowser(t)
	return f.loginSameBrowser(t, username, password, false)
}

func (f *caddyDocumentsFixture) loginSameBrowser(t *testing.T, username, password string, fresh bool) string {
	t.Helper()
	path := "/login?redirect_url="
	if fresh {
		path += "&fresh=1"
		f.request(t, "GET", path, nil, nil).requireStatus(t, 200)
	}
	r := f.request(t, "POST", path, url.Values{"username": {username}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
	r.requireStatus(t, 303)
	location, err := url.Parse(r.header.Get("Location"))
	if err != nil || location.Scheme != "https" || location.Host != strings.TrimPrefix(f.base, "https://") || !strings.HasPrefix(location.Path, f.mount+"/sandbox/") || location.RawQuery != "" {
		t.Fatal("Documents login left the selected TLS sandbox")
	}
	for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
		if cookie.Value != "" && cookie.MaxAge >= 0 && strings.HasPrefix(cookie.Name, "AUTHP_SANDBOX_ID") {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	f.request(t, "POST", location.String(), url.Values{"secret": {password}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
	f.request(t, "GET", location.String(), nil, nil).requireStatus(t, 303)
	token := f.cookie("AUTHP_ACCESS_TOKEN")
	if token == "" {
		t.Fatal("Documents form login did not issue an access cookie")
	}
	f.verifyAccess(t, token)
	f.secrets = append(f.secrets, password, token, f.cookie("AUTHP_REFRESH_TOKEN"))
	return token
}

type caddyDocumentsOperation struct{ method, path string }

var caddyDocumentsOperations = map[string]caddyDocumentsOperation{
	"bootstrap":     {"GET", "/api/documents/bootstrap"},
	"key.fetch":     {"GET", "/api/documents/keys/fetch"},
	"key.register":  {"PUT", "/api/documents/keys/register"},
	"key.reset":     {"POST", "/api/documents/keys/reset"},
	"key.lookup":    {"GET", "/api/documents/key/{user_id}/lookup"},
	"file.list":     {"GET", "/api/documents/files"},
	"file.allocate": {"POST", "/api/documents/files/allocate"},
	"file.fetch":    {"GET", "/api/documents/file/{id}/fetch"},
	"file.manifest": {"PUT", "/api/documents/file/{id}/manifest"},
	"file.commit":   {"POST", "/api/documents/file/{id}/commit"},
	"file.delete":   {"DELETE", "/api/documents/file/{id}/delete"},
	"chunk.put":     {"PUT", "/api/documents/file/{id}/chunk/{idx}/put"},
	"chunk.fetch":   {"GET", "/api/documents/file/{id}/chunk/{idx}/fetch"},
	"share.put":     {"PUT", "/api/documents/file/{id}/share/{user_id}/put"},
	"share.list":    {"GET", "/api/documents/file/{id}/share/list"},
	"share.delete":  {"DELETE", "/api/documents/file/{id}/share/{user_id}/delete"},
}

func caddyDocumentsRequest(t *testing.T, operation string, params map[string]string, payload any) (caddyDocumentsOperation, string, []byte) {
	t.Helper()
	op, ok := caddyDocumentsOperations[operation]
	if !ok {
		t.Fatal("unknown Documents fixture operation")
	}
	path := op.path
	for name, value := range params {
		if name == "after" && operation == "file.list" {
			path += "?after=" + url.QueryEscape(value)
		} else {
			path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(value))
		}
	}
	if strings.ContainsAny(path, "{}") {
		t.Fatal("Documents fixture omitted a resource parameter")
	}
	var body []byte
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal("cannot encode Documents request")
		}
	}
	return op, strings.TrimPrefix(path, "/api/documents"), body
}

func (f *caddyDocumentsFixture) doc(t *testing.T, token, operation string, params map[string]string, payload any, want int) oidcRPResponse {
	t.Helper()
	op, path, body := caddyDocumentsRequest(t, operation, params, payload)
	r := f.raw(t, token, op.method, path, body, want)
	f.contracts.AssertResponse(t, op.method, op.path, r.status, r.header, r.body)
	if want == 200 && payload != nil {
		f.contracts.AssertRequest(t, op.method, op.path, http.Header{"Content-Type": {"application/json"}}, body)
	}
	if want == 200 {
		switch operation {
		case "key.register", "key.reset", "file.manifest", "file.commit", "file.delete", "chunk.put", "share.put", "share.delete":
			var value map[string]json.RawMessage
			if json.Unmarshal(r.body, &value) != nil || len(value) != 1 || string(value["success"]) != "true" {
				t.Fatal("Documents mutation omitted its exact confirmation")
			}
		}
	}
	return r
}

func (f *caddyDocumentsFixture) raw(t *testing.T, token, method, suffix string, body []byte, want int, headers ...http.Header) oidcRPResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, f.issuer+"/api/documents"+suffix, bytes.NewReader(body))
	if err != nil {
		t.Fatal("cannot construct Documents request")
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, h := range headers {
		maps.Copy(req.Header, h)
	}
	response, err := f.plain.Do(req)
	if err != nil {
		t.Fatal("Documents TLS request failed")
	}
	return caddyDocumentsRead(t, response, method, want)
}

func caddyDocumentsRead(t *testing.T, response *http.Response, method string, want int) oidcRPResponse {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("Documents response exceeded bounds or lacked verified TLS")
	}
	if response.StatusCode != want {
		t.Fatalf("Documents HTTP %d, want %d", response.StatusCode, want)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("Documents response omitted privacy headers")
	}
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || media != "application/json" {
		t.Fatal("Documents response omitted JSON media")
	}
	for _, c := range response.Cookies() {
		if c.Value != "" && c.MaxAge >= 0 {
			t.Fatal("Documents operation issued a cookie")
		}
	}
	if method == "HEAD" {
		if len(body) != 0 {
			t.Fatal("Documents HEAD returned a body")
		}
	} else {
		var value map[string]json.RawMessage
		if json.Unmarshal(body, &value) != nil || len(value) == 0 || value["operation"] != nil || value["result"] != nil {
			t.Fatal("Documents response was not a direct JSON resource")
		}
		if want >= 400 {
			var failure struct {
				Status  int    `json:"status"`
				Message string `json:"message"`
			}
			if len(value) != 2 || json.Unmarshal(body, &failure) != nil || failure.Status != want || failure.Message == "" || len(failure.Message) > 256 {
				t.Fatal("Documents failure was not a bounded generic error")
			}
		}
	}
	return oidcRPResponse{status: response.StatusCode, header: response.Header, body: body}
}

func caddyDocumentsDecode[T any](t *testing.T, r oidcRPResponse) T {
	t.Helper()
	var value T
	if json.Unmarshal(r.body, &value) != nil {
		t.Fatal("cannot decode Documents resource")
	}
	return value
}

type caddyDocumentsBootstrap struct {
	Protocol  string `json:"protocol"`
	PortalID  string `json:"portal_id"`
	UserID    string `json:"user_id"`
	ChunkSize int    `json:"chunk_size"`
}

func (f *caddyDocumentsFixture) bootstrap(t *testing.T, token, username string) caddyDocumentsBootstrap {
	t.Helper()
	b := caddyDocumentsDecode[caddyDocumentsBootstrap](t, f.doc(t, token, "bootstrap", nil, nil, 200))
	if b.Protocol != documents.Protocol || !documents.ValidID(b.PortalID) || b.UserID != f.expectedUsers[username] || b.ChunkSize != documents.ChunkSize {
		t.Fatal("Documents bootstrap did not bind the canonical local identity")
	}
	return b
}

func (f *caddyDocumentsFixture) enroll(t *testing.T, token, username string) documents.Key {
	t.Helper()
	b := f.bootstrap(t, token, username)
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot generate synthetic protocol public key")
	}
	public := private.PublicKey().Bytes()
	fingerprint := sha256.Sum256(public)
	encode := base64.RawURLEncoding.EncodeToString
	key := documents.Key{UserID: b.UserID, KeyID: encode(fingerprint[:]), PublicKey: encode(public), Vault: &documents.Vault{Salt: encode(make([]byte, 32)), Nonce: encode(make([]byte, 12)), Ciphertext: encode(make([]byte, 48))}}
	f.doc(t, token, "key.register", nil, map[string]any{"key": key}, 200)
	return key
}

func caddyDocumentsEnvelope(key documents.Key) documents.Envelope {
	return documents.Envelope{KeyID: key.KeyID, EphemeralKey: key.PublicKey, Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 48))}
}

func caddyDocumentsParams(id string) map[string]string { return map[string]string{"id": id} }

func (f *caddyDocumentsFixture) pending(t *testing.T, token string, key documents.Key) documents.File {
	t.Helper()
	file := caddyDocumentsDecode[documents.File](t, f.doc(t, token, "file.allocate", nil, map[string]any{"size": 32, "chunks": 1}, 200))
	manifest := documents.Manifest{Metadata: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Envelope: caddyDocumentsEnvelope(key)}
	f.doc(t, token, "file.manifest", caddyDocumentsParams(file.ID), map[string]any{"manifest": manifest}, 200)
	return file
}

func (f *caddyDocumentsFixture) ready(t *testing.T, token string, key documents.Key) documents.File {
	t.Helper()
	file := f.pending(t, token, key)
	f.doc(t, token, "chunk.put", map[string]string{"id": file.ID, "idx": "0"}, map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, 200)
	f.doc(t, token, "file.commit", caddyDocumentsParams(file.ID), nil, 200)
	return file
}

func TestCaddyDocumentsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_DOCUMENTS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct {
		name    string
		options caddyDocumentsOptions
	}{
		{"root_smoke", caddyDocumentsOptions{mount: "/"}},
		{"legacy_smoke", caddyDocumentsOptions{mount: "/auth", legacyMount: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaddyDocumentsFixture(t, tc.options, cert, key, roots)
			token := f.login(t, "alice")
			key := f.enroll(t, token, "alice")
			file := f.ready(t, token, key)
			f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
			f.doc(t, token, "file.delete", caddyDocumentsParams(file.ID), nil, 200)
			f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
		})
	}
	t.Run("protocol_authority", func(t *testing.T) { testCaddyDocumentsProtocol(t, cert, key, roots) })
	t.Run("native_authority", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", refresh: true}, cert, key, roots)
		credentials, err := f.nativeLogin(t, lifecyclePassword, false)
		if err != nil || credentials == nil || credentials.RefreshToken == "" {
			t.Fatal("Documents authority control native login failed")
		}
		f.assertResource(t, credentials.AccessToken)
		f.doc(t, credentials.AccessToken, "bootstrap", nil, nil, 401)
		renewed := localIdentityAuth(t, f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": credentials.RefreshToken}, ""))
		if renewed.AccessToken == "" || renewed.RefreshToken == "" {
			t.Fatal("native authority control did not renew")
		}
		f.secrets = append(f.secrets, renewed.AccessToken, renewed.RefreshToken)
		f.assertResource(t, renewed.AccessToken)
		f.doc(t, renewed.AccessToken, "bootstrap", nil, nil, 401)
	})
	for _, storageOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled/storage_only=%t", storageOnly), func(t *testing.T) {
			f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", disabled: !storageOnly, storageOnly: storageOnly}, cert, key, roots)
			f.raw(t, "", "GET", "/bootstrap", nil, 404)
			if _, err := os.Stat(f.documentsDB); !os.IsNotExist(err) {
				t.Fatal("disabled Documents provisioned storage")
			}
		})
	}
	t.Run("slow_body", func(t *testing.T) { testCaddyDocumentsSlowBody(t, cert, key, roots) })
	t.Run("quotas", func(t *testing.T) { testCaddyDocumentsQuotas(t, cert, key, roots) })
	t.Run("source_binding", func(t *testing.T) { testCaddyDocumentsSourceBinding(t, cert, key, roots) })
	t.Run("rejected_reload", func(t *testing.T) { testCaddyDocumentsRejectedReload(t, cert, key, roots) })
	t.Run("expiry", func(t *testing.T) { testCaddyDocumentsExpiry(t, cert, key, roots) })
	t.Run("browser_recovery", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth"}, cert, key, roots)
		runCaddyDocumentsBrowser(t, f)
	})
}

func testCaddyDocumentsProtocol(t *testing.T, cert, tlsKey string, roots *x509.CertPool) {
	f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", transform: true}, cert, tlsKey, roots)
	f.raw(t, "", "GET", "/bootstrap", nil, 401)
	accessOnly := f.completeJSON(t, f.jsonPassword(t, f.plain, "alice", lifecyclePassword, ""), false)
	f.assertResource(t, accessOnly.AccessToken)
	f.doc(t, accessOnly.AccessToken, "bootstrap", nil, nil, 401)
	aliceToken, bobToken, adminToken := f.login(t, "alice"), f.login(t, "bob"), f.login(t, "admin")
	claims := f.verifyAccess(t, aliceToken)
	if claims["sub"] != "bob" || claims["email"] != "alias@example.test" {
		t.Fatal("Documents ownership test did not transform display identity")
	}
	alice, bob := f.enroll(t, aliceToken, "alice"), f.enroll(t, bobToken, "bob")
	file := f.ready(t, aliceToken, alice)
	for _, token := range []string{bobToken, adminToken} {
		f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
		f.doc(t, token, "file.delete", caddyDocumentsParams(file.ID), nil, 404)
		f.doc(t, token, "share.list", caddyDocumentsParams(file.ID), nil, 404)
	}
	for _, key := range []documents.Key{alice, bob} {
		public := caddyDocumentsDecode[documents.Key](t, f.doc(t, aliceToken, "key.lookup", map[string]string{"user_id": key.UserID}, nil, 200))
		if public.Vault != nil || public.KeyID != key.KeyID || public.UserID != key.UserID {
			t.Fatal("Documents public lookup exposed a vault or changed fingerprint")
		}
	}
	share := map[string]string{"id": file.ID, "user_id": bob.UserID}
	f.doc(t, aliceToken, "share.put", share, map[string]any{"envelope": caddyDocumentsEnvelope(bob)}, 200)
	shared := caddyDocumentsDecode[documents.File](t, f.doc(t, bobToken, "file.fetch", caddyDocumentsParams(file.ID), nil, 200))
	if shared.Owner != alice.UserID || shared.Envelope == nil || shared.Envelope.KeyID != bob.KeyID {
		t.Fatal("Documents recipient received incorrect ownership or envelope")
	}
	page := caddyDocumentsDecode[documents.Page](t, f.doc(t, bobToken, "file.list", nil, nil, 200))
	if len(page.Files) != 1 || page.Files[0].ID != file.ID || page.Files[0].Metadata != "" || page.Files[0].Envelope != nil {
		t.Fatal("Documents listing exposed private resource details")
	}
	after := caddyDocumentsDecode[documents.Page](t, f.doc(t, bobToken, "file.list", map[string]string{"after": file.ID}, nil, 200))
	if len(after.Files) != 0 {
		t.Fatal("Documents cursor was not exclusive")
	}
	f.doc(t, bobToken, "chunk.fetch", map[string]string{"id": file.ID, "idx": "0"}, nil, 200)
	f.doc(t, bobToken, "share.put", map[string]string{"id": file.ID, "user_id": alice.UserID}, map[string]any{"envelope": caddyDocumentsEnvelope(alice)}, 404)
	f.doc(t, aliceToken, "share.delete", share, nil, 200)
	f.doc(t, bobToken, "chunk.fetch", map[string]string{"id": file.ID, "idx": "0"}, nil, 404)
	testCaddyDocumentsRequestBoundaries(t, f, aliceToken, file, alice)
	// Confirm reset against both the current account and the displayed key.
	bobFile := f.ready(t, bobToken, bob)
	f.doc(t, bobToken, "share.put", map[string]string{"id": bobFile.ID, "user_id": alice.UserID}, map[string]any{"envelope": caddyDocumentsEnvelope(alice)}, 200)
	f.doc(t, aliceToken, "file.fetch", caddyDocumentsParams(bobFile.ID), nil, 200)
	confirmation := map[string]string{"user_id": alice.UserID, "key_id": alice.KeyID}
	f.doc(t, bobToken, "key.reset", nil, confirmation, 409)
	f.doc(t, bobToken, "file.fetch", caddyDocumentsParams(bobFile.ID), nil, 200)
	f.doc(t, aliceToken, "key.reset", nil, confirmation, 200)
	f.doc(t, aliceToken, "key.reset", nil, confirmation, 200)
	f.doc(t, aliceToken, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
	f.doc(t, aliceToken, "file.fetch", caddyDocumentsParams(bobFile.ID), nil, 404)
	f.doc(t, bobToken, "file.fetch", caddyDocumentsParams(bobFile.ID), nil, 200)
	replacement := f.enroll(t, aliceToken, "alice")
	f.doc(t, aliceToken, "key.reset", nil, confirmation, 409)
	if got := caddyDocumentsDecode[documents.Key](t, f.doc(t, aliceToken, "key.fetch", nil, nil, 200)); got.KeyID != replacement.KeyID {
		t.Fatal("stale reset removed replacement key")
	}
	oldFile := f.ready(t, aliceToken, replacement)
	f.admin(t, adminToken, "delete", nil)
	added := f.admin(t, adminToken, "add", map[string]any{"name": "Alice Recreated", "roles": []string{"authp/user", "alice"}})
	password, _ := added["password"].(string)
	if password == "" || localIdentityRecord(t, f.database, "alice").ID == alice.UserID {
		t.Fatal("admin recreation reused Documents owner")
	}
	f.secrets = append(f.secrets, password)
	f.doc(t, aliceToken, "bootstrap", nil, nil, 401)
	f.newBrowser(t)
	fresh := f.loginSameBrowser(t, "alice", password, false)
	f.doc(t, fresh, "file.fetch", caddyDocumentsParams(oldFile.ID), nil, 404)
	f.doc(t, fresh, "key.fetch", nil, nil, 404)
}

func testCaddyDocumentsRequestBoundaries(t *testing.T, f *caddyDocumentsFixture, token string, file documents.File, key documents.Key) {
	t.Helper()
	for name, op := range caddyDocumentsOperations {
		t.Run("method/"+name, func(t *testing.T) {
			_, path, _ := caddyDocumentsRequest(t, name, map[string]string{"id": file.ID, "user_id": key.UserID, "idx": "0"}, nil)
			r := f.raw(t, token, "HEAD", path, nil, 405)
			if r.header.Get("Allow") != op.method {
				t.Fatal("Documents method refusal omitted exact Allow")
			}
		})
	}
	for _, headers := range []http.Header{
		{"Origin": {"https://untrusted.example.test"}}, {"Origin": {f.base, f.base}}, {"Sec-Fetch-Site": {"same-site"}},
	} {
		f.raw(t, token, "GET", "/bootstrap", nil, 403, headers)
	}
	f.raw(t, token, "GET", "/bootstrap", nil, 415, http.Header{"Content-Encoding": {"identity"}})
	for _, media := range []http.Header{{"Content-Type": {"text/plain"}}, {"Content-Type": {"application/json", "application/json"}}} {
		f.raw(t, token, "POST", "/files/allocate", []byte(`{"size":32,"chunks":1}`), 415, media)
	}
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"size":32,"chunks":1,"filename":"plaintext"}`, `{"size":32.5,"chunks":1}`, `{"Size":32,"chunks":1}`, `{"size":null,"chunks":1}`, `{"size":32,"size":16,"chunks":1}`, `{"size":32,"\u0073ize":16,"chunks":1}`, `{"operation":"file.allocate","payload":{"size":32,"chunks":1}}`} {
		f.raw(t, token, "POST", "/files/allocate", []byte(body), 400)
	}
	f.raw(t, token, "POST", "/files/allocate", []byte(`{}`+strings.Repeat(" ", 65537)), 413)
	f.doc(t, token, "chunk.put", map[string]string{"id": file.ID, "idx": "0"}, map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, documents.ChunkSize+17))}, 413)
	f.raw(t, token, "PUT", "/file/"+file.ID+"/chunk/0/put", []byte(`{"id":"`+file.ID+`","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}`), 400)
	for _, suffix := range []string{"/file/bad/fetch", "/key/bad/lookup", "/file/" + file.ID + "/chunk/01/fetch"} {
		f.raw(t, token, "GET", suffix, nil, 400)
	}
	for _, suffix := range []string{"", "/", "/bootstrap/", "/%62ootstrap", "/keys%2ffetch", "/keys//fetch", "/key/fetch", "/file/list", "/unknown/api/logout", "/unknown/api/profile"} {
		f.raw(t, token, "GET", suffix, nil, 404)
	}
	for _, query := range []string{"?", "?unknown=1", "?after=", "?after=bad", "?%61fter=" + file.ID, "?after=" + file.ID + "&after=" + file.ID} {
		f.raw(t, token, "GET", "/files"+query, nil, 400)
	}
	f.raw(t, token, "GET", "/bootstrap", []byte(`{}`), 400)
	f.doc(t, token, "bootstrap", nil, nil, 200)
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	status, _, _ := registrationHTTP(t, f.plain, "GET", f.base+"/api/documents/bootstrap", nil, nil)
	if status != 404 {
		t.Fatal("Documents escaped the declared nested mount")
	}
}
