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
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	"golang.org/x/crypto/bcrypt"
)

type externalPolicyService struct {
	server                    *httptest.Server
	ca, clientCert, clientKey string
	mode                      atomic.Value
	hits, redirects, canceled atomic.Int64
	connections               atomic.Int64
	hold                      atomic.Pointer[lifecycleHold]
	mu                        sync.Mutex
	requests                  []external.Request
}

func newExternalPolicyService(t *testing.T) *externalPolicyService {
	t.Helper()
	cert, key, _ := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, _ := cookieTLSCertificate(t)
	data, err := os.ReadFile(clientCert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	template, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateData, err := os.ReadFile(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	privateBlock, _ := pem.Decode(privateData)
	private, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	template.Subject.CommonName = "policy-service-client"
	template.RawSubject = nil
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.(crypto.Signer).Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(clientCert, clientPEM, 0600); err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientPEM) {
		t.Fatal("invalid client trust")
	}
	s := &externalPolicyService{ca: cert, clientCert: clientCert, clientKey: clientKey}
	s.mode.Store("allow")
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			s.redirects.Add(1)
			w.WriteHeader(200)
			return
		}
		s.hits.Add(1)
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "policy-service-client" {
			t.Error("policy service did not authenticate its mTLS client")
		}
		if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Error("changed policy service wire request")
		}
		for _, name := range []string{"Authorization", "Cookie", "X-Api-Key", "X-Auth-Realm", "X-Private-Input"} {
			if r.Header.Get(name) != "" {
				t.Error("forwarded end-user credentials or unselected headers")
			}
		}
		var request external.Request
		d := json.NewDecoder(io.LimitReader(r.Body, 65537))
		d.DisallowUnknownFields()
		d.UseNumber()
		if err := d.Decode(&request); err != nil {
			t.Error("invalid policy request")
			w.WriteHeader(400)
			return
		}
		s.mu.Lock()
		s.requests = append(s.requests, request)
		s.mu.Unlock()
		if h := s.hold.Load(); h != nil && request.Resource == "/hold" {
			h.once.Do(func() { close(h.entered) })
			select {
			case <-h.release:
			case <-r.Context().Done():
				s.canceled.Add(1)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		switch s.mode.Load().(string) {
		case "timeout":
			<-r.Context().Done()
			s.canceled.Add(1)
			return
		case "late":
			time.Sleep(2200 * time.Millisecond)
		case "path_timeout":
			select {
			case <-time.After(1200 * time.Millisecond):
			case <-r.Context().Done():
				s.canceled.Add(1)
				return
			}
		case "redirect":
			w.Header().Set("Location", s.server.URL+"/redirect")
			w.WriteHeader(302)
			return
		case "status":
			w.WriteHeader(503)
			_, _ = io.WriteString(w, "private-policy-diagnostic")
			return
		case "media":
			w.Header().Set("Content-Type", "text/plain")
		case "unknown":
			_, _ = io.WriteString(w, `{"decision":"allow","policy":"reports","version":"revision-1","private-policy-diagnostic":true}`)
			return
		case "duplicate":
			_, _ = io.WriteString(w, `{"decision":"deny","decision":"allow","policy":"reports","version":"revision-1"}`)
			return
		case "wrong_case":
			_, _ = io.WriteString(w, `{"Decision":"allow","policy":"reports","version":"revision-1"}`)
			return
		case "mismatch":
			_, _ = io.WriteString(w, `{"decision":"allow","policy":"other","version":"revision-1"}`)
			return
		case "malformed":
			_, _ = io.WriteString(w, `{"decision":`)
			return
		case "extra":
			_, _ = io.WriteString(w, `{"decision":"allow","policy":"reports","version":"revision-1"} {}`)
			return
		case "oversize":
			_, _ = io.WriteString(w, strings.Repeat(" ", 4097))
			return
		case "oversize_gzip":
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			_, _ = io.WriteString(z, strings.Repeat(" ", 4097))
			_ = z.Close()
			return
		}
		decision := "allow"
		if s.mode.Load() == "deny" || request.Resource == "/denied-clean" {
			decision = "deny"
		}
		_ = json.NewEncoder(w).Encode(external.Result{Decision: decision, Policy: request.Policy, Version: request.Version})
	}))
	s.server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	s.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.connections.Add(1)
		}
		if state == http.StateClosed {
			s.connections.Add(-1)
		}
	}
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	return s
}
func (s *externalPolicyService) block(issuer, realm string) string {
	return fmt.Sprintf(`external authorization httpjson {
 endpoint %s/decide
 policy reports
 version revision-1
 issuer %s
 realm %s
 attribute roles
 attribute department
 attribute enrichment.department
 timeout 2s
 tls ca file %q
 tls client certificate %q %q
}`, s.server.URL, issuer, realm, s.ca, s.clientCert, s.clientKey)
}
func (s *externalPolicyService) snapshot() []external.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]external.Request(nil), s.requests...)
}

func TestCaddyExternalAuthorizationE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyExternalAuthorizationProcess$", "-test.v", "-test.timeout=135s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_EXTERNAL_AUTHORIZATION_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS external authorization: %v\n%s", err, output)
	}
}

func TestCaddyExternalAuthorizationProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_EXTERNAL_AUTHORIZATION_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	service := newExternalPolicyService(t)
	cert, key, roots := cookieTLSCertificate(t)
	const secret = "synthetic-external-policy-signing-secret"
	f := newCaddyJWKSFixture(t, "/auth", "crypto key sign-verify "+secret, "crypto key verify "+secret, cert, key, roots)
	f.client.Transport.(*http.Transport).DisableKeepAlives = true
	logPath := filepath.Join(t.TempDir(), "policy.jsonl")
	f.input = strings.Replace(f.input, "level ERROR", fmt.Sprintf("level DEBUG\noutput file %q\nformat json", logPath), 1)
	apiKey := strings.Repeat("k", 24) + strings.Repeat("A", 40)
	hash, err := bcrypt.GenerateFromPassword([]byte(apiKey), 8)
	if err != nil {
		t.Fatal(err)
	}
	f.input = strings.Replace(f.input, "roles authp/admin authp/user", fmt.Sprintf("roles authp/admin authp/user\napi key %s %q", apiKey[:24], "bcrypt:8:"+string(hash)), 1)
	f.input = strings.Replace(f.input, "enable identity store localdb", "enable identity store localdb\ntransform user {\nmatch realm local\noverwrite iss "+f.base+"/auth/login\nadd department signed as string\n}", 1)
	settings := "disable auth redirect\nbypass uri exact /public\n" + service.block(f.base+"/auth/login", "local")
	f.input = strings.Replace(f.input, "allow roles authp/user", settings+"\nallow roles authp/user", 1)
	if err := f.reload(""); err != nil {
		t.Fatal(err)
	}
	baseline := f.input
	token := f.login(t, "keyadmin")
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS512"}))
	if err != nil {
		t.Fatal("could not independently verify password credential")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != f.base+"/auth/login" || claims["origin"] != "local" {
		t.Fatal("explicit stable issuer or realm was not applied")
	}

	auth := http.Header{"Authorization": {"Bearer " + token}, "X-Private-Input": {"private-input"}, "Cookie": {"unrelated=private-cookie"}}
	request := func(method, path string, headers http.Header, want int) {
		t.Helper()
		status, reply, body := jwksHTTPRequest(t, f, method, path, headers)
		if status != want || (want == 200 && string(body) != "allowed") {
			data, _ := os.ReadFile(logPath)
			var messages []string
			for _, line := range strings.Split(string(data), "\n") {
				var record struct {
					Message string `json:"msg"`
				}
				if json.Unmarshal([]byte(line), &record) == nil {
					messages = append(messages, record.Message)
				}
			}
			t.Fatalf("protected request: HTTP %d, want %d; decisions=%d; messages=%v", status, want, service.hits.Load(), messages)
		}
		if want == 403 && (reply.Get("Cache-Control") != "no-store" || len(reply.Values("Set-Cookie")) != 0) {
			t.Fatal("external denial cleared valid credentials or lost no-store")
		}
		if strings.Contains(string(body), "private-policy-diagnostic") || strings.Contains(string(body), service.server.URL) {
			t.Fatal("remote diagnostics escaped")
		}
	}
	cacheMisses := func() int {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Count(string(data), `"msg":"cache miss for JWT credentials"`)
	}
	before, misses := service.hits.Load(), cacheMisses()
	for range 2 {
		request("GET", "/protected?private-query=yes", auth, 200)
	}
	if service.hits.Load() != before+2 || cacheMisses() != misses+1 {
		t.Fatal("cached credential bypassed a fresh remote decision")
	}
	service.mode.Store("deny")
	request("GET", "/protected", auth, 403)
	service.mode.Store("allow")
	request("GET", "/protected", http.Header{"Cookie": {"AUTHP_ACCESS_TOKEN=" + token}}, 200)
	for _, r := range service.snapshot() {
		if r.Policy != "reports" || r.Version != "revision-1" || r.Identity.Subject != "keyadmin" || r.Identity.Issuer != f.base+"/auth/login" || r.Identity.Realm != "local" || r.Resource != "/protected" || r.Action != "GET" || r.Attributes["department"] != "signed" || len(r.Attributes) != 2 {
			t.Fatal("incorrect decision snapshot")
		}
	}

	for _, name := range []string{"role", "issuer", "realm", "expired"} {
		t.Run("local_denial_"+name, func(t *testing.T) {
			copy := maps.Clone(claims)
			switch name {
			case "role":
				copy["roles"] = []string{"untrusted"}
			case "issuer":
				copy["iss"] = "foreign"
			case "realm":
				copy["origin"] = "foreign"
			case "expired":
				copy["exp"] = time.Now().Add(-time.Hour).Unix()
			}
			signed, err := jwt.NewWithClaims(jwt.SigningMethodHS512, copy).SignedString([]byte(secret))
			if err != nil {
				t.Fatal(err)
			}
			before := service.hits.Load()
			status, _, _ := jwksHTTPRequest(t, f, "GET", "/protected", http.Header{"Authorization": {"Bearer " + signed}})
			if status != 401 && status != 403 {
				t.Fatalf("invalid identity HTTP %d", status)
			}
			if service.hits.Load() != before {
				t.Fatal("local denial reached policy service")
			}
		})
	}
	before = service.hits.Load()
	request("GET", "/public", nil, 200)
	if service.hits.Load() != before {
		t.Fatal("explicit bypass consulted service")
	}
	for _, mode := range []string{"unknown", "duplicate", "wrong_case", "mismatch", "malformed", "extra", "oversize", "oversize_gzip", "redirect", "status", "media", "timeout", "late"} {
		t.Run(mode, func(t *testing.T) { service.mode.Store(mode); request("GET", "/protected", auth, 403) })
	}
	if service.redirects.Load() != 0 {
		t.Fatal("policy redirect followed")
	}
	service.mode.Store("allow")
	request("PATCH", "/files/a%20b", auth, 200)
	request("GET", "/files/a%20", auth, 200)
	before = service.hits.Load()
	request("GET", "/files/a%2fb", auth, 403)
	if service.hits.Load() != before {
		t.Fatal("encoded separator reached service")
	}
	service.mode.Store("path_timeout")
	request("GET", "/x/../shared", auth, 403)
	service.mode.Store("allow")
	request("GET", "/x/../denied-clean", auth, 403)
	requests := service.snapshot()
	if requests[len(requests)-1].Resource != "/denied-clean" {
		t.Fatal("cleaned path was not independently authorized")
	}
	t.Run("client_cancellation", func(t *testing.T) {
		service.mode.Store("timeout")
		before := service.hits.Load()
		canceled := service.canceled.Load()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", f.base+"/protected", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header = auth.Clone()
		done := make(chan error, 1)
		go func() {
			resp, err := f.client.Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			done <- err
		}()
		deadline := time.After(3 * time.Second)
		for service.hits.Load() == before {
			select {
			case <-deadline:
				t.Fatal("policy request did not start")
			case <-time.After(time.Millisecond):
			}
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("cancellation unexpectedly succeeded")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancellation stuck")
		}
		for service.canceled.Load() == canceled {
			select {
			case <-deadline:
				t.Fatal("policy transport ignored cancellation")
			case <-time.After(time.Millisecond):
			}
		}
		service.mode.Store("allow")
	})
	t.Run("enrichment_is_ACL_only", func(t *testing.T) {
		f.input = strings.Replace(baseline, "allow roles authp/user", fmt.Sprintf(`claims enrichment static {
 source static
 version v1
 issuer %s/auth/login
 realm local
 subject claim sub
 tenant claim origin
 audience %s
 attribute enrichment.department string
 claim enrichment.department engineering
}
acl field department {
 claim enrichment.department
 type string
}
acl rule {
 match department engineering
 allow stop
}`, f.base, "api"), 1)
		// The fixture credential is signed with an audience solely for this composed policy.
		copy := maps.Clone(claims)
		copy["aud"] = "api"
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS512, copy).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.reload(""); err != nil {
			t.Fatal(err)
		}
		request("GET", "/protected", http.Header{"Authorization": {"Bearer " + signed}}, 200)
		latest := service.snapshot()
		last := latest[len(latest)-1]
		if _, exists := last.Attributes["enrichment.department"]; exists || last.Attributes["department"] != "signed" {
			t.Fatal("enrichment changed original external attributes")
		}
		service.mode.Store("deny")
		request("GET", "/protected", http.Header{"Authorization": {"Bearer " + signed}}, 403)
		service.mode.Store("allow")
	})
	t.Run("basic_and_API_key", func(t *testing.T) {
		f.input = strings.Replace(strings.Replace(baseline, "overwrite iss "+f.base+"/auth/login\n", "", 1), service.block(f.base+"/auth/login", "local"), service.block("authp", "local")+"\nwith basic auth portal portal realm local\nwith api key auth portal portal realm local", 1)
		if err := f.reload(""); err != nil {
			t.Fatal(err)
		}
		for _, headers := range []http.Header{
			{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("keyadmin:"+lifecyclePassword))}, "X-Auth-Realm": {"local"}},
			{"X-Api-Key": {apiKey}, "X-Auth-Realm": {"local"}},
		} {
			before := service.hits.Load()
			for range 2 {
				request("GET", "/protected", headers, 200)
			}
			service.mode.Store("deny")
			request("GET", "/protected", headers, 403)
			service.mode.Store("allow")
			if service.hits.Load() != before+3 {
				t.Fatal("authenticated credential bypassed remote decisions")
			}
		}
	})
	t.Run("reload_and_drain", func(t *testing.T) {
		f.input = baseline
		if err := f.reload(""); err != nil {
			t.Fatal(err)
		}
		active, err := caddy.ActiveContext().AppIfConfigured("security")
		if err != nil {
			t.Fatal(err)
		}
		old := active.(*App)
		backend := old.pluginClosers[0].(*httpJSONExternalBackend)
		for _, bad := range []string{strings.Replace(baseline, service.ca, service.ca+".missing", 1), strings.Replace(baseline, "version revision-1", "version \"\"", 1)} {
			f.input = bad
			if err := f.reload(""); err == nil {
				t.Fatal("invalid candidate published")
			}
			request("GET", "/protected", auth, 200)
		}
		hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
		service.hold.Store(hold)
		var once sync.Once
		defer once.Do(func() { close(hold.release) })
		done := make(chan int, 1)
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "GET", f.base+"/hold", nil)
			req.Header = auth.Clone()
			resp, err := f.client.Do(req)
			if err != nil {
				done <- 0
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			done <- resp.StatusCode
		}()
		awaitLifecycle(t, hold.entered, "policy decision")
		f.input = strings.Replace(baseline, "version revision-1", "version revision-2", 1)
		reload := make(chan error, 1)
		go func() { reload <- f.reload("") }()
		waitDisposing(t, old)
		request("GET", "/protected", auth, 200)
		select {
		case err := <-reload:
			t.Fatal("reload skipped drain", err)
		default:
		}
		once.Do(func() { close(hold.release) })
		select {
		case status := <-done:
			if status != 200 {
				t.Fatalf("retired in-flight decision HTTP %d", status)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("held decision stuck")
		}
		select {
		case err := <-reload:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("reload stuck")
		}
		before := service.hits.Load()
		if _, err := backend.Decide(t.Context(), service.snapshot()[0]); err == nil || service.hits.Load() != before {
			t.Fatal("retired backend accepted work")
		}
		service.hold.Store(nil)
	})
	t.Run("outage", func(t *testing.T) { service.server.Close(); request("GET", "/protected", auth, 403) })
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{token, lifecyclePassword, apiKey, "private-policy-diagnostic", "private-input", "private-cookie"} {
		if strings.Contains(string(logs), private) {
			t.Fatal("credential or remote diagnostic leaked into logs")
		}
	}
}
