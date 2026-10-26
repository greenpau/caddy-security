// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	storage "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
	"go.uber.org/zap"
)

// Each peer is the real Caddy command with production modules. The existing
// fixture entrypoint adds only private TLS roots, without changing machine trust.
// The parent remains race-instrumented; the bounded command build is cgo-free.
func TestCaddySharedOAuthLoginStoreE2E(t *testing.T) {
	binary := buildSharedOAuthCaddy(t)

	t.Run("nested_shared_transactions", func(t *testing.T) {
		f := newCaddySharedOAuthPair(t, binary, "/tenant/auth", 8, false)
		f.qualifyTLS(t)
		f.direction(t, 0, f.destination("first"))
		f.direction(t, 1, "")
		f.concurrentCallbacks(t)
		f.shutdownAndReload(t)
		f.isolation(t)
		f.cancelDuringExchange(t)
	})
	t.Run("root_mount", func(t *testing.T) {
		f := newCaddySharedOAuthPair(t, binary, "", 8, false)
		f.direction(t, 0, f.destination("root"))
	})
	t.Run("capacity_and_direct_policy", func(t *testing.T) {
		f := newCaddySharedOAuthPair(t, binary, "/tenant/auth", 1, true)
		f.capacityAndDirectPolicy(t)
	})
}

func buildSharedOAuthCaddy(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath -p=1")
	build.WaitDelay = 5 * time.Second
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build actual Caddy command: %v\n%s", err, output)
	}
	return binary
}

const sharedOAuthPeerHeader = "X-Caddy-Test-OAuth-Peer"

type caddySharedOAuthProcess struct {
	pair                                 *caddySharedOAuthPair
	index                                int
	origin, admin, workspace, configPath string
	input                                []byte
	cmd                                  *exec.Cmd
	done                                 chan error
	log                                  *os.File
	cancel                               context.CancelFunc
}

type caddySharedOAuthPair struct {
	binary, origin, mount, callback, database, cert, key string
	consulAddress                                        string
	capacity                                             int
	peers                                                [2]*caddySharedOAuthProcess
	upstream, directUpstream                             *oauthE2EUpstream
	proxy                                                *httptest.Server
	client                                               *http.Client
	transport                                            *http.Transport
	signer                                               jwksKeyFiles
	keys                                                 []map[string]string
	providerJSON                                         []byte
	secrets, bindings                                    []string
	proxyFailures                                        atomic.Int32
}

type caddySharedOAuthFlow struct {
	client                                                *http.Client
	callback, state, sessionID, cookieHeader, destination string
}

type sharedOAuthHTTPResult struct {
	response oidcRPResponse
	err      error
}

func newCaddySharedOAuthPair(t *testing.T, binary, mount string, capacity int, direct bool, configure ...func(*caddySharedOAuthPair)) *caddySharedOAuthPair {
	t.Helper()
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("cannot load shared OAuth TLS fixture")
	}
	f := &caddySharedOAuthPair{binary: binary, mount: mount, capacity: capacity, cert: cert, key: key,
		database: filepath.Join(registrationTestDirectory(t), "oauth.db"), signer: newJWKSKeyFiles(t, "RSA", "access")}
	for _, option := range configure {
		option(f)
	}
	f.secrets = append(f.secrets, oauthE2ESecret)
	f.upstream = newOAuthE2EUpstream(t, pair, "EdDSA")
	f.upstream.fixedSubject = "shared-oauth-subject"
	if direct {
		f.directUpstream = newOAuthE2EUpstream(t, pair, "EdDSA")
		f.directUpstream.fixedSubject = "shared-direct-subject"
	}
	f.transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	f.client = &http.Client{Transport: f.transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for i := range f.peers {
		workspace := registrationTestDirectory(t)
		f.peers[i] = &caddySharedOAuthProcess{pair: f, index: i, origin: "https://" + lifecycleAddress(t), admin: lifecycleAddress(t), workspace: workspace, configPath: filepath.Join(workspace, "config.json")}
	}
	proxyTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	proxy := &httputil.ReverseProxy{
		Transport: proxyTransport,
		ErrorLog:  log.New(io.Discard, "", 0),
		Rewrite: func(r *httputil.ProxyRequest) {
			peer, _ := strconv.Atoi(r.In.Header.Get(sharedOAuthPeerHeader))
			backend, _ := url.Parse(f.peers[peer].origin)
			r.Out.URL.Scheme, r.Out.URL.Host = backend.Scheme, backend.Host
			public, _ := url.Parse(f.origin)
			r.Out.Host = public.Host
			for name := range r.Out.Header {
				lower := strings.ToLower(name)
				if lower == strings.ToLower(sharedOAuthPeerHeader) || lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
					r.Out.Header.Del(name)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			f.proxyFailures.Add(1)
			http.Error(w, "fixture backend unavailable", http.StatusBadGateway)
		},
	}
	f.proxy = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		public, _ := url.Parse(f.origin)
		peer, err := strconv.Atoi(r.Header.Get(sharedOAuthPeerHeader))
		if public == nil || r.Host != public.Host || err != nil || peer < 0 || peer >= len(f.peers) {
			http.Error(w, "fixture route rejected", http.StatusBadRequest)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	f.proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.proxy.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	f.proxy.StartTLS()
	f.origin = f.proxy.URL
	f.callback = f.origin + mount + "/oauth2/upstream/authorization-code-callback"
	f.upstream.callback = f.callback
	if f.directUpstream != nil {
		f.directUpstream.callback = f.origin + "/_authcrunch/oauth2/direct/authorization-code-callback"
	}
	// Register before starting either process, including partial-start failures.
	t.Cleanup(func() {
		defer f.proxy.Close()
		defer proxyTransport.CloseIdleConnections()
		defer f.transport.CloseIdleConnections()
		// A fatal redaction assertion must not skip the other peer's cleanup.
		defer func() {
			for _, p := range f.peers {
				p.forceCleanup(t)
			}
		}()
		for _, p := range f.peers {
			p.stop(t)
		}
		for _, u := range []*oauthE2EUpstream{f.upstream, f.directUpstream} {
			if u != nil {
				u.mu.Lock()
				f.secrets = append(f.secrets, u.issuedSecrets...)
				u.mu.Unlock()
			}
		}
		f.scanLogs(t)
	})
	for _, p := range f.peers {
		p.input = f.adapt(t, p, "cluster", oauthE2ESecret, false)
		p.start(t)
	}
	if f.peers[0].cmd.Process.Pid == f.peers[1].cmd.Process.Pid {
		t.Fatal("shared OAuth fixture did not start independent OS processes")
	}
	return f
}

func (f *caddySharedOAuthPair) adapt(t *testing.T, p *caddySharedOAuthProcess, namespace, secret string, missingPortal bool) []byte {
	t.Helper()
	loginStore := ""
	if namespace != "" {
		loginStore = "login store shared namespace " + namespace
	}
	portal, mount := "portal", f.mount
	if missingPortal {
		portal = "missing"
	}
	if mount == "" {
		mount = "/"
	}
	var directProvider, directRoutes string
	if f.directUpstream != nil {
		directProvider = fmt.Sprintf(`oauth identity provider direct_upstream {
 driver generic
 realm direct_upstream
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 scopes openid profile email
 login store shared namespace direct-cluster
}
authorization policy direct {
 use oauth identity provider direct_upstream
 oauth public origin %s
 allow roles authp/user
}
`, oauthE2EClient, oauthE2ESecret, f.directUpstream.server.URL, f.directUpstream.server.URL, f.origin)
		directRoutes = `route /direct-resource {
 authorize with direct
 respond "direct resource" 200
}
route /_authcrunch/oauth2/direct/* {
 authorize with direct
 respond "callback reached downstream" 500
}
`
	}
	backend := fmt.Sprintf("oauth login store sqlite shared {\npath %q\ntimeout 5s\ncapacity %d\n}", f.database, f.capacity)
	globalStorage := ""
	if f.consulAddress != "" {
		globalStorage = fmt.Sprintf("storage consul {\naddress %q\nprefix issue508\naes_key 0123456789abcdef0123456789abcdef\n}", f.consulAddress)
		backend = fmt.Sprintf("oauth login store consul shared {\ntimeout 5s\ncapacity %d\n}", f.capacity)
	}
	input := fmt.Sprintf(`{
 admin %s
 persist_config off
 %s
 auto_https off
 servers {
  protocols h1 h2
 }
 log {
  level INFO
  output file %q
  format filter {
   wrap json
   fields {
    request>uri delete
    resp_headers>Location delete
    request>headers>Referer delete
   }
  }
 }
 security {
  %s
  oauth identity provider upstream {
   driver generic
   realm upstream
   client_id %s
   client_secret %s
   base_auth_url %s
   metadata_url %s/metadata
   scopes openid profile email
   %s
  }
  authentication portal portal {
   enable identity provider upstream
   cookie path /
   %s
   trust login redirect uri domain exact %s path exact /resource
  }
  authorization policy resource {
   %s
   validate bearer header
   allow roles authp/user
   disable auth redirect
  }
  %s
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
    resp_headers>Location delete
    request>headers>Referer delete
   }
  }
 }
 route /ready {
  respond "shared OAuth ready" 200
 }
 route /resource {
  authorize with resource
  respond "shared OAuth resource" 200
 }
 %s
 route %s* {
  authenticate with %s at %s
 }
 route {
  respond "shared OAuth outside" 404
 }
}`, p.admin, globalStorage, filepath.Join(p.workspace, "runtime.log"), backend, oauthE2EClient, secret, f.upstream.server.URL, f.upstream.server.URL,
		loginStore, f.signer.signer("access"), strings.TrimPrefix(f.origin, "https://"), f.signer.verifier("access"), directProvider,
		p.origin, f.cert, f.key, filepath.Join(p.workspace, "access.log"), directRoutes, mount, portal, mount)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal("cannot adapt shared OAuth Caddy configuration")
	}
	if p.index == 0 && namespace == "cluster" && !missingPortal && f.providerJSON == nil {
		var document struct {
			Apps struct {
				Security struct {
					Config struct {
						Providers []struct {
							Name   string          `json:"name"`
							Params json.RawMessage `json:"params"`
						} `json:"identity_providers"`
					} `json:"config"`
				} `json:"security"`
			} `json:"apps"`
		}
		if json.Unmarshal(data, &document) != nil {
			t.Fatal("cannot retain exact provider snapshot")
		}
		for _, provider := range document.Apps.Security.Config.Providers {
			if provider.Name == "upstream" {
				f.providerJSON = bytes.Clone(provider.Params)
			}
		}
		if len(f.providerJSON) == 0 {
			t.Fatal("adapted provider snapshot is missing")
		}
	}
	return data
}

func (p *caddySharedOAuthProcess) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, p.pair.binary, args...)
	cmd.Dir = p.workspace
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_TEST_CA="+p.pair.cert, "XDG_DATA_HOME="+p.workspace, "XDG_CONFIG_HOME="+p.workspace)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func (p *caddySharedOAuthProcess) start(t *testing.T) {
	t.Helper()
	if p.done != nil {
		t.Fatal("shared OAuth peer already running")
	}
	if err := os.WriteFile(p.configPath, p.input, 0600); err != nil {
		t.Fatal("cannot write private peer configuration")
	}
	var err error
	p.log, err = os.OpenFile(filepath.Join(p.workspace, "process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("cannot open private peer diagnostics")
	}
	// testing.T.Context is canceled before Cleanup; retain an independently
	// bounded process context so Cleanup can exercise Caddy's real drain first.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 4*time.Minute)
	p.cancel = cancel
	p.cmd = p.command(ctx, "run", "--config", p.configPath)
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		p.cancel()
		_ = p.log.Close()
		t.Fatal("cannot start actual Caddy peer")
	}
	p.done = make(chan error, 1)
	command, done := p.cmd, p.done
	go func() { done <- command.Wait() }()
	p.ready(t)
}

func (p *caddySharedOAuthProcess) ready(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			p.done = nil
			p.cancel()
			_ = p.log.Close()
			t.Fatal("actual Caddy peer exited before mounted security readiness")
		case <-ctx.Done():
			t.Fatal("actual Caddy peer did not publish mounted JWKS")
		case <-ticker.C:
			// Probe the peer directly with its public Host; avoid expected startup
			// connection failures becoming proxy errors in the acceptance inventory.
			req, _ := http.NewRequestWithContext(ctx, "GET", p.origin+p.pair.mount+"/.well-known/jwks.json", nil)
			public, _ := url.Parse(p.pair.origin)
			req.Host = public.Host
			response, err := p.pair.client.Do(req)
			if err != nil {
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			_ = response.Body.Close()
			if readErr != nil || len(body) > 1<<20 || response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.Header.Get("Content-Type") != "application/jwk-set+json" {
				continue
			}
			var document struct {
				Keys []map[string]string `json:"keys"`
			}
			if json.Unmarshal(body, &document) != nil || len(document.Keys) != 1 || document.Keys[0]["kid"] != "access" || document.Keys[0]["alg"] != "RS512" {
				t.Fatal("peer readiness did not return the configured public key")
			}
			if p.pair.keys == nil {
				p.pair.keys = document.Keys
			} else {
				before, _ := json.Marshal(p.pair.keys)
				current, _ := json.Marshal(document.Keys)
				if !bytes.Equal(before, current) {
					t.Fatal("Caddy peers do not publish identical verifier keys")
				}
			}
			return
		}
	}
}

func (p *caddySharedOAuthProcess) stop(t *testing.T) {
	t.Helper()
	if p.done == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := p.command(ctx, "stop", "--address", p.admin)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Error("actual Caddy peer graceful-stop command failed (output withheld)")
		_ = p.cmd.Process.Kill()
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Error("actual Caddy peer did not exit cleanly")
		}
	case <-ctx.Done():
		t.Error("actual Caddy peer did not drain within its shutdown bound")
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("actual Caddy peer cleanup did not reap its process")
		}
	}
	p.done = nil
	p.cancel()
	_ = p.log.Close()
	p.pair.transport.CloseIdleConnections()
	assertAdminRedacted(t, output, p.pair.secrets)
}

func (p *caddySharedOAuthProcess) forceCleanup(t *testing.T) {
	t.Helper()
	if p.done == nil {
		return
	}
	// This path is containment after a failed assertion, never graceful-stop
	// acceptance. Join the command before temporary directories can disappear.
	t.Error("shared OAuth peer required emergency process cleanup")
	p.cancel()
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Error("shared OAuth emergency cleanup did not reap the command")
	}
	p.done = nil
	_ = p.log.Close()
}

func (p *caddySharedOAuthProcess) reload(t *testing.T, candidate []byte, accept bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+p.admin+"/load", bytes.NewReader(candidate))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "must-revalidate")
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("actual Caddy candidate reload transport failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	assertAdminRedacted(t, body, p.pair.secrets)
	if err != nil || len(body) > 1<<20 || (response.StatusCode == 200) != accept {
		t.Fatal("actual Caddy candidate reload outcome differed (body withheld)")
	}
	if accept {
		p.input = bytes.Clone(candidate)
	}
	p.ready(t)
}

func (f *caddySharedOAuthPair) browser(t *testing.T) *http.Client {
	t.Helper()
	client := *f.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal("cannot create ordinary OAuth cookie jar")
	}
	return &client
}

func (f *caddySharedOAuthPair) do(ctx context.Context, client *http.Client, peer int, target string, headers http.Header) sharedOAuthHTTPResult {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return sharedOAuthHTTPResult{err: errors.New("request construction failed")}
	}
	for name, values := range headers {
		req.Header[name] = slices.Clone(values)
	}
	if strings.HasPrefix(target, f.origin+"/") {
		req.Header.Set(sharedOAuthPeerHeader, strconv.Itoa(peer))
	}
	response, err := client.Do(req)
	if err != nil {
		return sharedOAuthHTTPResult{err: errors.New("verified TLS request failed")}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		return sharedOAuthHTTPResult{err: errors.New("response lacked bounded body or verified TLS")}
	}
	return sharedOAuthHTTPResult{response: oidcRPResponse{response.StatusCode, response.Header.Clone(), body}}
}

func (f *caddySharedOAuthPair) capture(response oidcRPResponse) {
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Value == "" || cookie.MaxAge < 0 {
			continue
		}
		if cookie.Name == "AUTHP_SESSION_ID" {
			f.bindings = append(f.bindings, cookie.Value)
		} else if cookie.Name != "AUTHP_REDIRECT_URL" {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	if value := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer "); value != "" {
		f.secrets = append(f.secrets, value)
	}
}

func (f *caddySharedOAuthPair) result(t *testing.T, stage string, result sharedOAuthHTTPResult, status int) oidcRPResponse {
	t.Helper()
	f.capture(result.response)
	if result.err != nil || result.response.status != status {
		t.Fatalf("shared OAuth %s: status=%d want=%d (private data withheld)", stage, result.response.status, status)
	}
	return result.response
}

func (f *caddySharedOAuthPair) request(t *testing.T, client *http.Client, peer int, target, stage string, status int, headers http.Header) oidcRPResponse {
	t.Helper()
	return f.result(t, stage, f.do(t.Context(), client, peer, target, headers), status)
}

func (f *caddySharedOAuthPair) destination(label string) string {
	return f.origin + "/resource?" + (url.Values{"flow": {label}, "path": {"/one/two"}, "value": {"one&two"}}).Encode() + "#section%202"
}

func (f *caddySharedOAuthPair) begin(t *testing.T, peer int, destination string) caddySharedOAuthFlow {
	t.Helper()
	client := f.browser(t)
	start := f.request(t, client, peer, f.origin+f.mount+"/oauth2/upstream?redirect_url="+url.QueryEscape(destination), "provider initiation", 302,
		http.Header{"Forwarded": {"for=192.0.2.1;host=attacker.invalid;proto=http"}, "X-Forwarded-Host": {"attacker.invalid"}, "X-Forwarded-Proto": {"http"}})
	start.noStore(t)
	var issuedBinding string
	for _, cookie := range (&http.Response{Header: start.header}).Cookies() {
		if cookie.Name != "AUTHP_SESSION_ID" || cookie.MaxAge < 0 {
			continue
		}
		if cookie.Value == "" || issuedBinding != "" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatal("shared OAuth initiation changed protected binding-cookie privacy")
		}
		issuedBinding = cookie.Value
	}
	authorize, err := url.Parse(start.header.Get("Location"))
	if err != nil || authorize.Scheme+"://"+authorize.Host != f.upstream.server.URL || authorize.Path != "/authorize" || authorize.User != nil || authorize.Fragment != "" {
		t.Fatal("shared OAuth initiation escaped its real issuer")
	}
	state, nonce := authorize.Query().Get("state"), authorize.Query().Get("nonce")
	f.secrets = append(f.secrets, state, nonce, authorize.Query().Get("code_challenge"))
	if state == "" || nonce == "" || authorize.Query().Get("redirect_uri") != f.callback {
		t.Fatal("shared OAuth initiation lost public callback binding")
	}
	authorized := f.request(t, client, peer, authorize.String(), "issuer authorization", 302, nil)
	callback, err := url.Parse(authorized.header.Get("Location"))
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != f.callback || callback.User != nil || callback.Fragment != "" || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		t.Fatal("shared OAuth issuer callback changed its trusted binding")
	}
	f.secrets = append(f.secrets, callback.Query().Get("code"))
	proof, _ := http.NewRequest("GET", callback.String(), nil)
	var sessionID string
	for _, cookie := range client.Jar.Cookies(callback) {
		proof.AddCookie(cookie)
		if cookie.Name == "AUTHP_SESSION_ID" {
			sessionID = cookie.Value
		}
	}
	if sessionID == "" || sessionID != issuedBinding {
		t.Fatal("shared OAuth initiation did not establish browser binding")
	}
	return caddySharedOAuthFlow{client: client, callback: callback.String(), state: state, sessionID: sessionID, cookieHeader: proof.Header.Get("Cookie"), destination: destination}
}

func (f *caddySharedOAuthPair) exchanges() int {
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	return f.upstream.exchanges
}

func (f *caddySharedOAuthPair) deny(t *testing.T, result oidcRPResponse) {
	t.Helper()
	result.noStore(t)
	f.denyCredentials(t, result)
}

func (f *caddySharedOAuthPair) denyDirect(t *testing.T, result oidcRPResponse) {
	t.Helper()
	if result.header.Get("Cache-Control") != "no-store" || result.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("direct-policy denial lost cache or referrer protection")
	}
	f.denyCredentials(t, result)
}

func (f *caddySharedOAuthPair) denyCredentials(t *testing.T, result oidcRPResponse) {
	t.Helper()
	providerDestinationNoIssuance(t, result)
	for _, cookie := range (&http.Response{Header: result.header}).Cookies() {
		if cookie.Name == "AUTHZ_direct_SESSION" && cookie.Value != "" && cookie.MaxAge >= 0 {
			t.Fatal("rejected direct-policy login published a session credential")
		}
	}
	if result.header.Get("Location") != "" || result.header.Get("Authorization") != "" {
		t.Fatal("rejected shared OAuth callback published a redirect or credential")
	}
}

func (f *caddySharedOAuthPair) success(t *testing.T, response oidcRPResponse, flow caddySharedOAuthFlow) string {
	t.Helper()
	response.noStore(t)
	want := flow.destination
	if want == "" {
		want = f.origin + f.mount + "/portal?redirect_url="
	}
	if response.header.Get("Location") != want {
		t.Fatal("shared OAuth callback lost its stored destination")
	}
	var token string
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		if cookie.Name == "AUTHP_ACCESS_TOKEN" && cookie.MaxAge >= 0 && cookie.Value != "" {
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || token != "" {
				t.Fatal("shared OAuth callback changed access cookie privacy")
			}
			token = cookie.Value
		}
		if (cookie.Name == "AUTHP_REFRESH_TOKEN" || cookie.Name == "AUTHP_OIDC_SESSION_ID") && cookie.MaxAge >= 0 && cookie.Value != "" {
			t.Fatal("shared pending login unexpectedly created refresh or OP authority")
		}
	}
	if token == "" {
		t.Fatal("shared OAuth callback omitted its actual access credential")
	}
	f.secrets = append(f.secrets, token)
	claims := verifyCaddyJWKSSignature(t, f.keys, token, "RS512", "access")
	roles, rolesOK := claims["roles"].([]any)
	id, idOK := claims["id"].(string)
	exp, expOK := claims["exp"].(float64)
	issuer, issuerOK := claims["iss"].(string)
	parsedIssuer, err := url.Parse(issuer)
	if !idOK || id == "" || !rolesOK || !slices.Contains(roles, any("authp/user")) || !expOK || exp <= float64(time.Now().Unix()) || !issuerOK || err != nil || parsedIssuer.Scheme+"://"+parsedIssuer.Host != f.origin || claims["email"] != "shared-oauth-subject@example.test" {
		t.Fatal("shared OAuth access failed independently verified identity/lifetime checks")
	}
	if parsedIssuer.User != nil || parsedIssuer.RawQuery != "" || parsedIssuer.Fragment != "" || (f.mount != "" && parsedIssuer.Path != f.mount && !strings.HasPrefix(parsedIssuer.Path, f.mount+"/")) {
		t.Fatal("shared OAuth access issuer escaped its configured portal mount")
	}
	for peer := range f.peers {
		if f.peers[peer].done == nil {
			continue
		}
		resource := f.request(t, f.client, peer, f.origin+"/resource", "peer stateless authorization", 200, http.Header{"Authorization": {"Bearer " + token}})
		if string(resource.body) != "shared OAuth resource" {
			t.Fatal("shared OAuth access did not authorize the real peer resource")
		}
	}
	return token
}

func (f *caddySharedOAuthPair) replay(t *testing.T, peer int, flow caddySharedOAuthFlow) {
	t.Helper()
	before := f.exchanges()
	r := f.request(t, f.client, peer, flow.callback, "spent transaction replay", 401, http.Header{"Cookie": {flow.cookieHeader}})
	f.deny(t, r)
	if f.exchanges() != before {
		t.Fatal("replay reached the issuer token exchange")
	}
}

func (f *caddySharedOAuthPair) direction(t *testing.T, peer int, destination string) {
	t.Helper()
	before := f.exchanges()
	flow := f.begin(t, peer, destination)
	wrong := f.request(t, f.browser(t), 1-peer, flow.callback, "wrong browser", 401, nil)
	f.deny(t, wrong)
	malformed := f.request(t, flow.client, 1-peer, flow.callback+"&state="+url.QueryEscape(flow.state), "duplicate callback state", 401, nil)
	f.deny(t, malformed)
	if f.mount != "" {
		alias := strings.Replace(flow.callback, f.origin+f.mount+"/", f.origin+f.mount+"-neighbor/", 1)
		outside := f.request(t, flow.client, 1-peer, alias, "callback outside declared mount", 404, nil)
		f.deny(t, outside)
	}
	if f.exchanges() != before {
		t.Fatal("wrong browser consumed a shared OAuth transaction")
	}
	// Both values arrive by ordinary portal requests. The stored destination,
	// including explicit empty, must win over this other-tab legacy cookie.
	f.request(t, flow.client, peer, f.origin+f.mount+"/login?fresh=1&redirect_url="+url.QueryEscape(f.destination("competing")), "legacy destination update", 200, nil)
	callback := flow.callback + "&redirect_url=" + url.QueryEscape(f.destination("callback"))
	completed := f.request(t, flow.client, 1-peer, callback, "cross-process completion", 303, nil)
	f.success(t, completed, flow)
	if f.exchanges() != before+1 {
		t.Fatal("cross-process completion did not exchange exactly once")
	}
	f.replay(t, peer, flow)
	f.replay(t, 1-peer, flow)
}

func (f *caddySharedOAuthPair) concurrentCallbacks(t *testing.T) {
	t.Helper()
	flow := f.begin(t, 0, f.destination("concurrent"))
	before := f.exchanges()
	var results [2]sharedOAuthHTTPResult
	var workers sync.WaitGroup
	start := make(chan struct{})
	for peer := range f.peers {
		workers.Go(func() {
			<-start
			results[peer] = f.do(t.Context(), f.client, peer, flow.callback, http.Header{"Cookie": {flow.cookieHeader}})
		})
	}
	close(start)
	workers.Wait()
	for _, result := range results {
		f.capture(result.response)
	}
	winners := 0
	for _, result := range results {
		if result.err != nil {
			t.Fatal("concurrent shared OAuth callback transport failed")
		}
		switch result.response.status {
		case 303:
			winners++
			f.success(t, result.response, flow)
		case 401:
			f.deny(t, result.response)
		default:
			t.Fatalf("concurrent callback returned HTTP %d", result.response.status)
		}
	}
	if winners != 1 || f.exchanges() != before+1 {
		t.Fatal("concurrent Caddy peers did not claim the transaction exactly once")
	}
	f.replay(t, 0, flow)
	f.replay(t, 1, flow)
}

func (f *caddySharedOAuthPair) shutdownAndReload(t *testing.T) {
	t.Helper()
	flow := f.begin(t, 0, f.destination("shutdown"))
	f.peers[0].stop(t)
	completed := f.request(t, flow.client, 1, flow.callback, "completion after initiating peer shutdown", 303, nil)
	f.success(t, completed, flow)
	f.peers[0].start(t)
	f.replay(t, 0, flow)
	f.replay(t, 1, flow)
	f.peers[1].stop(t)
	f.peers[1].start(t)
	f.replay(t, 1, flow)
	flow = f.begin(t, 0, f.destination("candidate"))
	candidate := f.adapt(t, f.peers[0], "cluster", oauthE2ESecret, true)
	f.peers[0].reload(t, candidate, false)
	completed = f.request(t, flow.client, 1, flow.callback, "completion after candidate rejection", 303, nil)
	f.success(t, completed, flow)
	f.direction(t, 1, f.destination("old-serving-runtime"))
}

func (f *caddySharedOAuthPair) isolation(t *testing.T) {
	t.Helper()
	for _, scenario := range []struct{ name, namespace, secret string }{
		{"namespace", "other-cluster", oauthE2ESecret},
		{"normalized-config", "cluster", "different-private-client-secret"},
		{"omitted-reference", "", oauthE2ESecret},
	} {
		f.secrets = append(f.secrets, scenario.secret)
		f.peers[1].reload(t, f.adapt(t, f.peers[1], scenario.namespace, scenario.secret, false), true)
		before := f.exchanges()
		flow := f.begin(t, 0, f.destination(scenario.name))
		denied := f.request(t, flow.client, 1, flow.callback, scenario.name+" isolation", 401, nil)
		f.deny(t, denied)
		if f.exchanges() != before {
			t.Fatal("isolated provider configuration reached the issuer")
		}
		completed := f.request(t, flow.client, 0, flow.callback, "matching provider recovery", 303, nil)
		f.success(t, completed, flow)
		if scenario.namespace == "" {
			memory := f.begin(t, 1, f.destination("private-memory"))
			denied = f.request(t, memory.client, 0, memory.callback, "memory flow on other peer", 401, nil)
			f.deny(t, denied)
			completed = f.request(t, memory.client, 1, memory.callback, "private memory completion", 303, nil)
			f.success(t, completed, memory)
		}
		f.peers[1].reload(t, f.adapt(t, f.peers[1], "cluster", oauthE2ESecret, false), true)
	}
}

func (f *caddySharedOAuthPair) cancelDuringExchange(t *testing.T) {
	t.Helper()
	client, err := storage.New(t.Context(), &storage.Config{Path: f.database, Timeout: "5s", Capacity: f.capacity})
	if err != nil {
		t.Fatal("cannot open independent cancellation client")
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error("independent cancellation store did not close cleanly")
		}
	}()
	var cfg oauth.Config
	if json.Unmarshal(f.providerJSON, &cfg) != nil {
		t.Fatal("cannot decode exact cancellation provider configuration")
	}
	cfg.Name = "upstream"
	provider, err := oauth.NewIdentityProviderWithLoginStore(&cfg, zap.NewNop(), client)
	if err != nil {
		t.Fatal("cannot construct public cancellation provider")
	}
	defer provider.Close()
	flow := f.begin(t, 0, f.destination("canceled"))
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	f.upstream.mu.Lock()
	f.upstream.exchangeEntered, f.upstream.exchangeRelease = entered, release
	f.upstream.mu.Unlock()
	result := make(chan sharedOAuthHTTPResult, 1)
	callbackContext, cancelCallback := context.WithCancel(t.Context())
	joined := false
	defer func() {
		unblock()
		cancelCallback()
		if !joined {
			select {
			case response := <-result:
				f.capture(response.response)
			case <-time.After(5 * time.Second):
				t.Error("held OAuth callback worker did not exit")
			}
		}
	}()
	go func() { result <- f.do(callbackContext, flow.client, 1, flow.callback, nil) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		unblock()
		t.Fatal("real issuer exchange did not reach its bounded hold")
	}
	// The issuer mutex is held until release. Cancellation needs only the public
	// provider's already normalized namespace; do not Configure or read counters.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	canceled, cancelErr := provider.CancelLoginContext(ctx, flow.state, sha256.Sum256([]byte(flow.sessionID)), f.callback)
	cancel()
	unblock()
	var response sharedOAuthHTTPResult
	select {
	case response = <-result:
		joined = true
	case <-time.After(15 * time.Second):
		t.Fatal("canceled shared OAuth exchange did not complete")
	}
	f.capture(response.response)
	if cancelErr != nil || !canceled {
		t.Fatal("independent cancellation was not acknowledged")
	}
	f.deny(t, f.result(t, "cancellation before identity publication", response, 401))
	f.replay(t, 0, flow)
	f.replay(t, 1, flow)
}

func (f *caddySharedOAuthPair) capacityAndDirectPolicy(t *testing.T) {
	t.Helper()
	flow := f.begin(t, 0, f.destination("capacity"))
	denied := f.request(t, f.browser(t), 1, f.origin+f.mount+"/oauth2/upstream", "shared capacity rejection", 401, nil)
	f.deny(t, denied)
	// A different named provider/namespace has the same database-wide capacity.
	// This observes direct-policy use of the injected backend before any exchange.
	directBrowser := f.browser(t)
	// Capacity becomes the provider's authorization-state-limit error. The portal
	// denies that error with 401, while direct-policy initiation fails with 502;
	// the portal's 503 is reserved for an unavailable store, not a full one.
	denied = f.request(t, directBrowser, 1, f.origin+"/direct-resource", "direct policy shared capacity rejection", 502, nil)
	f.denyDirect(t, denied)
	completed := f.request(t, flow.client, 1, flow.callback, "completion frees shared capacity", 303, nil)
	f.success(t, completed, flow)
	f.direction(t, 1, f.destination("capacity-recovery"))
	directBrowser = f.browser(t)
	started := f.request(t, directBrowser, 1, f.origin+"/direct-resource", "direct policy initiation", 302, nil)
	authorize, err := url.Parse(started.header.Get("Location"))
	if err != nil || authorize.Scheme+"://"+authorize.Host != f.directUpstream.server.URL || authorize.Path != "/authorize" {
		t.Fatal("direct shared-store policy escaped its issuer")
	}
	f.secrets = append(f.secrets, authorize.Query().Get("state"), authorize.Query().Get("nonce"), authorize.Query().Get("code_challenge"))
	authorized := f.request(t, directBrowser, 1, authorize.String(), "direct issuer authorization", 302, nil)
	callback, err := url.Parse(authorized.header.Get("Location"))
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != f.directUpstream.callback || callback.Query().Get("code") == "" {
		t.Fatal("direct callback escaped its registered endpoint")
	}
	f.secrets = append(f.secrets, callback.Query().Get("code"))
	completed = f.request(t, directBrowser, 1, callback.String(), "direct same-process completion", 303, nil)
	if completed.header.Get("Location") != "/direct-resource" || bytes.Contains(completed.body, []byte("callback reached downstream")) {
		t.Fatal("direct callback changed destination or ran downstream")
	}
	resource := f.request(t, directBrowser, 1, f.origin+"/direct-resource", "direct authenticated resource", 200, nil)
	if string(resource.body) != "direct resource" {
		t.Fatal("direct policy did not authorize its actual resource")
	}
	f.directUpstream.mu.Lock()
	count := f.directUpstream.exchanges
	f.directUpstream.mu.Unlock()
	if count != 1 {
		t.Fatal("direct shared-store policy did not exchange exactly once")
	}
}

func (f *caddySharedOAuthPair) qualifyTLS(t *testing.T) {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for _, target := range []string{f.origin, f.peers[0].origin, f.peers[1].origin, f.upstream.server.URL} {
		response, err := client.Get(target + "/ready")
		if response != nil {
			_ = response.Body.Close()
		}
		if err == nil {
			t.Fatal("shared OAuth TLS negative control accepted an untrusted issuer")
		}
		if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
			t.Fatal("shared OAuth TLS negative control failed outside certificate verification")
		}
	}
}

func (f *caddySharedOAuthPair) scanLogs(t *testing.T) {
	t.Helper()
	for _, p := range f.peers {
		for _, name := range []string{"runtime.log", "access.log", "process.log"} {
			file, err := os.Open(filepath.Join(p.workspace, name))
			if err != nil {
				t.Errorf("shared OAuth peer %d %s is unavailable", p.index, name)
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(file, (16<<20)+1))
			_ = file.Close()
			if readErr != nil || len(data) > 16<<20 {
				t.Errorf("shared OAuth peer %d %s could not be read within its bound", p.index, name)
				continue
			}
			// Caddy directs its runtime and access logs to these files. Captured
			// console output may be empty, but any emitted bytes still need scanning.
			if len(data) == 0 && name != "process.log" {
				t.Errorf("shared OAuth peer %d %s lacks required log evidence", p.index, name)
				continue
			}
			t.Logf("inspect shared OAuth peer %d %s", p.index, name)
			assertAdminRedacted(t, data, f.secrets)
			for line := range bytes.SplitSeq(data, []byte{'\n'}) {
				var record map[string]json.RawMessage
				if json.Unmarshal(line, &record) != nil {
					assertAdminRedacted(t, line, f.bindings)
					continue
				}
				// Preserve the documented correlation field; a browser binding in
				// any other field still fails. Do not exempt authentication tokens.
				delete(record, "session_id")
				remaining, err := json.Marshal(record)
				if err != nil {
					t.Errorf("cannot inspect shared OAuth peer %d %s structured log", p.index, name)
					continue
				}
				assertAdminRedacted(t, remaining, f.bindings)
			}
		}
	}
	if f.proxyFailures.Load() != 0 {
		t.Error("shared OAuth proxy observed an unexpected backend failure")
	}
}
