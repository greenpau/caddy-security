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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// The child is a built Caddy command, not the Go test process or an AuthCrunch
// stand-in. The fixture main adds only a private CA pool for upstream TLS.
func TestCaddyRuntimeStateE2E(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy: %v\n%s", err, output)
	}
	for _, tc := range []struct {
		name string
		run  func(*testing.T, string)
	}{
		{"direct_oauth", testPersistentDirectOAuth},
		{"portal_refresh_oidc", testPersistentPortal},
	} {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, binary) })
	}
}

type persistentCaddy struct {
	binary, base, admin, directory, config, ca, workspace string
	client                                                *http.Client
	cmd                                                   *exec.Cmd
	done                                                  chan error
	log                                                   *os.File
}

func newPersistentCaddy(t *testing.T, binary, cert, key string, roots *x509.CertPool) *persistentCaddy {
	t.Helper()
	f := &persistentCaddy{binary: binary, base: "https://" + lifecycleAddress(t), admin: lifecycleAddress(t), ca: cert, workspace: t.TempDir()}
	f.directory = filepath.Join(f.workspace, "private state")
	f.config = filepath.Join(f.workspace, "config.json")
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	f.client = &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { f.kill(t); transport.CloseIdleConnections() })
	return f
}

func (f *persistentCaddy) input(security, routes, cert, key string) string {
	return fmt.Sprintf(`{
 admin %s
 auto_https off
 log {
  level ERROR
 }
 security {
  state {
   directory %q
  }
  %s
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 %s
}`, f.admin, f.directory, security, f.base, cert, key, routes)
}

func (f *persistentCaddy) write(t *testing.T, input string) []byte {
	t.Helper()
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func (f *persistentCaddy) command(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), f.binary, args...)
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_TEST_CA="+f.ca, "CADDY_SECURITY_TEST_STATE_DIRECTORY="+f.directory, "XDG_CONFIG_HOME="+f.workspace, "XDG_DATA_HOME="+f.workspace)
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func (f *persistentCaddy) start(t *testing.T) {
	t.Helper()
	var err error
	f.log, err = os.OpenFile(filepath.Join(f.workspace, "process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.cmd = f.command(t, "run", "--config", f.config)
	f.cmd.Stdout, f.cmd.Stderr = f.log, f.log
	if err := f.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f.done = make(chan error, 1)
	go func() { f.done <- f.cmd.Wait() }()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-f.done:
			f.done = nil
			_ = f.log.Close()
			data, _ := os.ReadFile(filepath.Join(f.workspace, "process.log"))
			t.Fatalf("Caddy startup failed: %v\n%s", err, data)
		case <-deadline.C:
			t.Fatal("Caddy startup timed out")
		case <-tick.C:
			resp, err := f.client.Get(f.base + "/ready")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					// HTTP Start can precede security Start; probe a runtime route too.
					resp, err = f.client.Get(f.base + "/auth/.well-known/jwks.json")
					if err == nil {
						resp.Body.Close()
						if resp.StatusCode != 503 && resp.StatusCode != 401 {
							return
						}
					}
				}
			}
		}
	}
}

func (f *persistentCaddy) kill(t *testing.T) {
	t.Helper()
	if f.done == nil {
		return
	}
	if err := f.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Error(err)
	}
	select {
	case <-f.done:
	case <-time.After(10 * time.Second):
		t.Error("Caddy process did not exit")
	}
	f.done = nil
	_ = f.log.Close()
	f.client.CloseIdleConnections()
}

func (f *persistentCaddy) restart(t *testing.T) { t.Helper(); f.kill(t); f.start(t) }

func (f *persistentCaddy) browser(t *testing.T) *http.Client {
	t.Helper()
	client := *f.client
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &client
}

func persistentRequest(t *testing.T, client *http.Client, method, target string, form url.Values, headers http.Header, status int) oidcRPResponse {
	t.Helper()
	code, header, body := registrationHTTP(t, client, method, target, form, headers)
	r := oidcRPResponse{code, header, body}
	r.requireStatus(t, status)
	return r
}

func testPersistentDirectOAuth(t *testing.T, binary string) {
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	upstream := newOAuthE2EUpstream(t, pair, "EdDSA")
	f := newPersistentCaddy(t, binary, cert, key, roots)
	upstream.callback = f.base + "/_authcrunch/oauth2/direct/authorization-code-callback"
	security := fmt.Sprintf(`oauth identity provider upstream {
 driver generic
 realm upstream
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 scopes openid profile email
}
authorization policy direct {
 use oauth identity provider upstream
 oauth public origin %s
 validate method path
 acl rule {
  match path /restricted
  deny stop
 }
 allow roles authp/user
}
authorization policy secondary {
 use oauth identity provider upstream
 oauth base path /secondary/oauth
 allow roles authp/user
}`, oauthE2EClient, oauthE2ESecret, upstream.server.URL, upstream.server.URL, f.base)
	input := f.input(security, `route /secondary/* {
 authorize with secondary
 respond "secondary application"
}
route {
 authorize with direct
 respond "protected application"
}`, cert, key)
	// Exercise deferred resolution in the real process, including the quoted
	// directory's spaces and declarative preservation in Caddy's autosave.
	stateBlock := "  state {\n   directory {env.CADDY_SECURITY_TEST_STATE_DIRECTORY}\n  }\n"
	input = strings.Replace(input, fmt.Sprintf("  state {\n   directory %q\n  }\n", f.directory), stateBlock, 1)
	data := f.write(t, input)
	validation := f.command(t, "validate", "--config", f.config)
	if output, err := validation.CombinedOutput(); err != nil {
		t.Fatalf("validate: %v\n%s", err, output)
	}
	if _, err := os.Stat(f.directory); !os.IsNotExist(err) {
		t.Fatal("validation initialized persistent state")
	}
	f.start(t)
	login := func(client *http.Client) string {
		begin := persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
		provider := persistentRequest(t, client, "GET", begin.header.Get("Location"), nil, nil, 302)
		return provider.header.Get("Location")
	}
	client := f.browser(t)
	callback := login(client)
	completed := persistentRequest(t, client, "GET", callback, nil, nil, 303)
	if completed.header.Get("Location") != "/private" || bytes.Contains(completed.body, []byte("protected application")) {
		t.Fatal("callback ran downstream or changed redirect")
	}
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
	persistentRequest(t, client, "GET", f.base+"/restricted", nil, nil, 403)
	persistentRequest(t, client, "GET", callback, nil, nil, 400)
	pendingClient := f.browser(t)
	pending := login(pendingClient)
	f.restart(t)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
	persistentRequest(t, client, "GET", f.base+"/restricted", nil, nil, 403)
	persistentRequest(t, pendingClient, "GET", pending, nil, nil, 400)
	upstream.mu.Lock()
	exchanges := upstream.exchanges
	upstream.mu.Unlock()
	if exchanges != 1 {
		t.Fatal("restart exchanged original session with provider")
	}
	// Hold a real callback inside the provider exchange while Caddy attempts
	// replacement. Failed replacement must leave the admitted old call alive.
	heldClient := f.browser(t)
	heldCallback := login(heldClient)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	upstream.mu.Lock()
	upstream.exchangeEntered = entered
	upstream.exchangeRelease = release
	upstream.mu.Unlock()
	type callbackResult struct {
		response *http.Response
		err      error
	}
	callbackDone := make(chan callbackResult, 1)
	go func() { response, err := heldClient.Get(heldCallback); callbackDone <- callbackResult{response, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("callback did not reach provider")
	}
	// Force a real admin reload rather than Caddy's unchanged-config shortcut.
	req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+f.admin+"/load", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "must-revalidate")
	admin := &http.Client{Timeout: 15 * time.Second}
	reloadDone := make(chan callbackResult, 1)
	go func() { response, err := admin.Do(req); reloadDone <- callbackResult{response, err} }()
	for range 10 {
		persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
		persistentRequest(t, f.client, "POST", f.base+"/private", nil, nil, 401)
	}
	var resp *http.Response
	select {
	case result := <-reloadDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		resp = result.response
	case <-time.After(20 * time.Second):
		t.Fatal("reload did not finish")
	}
	reloadBody, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil || resp.StatusCode < 400 || !bytes.Contains(reloadBody, []byte("persistent security runtime does not support overlapping reload")) {
		t.Fatal("overlapping reload did not return the documented lifecycle failure")
	}
	if bytes.Contains(reloadBody, []byte(oauthE2ESecret)) {
		t.Fatal("reload failure exposed provider credentials")
	}
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
	persistentRequest(t, f.client, "POST", f.base+"/private", nil, nil, 401)
	unblock()
	select {
	case result := <-callbackDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		result.response.Body.Close()
		if result.response.StatusCode != 303 {
			t.Fatal("failed reload closed admitted callback")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("callback failed to drain")
	}
	// Autosave keeps the original declarative state field.
	saved, err := os.ReadFile(filepath.Join(f.workspace, "caddy", "autosave.json"))
	if err != nil || !bytes.Contains(saved, []byte(`"state":{"directory":"{env.CADDY_SECURITY_TEST_STATE_DIRECTORY}"}`)) {
		t.Fatal("autosave lost declarative state directory")
	}
	u, _ := url.Parse(f.base)
	old := client.Jar.Cookies(u)
	persistentRequest(t, client, "POST", f.base+"/_authcrunch/oauth2/direct/logout", nil, http.Header{"Origin": {f.base}}, 204)
	f.restart(t)
	client.Jar.SetCookies(u, old)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
	// A second OS process must fail on the same library-owned directory.
	// Its admin/listener addresses are distinct, so port binding cannot mask it.
	otherInput := strings.Replace(input, "admin "+f.admin, "admin off", 1)
	otherInput = strings.ReplaceAll(otherInput, f.base, "https://"+lifecycleAddress(t))
	f.write(t, otherInput)
	f.failStartup(t)
	f.write(t, input)
	// Changing and restoring configuration must not revive an old cookie.
	client = f.browser(t)
	persistentRequest(t, client, "GET", login(client), nil, nil, 303)
	f.kill(t)
	f.write(t, strings.Replace(input, "allow roles authp/user", "allow roles authp/user extra", 1))
	f.start(t)
	f.kill(t)
	f.write(t, input)
	f.start(t)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
	// Remove the policy, construct that configuration, then restore it. The
	// configuration epoch must prevent resurrection of the removed component.
	client = f.browser(t)
	persistentRequest(t, client, "GET", login(client), nil, nil, 303)
	f.kill(t)
	var removed map[string]any
	if err := json.Unmarshal(data, &removed); err != nil {
		t.Fatal(err)
	}
	apps := removed["apps"].(map[string]any)
	securityConfig := apps["security"].(map[string]any)["config"].(map[string]any)
	policies := securityConfig["authorization_policies"].([]any)
	securityConfig["authorization_policies"] = policies[1:]
	raw, err := json.Marshal(removed)
	if err != nil {
		t.Fatal(err)
	}
	// Keep a runtime-backed readiness probe, so the removed configuration is
	// fully constructed before SIGKILL (HTTP Start may run before security).
	raw = bytes.ReplaceAll(raw, []byte(`"gatekeeper_name":"direct"`), []byte(`"gatekeeper_name":"secondary"`))
	if err := os.WriteFile(f.config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	f.kill(t)
	f.write(t, input)
	f.start(t)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
	// Fill the actual 64 MiB snapshot through validated upstream identities.
	// No private DTOs, state-file synthesis or lowered library limits are used.
	client = f.browser(t)
	persistentRequest(t, client, "GET", login(client), nil, nil, 303)
	upstream.mu.Lock()
	upstream.identityName = strings.Repeat("n", 512<<10)
	upstream.mu.Unlock()
	refused := false
	for i := 0; i < 150; i++ {
		candidate := f.browser(t)
		callback := login(candidate)
		status, header, body := registrationHTTP(t, candidate, "GET", callback, nil, nil)
		if status == 503 {
			if header.Get("Location") != "" || bytes.Contains(body, []byte("protected application")) {
				t.Fatal("capacity refusal became success")
			}
			for _, cookie := range (&http.Response{Header: header}).Cookies() {
				if cookie.Name == "AUTHZ_direct_SESSION" && cookie.Value != "" && cookie.MaxAge >= 0 {
					t.Fatal("capacity refusal delivered credential")
				}
			}
			refused = true
			break
		}
		if status != 303 {
			t.Fatalf("snapshot admission status %d", status)
		}
	}
	if !refused {
		t.Fatal("fixture did not reach snapshot capacity")
	}
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
	upstream.mu.Lock()
	upstream.identityName = ""
	upstream.callback = f.base + "/secondary/oauth/authorization-code-callback"
	upstream.mu.Unlock()
	secondary := f.browser(t)
	begin := persistentRequest(t, secondary, "GET", f.base+"/secondary/private", nil, nil, 302)
	provider := persistentRequest(t, secondary, "GET", begin.header.Get("Location"), nil, nil, 302)
	persistentRequest(t, secondary, "GET", provider.header.Get("Location"), nil, nil, 303)
	persistentRequest(t, secondary, "GET", f.base+"/secondary/private", nil, nil, 200)
	old = client.Jar.Cookies(u)
	persistentRequest(t, client, "POST", f.base+"/_authcrunch/oauth2/direct/logout", nil, http.Header{"Origin": {f.base}}, 204)
	f.restart(t)
	client.Jar.SetCookies(u, old)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
	persistentRequest(t, secondary, "GET", f.base+"/secondary/private", nil, nil, 200)
	// Committed storage damage must fail startup, and releasing the failed
	// constructor must allow a repaired private fixture to retry immediately.
	f.kill(t)
	for _, name := range []string{"master.key", "catalog.state", fmt.Sprintf("%x.state", sha256.Sum256([]byte("oauth-sessions/secondary")))} {
		path := filepath.Join(f.directory, name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, damage := range []string{"missing", "corrupt"} {
			if damage == "missing" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("corrupt"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			f.failStartup(t)
			if err = os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			f.start(t)
			f.kill(t)
		}
	}
	if err := os.Chmod(f.directory, 0755); err != nil {
		t.Fatal(err)
	}
	f.failStartup(t)
	if err := os.Chmod(f.directory, 0700); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	// An IO failure at logout cannot publish success or keep cached authority.
	marker := filepath.Join(f.directory, fmt.Sprintf("%x.state.pending", sha256.Sum256([]byte("oauth-sessions/secondary"))))
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	persistentRequest(t, secondary, "POST", f.base+"/secondary/oauth/logout", nil, http.Header{"Origin": {f.base}}, 503)
	persistentRequest(t, secondary, "GET", f.base+"/secondary/private", nil, nil, 503)
	f.kill(t)
	upstream.mu.Lock()
	upstream.callback = f.base + "/_authcrunch/oauth2/direct/authorization-code-callback"
	upstream.mu.Unlock()
	volatileInput := strings.Replace(input, stateBlock, "", 1)
	if volatileInput == input {
		t.Fatal("fixture did not omit state")
	}
	f.write(t, volatileInput)
	f.start(t)
	client = f.browser(t)
	persistentRequest(t, client, "GET", login(client), nil, nil, 303)
	// A failed attempt to enable persistence must retain the currently serving
	// volatile routes, including their already authenticated sessions.
	for range 8 {
		req, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+f.admin+"/load", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cache-Control", "must-revalidate")
		resp, err := admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatal("corrupt persistent candidate was activated")
		}
		persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 200)
	}
	f.restart(t)
	persistentRequest(t, client, "GET", f.base+"/private", nil, nil, 302)
}

func (f *persistentCaddy) failStartup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.binary, "run", "--config", f.config)
	cmd.Env = f.command(t).Env
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil || !bytes.Contains(output, []byte("persistent security runtime could not start")) {
		t.Fatalf("expected controlled startup failure: %v", err)
	}
	if bytes.Contains(output, []byte(oauthE2ESecret)) || bytes.Contains(output, []byte(applicationTestSecret)) {
		t.Fatal("startup failure exposed credentials")
	}
}

func testPersistentPortal(t *testing.T, binary string) {
	cert, key, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	opKey := newOIDCRPKey(t, "persistent-op")
	database := filepath.Join(f.workspace, "users.json")
	seedLocalIdentity(t, database, false)
	security := fmt.Sprintf(`local identity store localdb {
 realm local
 path %q
}
oauth application basic {
 client_id basic
 client_secret %s
 redirect_uri %s
 scopes openid profile email offline_access
}
authentication portal myportal {
 enable identity store localdb
 crypto default autogenerate algorithm EdDSA
 crypto default autogenerate tag persistent-access
 cookie prefix RP
 token refresh {
  realms local
  public origin %s
  base path /auth
  body transport enabled
  access lifetime 600
  idle timeout 1800
  absolute timeout 3600
 }
 oidc provider {
  issuer %s/auth
  realms local
  signing key files %q
  applications basic
  refresh lifetime 3600
 }
}
authorization policy app_policy {
 crypto default autogenerate algorithm EdDSA
 crypto default autogenerate tag persistent-access
 set auth url /auth/login
 validate bearer header
 allow roles authp/user
}`, database, applicationTestSecret, oidcRPCallback, f.base, f.base, opKey.private)
	input := f.input(security, `route /auth/* {
 authenticate with myportal
}
route {
 authorize with app_policy
 respond "protected application"
}`, cert, key)
	f.write(t, input)
	f.start(t)
	keys := func() []map[string]string {
		r := persistentRequest(t, f.client, "GET", f.base+"/auth/.well-known/jwks.json", nil, nil, 200)
		var doc struct {
			Keys []map[string]string `json:"keys"`
		}
		if json.Unmarshal(r.body, &doc) != nil || len(doc.Keys) != 1 {
			t.Fatal("invalid generated JWKS")
		}
		return doc.Keys
	}
	before := keys()
	browser := f.browser(t)
	rp := &oidcRPFixture{client: browser, base: f.base, mount: "/auth", issuer: f.base + "/auth"}
	rp.discover(t)
	rp.login(t)
	oldJWT := jarCookie(t, browser.Jar, f.base+"/auth/", "RP_ACCESS_TOKEN")
	verifyCaddyJWKSSignature(t, before, oldJWT, "EdDSA", before[0]["kid"])
	tf := &caddyTokenRefreshFixture{base: f.base, mount: "/auth", client: f.client}
	native, _ := tf.login(t, f.client, "local", "body", 200)
	params := rp.authorization("basic")
	params.Set("scope", "openid profile email offline_access")
	params.Set("prompt", "consent")
	approved := rp.approve(t, rp.authorize(t, params), "allow")
	code := rp.callback(t, approved, params, "")
	f.restart(t)
	after := keys()
	x, _ := json.Marshal(before)
	y, _ := json.Marshal(after)
	if !bytes.Equal(x, y) {
		t.Fatal("generated signing keys changed after SIGKILL")
	}
	verifyCaddyJWKSSignature(t, after, oldJWT, "EdDSA", after[0]["kid"])
	persistentRequest(t, browser, "GET", f.base+"/auth/portal", nil, nil, 200)
	persistentRequest(t, f.client, "GET", f.base+"/private", nil, http.Header{"Authorization": {"Bearer " + oldJWT}}, 200)
	profile := &localIdentityFixture{oidcRPFixture: rp, plain: f.client, database: database}
	profile.profile(t, map[string]any{"kind": "fetch_user_api_keys"}, 200)
	exchanged := rp.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier)
	exchanged.requireStatus(t, 200)
	tokens := persistentTokens(t, exchanged)
	refresh := tokens["refresh_token"]
	if refresh == "" {
		t.Fatal("offline consent did not yield refresh credential")
	}
	// Completed consent survives: ordinary scopes no longer prompt.
	params.Del("prompt")
	params.Set("scope", "openid profile email")
	consented := rp.authorize(t, params)
	consented.requireStatus(t, 302)
	f.restart(t)
	rp.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"]}}).requireStatus(t, 200)
	rotated := persistentOIDCRefresh(t, rp, refresh)
	rotated.requireStatus(t, 200)
	next := persistentTokens(t, rotated)["refresh_token"]
	nativeNext, _ := tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, nil, 200)
	// Browser rotation restores a different family, preserving its own SID.
	_, browserCookies := tf.post(t, browser, "/api/refresh_token", struct{}{}, tf.headers(), 200)
	oldBrowserRefresh := tokenRefreshActiveCookie(t, browserCookies, "RP_REFRESH_TOKEN").Value
	f.restart(t)
	persistentOIDCRefresh(t, rp, refresh).failure(t, 400, "invalid_grant")
	tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, nil, 401)
	_, browserCookies = tf.post(t, browser, "/api/refresh_token", struct{}{}, tf.headers(), 200)
	browserDescendant := tokenRefreshActiveCookie(t, browserCookies, "RP_REFRESH_TOKEN").Value
	f.restart(t)
	persistentOIDCRefresh(t, rp, next).failure(t, 400, "invalid_grant")
	tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": nativeNext.RefreshToken}, nil, 401)
	headers := tf.headers()
	headers.Set("Cookie", "RP_REFRESH_TOKEN="+oldBrowserRefresh)
	tf.post(t, f.client, "/api/refresh_token", struct{}{}, headers, 401)
	f.restart(t)
	headers.Set("Cookie", "RP_REFRESH_TOKEN="+browserDescendant)
	tf.post(t, f.client, "/api/refresh_token", struct{}{}, headers, 401)
	// A spent code remains spent and revokes its issued descendants after restart.
	rp.newBrowser(t)
	rp.login(t)
	params = rp.authorization("basic")
	response := rp.authorize(t, params)
	if response.status == 200 {
		response = rp.approve(t, response, "allow")
	}
	code = rp.callback(t, response, params, "")
	response = rp.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier)
	response.requireStatus(t, 200)
	access := persistentTokens(t, response)["access_token"]
	f.restart(t)
	rp.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier).failure(t, 400, "invalid_grant")
	f.restart(t)
	rp.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + access}}).requireStatus(t, 401)
	// Durable logout also invalidates a still-live OIDC grant and refresh family.
	code = rp.callback(t, rp.authorize(t, params), params, "")
	response = rp.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier)
	response.requireStatus(t, 200)
	access = persistentTokens(t, response)["access_token"]
	u, _ := url.Parse(rp.issuer + "/")
	oldCookies := rp.client.Jar.Cookies(u)
	tf.post(t, rp.client, "/api/logout", struct{}{}, tf.headers(), 200)
	f.restart(t)
	rp.client.Jar.SetCookies(u, oldCookies)
	rp.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + access}}).requireStatus(t, 401)
	tf.post(t, rp.client, "/api/refresh_token", struct{}{}, tf.headers(), 401)
	// A password change invalidates identity proof, including after DB rollback.
	rp.newBrowser(t)
	rp.login(t)
	profile.oidcRPFixture = rp
	native, _ = tf.login(t, f.client, "local", "body", 200)
	params = rp.authorization("basic")
	response = rp.authorize(t, params)
	if response.status == 200 {
		response = rp.approve(t, response, "allow")
	}
	code = rp.callback(t, response, params, "")
	response = rp.exchange(t, "basic", code, oidcRPCallback, oidcRPVerifier)
	response.requireStatus(t, 200)
	access = persistentTokens(t, response)["access_token"]
	backup, err := os.ReadFile(database)
	if err != nil {
		t.Fatal(err)
	}
	profile.profile(t, map[string]any{"kind": "update_user_password", "old_password": lifecyclePassword, "new_password": "ReplacementPassword42!"}, 200)
	f.restart(t)
	tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, nil, 401)
	profile.profile(t, map[string]any{"kind": "fetch_user_api_keys"}, 401)
	rp.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + access}}).requireStatus(t, 401)
	f.kill(t)
	if err := os.WriteFile(database, backup, 0600); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, nil, 401)
	profile.profile(t, map[string]any{"kind": "fetch_user_api_keys"}, 401)
	rp.request(t, "GET", "/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + access}}).requireStatus(t, 401)
	// Session epochs change independently of stable generated signing keys.
	rp.newBrowser(t)
	rp.login(t)
	profile.oidcRPFixture = rp
	f.kill(t)
	f.write(t, strings.Replace(input, "allow roles authp/user", "allow roles authp/user extra", 1))
	f.start(t)
	f.kill(t)
	f.write(t, input)
	f.start(t)
	profile.profile(t, map[string]any{"kind": "fetch_user_api_keys"}, 401)
	verifyCaddyJWKSSignature(t, keys(), oldJWT, "EdDSA", before[0]["kid"])
}

func persistentTokens(t *testing.T, r oidcRPResponse) map[string]string {
	t.Helper()
	var raw map[string]any
	if json.Unmarshal(r.body, &raw) != nil {
		t.Fatal("invalid token response")
	}
	result := make(map[string]string)
	for _, name := range []string{"access_token", "refresh_token", "id_token"} {
		result[name], _ = raw[name].(string)
	}
	return result
}

func persistentOIDCRefresh(t *testing.T, rp *oidcRPFixture, token string) oidcRPResponse {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
	return rp.request(t, "POST", "/oidc/token", form, oidcRPAuth("basic", form))
}
