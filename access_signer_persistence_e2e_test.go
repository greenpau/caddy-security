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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

// The executable is the existing real Caddy command entrypoint with private
// test roots. Every phase starts a different OS process; the parent retains only
// observed credentials and explicitly persisted files. This qualifies current
// root-persisted refresh, separately from the later selected SQLite backend.
func TestCaddyAccessSignerPersistenceE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath -p=1")
	build.WaitDelay = 5 * time.Second
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build real Caddy signer command: %v\n%s", err, output)
	}
	for _, policyOnly := range []bool{false, true} {
		name := "selected_portal"
		if policyOnly {
			name = "policy_only_profile"
		}
		t.Run(name, func(t *testing.T) { testAccessSignerProcessEpoch(t, binary, policyOnly) })
	}
}

type accessSignerProcess struct {
	*persistentCaddy
	local                             *localIdentityFixture
	inputText, cert, tlsKey           string
	key, initial, replacement, legacy jwksKeyFiles
	policyOnly                        bool
	keys                              []map[string]string
	pids                              map[int]bool
}

func newAccessSignerProcess(t *testing.T, binary string, policyOnly bool) *accessSignerProcess {
	t.Helper()
	cert, tlsKey, roots := cookieTLSCertificate(t)
	p := &accessSignerProcess{persistentCaddy: newPersistentCaddy(t, binary, cert, tlsKey, roots), cert: cert, tlsKey: tlsKey, policyOnly: policyOnly, pids: make(map[int]bool)}
	p.workingDirectory = p.workspace
	p.initial, p.replacement, p.legacy = newJWKSKeyFiles(t, "RSA", "epoch-A"), newJWKSKeyFiles(t, "RSA", "epoch-B"), newJWKSKeyFiles(t, "RSA", "legacy")
	p.key = jwksKeyFiles{private: filepath.Join(p.workspace, "access-private.pem"), public: filepath.Join(p.workspace, "access-public.pem")}
	database := filepath.Join(p.workspace, "users.json")
	seedLocalIdentity(t, database, false)
	p.local = &localIdentityFixture{oidcRPFixture: &oidcRPFixture{client: p.client, base: p.base, mount: "/tenant/auth", issuer: p.base + "/tenant/auth"}, plain: p.client, database: database, secrets: []string{lifecyclePassword, localIdentityBobPassword}}
	p.material(t, p.initial)
	p.inputText = p.configuration(t, false)
	p.write(t, p.inputText)
	t.Cleanup(func() {
		p.stop(t)
		for _, name := range []string{"runtime.jsonl", "access.jsonl", "process.log"} {
			file, err := os.Open(filepath.Join(p.workspace, name))
			if err != nil {
				t.Errorf("signer process %s evidence missing", name)
				continue
			}
			data, err := io.ReadAll(io.LimitReader(file, (16<<20)+1))
			file.Close()
			if err != nil || len(data) > 16<<20 || (name != "process.log" && len(data) == 0) {
				t.Errorf("signer process %s evidence invalid", name)
				continue
			}
			assertAdminRedacted(t, data, p.local.secrets)
		}
	})
	return p
}

func (p *accessSignerProcess) material(t *testing.T, key jwksKeyFiles) {
	t.Helper()
	for _, pair := range [][2]string{{key.private, p.key.private}, {key.public, p.key.public}} {
		data, err := os.ReadFile(pair[0])
		if err != nil || os.WriteFile(pair[1], data, 0600) != nil {
			t.Fatal("cannot install fixture access-key epoch")
		}
		if pair[0] == key.private {
			p.local.secrets = append(p.local.secrets, string(data))
		}
	}
	p.key.key = key.key
}

func (p *accessSignerProcess) configuration(t *testing.T, omit bool) string {
	t.Helper()
	issuer := p.base + "/tenant/auth"
	profile := fmt.Sprintf("access token profile {\nissuer %s\naudience %s\nkey ids fixed\nmax lifetime 300\n}\n", issuer, accessSignerAudience)
	declaration := fmt.Sprintf("access signer rsapss selected {\nkey file %q\nkey id fixed\nissuer %s\naudience %s\nmax lifetime 300s\n}\n", p.key.private, issuer, accessSignerAudience)
	portalCrypto := "access signer selected\n" + profile + p.key.verifier("fixed")
	if p.policyOnly {
		declaration, portalCrypto = "", p.legacy.signer("legacy")
	}
	security := fmt.Sprintf(`%s
local identity store localdb {
 realm local
 path %q
}
authentication portal myportal {
 enable identity store localdb
 %s
 crypto default token lifetime 180
 cookie path /
 transform user {
  match any
  action overwrite aud %s
 }
 token refresh {
  realms local
  public origin %s
  base path /tenant/auth
  body transport enabled
  access lifetime 180
  idle timeout 600
  absolute timeout 900
 }
}
authorization policy app_policy {
 %s
 %s
 set auth url %s/login
 validate bearer header
 allow roles authp/user
}
`, declaration, p.local.database, portalCrypto, accessSignerAudience, p.base, profile, p.key.verifier("fixed"), issuer)
	routes := `route /resource {
 authorize with app_policy
 respond "identity resource"
}
route /tenant/auth/* {
 authenticate with myportal at /tenant/auth
}
respond "unmatched" 404`
	if omit {
		// A root needs at least one portal or policy. Keep an unrelated,
		// unmounted legacy policy while removing every selected-profile
		// consumer and signer; the same persistent root records that epoch.
		security = "authorization policy dormant {\n" + p.legacy.verifier("legacy") + "\nallow roles authp/user\n}\n"
		routes = "respond \"omitted portal\" 404"
	}
	input := p.input(security, routes, p.cert, p.tlsKey)
	logs := fmt.Sprintf("log {\nlevel INFO\noutput file %q\nformat filter {\nwrap json\nfields {\nrequest>uri delete\nresp_headers>Location delete\nrequest>headers>Referer delete\n}\n}\n}", filepath.Join(p.workspace, "runtime.jsonl"))
	input = strings.Replace(input, "log {\n  level ERROR\n }", logs, 1)
	input = strings.Replace(input, "auto_https off", "auto_https off\npersist_config off\nstorage file_system "+fmt.Sprintf("%q", filepath.Join(p.workspace, "caddy-storage")), 1)
	access := fmt.Sprintf("log {\noutput file %q\nformat filter {\nwrap json\nfields {\nrequest>uri delete\nresp_headers>Location delete\nrequest>headers>Referer delete\n}\n}\n}\n", filepath.Join(p.workspace, "access.jsonl"))
	return strings.Replace(input, "route /ready", access+"route /ready", 1)
}

// Readiness proves this exact mounted runtime and selected public key, not just
// a listener or static /ready response. The omitted phase has no portal by design.
func (p *accessSignerProcess) start(t *testing.T, omitted bool) {
	t.Helper()
	if p.done != nil {
		t.Fatal("signer process already running")
	}
	var err error
	p.log, err = os.OpenFile(filepath.Join(p.workspace, "process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("cannot create private signer process log")
	}
	p.cmd = p.command(t, "run", "--config", p.config)
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if p.cmd.Start() != nil {
		p.log.Close()
		t.Fatal("cannot start signer Caddy process")
	}
	if p.pids[p.cmd.Process.Pid] {
		t.Fatal("signer restart reused an observed OS process")
	}
	p.pids[p.cmd.Process.Pid] = true
	p.done = make(chan error, 1)
	command, done := p.cmd, p.done
	go func() { done <- command.Wait() }()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(40 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-p.done:
			p.done = nil
			p.log.Close()
			data, _ := os.ReadFile(filepath.Join(p.workspace, "process.log"))
			assertAdminRedacted(t, data, p.local.secrets)
			t.Fatalf("signer Caddy exited before runtime readiness: %v\n%s", err, data)
		case <-deadline.C:
			t.Fatal("signer Caddy runtime readiness timed out")
		case <-tick.C:
			target := p.local.issuer + adminJWKSPath
			if omitted {
				target = p.base + "/ready"
			}
			response, err := p.client.Get(target)
			if err != nil {
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
			response.Body.Close()
			if readErr != nil || len(data) > 64<<10 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("signer readiness lost verified bounded TLS")
			}
			if response.StatusCode != 200 {
				continue
			}
			if omitted {
				if string(data) == "ready" {
					return
				}
				continue
			}
			var document struct {
				Keys []map[string]string `json:"keys"`
			}
			if json.Unmarshal(data, &document) != nil || len(document.Keys) != 1 {
				t.Fatal("signer process discovery is not the expected runtime")
			}
			want := "fixed"
			if p.policyOnly {
				want = "legacy"
			}
			if document.Keys[0]["kid"] != want {
				t.Fatal("signer process published an unexpected key")
			}
			p.keys = document.Keys
			return
		}
	}
}

func (p *accessSignerProcess) stop(t *testing.T) {
	t.Helper()
	if p.done == nil {
		return
	}
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Error("cannot gracefully signal signer Caddy")
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Error("signer Caddy graceful shutdown failed")
		}
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("signer Caddy did not join after forced cleanup")
		}
		t.Error("signer Caddy exceeded graceful shutdown deadline")
	}
	p.done = nil
	_ = p.log.Close()
	p.client.CloseIdleConnections()
}

func (p *accessSignerProcess) rejectedStartup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.binary, "run", "--config", p.config)
	cmd.Dir = p.workspace
	cmd.Env = p.command(t).Env
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	assertAdminRedacted(t, output, p.local.secrets)
	if err == nil || ctx.Err() != nil {
		t.Fatal("invalid signer cold candidate did not reject promptly")
	}
	response, err := p.client.Get(p.base + "/ready")
	if err == nil {
		response.Body.Close()
		t.Fatal("rejected signer cold candidate left a listener")
	}
}

func (p *accessSignerProcess) login(t *testing.T) apiauth.AuthResponse {
	t.Helper()
	login, _ := accessSignerNative(t, p.local, p.client, "alice", "body", false)
	if login.RefreshToken == "" || login.SessionID == "" {
		t.Fatal("signer process did not create persistent renewal authority")
	}
	if !p.policyOnly {
		accessSignerVerify(t, login.AccessToken, p.local.issuer, accessSignerAudience, "fixed", 300, p.keys)
	}
	return login
}

func (p *accessSignerProcess) renew(t *testing.T, refresh string, allowed bool) apiauth.AuthResponse {
	t.Helper()
	r := p.local.json(t, p.client, "/api/refresh_token", map[string]string{"refresh_token": refresh}, "")
	accessSignerCapture(p.local, r)
	if !allowed {
		localIdentityRejectedAuth(t, r, 401)
		return apiauth.AuthResponse{}
	}
	login := localIdentityAuth(t, r)
	if login.AccessToken == "" || login.RefreshToken == "" {
		t.Fatal("same-epoch process lost renewal authority")
	}
	if !p.policyOnly {
		accessSignerVerify(t, login.AccessToken, p.local.issuer, accessSignerAudience, "fixed", 300, p.keys)
	}
	return login
}

func (p *accessSignerProcess) resource(t *testing.T, token string, allowed bool) {
	t.Helper()
	p.local.secrets = append(p.local.secrets, token)
	status, _, _ := registrationHTTP(t, p.client, "GET", p.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}})
	if allowed && status != 200 || !allowed && status == 200 {
		t.Fatalf("process trust epoch acceptance mismatch: HTTP %d", status)
	}
}

func testAccessSignerProcessEpoch(t *testing.T, binary string, policyOnly bool) {
	p := newAccessSignerProcess(t, binary, policyOnly)
	p.start(t, false)
	initial := p.login(t)
	oldAccess := initial.AccessToken
	if policyOnly {
		now := time.Now().Unix()
		oldAccess = accessSignerRawToken(t, p.initial, accessSignerJSON(t, map[string]string{"alg": "PS256", "typ": "authcrunch-access+jwt", "kid": "fixed"}), accessSignerJSON(t, map[string]any{"sub": "alice", "iss": p.local.issuer, "aud": accessSignerAudience, "iat": now, "nbf": now, "exp": now + 180, "roles": []string{"authp/user"}}), "PS256", crypto.SHA256, 32)
	}
	p.resource(t, oldAccess, true)
	p.stop(t)
	p.start(t, false)
	p.resource(t, oldAccess, true)
	current := p.renew(t, initial.RefreshToken, true)
	if current.SessionID != initial.SessionID {
		t.Fatal("same configuration process restart changed family identity")
	}
	// Different private PEM representation of identical RSA material is not a
	// trust transition. The opening pathname/kid/configuration remain unchanged.
	p.stop(t)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(p.initial.key.(*rsa.PrivateKey))})
	p.local.secrets = append(p.local.secrets, string(pkcs1))
	if os.WriteFile(p.key.private, pkcs1, 0600) != nil {
		t.Fatal("cannot re-encode fixture key")
	}
	p.start(t, false)
	current = p.renew(t, current.RefreshToken, true)
	p.stop(t)
	// A failed cold candidate cannot advance the durable root epoch.
	if os.WriteFile(p.key.public, []byte("invalid public key"), 0600) != nil {
		t.Fatal("cannot stage invalid public fixture")
	}
	p.rejectedStartup(t)
	p.material(t, p.initial)
	p.start(t, false)
	current = p.renew(t, current.RefreshToken, true)
	p.stop(t)
	// Same key pathname and kid, different loaded RSA material: policy-only
	// consumers must contribute to the root epoch just like selected portals.
	p.material(t, p.replacement)
	p.start(t, false)
	p.resource(t, oldAccess, false)
	p.renew(t, current.RefreshToken, false)
	second := p.login(t)
	p.stop(t)
	p.material(t, p.initial)
	p.start(t, false)
	p.renew(t, initial.RefreshToken, false)
	p.renew(t, second.RefreshToken, false)
	// Stateless trust was explicitly restored; retired stateful authority was not.
	p.resource(t, oldAccess, true)
	third := p.login(t)
	p.stop(t)
	p.write(t, p.configuration(t, true))
	p.start(t, true)
	status, _, _ := registrationHTTP(t, p.client, "GET", p.local.issuer+adminJWKSPath, nil, nil)
	if status != 404 {
		t.Fatal("omitted epoch retained an authentication portal")
	}
	p.stop(t)
	p.write(t, p.inputText)
	p.start(t, false)
	p.renew(t, third.RefreshToken, false)
	p.login(t)
	p.stop(t)
}
