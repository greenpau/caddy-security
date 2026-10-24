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
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

// The executable is the existing real Caddy entrypoint with private fixture CA
// roots. The selected refresh backend is the actual production SQLite module.
// Every start replaces the OS process and verifies this exact mounted JWKS.
func TestCaddySQLiteRefreshPersistenceE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private SQLite refresh backend requires POSIX ownership")
	}
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, "./testdata/runtime_state_caddy")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath -p=1")
	build.WaitDelay = 5 * time.Second
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build actual selected-refresh Caddy command: %v\n%s", err, output)
	}
	t.Run("live_spent_logout", func(t *testing.T) { testSQLiteRefreshProcessPersistence(t, binary) })
	t.Run("capacity_one_config_key_and_omission_epochs", func(t *testing.T) { testSQLiteRefreshProcessEpoch(t, binary) })
	t.Run("independent_loaded_policy_trust", func(t *testing.T) { testSQLiteRefreshPolicyEpoch(t, binary) })
}

type sqliteRefreshProcess struct {
	*accessSignerProcess
	storePath, selectedInput, storeDeclaration string
}

func newSQLiteRefreshProcess(t *testing.T, binary string) *sqliteRefreshProcess {
	t.Helper()
	p := newAccessSignerProcess(t, binary, false)
	if err := os.Chmod(p.workspace, 0700); err != nil {
		t.Fatal("cannot prepare private persistent SQLite refresh directory")
	}
	f := &sqliteRefreshProcess{accessSignerProcess: p, storePath: filepath.Join(p.workspace, "refresh.sqlite")}
	f.storeDeclaration = fmt.Sprintf("token refresh store sqlite selected {\npath %q\nmax sessions 1\nmax rotations 32\ntimeout 2s\n}\n", f.storePath)
	f.selectedInput = strings.Replace(p.inputText, "security {", "security {\n"+f.storeDeclaration, 1)
	f.selectedInput = strings.Replace(f.selectedInput, "token refresh {", "token refresh {\nstore selected\nmax sessions 1\nmax rotations 32\n", 1)
	p.inputText = f.selectedInput
	p.write(t, p.inputText)
	t.Cleanup(func() { p.stop(t); sqliteRefreshScanClosed(t, f.storePath, p.local.secrets) })
	return f
}
func (f *sqliteRefreshProcess) restart(t *testing.T) {
	t.Helper()
	f.stop(t)
	f.start(t, false)
}
func (f *sqliteRefreshProcess) denied(t *testing.T, refresh string) {
	t.Helper()
	sqliteRefreshRequest(t, f.local, f.client, "/api/refresh_token", map[string]string{"refresh_token": refresh}, nil, http.StatusUnauthorized)
}
func (f *sqliteRefreshProcess) change(t *testing.T, input string, omitted bool) {
	t.Helper()
	f.stop(t)
	f.write(t, input)
	f.start(t, omitted)
}
func sqliteRefreshProcessSame(t *testing.T, f *sqliteRefreshProcess, old, next apiauth.AuthResponse) {
	t.Helper()
	if old.SessionID == "" || old.SessionID != next.SessionID || old.SessionExpiresAt != next.SessionExpiresAt || old.AccessToken == next.AccessToken || old.RefreshToken == next.RefreshToken {
		t.Fatal("fresh-process selected SQLite renewal changed family or reused credentials")
	}
	before := accessSignerVerify(t, old.AccessToken, f.local.issuer, accessSignerAudience, "fixed", 300, f.keys)
	after := accessSignerVerify(t, next.AccessToken, f.local.issuer, accessSignerAudience, "fixed", 300, f.keys)
	for _, field := range []string{"id", "sub", "origin", "sid", "auth_time", "amr"} {
		if before[field] == nil || fmt.Sprint(before[field]) != fmt.Sprint(after[field]) {
			t.Fatalf("fresh-process selected renewal changed signed %s", field)
		}
	}
	if after["sub"] != "alice" || after["origin"] != "local" || after["sid"] != next.SessionID {
		t.Fatal("fresh-process selected renewal lost its actual authenticated identity")
	}
}
func testSQLiteRefreshProcessPersistence(t *testing.T, binary string) {
	f := newSQLiteRefreshProcess(t, binary)
	f.start(t, false)
	initial := f.login(t)
	f.resource(t, initial.AccessToken, true)
	f.restart(t)
	next := f.renew(t, initial.RefreshToken, true)
	sqliteRefreshProcessSame(t, f, initial, next)
	f.resource(t, next.AccessToken, true)
	// The spent lookup must survive an entire process replacement and retire the
	// descendant. A further fresh process must still deny that descendant.
	f.restart(t)
	f.denied(t, initial.RefreshToken)
	f.restart(t)
	f.denied(t, next.RefreshToken)
	fresh := f.login(t)
	f.resource(t, fresh.AccessToken, true)
	sqliteRefreshLogout(t, f.local, fresh.RefreshToken)
	f.restart(t)
	f.denied(t, fresh.RefreshToken)
	// Logout can also identify a family by a retained spent credential.
	another := f.login(t)
	rotated := f.renew(t, another.RefreshToken, true)
	f.restart(t)
	sqliteRefreshLogout(t, f.local, another.RefreshToken)
	f.restart(t)
	f.denied(t, rotated.RefreshToken)
	current := f.login(t)
	f.renew(t, current.RefreshToken, true)
	f.stop(t)
}
func testSQLiteRefreshProcessEpoch(t *testing.T, binary string) {
	f := newSQLiteRefreshProcess(t, binary)
	f.start(t, false)
	initial := f.login(t)
	// This genuinely fills the selected store. A subsequent fresh proof must
	// fail admission before any configuration transition frees that same slot.
	sqliteRefreshLogin(t, f.local, f.client, "alice", "body", 503)
	current := f.renew(t, initial.RefreshToken, true)
	sqliteRefreshProcessSame(t, f, initial, current)
	f.stop(t)
	// Different PEM encoding of identical selected material is not a trust
	// transition. The literal config, key path/kid and SQLite generation persist.
	alternate := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.initial.key.(*rsa.PrivateKey))})
	f.local.secrets = append(f.local.secrets, string(alternate))
	if os.WriteFile(f.key.private, alternate, 0600) != nil {
		t.Fatal("cannot stage equivalent selected signing material")
	}
	f.start(t, false)
	next := f.renew(t, current.RefreshToken, true)
	sqliteRefreshProcessSame(t, f, current, next)
	current = next
	f.stop(t)
	// Invalid cold candidates must not activate a new generation or retire the
	// surviving family's durable slot. Repairing the same file is not a new trust.
	if os.WriteFile(f.key.public, []byte("invalid selected public key"), 0600) != nil {
		t.Fatal("cannot stage invalid selected trust")
	}
	f.rejectedStartup(t)
	f.material(t, f.initial)
	f.start(t, false)
	next = f.renew(t, current.RefreshToken, true)
	sqliteRefreshProcessSame(t, f, current, next)
	current = next
	// A -> B -> A with real successful logins at B and restored A. No row or
	// schema manipulation forces capacity; new admission proves old retirement.
	changed := strings.Replace(f.selectedInput, "allow roles authp/user", "allow roles authp/user authp/admin", 1)
	if changed == f.selectedInput {
		t.Fatal("selected refresh fixture did not change policy")
	}
	f.change(t, changed, false)
	f.denied(t, current.RefreshToken)
	atB := f.login(t)
	f.resource(t, atB.AccessToken, true)
	f.change(t, f.selectedInput, false)
	f.denied(t, current.RefreshToken)
	f.denied(t, atB.RefreshToken)
	restored := f.login(t)
	f.resource(t, restored.AccessToken, true)
	restored = f.renew(t, restored.RefreshToken, true)
	// Keep the same key opening names, same kid and exact Caddy input while
	// replacing actual loaded signer/verifier material. The selected SQLite
	// family must retire even though the adapter declaration bytes did not change.
	f.stop(t)
	f.material(t, f.replacement)
	f.start(t, false)
	f.resource(t, restored.AccessToken, false)
	f.denied(t, restored.RefreshToken)
	keyB := f.login(t)
	f.resource(t, keyB.AccessToken, true)
	f.stop(t)
	f.material(t, f.initial)
	f.start(t, false)
	f.resource(t, restored.AccessToken, true)
	f.denied(t, restored.RefreshToken)
	f.denied(t, keyB.RefreshToken)
	active := f.login(t)
	// Distinguish portal omission with an unused named store from complete store
	// and portal omission. Both intermediate roots retain the same durable root
	// state directory, and each is a successful actual Caddy process.
	for _, keepStore := range []bool{true, false} {
		omitted := f.configuration(t, true)
		if keepStore {
			omitted = strings.Replace(omitted, "security {", "security {\n"+f.storeDeclaration, 1)
		}
		if !strings.Contains(omitted, f.directory) {
			t.Fatal("omitted configuration lost durable whole-root state")
		}
		f.change(t, omitted, true)
		status, headers, _ := registrationHTTP(t, f.client, "GET", f.local.issuer+adminJWKSPath, nil, nil)
		if status != 404 || headers.Get("Location") != "" || len(headers.Values("Set-Cookie")) != 0 {
			t.Fatal("omitted root retained portal authority")
		}
		f.change(t, f.selectedInput, false)
		f.denied(t, active.RefreshToken)
		fresh := f.login(t)
		f.resource(t, fresh.AccessToken, true)
		active = f.renew(t, fresh.RefreshToken, true)
	}
	// Old original/spent values cannot be resurrected or revoke the newest family.
	f.denied(t, initial.RefreshToken)
	f.denied(t, current.RefreshToken)
	f.renew(t, active.RefreshToken, true)
	f.stop(t)
}

func testSQLiteRefreshPolicyEpoch(t *testing.T, binary string) {
	f := newSQLiteRefreshProcess(t, binary)
	policyA, policyB := newJWKSKeyFiles(t, "RSA", "policy-A"), newJWKSKeyFiles(t, "RSA", "policy-B")
	stable := jwksKeyFiles{public: filepath.Join(f.workspace, "policy-public.pem")}
	writePolicy := func(key jwksKeyFiles) {
		t.Helper()
		data, err := os.ReadFile(key.public)
		if err != nil || os.WriteFile(stable.public, data, 0600) != nil {
			t.Fatal("cannot stage independent loaded policy trust")
		}
	}
	writePolicy(policyA)
	policy := fmt.Sprintf(`authorization policy independent_policy {
 access token profile {
  issuer %s
  audience %s
  key ids policy-fixed
  max lifetime 300
 }
 %s
 validate bearer header
 set auth url %s/login
 allow roles authp/user
}
`, f.local.issuer, accessSignerAudience, stable.verifier("policy-fixed"), f.local.issuer)
	input := strings.Replace(f.selectedInput, "authentication portal myportal {", policy+"authentication portal myportal {", 1)
	input = strings.Replace(input, "route /resource {", "route /policy-resource {\n authorize with independent_policy\n respond \"independent policy resource\"\n}\nroute /resource {", 1)
	f.write(t, input)
	f.start(t, false)
	// Only the verifier consumes these deliberately signed policy tokens. Portal
	// login/renewal continues to use its unchanged actual selected PS256 signer.
	policyToken := func(key jwksKeyFiles) string {
		now := time.Now().Unix()
		token := accessSignerRawToken(t, key, accessSignerJSON(t, map[string]string{"alg": "PS256", "typ": "authcrunch-access+jwt", "kid": "policy-fixed"}),
			accessSignerJSON(t, map[string]any{"sub": "policy-control", "iss": f.local.issuer, "aud": accessSignerAudience, "iat": now, "nbf": now, "exp": now + 180, "roles": []string{"authp/user"}}), "PS256", crypto.SHA256, 32)
		f.local.secrets = append(f.local.secrets, token)
		return token
	}
	accepted := func(token string, want bool) {
		t.Helper()
		status, _, body := registrationHTTP(t, f.client, "GET", f.base+"/policy-resource", nil, http.Header{"Authorization": {"Bearer " + token}})
		if want && (status != 200 || string(body) != "independent policy resource") || !want && status == 200 {
			t.Fatal("independent policy did not use its actual loaded key")
		}
	}
	first := f.login(t)
	oldPolicy := policyToken(policyA)
	accepted(oldPolicy, true)
	f.resource(t, first.AccessToken, true)
	f.stop(t)
	writePolicy(policyB)
	f.start(t, false)
	accepted(oldPolicy, false)
	accepted(policyToken(policyB), true)
	// The selected signer and its key bytes did not change; existing access
	// remains valid while the root epoch retires durable renewal authority.
	f.resource(t, first.AccessToken, true)
	f.denied(t, first.RefreshToken)
	second := f.login(t)
	f.resource(t, second.AccessToken, true)
	f.stop(t)
	writePolicy(policyA)
	f.start(t, false)
	accepted(oldPolicy, true)
	f.denied(t, first.RefreshToken)
	f.denied(t, second.RefreshToken)
	fresh := f.login(t)
	f.renew(t, fresh.RefreshToken, true)
	f.stop(t)
}
