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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// Each stage is a fresh OS process. Neither Caddy globals nor the library's
// generated-key buffer or token caches can preserve signing material for it.
func TestCaddyJWKSPersistenceE2E(t *testing.T) {
	current := newJWKSKeyFiles(t, "OKP", "ed-current")
	next := newJWKSKeyFiles(t, "OKP", "ed-next")
	stateFile := filepath.Join(t.TempDir(), "persistence.json")
	writeJWKSPersistenceState(t, stateFile, jwksPersistenceState{
		CurrentPrivate: current.private, CurrentPublic: current.public,
		NextPrivate: next.private, NextPublic: next.public,
	})
	// These phases share persisted state. Keep the sequence in one test so a
	// subtest filter cannot skip the login or rotation that a later phase needs.
	for _, phase := range []string{"original", "restart", "rotate", "retire"} {
		t.Logf("persistence phase: %s", phase)
		func() {
			ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyJWKSPersistenceProcess$", "-test.v", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), "CADDY_SECURITY_JWKS_PERSISTENCE_CHILD=1", "CADDY_SECURITY_JWKS_STATE="+stateFile, "CADDY_SECURITY_JWKS_PHASE="+phase)
			collectSubprocessCoverage(t, cmd)
			cmd.WaitDelay = 5 * time.Second
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("TLS Caddy JWKS persistence %s: %v\n%s", phase, err, output)
			}
		}()
	}
}

type jwksPersistenceState struct {
	CurrentPrivate, CurrentPublic string
	NextPrivate, NextPublic       string
	OldToken, NewToken            string
	OriginalKeys                  []map[string]string
}

func writeJWKSPersistenceState(t *testing.T, path string, state jwksPersistenceState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal("could not encode persistence state")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("could not save persistence state")
	}
}

func TestCaddyJWKSPersistenceProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_JWKS_PERSISTENCE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	stateFile, phase := os.Getenv("CADDY_SECURITY_JWKS_STATE"), os.Getenv("CADDY_SECURITY_JWKS_PHASE")
	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal("could not read persistence state")
	}
	var state jwksPersistenceState
	if json.Unmarshal(data, &state) != nil {
		t.Fatal("could not decode persistence state")
	}
	current := jwksKeyFiles{private: state.CurrentPrivate, public: state.CurrentPublic}
	next := jwksKeyFiles{private: state.NextPrivate, public: state.NextPublic}
	oldPrivateVerifier := strings.Replace(current.signer("ed-current"), "sign-verify", "verify", 1)
	var portal, policy string
	count := 1
	switch phase {
	case "original", "restart":
		portal = current.signer("ed-current") + "\n" + next.signer("ed-next")
		policy = current.verifier("ed-current") + "\n" + next.verifier("ed-next")
		count = 2
	case "rotate":
		portal = next.signer("ed-next") + "\n" + oldPrivateVerifier
		policy = next.verifier("ed-next") + "\n" + current.verifier("ed-current")
	case "retire":
		portal, policy = next.signer("ed-next"), next.verifier("ed-next")
	default:
		t.Fatal("unknown persistence phase")
	}
	certFile, certKey, roots := cookieTLSCertificate(t)
	f := newCaddyJWKSFixture(t, "/auth", portal, policy, certFile, certKey, roots)
	keys := fetchCaddyJWKS(t, f, count)
	switch phase {
	case "original":
		state.OldToken = f.login(t, "keyadmin")
		state.OriginalKeys = keys
		verifyCaddyJWKSToken(t, keys, state.OldToken, "EdDSA", "ed-current")
		assertCaddyGatekeeper(t, f, state.OldToken, true)
	case "restart":
		if cmp.Diff(state.OriginalKeys, keys) != "" {
			t.Fatal("process restart changed persisted JWKS")
		}
		verifyCaddyJWKSToken(t, keys, state.OldToken, "EdDSA", "ed-current")
		assertCaddyGatekeeper(t, f, state.OldToken, true)
		verifyCaddyJWKSToken(t, keys, f.login(t, "keyadmin"), "EdDSA", "ed-current")
	case "rotate":
		state.NewToken = f.login(t, "keyadmin")
		verifyCaddyJWKSToken(t, keys, state.NewToken, "EdDSA", "ed-next")
		verifyCaddyJWKSToken(t, state.OriginalKeys, state.NewToken, "EdDSA", "ed-next")
		assertCaddyGatekeeper(t, f, state.OldToken, true)
		assertCaddyGatekeeper(t, f, state.NewToken, true)
		// Also retire through a live Caddy reload after both tokens have been
		// cached. Previous successful authorization must not hide key removal.
		f.input = strings.ReplaceAll(f.input, oldPrivateVerifier, "")
		f.input = strings.ReplaceAll(f.input, current.verifier("ed-current"), "")
		if err := f.reload(""); err != nil {
			t.Fatal("could not retire old verifier during reload")
		}
		// Probe the replacement on new connections. Caddy retires the old
		// server's idle keep-alives; reusing one can race that retirement,
		// especially for the non-idempotent discovery method probes below.
		// Do not retry requests to hide a transport or protocol failure.
		f.client.CloseIdleConnections()
		fetchCaddyJWKS(t, f, 1)
		assertCaddyGatekeeper(t, f, state.OldToken, false)
		assertCaddyGatekeeper(t, f, state.NewToken, true)
	case "retire":
		verifyCaddyJWKSToken(t, keys, state.NewToken, "EdDSA", "ed-next")
		assertCaddyGatekeeper(t, f, state.OldToken, false)
		assertCaddyGatekeeper(t, f, state.NewToken, true)
	}
	writeJWKSPersistenceState(t, stateFile, state)
}
