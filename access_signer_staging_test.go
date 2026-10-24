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
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

type stagedAccessSignerModule struct{ RSAPSSAccessSigner }
type stagedAccessSignerFactory struct {
	delegate AccessSignerFactory
	witness  *stagedAccessSignerWitness
}
type stagedAccessSigner struct {
	delegate kms.AccessSigner
	witness  *stagedAccessSignerWitness
}
type stagedAccessSignerWitness struct {
	mu     sync.Mutex
	mode   string
	tokens []string
	calls  int
	key    *rsa.PrivateKey
}

var stagedAccessSignerWitnesses sync.Map

func init() { caddy.RegisterModule(stagedAccessSignerModule{}) }
func (stagedAccessSignerModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.fixture_staged", New: func() caddy.Module { return new(stagedAccessSignerModule) }}
}
func (m *stagedAccessSignerModule) PrepareAccessSigner() (AccessSignerFactory, error) {
	factory, err := m.RSAPSSAccessSigner.PrepareAccessSigner()
	if err != nil {
		return nil, err
	}
	witness, ok := stagedAccessSignerWitnesses.Load(m.Name)
	if !ok {
		return nil, fmt.Errorf("staged signer fixture unavailable")
	}
	return &stagedAccessSignerFactory{delegate: factory, witness: witness.(*stagedAccessSignerWitness)}, nil
}
func (f *stagedAccessSignerFactory) AccessSignerConfig() (kms.ExternalAccessSignerConfig, error) {
	return f.delegate.AccessSignerConfig()
}
func (f *stagedAccessSignerFactory) NewAccessSigner(ctx context.Context) (kms.AccessSigner, error) {
	signer, err := f.delegate.NewAccessSigner(ctx)
	if err != nil {
		return nil, err
	}
	return &stagedAccessSigner{delegate: signer, witness: f.witness}, nil
}
func (s *stagedAccessSigner) Metadata() (kms.AccessSignerMetadata, error) {
	return s.delegate.Metadata()
}
func (s *stagedAccessSigner) PublicJWKS() ([]byte, error) { return s.delegate.PublicJWKS() }
func (s *stagedAccessSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	s.witness.mu.Lock()
	defer s.witness.mu.Unlock()
	s.witness.calls++
	encoded, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("staged signer claims unavailable")
	}
	var detached map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&detached) != nil {
		return "", fmt.Errorf("staged signer claims unavailable")
	}
	switch s.witness.mode {
	case "error":
		return "", fmt.Errorf("synthetic signing refusal")
	case "empty":
		return "", nil
	case "change":
		detached["sub"] = "unapproved-subject"
	case "add":
		detached["unapproved"] = "injected"
	case "remove":
		delete(detached, "approved_marker")
	case "mutate_input":
		claims["sub"] = "mutated-caller-subject"
		claims["unapproved"] = "injected"
		switch roles := claims["roles"].(type) {
		case []string:
			if len(roles) > 0 {
				roles[0] = "unapproved-role"
			}
		case []any:
			if len(roles) > 0 {
				roles[0] = "unapproved-role"
			}
		}
	}
	token, err := s.delegate.Sign(ctx, detached)
	if err != nil {
		return "", err
	}
	if s.witness.mode == "purpose" {
		parts := strings.Split(token, ".")
		var header map[string]any
		data, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil || json.Unmarshal(data, &header) != nil || s.witness.key == nil {
			return "", fmt.Errorf("staged fixture header unavailable")
		}
		header["typ"] = "JWT"
		data, err = json.Marshal(header)
		if err != nil {
			return "", fmt.Errorf("staged fixture header unavailable")
		}
		input := base64.RawURLEncoding.EncodeToString(data) + "." + parts[1]
		digest := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPSS(rand.Reader, s.witness.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
		if err != nil {
			return "", fmt.Errorf("staged fixture signing failed")
		}
		token = input + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	if s.witness.mode == "signature" {
		parts := strings.Split(token, ".")
		parts[2] = "AAAA" + parts[2][4:]
		token = strings.Join(parts, ".")
	}
	s.witness.tokens = append(s.witness.tokens, token)
	return token, nil
}

var _ AccessSignerBackendModule = (*stagedAccessSignerModule)(nil)
var _ AccessSignerFactory = (*stagedAccessSignerFactory)(nil)
var _ kms.AccessSigner = (*stagedAccessSigner)(nil)

func testAccessSignerStaging(t *testing.T, cert, key string, roots *x509.CertPool) {
	witness := new(stagedAccessSignerWitness)
	stagedAccessSignerWitnesses.Store("selected", witness)
	t.Cleanup(func() { stagedAccessSignerWitnesses.Delete("selected") })
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", refresh: true, oidc: true, transform: "transform user {\nmatch any\nadd approved_marker preserved as string\n}\n", configure: func(input string) string {
		return strings.Replace(input, "access signer rsapss selected", "access signer fixture_staged selected", 1)
	}}, cert, key, roots)
	witness.key = f.key.key.(*rsa.PrivateKey)
	t.Cleanup(func() { witness.mu.Lock(); f.secrets = append(f.secrets, witness.tokens...); witness.mu.Unlock() })
	for _, mode := range []string{"error", "empty", "signature", "purpose", "change", "add", "remove"} {
		t.Run(mode, func(t *testing.T) {
			witness.mu.Lock()
			witness.mode = mode
			before := witness.calls
			witness.mu.Unlock()
			f.newBrowser(t)
			start := f.json(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, "")
			accessSignerCapture(f.localIdentityFixture, start)
			identified := localIdentityAuth(t, start)
			raw := f.json(t, f.client, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", SandboxID: identified.SandboxID, SandboxSecret: identified.SandboxSecret, ChallengeKind: "password", ChallengeResponse: lifecyclePassword}, "")
			accessSignerCapture(f.localIdentityFixture, raw)
			var result apiauth.AuthResponse
			if json.Unmarshal(raw.body, &result) != nil || raw.status == 200 || result.Authenticated || result.AccessToken != "" || result.RefreshToken != "" || result.SessionID != "" {
				t.Fatal("unapproved staged credential was published")
			}
			providerDestinationNoIssuance(t, raw)
			f.noCredentials(t)
			witness.mu.Lock()
			calls := witness.calls
			witness.mu.Unlock()
			if calls <= before {
				t.Fatal("staging rejection occurred before the selected signer")
			}
		})
	}
	witness.mu.Lock()
	witness.mode = "mutate_input"
	witness.mu.Unlock()
	login, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "body", false)
	claims := f.verify(t, login.AccessToken)
	if claims["sub"] != "alice" || claims["unapproved"] != nil || claims["approved_marker"] != "preserved" {
		t.Fatal("signer input mutation changed the approved portal User")
	}
	f.consumers(t, login.AccessToken, true)
	// A renewal signer failure must not publish or silently recover staged output.
	witness.mu.Lock()
	witness.mode = "change"
	witness.mu.Unlock()
	raw := f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, "")
	accessSignerCapture(f.localIdentityFixture, raw)
	providerDestinationNoIssuance(t, raw)
	if raw.status == 200 {
		t.Fatal("changed renewal grant was committed")
	}
	witness.mu.Lock()
	witness.mode = ""
	witness.mu.Unlock()
	fresh, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "body", false)
	f.verify(t, fresh.AccessToken)
}
