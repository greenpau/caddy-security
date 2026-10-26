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

package consul

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
)

func TestConsulCredentialConfiguration(t *testing.T) {
	good := "keys {\nrealm staff\n}"
	var m ConsulCredentialAuthenticator
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil || m.Prefix != "security/credentials" || m.Capacity != 1000 || m.Timeout != "3s" {
		t.Fatal("defaults not preserved", err)
	}
	for name, input := range map[string]string{"missing_realm": "keys", "duplicate": "keys {\nrealm staff\nrealm other\n}", "zero": "keys {\nrealm staff\ncapacity 0\n}", "unknown": "keys {\nrealm staff\npath /private/file\n}", "traversal": "keys {\nrealm staff\nprefix ../escape\n}", "timeout": "keys {\nrealm staff\ntimeout 31s\n}", "remote_name": "https://keys.example.test {\nrealm staff\n}", "nested": "keys {\nrealm {\nstaff\n}\n}"} {
		t.Run(name, func(t *testing.T) {
			if new(ConsulCredentialAuthenticator).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
}
func TestConsulCredentialAuthenticator(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "credential-unit")
	openBackend := func(name, realm string, capacity int) *Authenticator {
		c, err := (&ConsulCredentialAuthenticator{Name: name, Realm: realm, Capacity: capacity}).normalized()
		if err != nil {
			t.Fatal(err)
		}
		m := &ConsulCredentialAuthenticator{Name: name, Realm: realm, binding: binding, prepared: &c}
		m.Name = "changed"
		m.Realm = "changed"
		runtime, err := m.NewCredentialAuthenticator(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		a := runtime.(*Authenticator)
		if a.GetName() != name || a.GetConfig()["realm"] != realm || !a.RequireFreshAuthentication() {
			t.Fatal("factory lost frozen identity")
		}
		t.Cleanup(func() { _ = a.Close() })
		return a
	}
	a, b := openBackend("keys", "staff", 2), openBackend("keys", "staff", 2)
	key, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := &authproxy.Request{Realm: "staff", Secret: key}
	if err := b.APIKeyAuthContext(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if json.Unmarshal([]byte(request.Response.Payload), &claims) != nil || claims["sub"] != "alice" || claims["origin"] != "staff" || claims["amr"].([]any)[0] != "api_key" {
		t.Fatal("incorrect trusted claims")
	}
	request.Realm = "other"
	if err := b.APIKeyAuth(request); !errors.Is(err, ErrDenied) || request.Response.Payload != "" {
		t.Fatal("wrong realm reused claims", err)
	}
	request.Realm = "staff"
	if err := b.BasicAuthContext(t.Context(), request); !errors.Is(err, ErrDenied) || request.Response.Payload != "" {
		t.Fatal("Basic authentication accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if b.APIKeyAuthContext(ctx, request) == nil || request.Response.Payload != "" {
		t.Fatal("cancelled request reused credentials")
	}
	if err := a.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	if b.APIKeyAuth(request) == nil || request.Response.Payload != "" {
		t.Fatal("revocation was cached")
	}
	if err := b.Revoke(t.Context(), key); err != nil {
		t.Fatal("revoke not idempotent", err)
	}
	if _, err := a.Issue(t.Context(), "alice", "Alice <alice@example.test>", []string{"viewer"}, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("non-bare email accepted")
	}
	if _, err := a.Issue(t.Context(), "alice", "alice@example.test", nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("empty roles accepted")
	}
	if _, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(31*24*time.Hour)); err == nil {
		t.Fatal("unbounded lifetime accepted")
	}
	var issued []string
	for range 2 {
		if issuedKey, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		} else {
			issued = append(issued, issuedKey)
		}
	}
	if _, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour)); !errors.Is(err, consulstate.ErrCapacity) {
		t.Fatal("capacity not enforced", err)
	}
	digest := sha256.Sum256([]byte(issued[0]))
	if err := a.run(t.Context(), func(d *document) (bool, error) {
		v := d.Keys[digest]
		v.Expires = 1
		d.Keys[digest] = v
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: issued[0]}); !errors.Is(err, ErrDenied) {
		t.Fatal("expired key accepted", err)
	}

	replacement, err := a.Issue(t.Context(), "new", "new@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal("expired key did not release capacity", err)
	}
	other := openBackend("other", "staff", 2)
	if err := other.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: replacement}); !errors.Is(err, ErrDenied) {
		t.Fatal("backend names shared credentials", err)
	}
	mismatch, _ := (&ConsulCredentialAuthenticator{Name: "keys", Realm: "different", Capacity: 2}).normalized()
	if runtime, err := open(t.Context(), mismatch, binding); err == nil || runtime != nil {
		t.Fatal("realm storage mismatch admitted")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: replacement}); err != nil {
		t.Fatal("peer close lost shared client", err)
	}
	if err := a.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: replacement}); !errors.Is(err, consulstate.ErrUnavailable) {
		t.Fatal("closed handle accepted", err)
	}
	first, second := openBackend("single", "staff", 1), openBackend("single", "staff", 1)
	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, issuer := range []*Authenticator{first, second} {
		wg.Add(1)
		go func(issuer *Authenticator) {
			defer wg.Done()
			_, err := issuer.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
			outcomes <- err
		}(issuer)
	}
	wg.Wait()
	close(outcomes)
	wins := 0
	for err := range outcomes {
		if err == nil {
			wins++
		} else if !errors.Is(err, consulstate.ErrCapacity) {
			t.Fatal("unexpected competing issuance error", err)
		}
	}
	if wins != 1 {
		t.Fatalf("capacity-one issuance winners: %d", wins)
	}
	if validKey(strings.Repeat("x", 42)) {
		t.Fatal("malformed key accepted")
	}
}
