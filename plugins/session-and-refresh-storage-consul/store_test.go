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
	"crypto/sha256"
	"errors"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConsulRefreshParser(t *testing.T) {
	for _, input := range []string{"shared", "shared {\n}", "shared {\nmax sessions 2\nmax rotations 3\ntimeout 2s\n}"} {
		if err := new(ConsulRefreshStore).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"shared {\nmax sessions 0\n}", "shared {\nmax sessions 1\nmax sessions 2\n}", "shared {\ntimeout 31s\n}", "shared {\npath /private/test\n}"} {
		if new(ConsulRefreshStore).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
}
func TestConsulRefreshStore(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "refresh-tests")
	open := func() *Store {
		m := &ConsulRefreshStore{Name: "shared", MaxSessions: 2, MaxRotations: 2, binding: binding}
		f, err := m.PrepareRefreshStore()
		if err != nil {
			t.Fatal(err)
		}
		m.MaxSessions = 9
		runtime, err := f.NewRefreshStore(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		s := runtime.(*Store)
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	a, b := open(), open()
	g := tokenrefresh.Generation{Namespace: strings.Repeat("a", 64), ID: strings.Repeat("b", 64)}
	va, err := a.ActivateGeneration(t.Context(), g)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := b.ActivateGeneration(t.Context(), g)
	if err != nil {
		t.Fatal(err)
	}
	bindingValue := tokenrefresh.Binding{Portal: "portal", Origin: "https://auth.example.test", BasePath: "/auth", Transport: "body", Namespace: g.Namespace, Generation: g.ID}
	now := time.Now().Unix()
	first := sha256.Sum256([]byte("first"))
	next := sha256.Sum256([]byte("next"))
	s := tokenrefresh.Session{ID: "session-one", Binding: bindingValue, Current: first, IdleExpiresAt: now + 120, AbsoluteExpiresAt: now + 240, Principal: tokenrefresh.Principal{Backend: "accounts", Realm: "staff", UserID: "immutable-user", BackendVersion: "immutable-version", CredentialVersion: 1, Methods: []string{"pwd"}}}
	s.Principal.ExternalIdentity = requests.ExternalIdentity{Provider: "upstream", Kind: "oauth", Issuer: "https://issuer.example.test", Subject: "immutable-subject", Evidence: requests.AuthenticationEvidence{UserID: "attached-id", CredentialVersion: 7, BackendVersion: "attached-epoch", AuthenticatedAt: now, Method: "federated"}}
	if err := va.Create(t.Context(), s, now+30); err != nil {
		t.Fatal(err)
	}
	current, err := vb.Lookup(t.Context(), first, bindingValue)
	if err != nil || current.Principal.UserID != s.Principal.UserID || current.Principal.Methods[0] != "pwd" || current.Principal.ExternalIdentity.Evidence.CredentialVersion != 7 || current.Principal.ExternalIdentity.Subject != "immutable-subject" {
		t.Fatal("gob lost server-only evidence", err)
	}
	wrong := bindingValue
	wrong.Portal = "other"
	if _, err := vb.Lookup(t.Context(), first, wrong); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("wrong binding accepted", err)
	}
	if err := vb.Rotate(t.Context(), current, next, now+120, now+30); err != nil {
		t.Fatal(err)
	}
	if _, err := va.Lookup(t.Context(), first, bindingValue); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("spent token accepted", err)
	}
	if _, err := vb.Lookup(t.Context(), next, bindingValue); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replay did not revoke descendant", err)
	}
	if err := va.Create(t.Context(), s, now+30); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wins := make(chan bool, 2)
	for i, view := range []tokenrefresh.ActiveStore{va, vb} {
		wg.Add(1)
		go func(i int, v tokenrefresh.ActiveStore) {
			defer wg.Done()
			digest := sha256.Sum256([]byte{byte(i + 1)})
			wins <- v.Rotate(t.Context(), s, digest, now+120, now+30) == nil
		}(i, view)
	}
	wg.Wait()
	close(wins)
	count := 0
	for ok := range wins {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent winners: %d", count)
	}
	g.ID = strings.Repeat("c", 64)
	fresh, err := a.ActivateGeneration(t.Context(), g)
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.ValidateSession(t.Context(), s.ID, bindingValue); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("retired view accepted", err)
	}
	updated := bindingValue
	updated.Generation = g.ID
	s.Binding = updated
	if err := fresh.Create(t.Context(), s, now+30); err != nil {
		t.Fatal(err)
	}
	second := s
	second.ID = "second"
	second.Current = sha256.Sum256([]byte("second"))
	if err := fresh.Create(t.Context(), second, now+30); err != nil {
		t.Fatal(err)
	}
	third := s
	third.ID = "third"
	third.Current = sha256.Sum256([]byte("third"))
	if err := fresh.Create(t.Context(), third, now+30); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("capacity not enforced", err)
	}
	if err := fresh.CreateReplacing(t.Context(), third, now+30, [][32]byte{second.Current}); err != nil {
		t.Fatal(err)
	}
	if err := fresh.ValidateSession(t.Context(), second.ID, updated); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("replaced family remained live", err)
	}
	if err := fresh.Revoke(t.Context(), third.Current, updated); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Revoke(t.Context(), third.Current, updated); err != nil {
		t.Fatal("logout was not idempotent", err)
	}
	for i := range 2 {
		current, err := fresh.Lookup(t.Context(), s.Current, updated)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte{byte(i + 70)})
		if err := fresh.Rotate(t.Context(), current, digest, now+120, now+30); err != nil {
			t.Fatal(err)
		}
		s.Current = digest
	}
	current, err = fresh.Lookup(t.Context(), s.Current, updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Rotate(t.Context(), current, sha256.Sum256([]byte("exhausted")), now+120, now+30); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("rotation bound not enforced", err)
	}
	if err := fresh.ValidateSession(t.Context(), s.ID, updated); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("exhausted family not retired", err)
	}
	if err := fresh.Create(t.Context(), second, now+30); err != nil {
		t.Fatal(err)
	}
	if err := consulstate.Update(t.Context(), a.handle, a.initial, func(d *document) (bool, error) {
		f := d.Families[second.ID]
		f.Session.IdleExpiresAt = now - 1
		d.Families[second.ID] = f
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Lookup(t.Context(), second.Current, updated); !errors.Is(err, tokenrefresh.ErrInvalid) {
		t.Fatal("expired family accepted", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.CheckReady(t.Context()); err != nil {
		t.Fatal("peer closed global client", err)
	}
	_ = fresh
}
