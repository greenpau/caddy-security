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
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	consulapi "github.com/hashicorp/consul/api"
)

// This fixture models only Consul's documented conditional transaction behavior.
// Real Consul and real Caddy processes are exercised by the focused E2E parent.
type memoryKV struct {
	mu        sync.Mutex
	rows      map[string]*consulapi.KVPair
	revision  uint64
	failRead  bool
	uncertain bool
	conflicts bool
	writes    int
}

func (m *memoryKV) Get(key string, q *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !q.RequireConsistent {
		return nil, nil, errors.New("nonconsistent read")
	}
	if m.failRead || q.Context().Err() != nil {
		return nil, nil, errors.New("read unavailable")
	}
	if p := m.rows[key]; p != nil {
		copy := *p
		copy.Value = append([]byte(nil), p.Value...)
		return &copy, nil, nil
	}
	return nil, nil, nil
}
func (m *memoryKV) Txn(ops consulapi.KVTxnOps, q *consulapi.QueryOptions) (bool, *consulapi.KVTxnResponse, *consulapi.QueryMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writes++
	if q.Context().Err() != nil {
		return false, nil, nil, q.Context().Err()
	}
	if len(ops) > 64 {
		return false, nil, nil, errors.New("transaction too large")
	}
	if m.conflicts {
		return false, &consulapi.KVTxnResponse{}, nil, nil
	}
	for _, op := range ops {
		p := m.rows[op.Key]
		var revision uint64
		if p != nil {
			revision = p.ModifyIndex
		}
		if (op.Verb == consulapi.KVCAS || op.Verb == consulapi.KVDeleteCAS) && revision != op.Index {
			return false, &consulapi.KVTxnResponse{}, nil, nil
		}
	}
	m.revision++
	for _, op := range ops {
		switch op.Verb {
		case consulapi.KVSet, consulapi.KVCAS:
			m.rows[op.Key] = &consulapi.KVPair{Key: op.Key, Value: append([]byte(nil), op.Value...), ModifyIndex: m.revision}
		case consulapi.KVDelete, consulapi.KVDeleteCAS:
			delete(m.rows, op.Key)
		default:
			return false, nil, nil, errors.New("unsupported operation")
		}
	}
	if m.uncertain {
		return false, nil, nil, errors.New("response lost after committed write")
	}
	return true, &consulapi.KVTxnResponse{}, nil, nil
}
func newTestStore(t *testing.T, capacity int) (*store, *store, *memoryKV, *atomic.Int64) {
	t.Helper()
	block, err := aes.NewCipher([]byte(strings.Repeat("a", 32)))
	if err != nil {
		t.Fatal(err)
	}
	codec, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	clock := new(atomic.Int64)
	clock.Store(time.Now().Unix())
	kv := &memoryKV{rows: make(map[string]*consulapi.KVPair)}
	f := factory{kv: kv, codec: codec, prefix: "private/pending", capacity: capacity, timeout: time.Second}
	newStore := func() *store { return &store{factory: f, now: func() time.Time { return time.Unix(clock.Load(), 0) }} }
	return newStore(), newStore(), kv, clock
}
func loginTransaction(clock *atomic.Int64, state string) oauth.LoginTransaction {
	return oauth.LoginTransaction{State: state, Nonce: "private-nonce", NonceRequired: true, Verifier: "private-pkce-proof",
		Binding:   oauth.LoginBinding{Browser: sha256.Sum256([]byte("browser")), Callback: "https://auth.example.test/auth/oauth2/upstream/authorization-code-callback"},
		ReturnURL: "https://app.example.test/resource", CreatedAt: clock.Load(), ExpiresAt: clock.Load() + 60}
}
func TestConsulOAuthTransactions(t *testing.T) {
	a, b, kv, clock := newTestStore(t, 2)
	ctx := t.Context()
	tx := loginTransaction(clock, "state")
	if err := a.Create(ctx, "cluster", tx); err != nil {
		t.Fatal(err)
	}
	if err := b.Create(ctx, "cluster", tx); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("duplicate state was admitted", err)
	}
	if _, err := b.Get(ctx, "other", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("namespace isolation failed", err)
	}
	wrong := tx.Binding
	wrong.Callback += "/wrong"
	if _, err := b.Claim(ctx, "cluster", tx.State, wrong, "claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("wrong binding consumed state", err)
	}
	got, err := b.Claim(ctx, "cluster", tx.State, tx.Binding, "winner")
	if err != nil || got.Verifier != tx.Verifier || got.Claim != "winner" {
		t.Fatal("peer claim lost proof", err)
	}
	if _, err := a.Claim(ctx, "cluster", tx.State, tx.Binding, "replay"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("claim replay succeeded", err)
	}
	if err := a.Complete(ctx, "cluster", tx.State, "wrong"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("wrong claim completed", err)
	}
	if err := a.Complete(ctx, "cluster", tx.State, "winner"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, "cluster", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("consumed state returned", err)
	}
	tx.State = "cancel"
	if err := a.Create(ctx, "cluster", tx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Claim(ctx, "cluster", tx.State, tx.Binding, "claim"); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.Cancel(ctx, "cluster", tx.State, wrong); ok || err != nil {
		t.Fatal("wrong browser canceled", ok, err)
	}
	if ok, err := b.Cancel(ctx, "cluster", tx.State, tx.Binding); !ok || err != nil {
		t.Fatal("peer cancellation failed", ok, err)
	}
	if err := a.Complete(ctx, "cluster", tx.State, "claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("canceled claim completed", err)
	}
	for _, row := range kv.rows {
		if strings.Contains(string(row.Value), tx.Verifier) || strings.Contains(string(row.Value), tx.ReturnURL) {
			t.Fatal("private transaction was stored in plaintext")
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Get(ctx, "cluster", "state"); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("closed handle stayed usable", err)
	}
	tx.State = "surviving-peer"
	if err := b.Create(ctx, "cluster", tx); err != nil {
		t.Fatal("closing peer closed shared client", err)
	}
}
func TestConsulOAuthConcurrentClaim(t *testing.T) {
	a, b, _, clock := newTestStore(t, 1)
	tx := loginTransaction(clock, "concurrent")
	if err := a.Create(t.Context(), "cluster", tx); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := a
			if i%2 == 1 {
				s = b
			}
			_, err := s.Claim(t.Context(), "cluster", tx.State, tx.Binding, fmt.Sprintf("claim-%d", i))
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, oauth.ErrLoginInvalid) {
				t.Errorf("unexpected claim error: %v", err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("callbacks did not have exactly one winner", winners.Load())
	}
}
func TestConsulOAuthCapacityExpiryAndCompatibility(t *testing.T) {
	a, b, _, clock := newTestStore(t, 1)
	tx := loginTransaction(clock, "first")
	ctx := t.Context()
	if err := a.Create(ctx, "cluster", tx); err != nil {
		t.Fatal(err)
	}
	second := loginTransaction(clock, "second")
	if err := b.Create(ctx, "another", second); !errors.Is(err, oauth.ErrLoginCapacity) {
		t.Fatal("capacity was not shared", err)
	}
	if _, err := b.Get(ctx, "cluster", tx.State); err != nil {
		t.Fatal("capacity refusal lost original", err)
	}
	clock.Add(60)
	if _, err := b.Get(ctx, "cluster", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("expiry depended on cleanup", err)
	}
	if ok, err := b.Cancel(ctx, "cluster", tx.State, tx.Binding); ok || err != nil {
		t.Fatal("expired cancellation", ok, err)
	}
	second = loginTransaction(clock, "second")
	if err := b.Create(ctx, "another", second); err != nil {
		t.Fatal("expired capacity was not reclaimed", err)
	}
	c := &store{factory: a.factory, now: a.now}
	c.capacity = 2
	if _, _, err := c.readIndex(ctx); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("mismatched capacity accepted", err)
	}
}
func TestConsulOAuthUncertainWrites(t *testing.T) {
	for _, operation := range []string{"create", "claim", "complete", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			a, b, kv, clock := newTestStore(t, 2)
			ctx := t.Context()
			tx := loginTransaction(clock, "uncertain")
			if operation != "create" {
				if err := a.Create(ctx, "cluster", tx); err != nil {
					t.Fatal(err)
				}
			}
			if operation == "complete" {
				if _, err := a.Claim(ctx, "cluster", tx.State, tx.Binding, "claim"); err != nil {
					t.Fatal(err)
				}
			}
			before := kv.writes
			kv.uncertain = true
			var err error
			switch operation {
			case "create":
				err = a.Create(ctx, "cluster", tx)
			case "claim":
				var got oauth.LoginTransaction
				got, err = a.Claim(ctx, "cluster", tx.State, tx.Binding, "claim")
				if got.State != "" {
					t.Fatal("tentative evidence escaped")
				}
			case "complete":
				err = a.Complete(ctx, "cluster", tx.State, "claim")
			case "cancel":
				var canceled bool
				canceled, err = a.Cancel(ctx, "cluster", tx.State, tx.Binding)
				if canceled {
					t.Fatal("uncertain cancellation reported success")
				}
			}
			if !errors.Is(err, oauth.ErrLoginUnavailable) || kv.writes != before+1 {
				t.Fatal("uncertain write retried or reported success", err, kv.writes-before)
			}
			kv.uncertain = false
			if operation == "claim" {
				if _, err := b.Claim(ctx, "cluster", tx.State, tx.Binding, "new-claim"); !errors.Is(err, oauth.ErrLoginInvalid) {
					t.Fatal("uncertain claim became pending", err)
				}
			}
			if operation == "complete" || operation == "cancel" {
				if _, err := b.Get(ctx, "cluster", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
					t.Fatal("consumed evidence resurrected", err)
				}
			}
		})
	}
}
func TestConsulOAuthStorageFailures(t *testing.T) {
	a, _, kv, clock := newTestStore(t, 2)
	tx := loginTransaction(clock, "faults")
	ctx := t.Context()
	if err := a.Create(ctx, string([]byte{0xff}), tx); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("invalid namespace was repaired", err)
	}
	kv.conflicts = true
	if err := a.Create(ctx, "cluster", tx); !errors.Is(err, oauth.ErrLoginUnavailable) || kv.writes != 8 {
		t.Fatal("conflicts were not bounded", err)
	}
	kv.conflicts = false
	if err := a.Create(ctx, "cluster", tx); err != nil {
		t.Fatal(err)
	}
	kv.failRead = true
	if _, err := a.Get(ctx, "cluster", tx.State); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("read outage accepted", err)
	}
	kv.failRead = false
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := a.Create(canceled, "cluster", loginTransaction(clock, "canceled")); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("canceled operation accepted", err)
	}
	id, _ := a.key("cluster", tx.State)
	kv.rows[a.recordKey(id)].Value[0] ^= 0xff
	if _, err := a.Get(ctx, "cluster", tx.State); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("tampered ciphertext accepted", err)
	}
}
