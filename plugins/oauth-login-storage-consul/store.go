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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	consulapi "github.com/hashicorp/consul/api"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

type consulKV interface {
	Get(string, *consulapi.QueryOptions) (*consulapi.KVPair, *consulapi.QueryMeta, error)
	Txn(consulapi.KVTxnOps, *consulapi.QueryOptions) (bool, *consulapi.KVTxnResponse, *consulapi.QueryMeta, error)
}

type store struct {
	factory
	closed atomic.Bool
	now    func() time.Time
}

// The encrypted index bounds storage and coordinates admissions/removals. Claims
// CAS only their own record. Every record creation also CASes the index, so an
// expired-record deletion cannot remove a newer admission at the same key.
type index struct {
	Version  int              `json:"version"`
	Capacity int              `json:"capacity"`
	Entries  map[string]int64 `json:"entries"`
}

type record struct {
	Namespace   string                 `json:"namespace"`
	Transaction oauth.LoginTransaction `json:"transaction"`
}

func (s *store) OAuthLoginStoreConfig() (plugin.OAuthLoginStoreConfig, error) {
	if s == nil || s.closed.Load() {
		return plugin.OAuthLoginStoreConfig{}, oauth.ErrLoginUnavailable
	}
	return s.descriptor, nil
}

func (s *store) Close() error {
	if s != nil {
		s.closed.Store(true)
	}
	// The configured Consul client belongs to Caddy; never close or purge it.
	return nil
}

func (s *store) options(ctx context.Context) *consulapi.QueryOptions {
	return (&consulapi.QueryOptions{RequireConsistent: true}).WithContext(ctx)
}

func (s *store) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if s == nil || s.closed.Load() {
		return nil, nil, oauth.ErrLoginUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	if err := ctx.Err(); err != nil {
		cancel()
		return nil, nil, oauth.ErrLoginUnavailable
	}
	return ctx, cancel, nil
}

func (s *store) key(namespace, state string) (string, error) {
	if namespace == "" || len(namespace) > 1024 || !utf8.ValidString(namespace) || strings.TrimSpace(namespace) != namespace || strings.ContainsFunc(namespace, unicode.IsControl) || state == "" || len(state) > 128 {
		return "", oauth.ErrLoginInvalid
	}
	digest := sha256.Sum256([]byte(namespace + "\x00" + state))
	return hex.EncodeToString(digest[:]), nil
}

func (s *store) recordKey(id string) string { return path.Join(s.prefix, "transactions", id) }
func (s *store) indexKey() string           { return path.Join(s.prefix, "index") }

func (s *store) seal(key string, value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 256*1024 {
		return nil, oauth.ErrLoginUnavailable
	}
	nonce := make([]byte, s.codec.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, oauth.ErrLoginUnavailable
	}
	return s.codec.Seal(nonce, nonce, data, []byte(key)), nil
}

func (s *store) open(key string, data []byte, value any) error {
	if len(data) < s.codec.NonceSize()+s.codec.Overhead() || len(data) > 300*1024 {
		return oauth.ErrLoginUnavailable
	}
	data, err := s.codec.Open(nil, data[:s.codec.NonceSize()], data[s.codec.NonceSize():], []byte(key))
	if err != nil {
		return oauth.ErrLoginUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return oauth.ErrLoginUnavailable
	}
	return nil
}

func (s *store) readIndex(ctx context.Context) (*index, uint64, error) {
	pair, _, err := s.kv.Get(s.indexKey(), s.options(ctx))
	if err != nil || ctx.Err() != nil {
		return nil, 0, oauth.ErrLoginUnavailable
	}
	if pair == nil {
		return &index{Version: 1, Capacity: s.capacity, Entries: make(map[string]int64)}, 0, nil
	}
	var value index
	if s.open(s.indexKey(), pair.Value, &value) != nil || value.Version != 1 || value.Capacity != s.capacity || value.Entries == nil || len(value.Entries) > s.capacity || pair.ModifyIndex == 0 {
		return nil, 0, oauth.ErrLoginUnavailable
	}
	for id, deadline := range value.Entries {
		decoded, err := hex.DecodeString(id)
		if err != nil || len(decoded) != 32 || deadline <= 0 {
			return nil, 0, oauth.ErrLoginUnavailable
		}
	}
	return &value, pair.ModifyIndex, nil
}

func (s *store) readRecord(ctx context.Context, namespace, state, id string) (*record, uint64, error) {
	pair, _, err := s.kv.Get(s.recordKey(id), s.options(ctx))
	if err != nil || ctx.Err() != nil {
		return nil, 0, oauth.ErrLoginUnavailable
	}
	if pair == nil {
		return nil, 0, oauth.ErrLoginInvalid
	}
	var value record
	if s.open(s.recordKey(id), pair.Value, &value) != nil || value.Namespace != namespace || value.Transaction.State != state || pair.ModifyIndex == 0 {
		return nil, 0, oauth.ErrLoginUnavailable
	}
	if value.Transaction.Validate(s.now()) != nil {
		return nil, 0, oauth.ErrLoginInvalid
	}
	return &value, pair.ModifyIndex, nil
}

func (s *store) commit(ctx context.Context, ops consulapi.KVTxnOps) (bool, error) {
	ok, _, _, err := s.kv.Txn(ops, s.options(ctx))
	if err != nil || ctx.Err() != nil {
		// A network error may follow an applied write. Never retry that outcome.
		return false, oauth.ErrLoginUnavailable
	}
	return ok, nil
}

func (s *store) indexCAS(value *index, revision uint64) (*consulapi.KVTxnOp, error) {
	data, err := s.seal(s.indexKey(), value)
	return &consulapi.KVTxnOp{Verb: consulapi.KVCAS, Key: s.indexKey(), Index: revision, Value: data}, err
}

func (s *store) Create(ctx context.Context, namespace string, tx oauth.LoginTransaction) error {
	id, err := s.key(namespace, tx.State)
	if err != nil || tx.Claim != "" || tx.Validate(s.now()) != nil {
		return oauth.ErrLoginInvalid
	}
	ctx, cancel, err := s.operation(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	data, err := s.seal(s.recordKey(id), record{namespace, tx})
	if err != nil {
		return err
	}
	for attempt := 0; attempt < 8; attempt++ {
		value, revision, err := s.readIndex(ctx)
		if err != nil {
			return err
		}
		now := s.now()
		if tx.Validate(now) != nil {
			return oauth.ErrLoginInvalid
		}
		if deadline, exists := value.Entries[id]; exists && deadline > now.Unix() {
			return oauth.ErrLoginInvalid
		}
		var ops consulapi.KVTxnOps
		// At most 60 cleanup operations plus index CAS and admission (Consul's
		// transaction limit is 64). The target is overwritten under the index CAS.
		delete(value.Entries, id)
		for expired, deadline := range value.Entries {
			if deadline <= now.Unix() && len(ops) < 60 {
				delete(value.Entries, expired)
				ops = append(ops, &consulapi.KVTxnOp{Verb: consulapi.KVDelete, Key: s.recordKey(expired)})
			}
		}
		if len(value.Entries) >= s.capacity {
			return oauth.ErrLoginCapacity
		}
		value.Entries[id] = tx.ExpiresAt
		indexOp, err := s.indexCAS(value, revision)
		if err != nil {
			return err
		}
		ops = append(ops, indexOp, &consulapi.KVTxnOp{Verb: consulapi.KVSet, Key: s.recordKey(id), Value: data})
		ok, err := s.commit(ctx, ops)
		if err != nil {
			return err
		}
		if ok {
			return tx.Validate(s.now())
		}
	}
	return oauth.ErrLoginUnavailable
}

func (s *store) Get(ctx context.Context, namespace, state string) (oauth.LoginTransaction, error) {
	id, err := s.key(namespace, state)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	ctx, cancel, err := s.operation(ctx)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	defer cancel()
	value, _, err := s.readRecord(ctx, namespace, state, id)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	return value.Transaction, nil
}

func (s *store) Claim(ctx context.Context, namespace, state string, binding oauth.LoginBinding, claim string) (oauth.LoginTransaction, error) {
	id, err := s.key(namespace, state)
	if err != nil || claim == "" {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	ctx, cancel, err := s.operation(ctx)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	defer cancel()
	value, revision, err := s.readRecord(ctx, namespace, state, id)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	if value.Transaction.Claim != "" || !value.Transaction.Binding.Matches(binding) {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	value.Transaction.Claim = claim
	if value.Transaction.Validate(s.now()) != nil {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	data, err := s.seal(s.recordKey(id), value)
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	ok, err := s.commit(ctx, consulapi.KVTxnOps{&consulapi.KVTxnOp{Verb: consulapi.KVCAS, Key: s.recordKey(id), Index: revision, Value: data}})
	if err != nil {
		return oauth.LoginTransaction{}, err
	}
	if !ok || value.Transaction.Validate(s.now()) != nil {
		return oauth.LoginTransaction{}, oauth.ErrLoginInvalid
	}
	return value.Transaction, nil
}

func (s *store) Complete(ctx context.Context, namespace, state, claim string) error {
	if claim == "" {
		return oauth.ErrLoginInvalid
	}
	_, err := s.remove(ctx, namespace, state, claim, nil)
	return err
}

func (s *store) Cancel(ctx context.Context, namespace, state string, binding oauth.LoginBinding) (bool, error) {
	return s.remove(ctx, namespace, state, "", &binding)
}

func (s *store) remove(ctx context.Context, namespace, state, claim string, binding *oauth.LoginBinding) (bool, error) {
	id, err := s.key(namespace, state)
	if err != nil {
		if binding != nil {
			return false, nil
		}
		return false, err
	}
	ctx, cancel, err := s.operation(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		value, rowRevision, err := s.readRecord(ctx, namespace, state, id)
		if err != nil {
			if binding != nil && err == oauth.ErrLoginInvalid {
				return false, nil
			}
			return false, err
		}
		if (binding != nil && !value.Transaction.Binding.Matches(*binding)) || (binding == nil && value.Transaction.Claim != claim) {
			if binding != nil {
				return false, nil
			}
			return false, oauth.ErrLoginInvalid
		}
		idx, revision, err := s.readIndex(ctx)
		if err != nil {
			return false, err
		}
		if idx.Entries[id] != value.Transaction.ExpiresAt {
			return false, oauth.ErrLoginUnavailable
		}
		delete(idx.Entries, id)
		indexOp, err := s.indexCAS(idx, revision)
		if err != nil {
			return false, err
		}
		if value.Transaction.Validate(s.now()) != nil {
			if binding != nil {
				return false, nil
			}
			return false, oauth.ErrLoginInvalid
		}
		ok, err := s.commit(ctx, consulapi.KVTxnOps{indexOp, &consulapi.KVTxnOp{Verb: consulapi.KVDeleteCAS, Key: s.recordKey(id), Index: rowRevision}})
		if err != nil {
			return false, err
		}
		if ok {
			if binding == nil && value.Transaction.Validate(s.now()) != nil {
				return false, oauth.ErrLoginInvalid
			}
			return true, nil
		}
	}
	return false, oauth.ErrLoginUnavailable
}

var (
	_ plugin.OAuthLoginStore = (*store)(nil)
	_ io.Closer              = (*store)(nil)
	_ consulKV               = (*consulapi.KV)(nil)
)
