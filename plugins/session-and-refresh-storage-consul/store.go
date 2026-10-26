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
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"

	"github.com/greenpau/caddy-security/internal/consulstate"
)

type family struct {
	Session tokenrefresh.Session
	Digests [][32]byte
}
type document struct {
	Version, MaxSessions, MaxRotations int
	Generations                        map[string]string
	Families                           map[string]family
}

// Store retains encrypted refresh families and all live spent-credential history.
// Each operation atomically fences its immutable generation using one CAS document.
type Store struct {
	config     ConsulRefreshStore
	descriptor tokenrefresh.ExternalStoreConfig
	handle     *consulstate.Handle
}
type activeStore struct {
	store      *Store
	generation tokenrefresh.Generation
}

func validIdentity(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func validGeneration(g tokenrefresh.Generation) bool {
	return validIdentity(g.Namespace) && validIdentity(g.ID)
}
func (s *Store) initial() document {
	return document{Version: 1, MaxSessions: s.config.MaxSessions, MaxRotations: s.config.MaxRotations, Generations: map[string]string{}, Families: map[string]family{}}
}
func (s *Store) valid(d *document) error {
	if d.Version != 1 || d.MaxSessions != s.config.MaxSessions || d.MaxRotations != s.config.MaxRotations || d.Generations == nil || d.Families == nil || len(d.Families) > d.MaxSessions || len(d.Generations) > 1000 {
		return tokenrefresh.ErrUnavailable
	}
	for ns, g := range d.Generations {
		if !validGeneration(tokenrefresh.Generation{Namespace: ns, ID: g}) {
			return tokenrefresh.ErrUnavailable
		}
	}
	digests := map[[32]byte]bool{}
	for id, f := range d.Families {
		v := f.Session
		if id == "" || len(id) > 256 || id != v.ID || v.IdleExpiresAt > v.AbsoluteExpiresAt || len(f.Digests) < 1 || len(f.Digests) > d.MaxRotations+1 || uint64(len(f.Digests)-1) != v.Revision || f.Digests[len(f.Digests)-1] != v.Current || !validGeneration(tokenrefresh.Generation{Namespace: v.Binding.Namespace, ID: v.Binding.Generation}) || d.Generations[v.Binding.Namespace] != v.Binding.Generation {
			return tokenrefresh.ErrUnavailable
		}
		if len(v.Principal.ProviderSnapshot) > tokenrefresh.MaxProviderSnapshotSize {
			return tokenrefresh.ErrUnavailable
		}
		switch v.Principal.Source {
		case "", tokenrefresh.IdentityStoreSource:
			if len(v.Principal.ProviderSnapshot) != 0 || v.Principal.BackendKind != "" {
				return tokenrefresh.ErrUnavailable
			}
		case tokenrefresh.ProviderSnapshotSource:
			if v.Principal.BackendKind != "oauth" || len(v.Principal.ProviderSnapshot) == 0 || !json.Valid(v.Principal.ProviderSnapshot) {
				return tokenrefresh.ErrUnavailable
			}
		default:
			return tokenrefresh.ErrUnavailable
		}
		for _, digest := range f.Digests {
			if digests[digest] {
				return tokenrefresh.ErrUnavailable
			}
			digests[digest] = true
		}
	}
	return nil
}
func safeError(err error) error {
	if err == consulstate.ErrUnavailable || err == consulstate.ErrCapacity {
		return tokenrefresh.ErrUnavailable
	}
	return err
}

// Metadata returns immutable configuration metadata for an open handle.
func (s *Store) Metadata() (tokenrefresh.StoreMetadata, error) {
	if s == nil || !s.handle.Ready() {
		return tokenrefresh.StoreMetadata{}, tokenrefresh.ErrUnavailable
	}
	c := s.descriptor
	return tokenrefresh.StoreMetadata{Kind: c.Kind, ConfigDigest: c.ConfigDigest, MaxSessions: c.MaxSessions, MaxRotations: c.MaxRotations}, nil
}

// CheckReady checks schema and limits without creating a sentinel record.
func (s *Store) CheckReady(ctx context.Context) error {
	if s == nil {
		return tokenrefresh.ErrUnavailable
	}
	return safeError(consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) { return false, s.valid(d) }))
}

// Close retires this logical handle while retaining Caddy storage and peer data.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.handle.Close()
}

// ActivateGeneration atomically retires old families and returns an immutable generation view.
func (s *Store) ActivateGeneration(ctx context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	if !validGeneration(g) {
		return nil, tokenrefresh.ErrInvalid
	}
	err := consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		if d.Generations[g.Namespace] == g.ID {
			return false, nil
		}
		if _, exists := d.Generations[g.Namespace]; !exists && len(d.Generations) >= 1000 {
			return false, tokenrefresh.ErrUnavailable
		}
		for id, f := range d.Families {
			if f.Session.Binding.Namespace == g.Namespace {
				delete(d.Families, id)
			}
		}
		d.Generations[g.Namespace] = g.ID
		return true, nil
	})
	if err != nil {
		return nil, safeError(err)
	}
	return &activeStore{store: s, generation: g}, nil
}

// Generation returns this view's immutable namespace and generation.
func (v *activeStore) Generation() tokenrefresh.Generation { return v.generation }
func (v *activeStore) matches(b tokenrefresh.Binding) bool {
	return v != nil && v.store != nil && b.Namespace == v.generation.Namespace && b.Generation == v.generation.ID
}
func (v *activeStore) run(ctx context.Context, action func(*document) (bool, error)) error {
	if v == nil || v.store == nil {
		return tokenrefresh.ErrUnavailable
	}
	return safeError(consulstate.Update(ctx, v.store.handle, v.store.initial, func(d *document) (bool, error) {
		if err := v.store.valid(d); err != nil {
			return false, err
		}
		if d.Generations[v.generation.Namespace] != v.generation.ID {
			return false, tokenrefresh.ErrInvalid
		}
		return action(d)
	}))
}
func live(f family, now int64) bool {
	return now < f.Session.IdleExpiresAt && now < f.Session.AbsoluteExpiresAt
}
func find(d *document, digest [32]byte, b tokenrefresh.Binding) (family, bool) {
	for _, f := range d.Families {
		if f.Session.Binding != b {
			continue
		}
		for _, old := range f.Digests {
			if old == digest {
				return f, true
			}
		}
	}
	return family{}, false
}
func known(d *document, digest [32]byte) bool {
	for _, f := range d.Families {
		for _, old := range f.Digests {
			if old == digest {
				return true
			}
		}
	}
	return false
}
func lookup(d *document, digest [32]byte, b tokenrefresh.Binding) (family, bool, error) {
	f, ok := find(d, digest, b)
	if !ok {
		return family{}, false, tokenrefresh.ErrInvalid
	}
	if f.Session.Current != digest || !live(f, time.Now().Unix()) {
		delete(d.Families, f.Session.ID)
		return family{}, true, tokenrefresh.ErrInvalid
	}
	return f, false, nil
}
func clone(s tokenrefresh.Session) tokenrefresh.Session {
	s.Principal.ProviderSnapshot = append([]byte(nil), s.Principal.ProviderSnapshot...)
	s.Principal.Methods = append([]string(nil), s.Principal.Methods...)
	s.Principal.Challenges = append([]string(nil), s.Principal.Challenges...)
	s.Principal.Audience = append([]string(nil), s.Principal.Audience...)
	s.Principal.Scopes = append([]string(nil), s.Principal.Scopes...)
	return s
}

// Create commits a fresh family and staged access deadline.
func (v *activeStore) Create(ctx context.Context, s tokenrefresh.Session, access int64) error {
	return v.CreateReplacing(ctx, s, access, nil)
}

// CreateReplacing atomically replaces only presented families with the exact binding.
func (v *activeStore) CreateReplacing(ctx context.Context, s tokenrefresh.Session, access int64, previous [][32]byte) error {
	if !v.matches(s.Binding) || !consulstate.ValidText(s.ID, 256) || s.Revision != 0 {
		return tokenrefresh.ErrInvalid
	}
	s = clone(s)
	err := v.run(ctx, func(d *document) (bool, error) {
		now := time.Now().Unix()
		if now >= s.IdleExpiresAt || s.IdleExpiresAt > s.AbsoluteExpiresAt || access <= now || access > s.AbsoluteExpiresAt {
			return false, tokenrefresh.ErrInvalid
		}
		for id, f := range d.Families {
			if !live(f, now) {
				delete(d.Families, id)
			}
		}
		if _, exists := d.Families[s.ID]; exists || known(d, s.Current) {
			return false, tokenrefresh.ErrUnavailable
		}
		retired := map[string]bool{}
		for _, digest := range previous {
			if f, ok := find(d, digest, s.Binding); ok {
				retired[f.Session.ID] = true
			}
		}
		if len(d.Families)-len(retired) >= d.MaxSessions {
			return false, tokenrefresh.ErrUnavailable
		}
		for id := range retired {
			delete(d.Families, id)
		}
		d.Families[s.ID] = family{Session: s, Digests: [][32]byte{s.Current}}
		if err := v.store.valid(d); err != nil {
			return false, tokenrefresh.ErrInvalid
		}
		return true, nil
	})
	if err == nil && (time.Now().Unix() >= s.IdleExpiresAt || time.Now().Unix() >= access) {
		return tokenrefresh.ErrUnavailable
	}
	return err
}

// Lookup checks current credentials and commits matching replay revocation.
func (v *activeStore) Lookup(ctx context.Context, digest [32]byte, b tokenrefresh.Binding) (tokenrefresh.Session, error) {
	if !v.matches(b) {
		return tokenrefresh.Session{}, tokenrefresh.ErrInvalid
	}
	var result tokenrefresh.Session
	err := v.run(ctx, func(d *document) (bool, error) {
		f, changed, err := lookup(d, digest, b)
		if err == nil {
			result = clone(f.Session)
		}
		return changed, err
	})
	if err != nil {
		return tokenrefresh.Session{}, err
	}
	if time.Now().Unix() >= result.IdleExpiresAt || time.Now().Unix() >= result.AbsoluteExpiresAt {
		return tokenrefresh.Session{}, tokenrefresh.ErrInvalid
	}
	return result, nil
}

// Rotate atomically commits one descendant while retaining its spent history.
func (v *activeStore) Rotate(ctx context.Context, previous tokenrefresh.Session, next [32]byte, idle, access int64) error {
	if !v.matches(previous.Binding) {
		return tokenrefresh.ErrInvalid
	}
	err := v.run(ctx, func(d *document) (bool, error) {
		f, changed, err := lookup(d, previous.Current, previous.Binding)
		if err != nil {
			return changed, err
		}
		if f.Session.ID != previous.ID || f.Session.Revision != previous.Revision {
			return false, tokenrefresh.ErrInvalid
		}
		now := time.Now().Unix()
		if access <= now {
			return false, tokenrefresh.ErrUnavailable
		}
		if idle <= now || idle > f.Session.AbsoluteExpiresAt || access > f.Session.AbsoluteExpiresAt {
			return false, tokenrefresh.ErrInvalid
		}
		if len(f.Digests) > d.MaxRotations {
			delete(d.Families, f.Session.ID)
			return true, tokenrefresh.ErrInvalid
		}
		if known(d, next) {
			return false, tokenrefresh.ErrUnavailable
		}
		f.Session.Current = next
		f.Session.Revision++
		f.Session.IdleExpiresAt = idle
		f.Digests = append(f.Digests, next)
		d.Families[f.Session.ID] = f
		return true, nil
	})
	if err == nil && (time.Now().Unix() >= idle || time.Now().Unix() >= access) {
		return tokenrefresh.ErrUnavailable
	}
	return err
}

// Revoke revokes the exact bound family using a current or spent credential.
func (v *activeStore) Revoke(ctx context.Context, digest [32]byte, b tokenrefresh.Binding) error {
	if !v.matches(b) {
		return tokenrefresh.ErrInvalid
	}
	return v.run(ctx, func(d *document) (bool, error) {
		f, ok := find(d, digest, b)
		if ok {
			delete(d.Families, f.Session.ID)
		}
		return ok, nil
	})
}

// ValidateSession checks a trusted session reference without rotating credentials.
func (v *activeStore) ValidateSession(ctx context.Context, id string, b tokenrefresh.Binding) error {
	if !v.matches(b) {
		return tokenrefresh.ErrInvalid
	}
	return v.run(ctx, func(d *document) (bool, error) {
		f, ok := d.Families[id]
		if !ok || f.Session.Binding != b || !live(f, time.Now().Unix()) {
			return false, tokenrefresh.ErrInvalid
		}
		return false, nil
	})
}

var (
	_ tokenrefresh.ManagedStore = (*Store)(nil)
	_ tokenrefresh.ActiveStore  = (*activeStore)(nil)
)
