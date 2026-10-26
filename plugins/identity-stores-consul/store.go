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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/caddy-security/internal/consulstate"
)

var (
	ErrDenied      = errors.New("Consul identity authentication denied")
	ErrUnsupported = errors.New("Consul identity operation unsupported")
)

// Account is trusted account provisioning input; password hashes never leave storage.
type Account struct {
	Username, Email, Name string
	Roles                 []string
}
type accountRecord struct {
	Account  Account
	ID, Hash string
	Version  uint64
	Enabled  bool
}
type document struct {
	Version, Capacity int
	Realm, Epoch      string
	Accounts          map[string]accountRecord
}

// Store owns a logical account handle and never closes the global Consul client.
type Store struct {
	config ConsulIdentityStore
	handle *consulstate.Handle
}

func (s *Store) initial() document {
	return document{Version: 1, Capacity: s.config.Capacity, Realm: s.config.Realm, Accounts: map[string]accountRecord{}}
}
func (s *Store) valid(d *document) error {
	if d.Version != 1 || d.Capacity != s.config.Capacity || d.Realm != s.config.Realm || d.Accounts == nil || len(d.Accounts) > d.Capacity || len(d.Accounts) > 0 && len(d.Epoch) != 64 {
		return consulstate.ErrUnavailable
	}
	for id, a := range d.Accounts {
		if id != a.ID || a.Version < 1 || len(id) != 64 {
			return consulstate.ErrUnavailable
		}
		if _, err := normalize(a.Account); err != nil {
			return consulstate.ErrUnavailable
		}
		if cost, err := bcrypt.Cost([]byte(a.Hash)); err != nil || cost != bcrypt.DefaultCost {
			return consulstate.ErrUnavailable
		}
	}
	return nil
}
func (s *Store) check(ctx context.Context) error {
	return consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) { return false, s.valid(d) })
}
func randomID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", consulstate.ErrUnavailable
	}
	return hex.EncodeToString(b[:]), nil
}
func normalize(a Account) (Account, error) {
	a.Username = strings.ToLower(a.Username)
	a.Email = strings.ToLower(a.Email)
	address, err := mail.ParseAddress(a.Email)
	if !consulstate.ValidText(a.Username, 128) || !consulstate.ValidText(a.Email, 254) || err != nil || address.Address != a.Email || !consulstate.ValidText(a.Name, 256) || len(a.Roles) == 0 || len(a.Roles) > 64 {
		return Account{}, consulstate.ErrInvalid
	}
	for _, r := range a.Roles {
		if !consulstate.ValidText(r, 128) {
			return Account{}, consulstate.ErrInvalid
		}
	}
	a.Roles = append([]string(nil), a.Roles...)
	return a, nil
}
func accountMap(a accountRecord) map[string]any {
	return map[string]any{"id": a.ID, "username": a.Account.Username, "email": a.Account.Email, "name": a.Account.Name, "roles": append([]string(nil), a.Account.Roles...), "enabled": a.Enabled}
}
func find(d *document, username, email string) (accountRecord, error) {
	username, email = strings.ToLower(username), strings.ToLower(email)
	for _, a := range d.Accounts {
		if username != "" && (a.Account.Username == username || a.Account.Email == username) && (email == "" || a.Account.Email == email) || username == "" && email != "" && a.Account.Email == email {
			return a, nil
		}
	}
	return accountRecord{}, ErrDenied
}

// Create provisions one account with a fresh stable ID. It never accepts hash imports.
func (s *Store) Create(ctx context.Context, a *Account, password string) (map[string]any, error) {
	if a == nil || len(password) < 8 || len(password) > 72 {
		return nil, consulstate.ErrInvalid
	}
	input, err := normalize(*a)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, consulstate.ErrInvalid
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	epoch, err := randomID()
	if err != nil {
		return nil, err
	}
	record := accountRecord{Account: input, ID: id, Hash: string(hash), Version: 1, Enabled: true}
	err = consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		for _, a := range d.Accounts {
			if a.Account.Username == input.Username || a.Account.Email == input.Email || a.Account.Username == input.Email || a.Account.Email == input.Username {
				return false, ErrDenied
			}
		}
		if len(d.Accounts) >= d.Capacity {
			return false, consulstate.ErrCapacity
		}
		if d.Epoch == "" {
			d.Epoch = epoch
		}
		d.Accounts[id] = record
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return accountMap(record), nil
}
func (s *Store) read(ctx context.Context) (document, uint64, error) {
	if s == nil || !s.handle.Ready() {
		return document{}, 0, consulstate.ErrUnavailable
	}
	d := s.initial()
	index, err := s.handle.Load(ctx, &d)
	if err == nil {
		err = s.valid(&d)
	}
	return d, index, err
}
func fill(r *requests.Request, a accountRecord, epoch string) {
	r.User.Username = a.Account.Username
	r.User.Email = a.Account.Email
	r.User.FullName = a.Account.Name
	r.User.Roles = append([]string(nil), a.Account.Roles...)
	r.User.Challenges = []string{"password"}
	r.User.AuthMethods = []string{"password"}
	r.User.AuthChallengePolicy = false
	r.Authentication = requests.AuthenticationEvidence{UserID: a.ID, CredentialVersion: a.Version, BackendVersion: epoch}
}

// Request handles password evidence and trusted account creation, preserving exact realms.
func (s *Store) Request(op operator.Type, r *requests.Request) error {
	if r == nil {
		return consulstate.ErrInvalid
	}
	proof := r.Authentication
	r.Authentication = requests.AuthenticationEvidence{}
	r.Response = requests.Response{}
	if s == nil || !s.handle.Ready() {
		return consulstate.ErrUnavailable
	}
	if r.Upstream.Realm != "" && r.Upstream.Realm != s.config.Realm {
		return ErrDenied
	}
	ctx := context.Background()
	if r.Upstream.Request != nil {
		ctx = r.Upstream.Request.Context()
	}
	if op == operator.AddUser {
		result, err := s.Create(ctx, &Account{Username: r.User.Username, Email: r.User.Email, Name: r.User.FullName, Roles: r.User.Roles}, r.User.Password)
		if err == nil {
			r.Response.Payload = result
		}
		return err
	}
	if op != operator.IdentifyUser && op != operator.Authenticate {
		return ErrUnsupported
	}
	username, password := r.User.Username, r.User.Password
	r.User = requests.User{Username: username, Password: password}
	var found accountRecord
	var epoch string
	err := consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) {
		found = accountRecord{}
		if err := s.valid(d); err != nil {
			return false, err
		}
		a, err := find(d, username, "")
		if op == operator.IdentifyUser {
			if err == nil && a.Enabled {
				found = a
				epoch = d.Epoch
			}
			return false, nil
		}
		// Equal-cost verification also runs for absent or disabled accounts.
		hash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
		real := err == nil && a.Enabled
		if real {
			hash = a.Hash
		}
		compare := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if !real || password == "" || len(password) > 72 || compare != nil {
			return false, ErrDenied
		}
		if proof.UserID != "" && (proof.UserID != a.ID || proof.CredentialVersion != a.Version || proof.BackendVersion != d.Epoch) {
			return false, ErrDenied
		}
		found = a
		epoch = d.Epoch
		return false, nil
	})
	if err != nil {
		return err
	}
	if found.ID == "" {
		r.User.Username = "nobody"
		r.User.Email = "nobody@localhost"
		r.User.Challenges = []string{"password"}
		r.User.AuthMethods = []string{"password"}
		return nil
	}
	fill(r, found, epoch)
	r.Response.Code = 200
	if op == operator.Authenticate {
		r.Authentication.AuthenticatedAt = time.Now().Unix()
		r.Authentication.Method = "pwd"
		r.Response.Authenticated = true
	}
	return nil
}

// WithRefreshIdentity stages a callback once and fences it against any concurrent
// account write. Consumers publish callback results only after this returns nil.
func (s *Store) WithRefreshIdentity(ctx context.Context, proof requests.AuthenticationEvidence, apply func(identity.RefreshIdentity) error) error {
	if s == nil || !s.handle.Ready() || ctx == nil {
		return consulstate.ErrUnavailable
	}
	ctx, cancel := s.handle.Context(ctx)
	defer cancel()
	d, index, err := s.read(ctx)
	if err != nil {
		return err
	}
	a, ok := d.Accounts[proof.UserID]
	if apply == nil || !ok || !a.Enabled || proof.BackendVersion != d.Epoch || proof.CredentialVersion != a.Version {
		return identity.ErrRefreshIdentityDenied
	}
	if err := apply(identity.RefreshIdentity{Username: a.Account.Username, Email: a.Account.Email, Name: a.Account.Name, Roles: append([]string(nil), a.Account.Roles...), Challenges: []string{"password"}, AuthMethods: []string{"password"}}); err != nil {
		return err
	}
	ok, err = s.handle.Check(ctx, index)
	if err != nil {
		return err
	}
	if !ok {
		return identity.ErrRefreshIdentityDenied
	}
	return nil
}
func (s *Store) mutate(username, email string, change func(*accountRecord) error) error {
	return consulstate.Update(context.Background(), s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		a, err := find(d, username, email)
		if err != nil {
			return false, err
		}
		if err := change(&a); err != nil {
			return false, err
		}
		a.Version++
		d.Accounts[a.ID] = a
		return true, nil
	})
}

// SetPassword replaces a password and advances the credential version atomically.
func (s *Store) SetPassword(ctx context.Context, username, email, password string) error {
	if len(password) < 8 || len(password) > 72 {
		return consulstate.ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return consulstate.ErrInvalid
	}
	return consulstate.Update(ctx, s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		a, err := find(d, username, email)
		if err != nil {
			return false, err
		}
		a.Hash = string(hash)
		a.Version++
		d.Accounts[a.ID] = a
		return true, nil
	})
}

// DeleteUser removes the exact selected account.
func (s *Store) DeleteUser(username, email string) error {
	return consulstate.Update(context.Background(), s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		a, err := find(d, username, email)
		if err != nil {
			return false, err
		}
		delete(d.Accounts, a.ID)
		return true, nil
	})
}

// DisableUser disables the account and invalidates captured authentication evidence.
func (s *Store) DisableUser(u, e string) error {
	return s.mutate(u, e, func(a *accountRecord) error { a.Enabled = false; return nil })
}

// EnableUser enables the account with a new credential version.
func (s *Store) EnableUser(u, e string) error {
	return s.mutate(u, e, func(a *accountRecord) error { a.Enabled = true; return nil })
}

// FetchUserData returns a detached public account snapshot.
func (s *Store) FetchUserData(u, e string) (map[string]any, error) {
	var result map[string]any
	err := consulstate.Update(context.Background(), s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		a, err := find(d, u, e)
		if err == nil {
			result = accountMap(a)
		}
		return false, err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUsersMetadata returns public account snapshots in stable ID order.
func (s *Store) GetUsersMetadata(_ string) ([]map[string]any, error) {
	var result []map[string]any
	err := consulstate.Update(context.Background(), s.handle, s.initial, func(d *document) (bool, error) {
		if err := s.valid(d); err != nil {
			return false, err
		}
		result = nil
		ids := make([]string, 0, len(d.Accounts))
		for id := range d.Accounts {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			result = append(result, accountMap(d.Accounts[id]))
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetMetadata returns safe backend identifiers and the current account count.
func (s *Store) GetMetadata(_ string) (map[string]any, error) {
	users, err := s.GetUsersMetadata("")
	if err != nil {
		return nil, err
	}
	return map[string]any{"name": s.GetName(), "realm": s.GetRealm(), "count": len(users)}, nil
}

// AddUser creates an account with a generated password for trusted administration.
func (s *Store) AddUser(u, e, n string, roles []string) (map[string]any, error) {
	password, err := randomID()
	if err != nil {
		return nil, err
	}
	result, err := s.Create(context.Background(), &Account{Username: u, Email: e, Name: n, Roles: roles}, password)
	if err == nil {
		result["password"] = password
	}
	return result, err
}

// ResetUserPassword commits a generated password before returning it to trusted administration.
func (s *Store) ResetUserPassword(u, e string) (map[string]any, error) {
	password, err := randomID()
	if err != nil {
		return nil, err
	}
	if err := s.SetPassword(context.Background(), u, e, password); err != nil {
		return nil, err
	}
	return map[string]any{"password": password}, nil
}

// OverwriteUserRoles replaces roles and invalidates prior credential evidence.
func (s *Store) OverwriteUserRoles(u, e string, roles []string) (map[string]any, error) {
	err := s.mutate(u, e, func(a *accountRecord) error {
		a.Account.Roles = append([]string(nil), roles...)
		_, err := normalize(a.Account)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.FetchUserData(u, e)
}

// AddUserRoles appends validated roles and invalidates prior credential evidence.
func (s *Store) AddUserRoles(u, e string, roles []string) (map[string]any, error) {
	err := s.mutate(u, e, func(a *accountRecord) error {
		a.Account.Roles = append(a.Account.Roles, roles...)
		_, err := normalize(a.Account)
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.FetchUserData(u, e)
}

// OverwriteUserAuthChallengeRules rejects unsupported local challenge policy.
func (s *Store) OverwriteUserAuthChallengeRules(string, string, []string) (map[string]any, error) {
	return nil, ErrUnsupported
}

// GetName returns the configured instance name.
func (s *Store) GetName() string { return s.config.Name }

// GetRealm returns the configured login realm.
func (s *Store) GetRealm() string { return s.config.Realm }

// GetKind returns the backend kind used by root binding.
func (s *Store) GetKind() string { return "consul" }

// GetConfig returns public identifiers without credentials or storage details.
func (s *Store) GetConfig() map[string]any {
	return map[string]any{"name": s.GetName(), "realm": s.GetRealm(), "kind": s.GetKind()}
}

// Configure checks the current backend without changing configuration.
func (s *Store) Configure() error {
	if s == nil {
		return consulstate.ErrUnavailable
	}
	return s.check(context.Background())
}

// Configured reports current readiness for root binding.
func (s *Store) Configured() bool { return s != nil && s.Configure() == nil }

// Reload checks current shared storage; there is no local account cache.
func (s *Store) Reload() error { return s.Configure() }

// GetLoginIcon returns detached portal login metadata.
func (s *Store) GetLoginIcon() *icons.LoginIcon {
	i := icons.NewLoginIcon("local")
	i.SetRealm(s.GetRealm())
	return i
}

// Close retires this logical handle while retaining Caddy storage and peer data.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.handle.Close()
}

var _ ids.IdentityStore = (*Store)(nil)
