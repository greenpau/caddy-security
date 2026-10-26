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
	"errors"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"strings"
	"testing"
)

func TestConsulIdentityParser(t *testing.T) {
	for _, input := range []string{"accounts {\nrealm staff\n}", "accounts {\nrealm staff\nprefix private/accounts\ntimeout 2s\ncapacity 2\n}"} {
		var m ConsulIdentityStore
		if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"accounts", "accounts {\nrealm staff\nrealm other\n}", "accounts {\nrealm staff\ncapacity 0\n}", "accounts {\nrealm staff\nprefix ../other\n}", "accounts {\nrealm staff\ntimeout 31s\n}"} {
		if new(ConsulIdentityStore).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
}
func TestConsulIdentityStore(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "identity-tests")
	open := func() *Store {
		m := &ConsulIdentityStore{Name: "accounts", Realm: "staff", Timeout: "5s", Capacity: 1, binding: binding}
		if _, err := m.IdentityStoreConfig(); err != nil {
			t.Fatal(err)
		}
		runtime, err := m.NewIdentityStore(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		s := runtime.(*Store)
		t.Cleanup(func() { _ = s.Close() })
		return s
	}
	a, b := open(), open()
	account := &Account{Username: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}
	if _, err := a.Create(t.Context(), account, "Password-for-Consul-2026!"); err != nil {
		t.Fatal(err)
	}
	request := func(op operator.Type, password string) *requests.Request {
		r := requests.NewRequest()
		r.User.Username = "ALICE@EXAMPLE.TEST"
		r.User.Password = password
		if err := b.Request(op, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := request(operator.Authenticate, "Password-for-Consul-2026!")
	if !r.Response.Authenticated || r.Authentication.UserID == "" {
		t.Fatal("missing shared password proof")
	}
	proof := r.Authentication
	if err := b.WithRefreshIdentity(t.Context(), proof, func(current identity.RefreshIdentity) error {
		if len(current.Roles) != 1 {
			t.Fatal("lost policy")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { return b.DisableUser("alice", "") }); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("concurrent mutation was not fenced", err)
	}
	r = request(operator.IdentifyUser, "")
	if r.Authentication.UserID != "" {
		t.Fatal("disabled user identified")
	}
	if err := b.EnableUser("alice", ""); err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(t.Context(), "alice", "", "Changed-password-2026!"); err != nil {
		t.Fatal(err)
	}
	if err := b.WithRefreshIdentity(t.Context(), proof, func(identity.RefreshIdentity) error { return nil }); !errors.Is(err, identity.ErrRefreshIdentityDenied) {
		t.Fatal("old proof remained valid")
	}
	if _, err := a.Create(t.Context(), &Account{Username: "bob", Email: "bob@example.test", Name: "Bob", Roles: []string{"authp/user"}}, "Other-password-2026!"); !errors.Is(err, consulstate.ErrCapacity) {
		t.Fatal("capacity not enforced", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	request(operator.Authenticate, "Changed-password-2026!")
	if data, err := b.FetchUserData("alice", ""); err != nil || strings.Contains(strings.ToLower(data["username"].(string)), "password") {
		t.Fatal("account lookup failed", err)
	}
	if _, err := b.OverwriteUserRoles("alice", "", []string{"authp/user", "team/one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddUserRoles("alice", "", []string{"team/two"}); err != nil {
		t.Fatal(err)
	}
	if users, err := b.GetUsersMetadata(""); err != nil || len(users) != 1 || len(users[0]["roles"].([]string)) != 3 {
		t.Fatal("administration lost roles", err)
	}
	if metadata, err := b.GetMetadata(""); err != nil || metadata["count"] != 1 {
		t.Fatal("incorrect account metadata", err)
	}
	reset, err := b.ResetUserPassword("alice", "")
	if err != nil {
		t.Fatal(err)
	}
	request(operator.Authenticate, reset["password"].(string))
	if err := b.DeleteUser("alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := b.FetchUserData("alice", ""); !errors.Is(err, ErrDenied) {
		t.Fatal("deleted user remained visible", err)
	}
	if created, err := b.AddUser("bob", "bob@example.test", "Bob", []string{"authp/user"}); err != nil || created["password"] == "" {
		t.Fatal("trusted generated-password provisioning failed", err)
	}
	bad := &ConsulIdentityStore{Name: "accounts", Realm: "staff", Capacity: 2, binding: binding}
	if _, err := bad.IdentityStoreConfig(); err != nil {
		t.Fatal(err)
	}
	if runtime, err := bad.NewIdentityStore(t.Context()); err == nil || runtime != nil {
		t.Fatal("incompatible capacity admitted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if b.WithRefreshIdentity(ctx, proof, func(identity.RefreshIdentity) error { return nil }) == nil {
		t.Fatal("cancelled operation succeeded")
	}
}
