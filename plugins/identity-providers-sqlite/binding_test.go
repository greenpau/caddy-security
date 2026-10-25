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

package sqlite_test

import (
	"errors"
	"os"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/identity-providers-sqlite"
)

func TestTicketFactoryPreservesBrowserBinding(t *testing.T) {
	module := sqliteTicketTestConfig(t)
	runtime, err := module.NewIdentityProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provider := runtime.(*tickets.Provider)
	t.Cleanup(func() { _ = provider.Close() })
	request, cookie := sqliteTicketBegin(t, provider)
	ticket, err := provider.Issue(t.Context(), request, &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	wrong := *cookie
	wrong.Value = "wrong-browser-binding"
	if result, err := sqliteTicketRedeem(t, provider, request, ticket, &wrong); result != nil || !errors.Is(err, tickets.ErrDenied) {
		t.Fatal("wrong browser received identity", err)
	}
	if result, err := sqliteTicketRedeem(t, provider, request, ticket, cookie); err != nil || result.Identity == nil {
		t.Fatal("wrong browser consumed the legitimate ticket", err)
	}
	if result, err := sqliteTicketRedeem(t, provider, request, ticket, cookie); result != nil || !errors.Is(err, tickets.ErrDenied) {
		t.Fatal("single-use ticket replay accepted", err)
	}
}

func TestTicketInvalidDeclarationBeforeConstruction(t *testing.T) {
	module := sqliteTicketTestConfig(t)
	module.PublicOrigin = ""
	if err := module.Validate(); err == nil {
		t.Fatal("invalid native declaration accepted")
	}
	if value, err := module.IdentityProviderConfig(); value != nil || err == nil {
		t.Fatal("invalid declaration published metadata", err)
	}
	if value, err := module.NewIdentityProvider(t.Context()); value != nil || err == nil {
		t.Fatal("invalid declaration published runtime", err)
	}
	if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
		t.Fatal("invalid declaration touched storage")
	}
}

func TestTicketNilDeclaration(t *testing.T) {
	var module *companion.SQLiteTicketIdentityProvider
	if config, err := module.BackendConfig(); err == nil || config != nil {
		t.Fatal("nil declaration published backend configuration", err)
	}
	if err := module.Validate(); err == nil {
		t.Fatal("nil declaration passed validation")
	}
	if config, err := module.IdentityProviderConfig(); err == nil || config != nil {
		t.Fatal("nil declaration published provider metadata", err)
	}
	if provider, err := module.NewIdentityProvider(t.Context()); err == nil || provider != nil {
		t.Fatal("nil declaration published a provider", err)
	}
}
