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

// Package consul provides shared password accounts through Caddy's Consul storage.
package consul

import (
	"context"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulIdentityStore declares a named, bounded password-account store.
type ConsulIdentityStore struct {
	Name            string `json:"name"`
	Realm           string `json:"realm"`
	Prefix          string `json:"prefix,omitempty"`
	Timeout         string `json:"timeout,omitempty"`
	Capacity        int    `json:"capacity,omitempty"`
	binding         *consulstate.Binding
	prepared        *ConsulIdentityStore
	preparedBinding *consulstate.Binding
}

// New opens a separate trusted application/administration handle using borrowed
// Caddy Consul storage. The caller closes the returned handle after its calls drain.
func New(ctx context.Context, config *ConsulIdentityStore, storage *storageconsul.ConsulStorage) (*Store, error) {
	if config == nil {
		return nil, consulstate.ErrInvalid
	}
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	c.binding, err = consulstate.Capture(storage)
	if err != nil {
		return nil, err
	}
	if _, err := c.IdentityStoreConfig(); err != nil {
		return nil, err
	}
	runtime, err := c.NewIdentityStore(ctx)
	if err != nil {
		return nil, err
	}
	return runtime.(*Store), nil
}

func init() { caddy.RegisterModule(ConsulIdentityStore{}) }

// CaddyModule registers the companion Caddy module.
func (ConsulIdentityStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_stores.consul", New: func() caddy.Module { return new(ConsulIdentityStore) }}
}
func (m *ConsulIdentityStore) normalized() (ConsulIdentityStore, error) {
	if m == nil {
		return ConsulIdentityStore{}, consulstate.ErrInvalid
	}
	c := *m
	c.binding = nil
	c.prepared = nil
	c.preparedBinding = nil
	var err error
	c.Prefix, c.Timeout, err = consulstate.Normalize(c.Name, c.Prefix, c.Timeout, "security/identities")
	if c.Capacity == 0 {
		c.Capacity = 1000
	}
	if err != nil || !consulstate.ValidText(c.Realm, 128) || c.Capacity < 1 || c.Capacity > 10000 {
		return c, consulstate.ErrInvalid
	}
	return c, nil
}

// Validate checks detached literal configuration without accessing Consul.
func (m *ConsulIdentityStore) Validate() error { _, err := m.normalized(); return err }

// Provision captures Caddy-owned storage without opening a logical runtime handle.
func (m *ConsulIdentityStore) Provision(ctx caddy.Context) error {
	b, err := consulstate.Bind(ctx)
	m.binding = b
	return err
}

// IdentityStoreConfig freezes normalized configuration for the root descriptor and factory.
func (m *ConsulIdentityStore) IdentityStoreConfig() (*ids.ExternalIdentityStoreConfig, error) {
	c, err := m.normalized()
	if err != nil {
		return nil, err
	}
	identity := ""
	if m.binding != nil {
		identity = m.binding.Identity
	}
	descriptor, err := ids.NewExternalIdentityStoreConfig(c.Name, "consul", c.Realm, struct {
		Config  ConsulIdentityStore
		Storage string
	}{c, identity})
	if err == nil {
		m.prepared = &c
		m.preparedBinding = m.binding
	}
	return descriptor, err
}

// NewIdentityStore transfers a new logical password-store handle to the app.
func (m *ConsulIdentityStore) NewIdentityStore(ctx context.Context) (ids.IdentityStore, error) {
	if m == nil || m.prepared == nil {
		return nil, consulstate.ErrUnavailable
	}
	c := *m.prepared
	handle, err := m.preparedBinding.Open("identity-stores", c.Name, c.Prefix, c.Timeout)
	if err != nil {
		return nil, err
	}
	s := &Store{config: c, handle: handle}
	if err := s.check(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return s, nil
}

// UnmarshalCaddyfile parses identity store consul NAME { realm REALM; prefix
// PREFIX; timeout DURATION; capacity COUNT }. Realm is required. Settings occur
// once, with literal values. Defaults: security/identities, 3s and 1000 accounts.
// Capacity is 1..10000; the complete encrypted document is also bounded to 384 KiB.
// Password authentication and administration are supported; local MFA is separate.
func (m *ConsulIdentityStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	name, body, err := consulstate.Parse(d)
	if err != nil {
		return err
	}
	c := ConsulIdentityStore{Name: name}
	seen := map[string]bool{}
	for _, args := range body {
		if len(args) != 2 || seen[args[0]] || args[1] == "" {
			return d.Errf("invalid Consul identity store setting")
		}
		seen[args[0]] = true
		switch args[0] {
		case "realm":
			c.Realm = args[1]
		case "prefix":
			c.Prefix = args[1]
		case "timeout":
			c.Timeout = args[1]
		case "capacity":
			c.Capacity, err = strconv.Atoi(args[1])
			if err != nil || c.Capacity < 1 {
				return d.Errf("invalid Consul identity store capacity")
			}
		default:
			return d.Errf("unknown Consul identity store setting")
		}
	}
	c, err = c.normalized()
	if err != nil {
		return d.Errf("invalid Consul identity store configuration")
	}
	*m = c
	return nil
}

var (
	_ caddy.Module                      = (*ConsulIdentityStore)(nil)
	_ caddy.Provisioner                 = (*ConsulIdentityStore)(nil)
	_ caddy.Validator                   = (*ConsulIdentityStore)(nil)
	_ caddyfile.Unmarshaler             = (*ConsulIdentityStore)(nil)
	_ plugin.IdentityStoreBackendModule = (*ConsulIdentityStore)(nil)
)
