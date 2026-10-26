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

// Package consul provides fresh API-key authentication using Caddy's Consul storage.
package consul

import (
	"context"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulCredentialAuthenticator declares a named realm-bound API-key backend.
// Configuration never contains API keys; trusted callers provision them separately.
type ConsulCredentialAuthenticator struct {
	Name     string `json:"name"`
	Realm    string `json:"realm"`
	Prefix   string `json:"prefix,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
	binding  *consulstate.Binding
	prepared *ConsulCredentialAuthenticator
}

func init() { caddy.RegisterModule(ConsulCredentialAuthenticator{}) }

// CaddyModule registers the bundled Consul API-key factory.
func (ConsulCredentialAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.credential_authenticators.consul", New: func() caddy.Module { return new(ConsulCredentialAuthenticator) }}
}
func (m *ConsulCredentialAuthenticator) normalized() (ConsulCredentialAuthenticator, error) {
	if m == nil {
		return ConsulCredentialAuthenticator{}, consulstate.ErrInvalid
	}
	c := *m
	c.binding = nil
	c.prepared = nil
	var err error
	c.Prefix, c.Timeout, err = consulstate.Normalize(c.Name, c.Prefix, c.Timeout, "security/credentials")
	if c.Capacity == 0 {
		c.Capacity = 1000
	}
	if err != nil || !consulstate.ValidText(c.Realm, 256) || strings.HasPrefix(c.Name, "http://") || strings.HasPrefix(c.Name, "https://") || c.Capacity < 1 || c.Capacity > 10000 {
		return c, consulstate.ErrInvalid
	}
	return c, nil
}

// Validate checks detached literal configuration without storage access.
func (m *ConsulCredentialAuthenticator) Validate() error { _, err := m.normalized(); return err }

// Provision captures a frozen configuration and Caddy-owned Consul resources.
func (m *ConsulCredentialAuthenticator) Provision(ctx caddy.Context) error {
	c, err := m.normalized()
	if err != nil {
		return err
	}
	b, err := consulstate.Bind(ctx)
	if err != nil {
		return err
	}
	m.binding = b
	m.prepared = &c
	return nil
}

// CredentialIdentity returns the exact name and realm used for policy binding.
func (m *ConsulCredentialAuthenticator) CredentialIdentity() (string, string) {
	if m.prepared != nil {
		return m.prepared.Name, m.prepared.Realm
	}
	return m.Name, m.Realm
}

// NewCredentialAuthenticator transfers a fresh logical runtime handle to the app.
// The module never owns or closes it after construction.
func (m *ConsulCredentialAuthenticator) NewCredentialAuthenticator(ctx context.Context) (plugin.CredentialAuthenticator, error) {
	if m == nil || m.prepared == nil {
		return nil, consulstate.ErrUnavailable
	}
	return open(ctx, *m.prepared, m.binding)
}

// New opens an independent trusted administration handle using borrowed Caddy
// storage. Call Issue/Revoke only through an authorized application; no HTTP or
// CLI issuance endpoint is installed. The caller closes the logical handle.
func New(ctx context.Context, config *ConsulCredentialAuthenticator, storage *storageconsul.ConsulStorage) (*Authenticator, error) {
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	b, err := consulstate.Capture(storage)
	if err != nil {
		return nil, err
	}
	return open(ctx, c, b)
}
func open(ctx context.Context, c ConsulCredentialAuthenticator, b *consulstate.Binding) (*Authenticator, error) {
	handle, err := b.Open("credential-authenticators", c.Name, c.Prefix, c.Timeout)
	if err != nil {
		return nil, err
	}
	a := &Authenticator{config: c, handle: handle}
	if err := a.check(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return a, nil
}

// UnmarshalCaddyfile parses a named factory inside security:
//
//	credential authenticator consul <name> {
//	    realm <realm>
//	    prefix <relative-prefix>
//	    timeout <duration>
//	    capacity <count>
//	}
//
// Realm is required; every setting occurs once with one literal argument.
// Defaults are security/credentials, 3s and 1000 keys. Timeout is 1ms..30s;
// capacity is 1..10000, also bounded by the shared 384 KiB document ceiling.
// Select with `with api key auth portal <name> realm <realm>` in a policy.
// Basic authentication and unused or mismatched policy bindings are rejected.
func (m *ConsulCredentialAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	name, body, err := consulstate.Parse(d)
	if err != nil {
		return err
	}
	c := ConsulCredentialAuthenticator{Name: name}
	seen := map[string]bool{}
	for _, args := range body {
		if len(args) != 2 || args[1] == "" || seen[args[0]] {
			return d.Errf("invalid Consul credential setting")
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
				return d.Errf("invalid Consul credential capacity")
			}
		default:
			return d.Errf("unknown Consul credential setting")
		}
	}
	c, err = c.normalized()
	if err != nil {
		return d.Errf("invalid Consul credential configuration")
	}
	*m = c
	return nil
}

var (
	_ caddy.Module                                = (*ConsulCredentialAuthenticator)(nil)
	_ caddy.Provisioner                           = (*ConsulCredentialAuthenticator)(nil)
	_ caddy.Validator                             = (*ConsulCredentialAuthenticator)(nil)
	_ caddyfile.Unmarshaler                       = (*ConsulCredentialAuthenticator)(nil)
	_ plugin.CredentialAuthenticatorBackendModule = (*ConsulCredentialAuthenticator)(nil)
)
