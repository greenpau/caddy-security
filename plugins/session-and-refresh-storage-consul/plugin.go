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

// Package consul supplies transactional refresh families using Caddy's Consul client.
package consul

import (
	"context"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulRefreshStore declares named managed refresh storage. Root state still owns
// configuration generations; this module does not distribute portal sandboxes.
type ConsulRefreshStore struct {
	Name         string `json:"name"`
	Prefix       string `json:"prefix,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
	MaxSessions  int    `json:"max_sessions,omitempty"`
	MaxRotations int    `json:"max_rotations,omitempty"`
	binding      *consulstate.Binding
}

func init() { caddy.RegisterModule(ConsulRefreshStore{}) }

// CaddyModule registers the companion Caddy module.
func (ConsulRefreshStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.consul", New: func() caddy.Module { return new(ConsulRefreshStore) }}
}
func (m *ConsulRefreshStore) normalized() (ConsulRefreshStore, error) {
	if m == nil {
		return ConsulRefreshStore{}, consulstate.ErrInvalid
	}
	c := *m
	c.binding = nil
	var err error
	c.Prefix, c.Timeout, err = consulstate.Normalize(c.Name, c.Prefix, c.Timeout, "security/refresh")
	if c.MaxSessions == 0 {
		c.MaxSessions = 1000
	}
	if c.MaxRotations == 0 {
		c.MaxRotations = 128
	}
	if err != nil || c.MaxSessions < 1 || c.MaxSessions > 10000 || c.MaxRotations < 1 || c.MaxRotations > 10000 {
		return c, consulstate.ErrInvalid
	}
	return c, nil
}

// Validate checks detached literal configuration without accessing Consul.
func (m *ConsulRefreshStore) Validate() error { _, err := m.normalized(); return err }

// Provision captures Caddy-owned storage without opening a logical runtime handle.
func (m *ConsulRefreshStore) Provision(ctx caddy.Context) error {
	b, err := consulstate.Bind(ctx)
	m.binding = b
	return err
}

type factory struct {
	config     ConsulRefreshStore
	descriptor tokenrefresh.ExternalStoreConfig
	binding    *consulstate.Binding
}

// PrepareRefreshStore captures immutable configuration and borrowed storage in a factory.
func (m *ConsulRefreshStore) PrepareRefreshStore() (plugin.RefreshStoreFactory, error) {
	c, err := m.normalized()
	if err != nil {
		return nil, err
	}
	if m.binding == nil {
		return nil, consulstate.ErrUnavailable
	}
	descriptor, err := tokenrefresh.NewExternalStoreConfig(c.Name, "consul", c.MaxSessions, c.MaxRotations, struct {
		Config  ConsulRefreshStore
		Storage string
	}{c, m.binding.Identity})
	if err != nil {
		return nil, err
	}
	return &factory{config: c, descriptor: *descriptor, binding: m.binding}, nil
}

// RefreshStoreConfig returns copied descriptor metadata.
func (f *factory) RefreshStoreConfig() (tokenrefresh.ExternalStoreConfig, error) {
	return f.descriptor, nil
}

// NewRefreshStore transfers a new logical managed-store handle to the app.
func (f *factory) NewRefreshStore(ctx context.Context) (tokenrefresh.ManagedStore, error) {
	handle, err := f.binding.Open("refresh-stores", f.config.Name, f.config.Prefix, f.config.Timeout)
	if err != nil {
		return nil, err
	}
	s := &Store{config: f.config, descriptor: f.descriptor, handle: handle}
	if err := s.CheckReady(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return s, nil
}

// UnmarshalCaddyfile parses token refresh store consul NAME with an optional flat
// block: prefix PREFIX, timeout DURATION, max sessions COUNT, max rotations COUNT.
// Settings occur once and are literal. Defaults: security/refresh, 3s, 1000 families
// and 128 rotations. Limits are 1..10000 plus a 384 KiB total document ceiling.
// Selected portals must use equal limits, enabled refresh and persistent root state.
func (m *ConsulRefreshStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	name, body, err := consulstate.Parse(d)
	if err != nil {
		return err
	}
	c := ConsulRefreshStore{Name: name}
	seen := map[string]bool{}
	for _, args := range body {
		if len(args) < 2 {
			return d.ArgErr()
		}
		key := args[0]
		value := args[len(args)-1]
		if key == "max" && len(args) == 3 {
			key = strings.Join(args[:2], " ")
		} else if len(args) != 2 {
			return d.ArgErr()
		}
		if seen[key] || value == "" {
			return d.Errf("duplicate or empty Consul refresh setting")
		}
		seen[key] = true
		switch key {
		case "prefix":
			c.Prefix = value
		case "timeout":
			c.Timeout = value
		case "max sessions", "max rotations":
			n, e := strconv.Atoi(value)
			if e != nil || n < 1 {
				return d.Errf("invalid Consul refresh limit")
			}
			if key == "max sessions" {
				c.MaxSessions = n
			} else {
				c.MaxRotations = n
			}
		default:
			return d.Errf("unknown Consul refresh setting")
		}
	}
	c, err = c.normalized()
	if err != nil {
		return d.Errf("invalid Consul refresh configuration")
	}
	*m = c
	return nil
}

var (
	_ caddy.Module                     = (*ConsulRefreshStore)(nil)
	_ caddy.Provisioner                = (*ConsulRefreshStore)(nil)
	_ caddy.Validator                  = (*ConsulRefreshStore)(nil)
	_ caddyfile.Unmarshaler            = (*ConsulRefreshStore)(nil)
	_ plugin.RefreshStoreBackendModule = (*ConsulRefreshStore)(nil)
	_ plugin.RefreshStoreFactory       = (*factory)(nil)
)
