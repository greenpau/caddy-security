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
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulSecretsManager reads one coherent secret record during provisioning and
// retains an immutable candidate snapshot. Consumers adopt writes only on reload.
// Secret values and client resources never enter declarative JSON.
type ConsulSecretsManager struct {
	Name     string `json:"name"`
	Record   string `json:"record"`
	Prefix   string `json:"prefix,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	mu       sync.RWMutex
	values   map[string]any
	metadata map[string]any
	closed   bool
}

func init() { caddy.RegisterModule(&ConsulSecretsManager{}) }

// CaddyModule registers the Consul secrets snapshot module.
func (*ConsulSecretsManager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.secrets.consul", New: func() caddy.Module { return new(ConsulSecretsManager) }}
}

// BackendConfig returns detached validated configuration without fetching secrets.
func (m *ConsulSecretsManager) BackendConfig() (*Config, error) {
	if m == nil {
		return nil, consulstate.ErrInvalid
	}
	c, err := (Config{Name: m.Name, Record: m.Record, Prefix: m.Prefix, Timeout: m.Timeout}).normalized()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks configuration without accessing Caddy storage or secret values.
func (m *ConsulSecretsManager) Validate() error { _, err := m.BackendConfig(); return err }

// Provision snapshots the complete selected record and closes its short-lived
// logical client before returning. Caddy retains ownership of the global client.
func (m *ConsulSecretsManager) Provision(ctx caddy.Context) error {
	b, err := consulstate.Bind(ctx)
	if err != nil {
		return err
	}
	return m.provision(ctx, b)
}
func (m *ConsulSecretsManager) provision(ctx context.Context, b *consulstate.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.values != nil {
		return errors.New("Consul secrets instance cannot be reprovisioned")
	}
	c, err := m.BackendConfig()
	if err != nil {
		return err
	}
	client, err := open(ctx, *c, b)
	if err != nil {
		return err
	}
	values, lookupErr := client.GetSecrets(ctx)
	closeErr := client.Close()
	if lookupErr != nil {
		return lookupErr
	}
	if closeErr != nil {
		return consulstate.ErrUnavailable
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.values = values
	m.metadata = client.GetConfig()
	m.metadata["id"] = c.Name
	return nil
}

// GetConfig returns detached allowlisted metadata, never secret values or key material.
func (m *ConsulSecretsManager) GetConfig(context.Context) map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.metadata == nil {
		return map[string]any{"id": m.Name, "name": m.Name, "kind": "consul", "record": m.Record}
	}
	return clone(m.metadata).(map[string]any)
}

// GetSecret returns a detached, type-preserving copy of the provisioned snapshot.
func (m *ConsulSecretsManager) GetSecret(ctx context.Context) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ctx == nil || m.closed || m.values == nil {
		return nil, consulstate.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return clone(m.values).(map[string]any), nil
}

// GetSecretByKey selects an exact top-level key. Present null differs from a
// missing key; empty strings fail and core consumers reject non-string values.
func (m *ConsulSecretsManager) GetSecretByKey(ctx context.Context, key string) (any, error) {
	values, err := m.GetSecret(ctx)
	if err != nil {
		return nil, err
	}
	v, ok := values[key]
	if !ok {
		return nil, ErrNotFound
	}
	if s, ok := v.(string); ok && s == "" {
		return nil, consulstate.ErrInvalid
	}
	return v, nil
}

// Cleanup retires only the candidate's snapshot, after its readers finish.
func (m *ConsulSecretsManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.values = nil
	return nil
}
func clone(value any) any {
	switch v := value.(type) {
	case map[string]any:
		c := make(map[string]any, len(v))
		for key, entry := range v {
			c[key] = clone(entry)
		}
		return c
	case []any:
		c := make([]any, len(v))
		for i, entry := range v {
			c[i] = clone(entry)
		}
		return c
	default:
		return value
	}
}

// UnmarshalCaddyfile parses a manager inside security:
//
//	secrets consul <manager-id> {
//	    record <exact-record-name>
//	    prefix <relative-prefix>
//	    timeout <duration>
//	}
//
// Record is required. Settings occur once with one literal argument. Defaults are
// security/secrets and 3s (1ms..30s). Manager IDs cannot contain colons. References
// use secrets:<manager-id>:<top-level-key>. Provision records separately with the
// trusted Go Client.Put API; this module installs no issuance CLI or HTTP endpoint.
// Provisioning must find a nonempty record; it never writes an empty fallback.
func (m *ConsulSecretsManager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	name, body, err := consulstate.Parse(d)
	if err != nil {
		return err
	}
	c := Config{Name: name}
	seen := map[string]bool{}
	for _, args := range body {
		if len(args) != 2 || args[1] == "" || seen[args[0]] {
			return d.Errf("invalid Consul secrets setting")
		}
		seen[args[0]] = true
		switch args[0] {
		case "record":
			c.Record = args[1]
		case "prefix":
			c.Prefix = args[1]
		case "timeout":
			c.Timeout = args[1]
		default:
			return d.Errf("unknown Consul secrets setting")
		}
	}
	c, err = c.normalized()
	if err != nil {
		return d.Errf("invalid Consul secrets configuration")
	}
	m.Name, m.Record, m.Prefix, m.Timeout = c.Name, c.Record, c.Prefix, c.Timeout
	return nil
}

var (
	_ caddy.Module          = (*ConsulSecretsManager)(nil)
	_ caddy.Provisioner     = (*ConsulSecretsManager)(nil)
	_ caddy.Validator       = (*ConsulSecretsManager)(nil)
	_ caddy.CleanerUpper    = (*ConsulSecretsManager)(nil)
	_ caddyfile.Unmarshaler = (*ConsulSecretsManager)(nil)
	_ plugin.SecretsManager = (*ConsulSecretsManager)(nil)
)
