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

package sqlite

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
	sqliteparser "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite/parser"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// SQLiteSecretsManager binds one pre-provisioned record to a Caddy manager ID.
// All fields are literal configuration; payloads never enter declarative JSON.
// Provision reads one coherent object, closes its database handle, and keeps an
// immutable snapshot for this candidate's resolution. HTTP consumers retain
// their resolved values until explicitly replaced by a successful Caddy reload.
type SQLiteSecretsManager struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Record   string `json:"record"`
	Timeout  string `json:"timeout,omitempty"`
	mu       sync.RWMutex
	values   map[string]any
	metadata map[string]any
	closed   bool
}

// SQLiteStoragePath reports the declarative opening path without storage I/O.
func (m *SQLiteSecretsManager) SQLiteStoragePath() string {
	if m == nil {
		return ""
	}
	return m.Path
}

func init() { caddy.RegisterModule(&SQLiteSecretsManager{}) }

// CaddyModule returns the bundled secrets adapter's registration.
func (*SQLiteSecretsManager) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.secrets.sqlite", New: func() caddy.Module { return new(SQLiteSecretsManager) }}
}

// BackendConfig returns a detached, validated configuration for host admission.
func (m *SQLiteSecretsManager) BackendConfig() (*sqlite.Config, error) {
	c := &sqlite.Config{Name: m.Name, Path: m.Path, Record: m.Record, Timeout: m.Timeout}
	if strings.Contains(c.Name, ":") {
		return nil, fmt.Errorf("SQLite secrets name cannot contain a colon")
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite secrets configuration")
	}
	return c, nil
}

// Validate performs no filesystem access or secret retrieval.
func (m *SQLiteSecretsManager) Validate() error { _, err := m.BackendConfig(); return err }

// UnmarshalCaddyfile parses a single flat block:
//
//	secrets sqlite <manager-id> {
//	    path <absolute-private-database-file>
//	    record <exact-record-name>
//	    timeout <duration>
//	}
//
// The header supplies the upstream name; it cannot be repeated in the body.
// Path and record are required once. Timeout defaults to 1s, within 1ms–30s.
// The public SQLite parser owns validation; parsing never opens a database.
// Lookups use secrets:<manager-id>:<literal-top-level-key>. Runtime environment
// and secret expansion are not supported in backend fields. Provision records
// separately with security secrets put; reload explicitly to adopt new values.
func (m *SQLiteSecretsManager) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// The root dispatcher has consumed `secrets sqlite`; Caddy passes a new
	// segment beginning at the manager ID, followed by its owned block.
	if !d.Next() {
		return d.Errf("expected SQLite secrets manager id")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := caddyfileutil.ReadFlatBlock(d, "SQLite secrets")
	if err != nil {
		return err
	}
	statements := []string{caddyfileutil.EncodeDirective([]string{"name", name})}
	for _, tokens := range body {
		statements = append(statements, caddyfileutil.EncodeDirective(tokens))
	}
	c, err := sqliteparser.NewSQLiteSecretsConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite secrets configuration")
	}
	m.Name, m.Path, m.Record, m.Timeout = c.Name, c.Path, c.Record, c.Timeout
	return m.Validate()
}

// Provision fetches one record for all related references. No database handle
// survives this call, including failure. Module cleanup only discards the private
// snapshot; it cannot close a resource borrowed by the running AuthCrunch root.
func (m *SQLiteSecretsManager) Provision(ctx caddy.Context) error {
	return m.provision(ctx, func(ctx context.Context, cfg *sqlite.Config) (secretSnapshotClient, error) {
		return sqlite.New(ctx, cfg)
	})
}

// A candidate owns this short-lived client until Close completes. Keeping the
// opener per call permits failure qualification without a global factory hook.
type secretSnapshotClient interface {
	GetSecrets(context.Context) (map[string]any, error)
	GetConfig() map[string]any
	Close() error
}

func (m *SQLiteSecretsManager) provision(ctx context.Context, openClient func(context.Context, *sqlite.Config) (secretSnapshotClient, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.values != nil {
		return fmt.Errorf("SQLite secrets instance cannot be reprovisioned")
	}
	c, err := m.BackendConfig()
	if err != nil {
		return err
	}
	// Ordinary configuration consumes an existing database. Only the explicit
	// trusted provisioning command may create a new one. The library still owns
	// file identity, permissions, schema and transaction checks on the open handle.
	if info, err := os.Lstat(c.Path); err != nil || !info.Mode().IsRegular() {
		return sqlite.ErrUnavailable
	}
	client, err := openClient(ctx, c)
	if err != nil {
		return sqlite.ErrUnavailable
	}
	values, lookupErr := client.GetSecrets(ctx)
	closeErr := client.Close()
	if lookupErr != nil || closeErr != nil {
		return sqlite.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.values = values
	m.metadata = client.GetConfig()
	m.metadata["id"] = c.Name // Existing host plugin.SecretsManager lookup contract.
	return nil
}

// GetConfig returns detached allowlisted metadata, never paths or payloads.
func (m *SQLiteSecretsManager) GetConfig(context.Context) map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.metadata == nil {
		return map[string]any{"id": m.Name, "name": m.Name, "kind": "sqlite", "record": m.Record}
	}
	return cloneSQLiteSecretValue(m.metadata).(map[string]any)
}

// GetSecret returns a detached, type-preserving copy of this candidate's record.
func (m *SQLiteSecretsManager) GetSecret(ctx context.Context) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.closed || m.values == nil {
		return nil, sqlite.ErrUnavailable
	}
	return cloneSQLiteSecretValue(m.values).(map[string]any), nil
}

// GetSecretByKey selects an exact key. Present null remains distinct from a
// missing key; the host rejects non-string consumer values without coercion.
// Empty strings are not usable credentials. Dots do not imply JSON traversal.
func (m *SQLiteSecretsManager) GetSecretByKey(ctx context.Context, key string) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.closed || m.values == nil {
		return nil, sqlite.ErrUnavailable
	}
	v, ok := m.values[key]
	if !ok {
		return nil, sqlite.ErrNotFound
	}
	if s, ok := v.(string); ok && s == "" {
		return nil, sqlite.ErrInvalid
	}
	return cloneSQLiteSecretValue(v), nil
}

// Cleanup waits for snapshot readers and discards their private data. It is
// idempotent, and no database access is needed during Caddy retirement.
func (m *SQLiteSecretsManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.values = nil
	return nil
}

// SQLite's public decoder yields only JSON values; immutable scalar values
// (including json.Number) retain their exact representation without remarshal.
func cloneSQLiteSecretValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		c := make(map[string]any, len(v))
		for k, entry := range v {
			c[k] = cloneSQLiteSecretValue(entry)
		}
		return c
	case []any:
		c := make([]any, len(v))
		for i, entry := range v {
			c[i] = cloneSQLiteSecretValue(entry)
		}
		return c
	default:
		return value
	}
}

var (
	_ caddy.Module          = (*SQLiteSecretsManager)(nil)
	_ caddy.Provisioner     = (*SQLiteSecretsManager)(nil)
	_ caddy.Validator       = (*SQLiteSecretsManager)(nil)
	_ caddy.CleanerUpper    = (*SQLiteSecretsManager)(nil)
	_ caddyfile.Unmarshaler = (*SQLiteSecretsManager)(nil)
	_ plugin.SecretsManager = (*SQLiteSecretsManager)(nil)
)
