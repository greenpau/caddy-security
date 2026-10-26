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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	identityparser "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// SQLiteIdentityStore is a configuration-only factory for password accounts.
// The app owns the opened database and lends it to its selected portals.
type SQLiteIdentityStore struct {
	Name    string `json:"name"`
	Realm   string `json:"realm"`
	Path    string `json:"path"`
	Timeout string `json:"timeout,omitempty"`
}

// SQLiteStoragePath reports the declarative opening path without storage I/O.
func (m *SQLiteIdentityStore) SQLiteStoragePath() string {
	if m == nil {
		return ""
	}
	return m.Path
}

func init() { caddy.RegisterModule(SQLiteIdentityStore{}) }

// CaddyModule registers the SQLite identity-store configuration module.
func (SQLiteIdentityStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_stores.sqlite", New: func() caddy.Module { return new(SQLiteIdentityStore) }}
}

// BackendConfig returns a detached, validated configuration for host admission.
func (m *SQLiteIdentityStore) BackendConfig() (*identitysqlite.Config, error) {
	cfg := &identitysqlite.Config{Name: m.Name, Realm: m.Realm, Path: m.Path, Timeout: m.Timeout}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite identity store configuration")
	}
	// Equivalent timeout spellings must not retire persistent sessions merely
	// because their textual representation differs.
	duration, _ := time.ParseDuration(cfg.Timeout) // Validate checks the duration.
	cfg.Timeout = duration.String()
	return cfg, nil
}

// Validate checks literal configuration without touching storage.
func (m *SQLiteIdentityStore) Validate() error { _, err := m.BackendConfig(); return err }

// IdentityStoreConfig binds the true backend kind and normalized configuration.
func (m *SQLiteIdentityStore) IdentityStoreConfig() (*ids.ExternalIdentityStoreConfig, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return nil, err
	}
	return ids.NewExternalIdentityStoreConfig(cfg.Name, "sqlite", cfg.Realm, cfg)
}

// NewIdentityStore opens existing private storage. Trusted offline provisioning
// creates accounts; ordinary app construction never creates an empty database.
func (m *SQLiteIdentityStore) NewIdentityStore(ctx context.Context) (ids.IdentityStore, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(cfg.Path); err != nil || !info.Mode().IsRegular() {
		return nil, identitysqlite.ErrUnavailable
	}
	store, err := identitysqlite.New(ctx, cfg)
	if err != nil {
		return nil, identitysqlite.ErrUnavailable
	}
	return store, nil
}

// UnmarshalCaddyfile parses a named global declaration:
//
//	identity store sqlite <name> {
//	    realm <realm>
//	    path <absolute-private-database-file>
//	    timeout <duration>
//	}
//
// The header supplies name; the public parser accepts one realm, path and
// optional timeout (default 1s, range 1ms through 30s). Fields are literal.
// Select the name with `enable identity store <name>` inside a portal.
// This password-only backend cannot satisfy MFA or local-only OP/profile uses.
func (m *SQLiteIdentityStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected identity store name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := caddyfileutil.ReadFlatBlock(d, "identity store")
	if err != nil {
		return err
	}
	statements := []string{caddyfileutil.EncodeDirective([]string{"name", name})}
	for _, args := range body {
		statements = append(statements, caddyfileutil.EncodeDirective(args))
	}
	cfg, err := identityparser.NewSQLiteIdentityStoreConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite identity store configuration")
	}
	m.Name, m.Realm, m.Path, m.Timeout = cfg.Name, cfg.Realm, cfg.Path, cfg.Timeout
	return m.Validate()
}

var (
	_ caddy.Module                      = (*SQLiteIdentityStore)(nil)
	_ caddy.Validator                   = (*SQLiteIdentityStore)(nil)
	_ caddyfile.Unmarshaler             = (*SQLiteIdentityStore)(nil)
	_ plugin.IdentityStoreBackendModule = (*SQLiteIdentityStore)(nil)
)
