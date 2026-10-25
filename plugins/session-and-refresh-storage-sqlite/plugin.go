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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	refreshsqlite "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
	refreshparser "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite/parser"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// SQLiteRefreshStore declares a private local refresh database. Validation and
// preparation perform no I/O; every runtime construction transfers a distinct
// owned connection to the app. Module Cleanup never owns those connections.
type SQLiteRefreshStore struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	MaxSessions  int    `json:"max_sessions,omitempty"`
	MaxRotations int    `json:"max_rotations,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
}

func init() { caddy.RegisterModule(SQLiteRefreshStore{}) }

// CaddyModule registers named SQLite refresh storage declarations.
func (SQLiteRefreshStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.sqlite", New: func() caddy.Module { return new(SQLiteRefreshStore) }}
}
func (m *SQLiteRefreshStore) config() (*refreshsqlite.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid SQLite refresh storage configuration")
	}
	cfg := &refreshsqlite.Config{Path: m.Path, MaxSessions: m.MaxSessions, MaxRotations: m.MaxRotations, Timeout: m.Timeout}
	if cfg.Validate() != nil {
		return nil, fmt.Errorf("invalid SQLite refresh storage configuration")
	}
	if _, err := tokenrefresh.NewExternalStoreConfig(m.Name, "sqlite", cfg.MaxSessions, cfg.MaxRotations, cfg); err != nil {
		return nil, fmt.Errorf("invalid SQLite refresh storage name")
	}
	return cfg, nil
}

// Validate delegates pure backend normalization on a detached configuration.
func (m *SQLiteRefreshStore) Validate() error { _, err := m.config(); return err }

// PrepareRefreshStore captures normalized literal fields in an immutable factory.
func (m *SQLiteRefreshStore) PrepareRefreshStore() (plugin.RefreshStoreFactory, error) {
	return m.prepareRefreshStore(tokenrefresh.NewExternalStoreConfig)
}

// Descriptor construction is part of preparation; failure cannot publish a
// factory with unbound storage limits or configuration. Dependencies are per call.
func (m *SQLiteRefreshStore) prepareRefreshStore(describe func(string, string, int, int, any) (*tokenrefresh.ExternalStoreConfig, error)) (plugin.RefreshStoreFactory, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	descriptor, err := describe(m.Name, "sqlite", cfg.MaxSessions, cfg.MaxRotations, cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid SQLite refresh storage configuration")
	}
	return &Factory{config: *cfg, descriptor: *descriptor}, nil
}

// Factory captures normalized configuration for deferred runtime construction.
type Factory struct {
	config     refreshsqlite.Config
	descriptor tokenrefresh.ExternalStoreConfig
}

// SQLiteConfig preserves the original normalized opening path, not a later
// canonical alias. Host preflight inspects this detached copy before New.
func (f *Factory) SQLiteConfig() refreshsqlite.Config { return f.config }
func (f *Factory) RefreshStoreConfig() (tokenrefresh.ExternalStoreConfig, error) {
	if f == nil {
		return tokenrefresh.ExternalStoreConfig{}, fmt.Errorf("SQLite refresh storage factory is unavailable")
	}
	return f.descriptor, nil
}
func (f *Factory) NewRefreshStore(ctx context.Context) (tokenrefresh.ManagedStore, error) {
	if f == nil {
		return nil, tokenrefresh.ErrUnavailable
	}
	cfg := f.config
	store, err := refreshsqlite.New(ctx, &cfg)
	if err != nil {
		return nil, err
	}
	return store, nil
}

// UnmarshalCaddyfile delegates the complete flat backend body to its public
// parser. All fields are literal, apart from Caddy lexical environment expansion.
//
//	token refresh store sqlite <name> {
//	    path <absolute-private-file>
//	    max sessions <count>
//	    max rotations <count>
//	    timeout <duration>
//	}
//
// The parent directory must exist and be private at runtime. Defaults are 10000
// families, 1024 rotations and 1s. Limits apply to the whole file and must agree
// across clients. Each selecting portal must use equal limits and persistent
// root state. This local transactional backend does not provide distributed HA.
func (m *SQLiteRefreshStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected refresh storage name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := caddyfileutil.ReadFlatBlock(d, "refresh storage")
	if err != nil {
		return err
	}
	statements := make([]string, 0, len(body))
	for _, args := range body {
		statements = append(statements, caddyfileutil.EncodeDirective(args))
	}
	cfg, err := refreshparser.NewSQLiteRefreshStorageConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite refresh storage configuration")
	}
	candidate := &SQLiteRefreshStore{Name: name, Path: cfg.Path, MaxSessions: cfg.MaxSessions, MaxRotations: cfg.MaxRotations, Timeout: cfg.Timeout}
	if candidate.Validate() != nil {
		return d.Errf("invalid SQLite refresh storage configuration")
	}
	*m = *candidate
	return nil
}

var (
	_ caddy.Module                     = (*SQLiteRefreshStore)(nil)
	_ caddy.Validator                  = (*SQLiteRefreshStore)(nil)
	_ caddyfile.Unmarshaler            = (*SQLiteRefreshStore)(nil)
	_ plugin.RefreshStoreBackendModule = (*SQLiteRefreshStore)(nil)
	_ plugin.RefreshStoreFactory       = (*Factory)(nil)
)
