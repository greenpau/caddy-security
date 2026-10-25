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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	loginsqlite "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
	loginparser "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite/parser"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// SQLiteOAuthLoginStore declares shared pending OAuth transactions. Preparing
// this module opens no files. Every prepared factory call transfers a separate
// connection to the app; module Cleanup never owns that runtime connection.
type SQLiteOAuthLoginStore struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Timeout  string `json:"timeout,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
}

func init() { caddy.RegisterModule(SQLiteOAuthLoginStore{}) }

// CaddyModule registers the SQLite OAuth login storage configuration module.
func (SQLiteOAuthLoginStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.oauth_login_stores.sqlite", New: func() caddy.Module { return new(SQLiteOAuthLoginStore) }}
}

func (m *SQLiteOAuthLoginStore) config() (*loginsqlite.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid SQLite OAuth login storage configuration")
	}
	// Use the public selector's identifier contract for the host-owned name.
	if err := (&oauth.LoginStoreConfig{Name: m.Name, Namespace: "caddy"}).Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite OAuth login storage name")
	}
	cfg := &loginsqlite.Config{Path: m.Path, Timeout: m.Timeout, Capacity: m.Capacity}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite OAuth login storage configuration")
	}
	duration, _ := time.ParseDuration(cfg.Timeout) // Public validation checks it.
	cfg.Timeout = duration.String()
	return cfg, nil
}

// Validate checks literal configuration without filesystem or network access.
func (m *SQLiteOAuthLoginStore) Validate() error { _, err := m.config(); return err }

// PrepareOAuthLoginStore captures normalized values in an independent factory.
// Later edits to this module cannot change the checked or opened database. The
// descriptor hash verifies host factory agreement, not the provider namespace.
func (m *SQLiteOAuthLoginStore) PrepareOAuthLoginStore() (plugin.OAuthLoginStoreFactory, error) {
	return m.prepareOAuthLoginStore(json.Marshal)
}

// Encoding failure must withhold both the descriptor and its runtime factory.
// The encoder belongs to this preparation call, never to mutable package state.
func (m *SQLiteOAuthLoginStore) prepareOAuthLoginStore(encode func(any) ([]byte, error)) (plugin.OAuthLoginStoreFactory, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	encoded, err := encode(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid SQLite OAuth login storage configuration")
	}
	digest := sha256.Sum256(encoded)
	descriptor := plugin.OAuthLoginStoreConfig{Name: m.Name, Driver: "sqlite", ConfigHash: hex.EncodeToString(digest[:])}
	return &Factory{config: *cfg, descriptor: descriptor}, nil
}

// Factory captures normalized configuration for deferred runtime construction.
type Factory struct {
	config     loginsqlite.Config
	descriptor plugin.OAuthLoginStoreConfig
}

// SQLiteConfig returns detached opening-path/capacity metadata to host preflight.
func (f *Factory) SQLiteConfig() loginsqlite.Config { return f.config }

func (f *Factory) OAuthLoginStoreConfig() (plugin.OAuthLoginStoreConfig, error) {
	if f == nil {
		return plugin.OAuthLoginStoreConfig{}, fmt.Errorf("SQLite OAuth login storage factory is unavailable")
	}
	return f.descriptor, nil
}

func (f *Factory) NewOAuthLoginStore(ctx context.Context) (plugin.OAuthLoginStore, error) {
	if f == nil {
		return nil, oauth.ErrLoginUnavailable
	}
	// The public constructor validates its own copy. Neither it nor the app
	// receives a pointer into the factory's immutable prepared configuration.
	cfg := f.config
	store, err := loginsqlite.New(ctx, &cfg)
	if err != nil {
		return nil, oauth.ErrLoginUnavailable
	}
	return &sqliteOAuthLoginStore{store: store, descriptor: f.descriptor}, nil
}

type sqliteOAuthLoginStore struct {
	store      *loginsqlite.Store
	descriptor plugin.OAuthLoginStoreConfig
	closed     atomic.Bool
}

func (s *sqliteOAuthLoginStore) available() bool {
	return s != nil && s.store != nil && !s.closed.Load()
}

func (s *sqliteOAuthLoginStore) OAuthLoginStoreConfig() (plugin.OAuthLoginStoreConfig, error) {
	if !s.available() {
		return plugin.OAuthLoginStoreConfig{}, oauth.ErrLoginUnavailable
	}
	return s.descriptor, nil
}

func (s *sqliteOAuthLoginStore) Create(ctx context.Context, namespace string, value oauth.LoginTransaction) error {
	if !s.available() {
		return oauth.ErrLoginUnavailable
	}
	return s.store.Create(ctx, namespace, value)
}

func (s *sqliteOAuthLoginStore) Claim(ctx context.Context, namespace, state string, binding oauth.LoginBinding, claim string) (oauth.LoginTransaction, error) {
	if !s.available() {
		return oauth.LoginTransaction{}, oauth.ErrLoginUnavailable
	}
	return s.store.Claim(ctx, namespace, state, binding, claim)
}

func (s *sqliteOAuthLoginStore) Get(ctx context.Context, namespace, state string) (oauth.LoginTransaction, error) {
	if !s.available() {
		return oauth.LoginTransaction{}, oauth.ErrLoginUnavailable
	}
	return s.store.Get(ctx, namespace, state)
}

func (s *sqliteOAuthLoginStore) Complete(ctx context.Context, namespace, state, claim string) error {
	if !s.available() {
		return oauth.ErrLoginUnavailable
	}
	return s.store.Complete(ctx, namespace, state, claim)
}

func (s *sqliteOAuthLoginStore) Cancel(ctx context.Context, namespace, state string, binding oauth.LoginBinding) (bool, error) {
	if !s.available() {
		return false, oauth.ErrLoginUnavailable
	}
	return s.store.Cancel(ctx, namespace, state, binding)
}

func (s *sqliteOAuthLoginStore) Close() error {
	if s == nil || s.store == nil || s.closed.Swap(true) {
		return nil
	}
	return s.store.Close()
}

// UnmarshalCaddyfile parses a named global backend:
//
//	oauth login store sqlite <name> {
//	    path <absolute-private-database-file>
//	    timeout <duration>
//	    capacity <count>
//	}
//
// The complete body delegates to the public SQLite parser. Path is required;
// timeout defaults to 1s (1ms..30s), capacity to 10000 (1..100000). Settings occur
// once and remain literal, apart from Caddy's lexical environment expansion.
// Capacity applies to the whole database and must agree across clients. This
// stores pending evidence, not completed sessions or account identities. Select
// it in an OAuth provider with login store <name> namespace <deployment-name>.
func (m *SQLiteOAuthLoginStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected OAuth login storage name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := caddyfileutil.ReadFlatBlock(d, "OAuth login storage")
	if err != nil {
		return err
	}
	statements := make([]string, 0, len(body))
	for _, args := range body {
		statements = append(statements, caddyfileutil.EncodeDirective(args))
	}
	cfg, err := loginparser.NewSQLiteOAuthLoginStoreConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite OAuth login storage configuration")
	}
	candidate := &SQLiteOAuthLoginStore{Name: name, Path: cfg.Path, Timeout: cfg.Timeout, Capacity: cfg.Capacity}
	cfg, err = candidate.config()
	if err != nil {
		return d.Errf("invalid SQLite OAuth login storage configuration")
	}
	m.Name, m.Path, m.Timeout, m.Capacity = name, cfg.Path, cfg.Timeout, cfg.Capacity
	return nil
}

var (
	_ caddy.Module                        = (*SQLiteOAuthLoginStore)(nil)
	_ caddy.Validator                     = (*SQLiteOAuthLoginStore)(nil)
	_ caddyfile.Unmarshaler               = (*SQLiteOAuthLoginStore)(nil)
	_ plugin.OAuthLoginStoreBackendModule = (*SQLiteOAuthLoginStore)(nil)
	_ plugin.OAuthLoginStoreFactory       = (*Factory)(nil)
	_ plugin.OAuthLoginStore              = (*sqliteOAuthLoginStore)(nil)
	_ io.Closer                           = (*sqliteOAuthLoginStore)(nil)
)
