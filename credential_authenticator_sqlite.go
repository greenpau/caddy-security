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

package security

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"
	credentialparser "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite/parser"
)

// SQLiteCredentialAuthenticator is a configuration-only Caddy factory. Runtime
// database handles belong to the app, independently of module context cleanup.
type SQLiteCredentialAuthenticator struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Realm   string `json:"realm"`
	Timeout string `json:"timeout,omitempty"`
}

func init() { caddy.RegisterModule(SQLiteCredentialAuthenticator{}) }

// CaddyModule registers the bundled, API-key-only SQLite factory.
func (SQLiteCredentialAuthenticator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.credential_authenticators.sqlite", New: func() caddy.Module { return new(SQLiteCredentialAuthenticator) }}
}

func (m *SQLiteCredentialAuthenticator) config() (*credentials.Config, error) {
	cfg := &credentials.Config{Name: m.Name, Path: m.Path, Realm: m.Realm, Timeout: m.Timeout}
	if err := cfg.Validate(); err != nil || strings.HasPrefix(cfg.Name, "http://") || strings.HasPrefix(cfg.Name, "https://") {
		return nil, fmt.Errorf("invalid SQLite credential authenticator configuration")
	}
	return cfg, nil
}

// Validate checks literal configuration without touching storage.
func (m *SQLiteCredentialAuthenticator) Validate() error { _, err := m.config(); return err }

// CredentialIdentity identifies the exact name and realm used in policy bindings.
func (m *SQLiteCredentialAuthenticator) CredentialIdentity() (string, string) { return m.Name, m.Realm }

// NewCredentialAuthenticator transfers a fresh handle to the app. Ordinary
// configuration consumes existing storage; trusted issuance may create it.
func (m *SQLiteCredentialAuthenticator) NewCredentialAuthenticator(ctx context.Context) (CredentialAuthenticator, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(cfg.Path); err != nil || !info.Mode().IsRegular() {
		return nil, credentials.ErrUnavailable
	}
	backend, err := credentials.New(ctx, cfg)
	if err != nil {
		return nil, credentials.ErrUnavailable
	}
	return backend, nil
}

// UnmarshalCaddyfile parses a named global declaration:
//
//	credential authenticator sqlite <name> {
//	    path <absolute-private-database-file>
//	    realm <realm>
//	    timeout <duration>
//	}
//
// Caddy passes the segment at <name>. The header supplies the upstream name;
// path and realm occur once, timeout defaults to 1s (1ms through 30s). The public
// parser owns validation. All fields are literal, and adaptation performs no I/O.
// Select it with `with api key auth portal <name> realm <realm>` in each policy.
// Basic bindings, portal/name collisions and mismatched realms are rejected.
func (m *SQLiteCredentialAuthenticator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected credential authenticator name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := readFlatDirectiveBlock(d, "credential authenticator")
	if err != nil {
		return err
	}
	statements := []string{encodeOAuthDirective([]string{"name", name})}
	for _, args := range body {
		statements = append(statements, encodeOAuthDirective(args))
	}
	cfg, err := credentialparser.NewSQLiteCredentialsConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite credential authenticator configuration")
	}
	m.Name, m.Path, m.Realm, m.Timeout = cfg.Name, cfg.Path, cfg.Realm, cfg.Timeout
	return m.Validate()
}

var (
	_ caddy.Module                         = (*SQLiteCredentialAuthenticator)(nil)
	_ caddy.Validator                      = (*SQLiteCredentialAuthenticator)(nil)
	_ caddyfile.Unmarshaler                = (*SQLiteCredentialAuthenticator)(nil)
	_ CredentialAuthenticatorBackendModule = (*SQLiteCredentialAuthenticator)(nil)
	_ CredentialAuthenticator              = (*credentials.Authenticator)(nil)
)
