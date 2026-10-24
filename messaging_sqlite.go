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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	messagingparser "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite/parser"
)

// SQLiteMessagingProvider prepares a durable outbox without opening storage.
// The app owns each returned queue and any worker using the named delivery
// provider. This configuration module never owns those runtime resources.
type SQLiteMessagingProvider struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Timeout  string `json:"timeout,omitempty"`
	Delivery string `json:"delivery,omitempty"`
}

func init() { caddy.RegisterModule(SQLiteMessagingProvider{}) }

// CaddyModule registers the SQLite messaging configuration module.
func (SQLiteMessagingProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.messaging.sqlite", New: func() caddy.Module { return new(SQLiteMessagingProvider) }}
}

func (m *SQLiteMessagingProvider) config() (*messagingsqlite.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid SQLite messaging configuration")
	}
	if m.Delivery != "" && (len(m.Delivery) > 128 || !utf8.ValidString(m.Delivery) || strings.TrimSpace(m.Delivery) != m.Delivery || strings.ContainsFunc(m.Delivery, unicode.IsControl)) {
		return nil, fmt.Errorf("invalid SQLite messaging delivery provider")
	}
	cfg := &messagingsqlite.Config{Name: m.Name, Path: m.Path, Timeout: m.Timeout}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite messaging configuration")
	}
	duration, _ := time.ParseDuration(cfg.Timeout) // Validate checks the duration.
	cfg.Timeout = duration.String()
	return cfg, nil
}

// Validate checks literal configuration without touching storage or transports.
func (m *SQLiteMessagingProvider) Validate() error { _, err := m.config(); return err }

// MessagingProviderName returns the validated logical queue name.
func (m *SQLiteMessagingProvider) MessagingProviderName() (string, error) {
	cfg, err := m.config()
	if err != nil {
		return "", err
	}
	return cfg.Name, nil
}

// NewMessagingProvider opens or creates a private queue in an existing private
// parent directory. Success from its Send method means durable acceptance;
// delivery and shutdown belong to the app, independently of this setup context.
func (m *SQLiteMessagingProvider) NewMessagingProvider(ctx context.Context) (messaging.Provider, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	outbox, err := messagingsqlite.New(ctx, cfg)
	if err != nil {
		return nil, messagingsqlite.ErrUnavailable
	}
	return outbox, nil
}

// UnmarshalCaddyfile parses a named global declaration:
//
//	messaging sqlite provider <name> {
//	    path <absolute-private-database-file>
//	    timeout <duration>
//	    delivery <email-provider-name>
//	}
//
// The header supplies name. The public parser owns required path and optional
// timeout (default 1s, range 1ms through 30s); each setting occurs once. All fields
// are literal. Optional delivery selects an existing email provider and starts
// an app-owned worker at Start. Omission only queues messages. SMTP credentials
// belong to that email provider and are never part of the queue configuration.
func (m *SQLiteMessagingProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected messaging provider name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := readFlatDirectiveBlock(d, "messaging provider")
	if err != nil {
		return err
	}
	statements := []string{encodeOAuthDirective([]string{"name", name})}
	var delivery string
	for _, args := range body {
		if args[0] == "delivery" {
			if len(args) != 2 || args[1] == "" || delivery != "" {
				return d.Errf("invalid SQLite messaging delivery provider")
			}
			delivery = args[1]
			continue
		}
		statements = append(statements, encodeOAuthDirective(args))
	}
	cfg, err := messagingparser.NewSQLiteMessagingConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite messaging configuration")
	}
	candidate := &SQLiteMessagingProvider{Name: cfg.Name, Path: cfg.Path, Timeout: cfg.Timeout, Delivery: delivery}
	cfg, err = candidate.config()
	if err != nil {
		return d.Errf("invalid SQLite messaging configuration")
	}
	m.Name, m.Path, m.Timeout, m.Delivery = cfg.Name, cfg.Path, cfg.Timeout, delivery
	return nil
}

var (
	_ caddy.Module                   = (*SQLiteMessagingProvider)(nil)
	_ caddy.Validator                = (*SQLiteMessagingProvider)(nil)
	_ caddyfile.Unmarshaler          = (*SQLiteMessagingProvider)(nil)
	_ MessagingProviderBackendModule = (*SQLiteMessagingProvider)(nil)
)
