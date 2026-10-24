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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	registrationsqlite "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	registrationparser "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite/parser"
)

// SQLiteRegistrationWorkflow configures open email-confirmed enrollment. The
// app owns its pending database and separately owns its account store and outbox.
type SQLiteRegistrationWorkflow struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Timeout       string `json:"timeout,omitempty"`
	IdentityStore string `json:"identity_store"`
	Realm         string `json:"realm"`
	EmailProvider string `json:"email_provider"`
	PublicOrigin  string `json:"public_origin"`
	BasePath      string `json:"base_path,omitempty"`
}

func init() { caddy.RegisterModule(SQLiteRegistrationWorkflow{}) }

// CaddyModule registers the SQLite registration configuration module.
func (SQLiteRegistrationWorkflow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.registration_workflows.sqlite", New: func() caddy.Module { return new(SQLiteRegistrationWorkflow) }}
}

func (m *SQLiteRegistrationWorkflow) config() (*registrationsqlite.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid SQLite registration configuration")
	}
	cfg := &registrationsqlite.Config{Name: m.Name, Path: m.Path, Timeout: m.Timeout, IdentityStore: m.IdentityStore, Realm: m.Realm, EmailProvider: m.EmailProvider, PublicOrigin: m.PublicOrigin, BasePath: m.BasePath}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite registration configuration")
	}
	duration, _ := time.ParseDuration(cfg.Timeout) // Validate checks the duration.
	cfg.Timeout = duration.String()
	return cfg, nil
}

// Validate checks literals without opening storage or inspecting Caddy routes.
func (m *SQLiteRegistrationWorkflow) Validate() error { _, err := m.config(); return err }

// RegistrationWorkflowConfig binds normalized policy and dependency names to
// persistent root state without publishing private backend configuration.
func (m *SQLiteRegistrationWorkflow) RegistrationWorkflowConfig() (*registry.ExternalUserRegistryConfig, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	return registry.NewExternalUserRegistryConfig(cfg.Name, "sqlite", cfg.IdentityStore, cfg.Realm, cfg.EmailProvider, cfg)
}

// NewRegistrationWorkflow borrows only the dependencies selected by the app.
// The returned workflow owns its pending file, never the account store/outbox.
func (m *SQLiteRegistrationWorkflow) NewRegistrationWorkflow(ctx context.Context, store ids.IdentityStore, provider messaging.Provider) (registry.Provider, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	accounts, ok := store.(*identitysqlite.Store)
	if !ok || accounts == nil {
		return nil, registrationsqlite.ErrUnavailable
	}
	outbox, ok := provider.(*messagingsqlite.Outbox)
	if !ok || outbox == nil || outbox.AsMap()["name"] != cfg.EmailProvider {
		return nil, registrationsqlite.ErrUnavailable
	}
	workflow, err := registrationsqlite.New(ctx, cfg, accounts, outbox)
	if err != nil {
		return nil, registrationsqlite.ErrUnavailable
	}
	return workflow, nil
}

// UnmarshalCaddyfile parses an explicit global enrollment workflow:
//
//	user registration sqlite <name> {
//	    path <absolute-private-pending-database>
//	    identity_store <sqlite-account-store-name>
//	    realm <realm>
//	    email_provider <sqlite-outbox-name>
//	    public_origin <canonical-https-origin>
//	    base_path <portal-mount>
//	    timeout <duration>
//	}
//
// The public parser owns all fields: one value per setting, required except
// base_path (default /auth, also supports /) and timeout (default 1s, 1ms..30s).
// Values are literal. Operators must match origin/mount to their deployed route;
// the app cannot infer arbitrary HTTP routing. Explicitly select the workflow
// with `enable user registration <name>` in each enrolling portal. Confirmation
// creates an enabled authp/user account; this backend has no approval/MX/MFA gate.
func (m *SQLiteRegistrationWorkflow) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected registration workflow name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := readFlatDirectiveBlock(d, "registration workflow")
	if err != nil {
		return err
	}
	statements := []string{encodeOAuthDirective([]string{"name", name})}
	for _, args := range body {
		statements = append(statements, encodeOAuthDirective(args))
	}
	cfg, err := registrationparser.NewSQLiteRegistrationConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite registration configuration")
	}
	duration, _ := time.ParseDuration(cfg.Timeout)
	*m = SQLiteRegistrationWorkflow{Name: cfg.Name, Path: cfg.Path, Timeout: duration.String(), IdentityStore: cfg.IdentityStore, Realm: cfg.Realm, EmailProvider: cfg.EmailProvider, PublicOrigin: cfg.PublicOrigin, BasePath: cfg.BasePath}
	return nil
}

var (
	_ caddy.Module                      = (*SQLiteRegistrationWorkflow)(nil)
	_ caddy.Validator                   = (*SQLiteRegistrationWorkflow)(nil)
	_ caddyfile.Unmarshaler             = (*SQLiteRegistrationWorkflow)(nil)
	_ RegistrationWorkflowBackendModule = (*SQLiteRegistrationWorkflow)(nil)
)
