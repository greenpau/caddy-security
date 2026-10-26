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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
	ticketparser "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite/parser"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// SQLiteTicketIdentityProvider declares browser-bound tickets issued by a trusted
// application. The app owns each runtime handle. Explicit attachments bind to a
// root-owned local store before publication; omission retains private memory.
type SQLiteTicketIdentityProvider struct {
	Name         string             `json:"name"`
	Realm        string             `json:"realm"`
	Path         string             `json:"path"`
	Timeout      string             `json:"timeout,omitempty"`
	PublicOrigin string             `json:"public_origin"`
	BasePath     string             `json:"base_path,omitempty"`
	CookieName   string             `json:"cookie_name,omitempty"`
	IssuerURL    string             `json:"issuer_url"`
	Attachment   *attachment.Config `json:"attachment,omitempty"`
}

// SQLiteStoragePath reports the declarative opening path without storage I/O.
func (m *SQLiteTicketIdentityProvider) SQLiteStoragePath() string {
	if m == nil {
		return ""
	}
	return m.Path
}

func init() { caddy.RegisterModule(SQLiteTicketIdentityProvider{}) }

// CaddyModule registers the SQLite ticket provider configuration module.
func (SQLiteTicketIdentityProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_providers.sqlite", New: func() caddy.Module { return new(SQLiteTicketIdentityProvider) }}
}

// BackendConfig returns a detached, validated configuration for host admission.
func (m *SQLiteTicketIdentityProvider) BackendConfig() (*tickets.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid SQLite ticket provider configuration")
	}
	cfg := &tickets.Config{Name: m.Name, Realm: m.Realm, Path: m.Path, Timeout: m.Timeout, PublicOrigin: m.PublicOrigin, BasePath: m.BasePath, CookieName: m.CookieName, IssuerURL: m.IssuerURL}
	if m.Attachment != nil {
		copy := *m.Attachment
		cfg.Attachment = &copy
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SQLite ticket provider configuration")
	}
	// Empty native attachments and omission both select private memory. Normalize
	// only the detached runtime config so declarative JSON remains unchanged.
	if cfg.Attachment != nil && cfg.Attachment.LocalIdentityStore == "" {
		cfg.Attachment = nil
	}
	duration, _ := time.ParseDuration(cfg.Timeout) // Validate checks the duration.
	cfg.Timeout = duration.String()
	return cfg, nil
}

// Validate checks literals without storage, issuer requests or route inspection.
func (m *SQLiteTicketIdentityProvider) Validate() error { _, err := m.BackendConfig(); return err }

// AttachmentStoreName identifies the selected root-owned local attachment.
func (m *SQLiteTicketIdentityProvider) AttachmentStoreName() (string, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return "", err
	}
	if cfg.Attachment == nil {
		return "", nil
	}
	return cfg.Attachment.LocalIdentityStore, nil
}

// PortalBasePath exposes the normalized mount restriction without resources.
func (m *SQLiteTicketIdentityProvider) PortalBasePath() (string, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return "", err
	}
	return cfg.BasePath, nil
}

// IdentityProviderConfig binds normalized backend settings without exposing them.
func (m *SQLiteTicketIdentityProvider) IdentityProviderConfig() (*idp.ExternalIdentityProviderConfig, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return nil, err
	}
	return idp.NewExternalIdentityProviderConfig(cfg.Name, "sqlite-ticket", "ticket", cfg.Realm, cfg)
}

// NewIdentityProvider opens private ticket storage in an existing private parent.
// Return the original dynamic provider so HTTP login and attachment capabilities
// remain shared across its portals. No issuer service or background worker starts.
func (m *SQLiteTicketIdentityProvider) NewIdentityProvider(ctx context.Context) (idp.IdentityProvider, error) {
	cfg, err := m.BackendConfig()
	if err != nil {
		return nil, err
	}
	provider, err := tickets.New(ctx, cfg)
	if err != nil {
		return nil, tickets.ErrUnavailable
	}
	return provider, nil
}

// UnmarshalCaddyfile parses a host-owned provider declaration:
//
//	identity provider sqlite <name> {
//	    realm <realm>
//	    path <absolute-private-database-file>
//	    public_origin <canonical-https-origin>
//	    issuer_url <pinned-https-issuer-url>
//	    base_path <portal-mount>
//	    cookie_name <binding-cookie-name>
//	    timeout <duration>
//	    attach to local identity store <name>
//	}
//
// Required fields are realm, path, public_origin and issuer_url; each takes one
// literal value once. Defaults are /auth, AUTHP_PROVIDER_SESSION_ID and 1s
// (1ms..30s). A root mount / and explicit __Secure- cookie names are supported;
// __Host- cannot use the callback subpath. The independent cookie name does not
// inherit the portal prefix. Select with enable identity provider <name>.
// Operators must align origin/mount with actual routes. Only a trusted application
// authenticating its user may call Issue; this module installs no issuer endpoint.
// An optional literal attachment selects exactly one root-owned local store by
// name, not realm or path. It neither enables that store as a login realm nor
// grants provider claims local-factor authority. Omission uses private memory.
func (m *SQLiteTicketIdentityProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected identity provider name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := caddyfileutil.ReadFlatBlock(d, "identity provider")
	if err != nil {
		return err
	}
	statements := []string{caddyfileutil.EncodeDirective([]string{"name", name})}
	for _, args := range body {
		statements = append(statements, caddyfileutil.EncodeDirective(args))
	}
	cfg, err := ticketparser.NewSQLiteTicketProviderConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid SQLite ticket provider configuration")
	}
	duration, _ := time.ParseDuration(cfg.Timeout)
	*m = SQLiteTicketIdentityProvider{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path, Timeout: duration.String(), PublicOrigin: cfg.PublicOrigin, BasePath: cfg.BasePath, CookieName: cfg.CookieName, IssuerURL: cfg.IssuerURL}
	if cfg.Attachment != nil {
		copy := *cfg.Attachment
		m.Attachment = &copy
	}
	return nil
}

var (
	_ caddy.Module                         = (*SQLiteTicketIdentityProvider)(nil)
	_ caddy.Validator                      = (*SQLiteTicketIdentityProvider)(nil)
	_ caddyfile.Unmarshaler                = (*SQLiteTicketIdentityProvider)(nil)
	_ plugin.IdentityProviderBackendModule = (*SQLiteTicketIdentityProvider)(nil)
)
