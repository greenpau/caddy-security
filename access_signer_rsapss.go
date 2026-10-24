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
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
	signingparser "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss/parser"
)

// RSAPSSAccessSigner declares a local access-token signer. Configuration and
// preparation are pure. Only the app-owned factory loads private key material;
// module cleanup never owns a returned runtime. Backend fields remain literal.
type RSAPSSAccessSigner struct {
	Name        string `json:"name"`
	KeyFile     string `json:"key_file"`
	KeyID       string `json:"key_id"`
	Algorithm   string `json:"algorithm,omitempty"`
	Issuer      string `json:"issuer"`
	Audience    string `json:"audience"`
	MaxLifetime string `json:"max_lifetime,omitempty"`
}

func init() { caddy.RegisterModule(RSAPSSAccessSigner{}) }

// CaddyModule registers the access-only PS256 signer configuration module.
func (RSAPSSAccessSigner) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.rsapss", New: func() caddy.Module { return new(RSAPSSAccessSigner) }}
}

func (m *RSAPSSAccessSigner) config() (*rsapss.Config, error) {
	if m == nil {
		return nil, fmt.Errorf("invalid RSA-PSS access signer configuration")
	}
	cfg := &rsapss.Config{KeyFile: m.KeyFile, KeyID: m.KeyID, Algorithm: m.Algorithm, Issuer: m.Issuer, Audience: m.Audience, MaxLifetime: m.MaxLifetime}
	if cfg.Validate() != nil {
		return nil, fmt.Errorf("invalid RSA-PSS access signer configuration")
	}
	return cfg, nil
}

// Validate derives copied metadata without opening or reading the key file.
func (m *RSAPSSAccessSigner) Validate() error { _, err := m.PrepareAccessSigner(); return err }

// PrepareAccessSigner freezes normalized configuration and its core descriptor.
func (m *RSAPSSAccessSigner) PrepareAccessSigner() (AccessSignerFactory, error) {
	cfg, err := m.config()
	if err != nil {
		return nil, err
	}
	lifetime, _ := time.ParseDuration(cfg.MaxLifetime) // Public Validate checks bounds and whole seconds.
	policy := kms.AccessSignerPolicy{Algorithm: cfg.Algorithm, KeyID: cfg.KeyID, TokenType: rsapss.TokenType, Issuer: cfg.Issuer, Audience: cfg.Audience, MaxLifetimeSeconds: int(lifetime / time.Second)}
	descriptor, err := kms.NewExternalAccessSignerConfig(m.Name, "rsapss", policy, cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA-PSS access signer binding")
	}
	return &rsapssAccessSignerFactory{config: *cfg, descriptor: *descriptor}, nil
}

type rsapssAccessSignerFactory struct {
	config     rsapss.Config
	descriptor kms.ExternalAccessSignerConfig
}

// signingConfig exposes only a detached opening-path snapshot for host preflight.
func (f *rsapssAccessSignerFactory) signingConfig() rsapss.Config { return f.config }

func (f *rsapssAccessSignerFactory) AccessSignerConfig() (kms.ExternalAccessSignerConfig, error) {
	if f == nil {
		return kms.ExternalAccessSignerConfig{}, fmt.Errorf("RSA-PSS access signer factory is unavailable")
	}
	return f.descriptor, nil
}

func (f *rsapssAccessSignerFactory) NewAccessSigner(ctx context.Context) (kms.AccessSigner, error) {
	if f == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("RSA-PSS access signer is unavailable")
	}
	cfg := f.config
	signer, err := rsapss.New(&cfg)
	// The synchronous public constructor retains no file/worker to close.
	// Context cancellation cannot interrupt its in-progress regular-file read.
	if err != nil || ctx.Err() != nil {
		return nil, fmt.Errorf("RSA-PSS access signer is unavailable")
	}
	return signer, nil
}

// UnmarshalCaddyfile delegates the complete flat body to the public parser:
//
//	access signer rsapss <name> {
//	    key file <private-RSA-PEM-path>
//	    key id <key-id>
//	    algorithm PS256
//	    issuer <exact-issuer>
//	    audience <exact-audience>
//	    max lifetime <duration>
//	}
//
// Settings occur once. Algorithm defaults to PS256; max lifetime defaults to
// 15m and accepts whole-second durations in 1s..24h. Other fields are required.
// The key is loaded only during construction, after storage alias preflight.
// Backend values are literal except Caddy lexical environment expansion. Select
// it with portal access signer <name> and an explicit matching access token
// profile. Its profile's max lifetime uses integer seconds, not durations.
func (m *RSAPSSAccessSigner) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Errf("expected access signer name")
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := readFlatDirectiveBlock(d, "access signer")
	if err != nil {
		return err
	}
	statements := make([]string, 0, len(body))
	for _, args := range body {
		statements = append(statements, encodeOAuthDirective(args))
	}
	cfg, err := signingparser.NewRSAPSSSigningConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("invalid RSA-PSS access signer configuration")
	}
	candidate := RSAPSSAccessSigner{Name: name, KeyFile: cfg.KeyFile, KeyID: cfg.KeyID, Algorithm: cfg.Algorithm, Issuer: cfg.Issuer, Audience: cfg.Audience, MaxLifetime: cfg.MaxLifetime}
	if candidate.Validate() != nil {
		return d.Errf("invalid RSA-PSS access signer configuration")
	}
	*m = candidate
	return nil
}

var (
	_ caddy.Module              = (*RSAPSSAccessSigner)(nil)
	_ caddy.Validator           = (*RSAPSSAccessSigner)(nil)
	_ caddyfile.Unmarshaler     = (*RSAPSSAccessSigner)(nil)
	_ AccessSignerBackendModule = (*RSAPSSAccessSigner)(nil)
	_ AccessSignerFactory       = (*rsapssAccessSignerFactory)(nil)
)
