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
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/idp"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// IdentityProviderBackendModule prepares an external provider without opening
// runtime resources. Its descriptor fingerprints normalized configuration.
// Each factory call transfers a fresh, configured handle to the app, preserving
// optional HTTP login and attachment capabilities. Return a safely closable
// partial handle or a real nil after unwinding acquisition on failure. Module
// Cleanup must not close the runtime; the app drains requests before disposal.
type IdentityProviderBackendModule = plugin.IdentityProviderBackendModule

type preparedIdentityProvider struct {
	config          idp.ExternalIdentityProviderConfig
	module          IdentityProviderBackendModule
	attachmentStore string
}

// prepareIdentityProviders derives descriptors on the private root snapshot.
// Caddy's module loader consumes copied raw bytes, preserving native declarations.
func (app *App) prepareIdentityProviders(ctx caddy.Context, config *authcrunch.Config) error {
	if len(config.ExternalIdentityProviders) != 0 {
		return fmt.Errorf("external identity provider descriptors are derived from security identity provider modules")
	}
	loader := &App{IdentityProviderConfigs: make([]json.RawMessage, len(app.IdentityProviderConfigs))}
	for i, raw := range app.IdentityProviderConfigs {
		loader.IdentityProviderConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "IdentityProviderConfigs")
	if err != nil {
		return fmt.Errorf("identity provider module configuration failed")
	}
	seen := make(map[string]bool)
	for _, cfg := range config.IdentityProviders {
		if cfg != nil {
			seen[cfg.Name] = true
		}
	}
	for i, entry := range loaded.([]any) {
		module, ok := entry.(IdentityProviderBackendModule)
		if !ok {
			return fmt.Errorf("identity provider %d has an incompatible module interface", i)
		}
		descriptor, err := module.IdentityProviderConfig()
		if err != nil || descriptor == nil || descriptor.Validate() != nil || seen[descriptor.Name] {
			return fmt.Errorf("identity provider %d requires a valid unique runtime binding", i)
		}
		seen[descriptor.Name] = true
		var attachmentStore string
		switch ticket := module.(type) {
		case *SQLiteTicketIdentityProvider:
			normalized, err := ticket.BackendConfig()
			if err != nil {
				return fmt.Errorf("identity provider %d attachment configuration is invalid", i)
			}
			if normalized.Attachment != nil {
				attachmentStore = normalized.Attachment.LocalIdentityStore
			}
		case *ConsulTicketIdentityProvider:
			var err error
			attachmentStore, err = ticket.AttachmentStoreName()
			if err != nil {
				return fmt.Errorf("identity provider %d attachment configuration is invalid", i)
			}
		}
		if attachmentStore != "" {
			matches := 0
			invalidKind := false
			for _, store := range config.IdentityStores {
				if store != nil && store.Name == attachmentStore {
					matches++
					invalidKind = invalidKind || store.Kind != "local"
				}
			}
			for _, store := range config.ExternalIdentityStores {
				if store != nil && store.Name == attachmentStore {
					matches++
					invalidKind = true
				}
			}
			if matches != 1 || invalidKind {
				return fmt.Errorf("identity provider %d attachment requires one configured local identity store", i)
			}
		}
		copy := *descriptor
		config.ExternalIdentityProviders = append(config.ExternalIdentityProviders, &copy)
		app.identityProviders = append(app.identityProviders, preparedIdentityProvider{config: copy, module: module, attachmentStore: attachmentStore})
	}
	app.pluginContext = ctx
	return nil
}

// Only the bundled ticket declaration opts into root attachment. Third-party
// providers retain their existing caller-bound or implicit-memory contract.
func (app *App) identityProviderAttachmentStores() map[string]string {
	var stores map[string]string
	for _, provider := range app.identityProviders {
		if provider.attachmentStore == "" {
			continue
		}
		if stores == nil {
			stores = make(map[string]string)
		}
		stores[provider.config.Name] = provider.attachmentStore
	}
	return stores
}

// attachIdentityProviders transfers all acquired closers to the caller, including
// on partial failure. The root borrows these exact dynamic instances and validates
// their metadata/readiness; it never owns their configuration or shutdown.
func (app *App) attachIdentityProviders(ctx context.Context) (map[string]idp.IdentityProvider, []io.Closer, error) {
	providers := make(map[string]idp.IdentityProvider, len(app.identityProviders))
	var closers []io.Closer
	for i, binding := range app.identityProviders {
		provider, err := binding.module.NewIdentityProvider(ctx)
		if closer, ok := provider.(io.Closer); ok {
			closers = append(closers, identityProviderOwnedCloser{closer: closer})
		}
		if err != nil || provider == nil {
			return nil, closers, fmt.Errorf("identity provider %d construction failed", i)
		}
		providers[binding.config.Name] = provider
	}
	return providers, closers, nil
}

// Contain only plugin disposal, including invalid typed nil Close methods, so
// other resources still unwind and private panic/error details remain private.
type identityProviderOwnedCloser struct{ closer io.Closer }

func (c identityProviderOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("identity provider cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("identity provider cleanup failed")
	}
	return nil
}
