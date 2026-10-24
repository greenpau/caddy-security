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
	"github.com/greenpau/go-authcrunch/pkg/ids"
)

// IdentityStoreBackendModule prepares a store without opening runtime storage.
// The descriptor fingerprints normalized configuration for root persistence.
// Each successful factory call transfers a distinct handle to the app. On
// failure return a partial handle safe to close or unwind acquisition before
// returning a real nil interface, never a typed nil. Cleanup panics from an
// invalid plugin are contained so other acquired stores can still be closed.
// Runtime calls use request contexts; the setup context is not a shutdown signal.
// Module Cleanup must not close the returned store.
type IdentityStoreBackendModule interface {
	IdentityStoreConfig() (*ids.ExternalIdentityStoreConfig, error)
	NewIdentityStore(context.Context) (ids.IdentityStore, error)
}

type preparedIdentityStore struct {
	config ids.ExternalIdentityStoreConfig
	module IdentityStoreBackendModule
}

// identityOwnedCloser contains only a plugin's disposal boundary. Root binding
// validation can reject a typed nil handle whose Close method would also panic.
// Such a violation must not interrupt the remaining candidate cleanup or expose
// the panic value, which may contain private backend diagnostics.
type identityOwnedCloser struct{ closer io.Closer }

func (c identityOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("identity store cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("identity store cleanup failed")
	}
	return nil
}

// prepareIdentityStores restores descriptors on the private runtime config
// before ordinary validation. Raw host declarations survive Caddy LoadModule.
func (app *App) prepareIdentityStores(ctx caddy.Context, config *authcrunch.Config) error {
	if len(config.ExternalIdentityStores) != 0 {
		return fmt.Errorf("external identity descriptors are derived from security identity store modules")
	}
	loader := &App{IdentityStoreConfigs: make([]json.RawMessage, len(app.IdentityStoreConfigs))}
	for i, raw := range app.IdentityStoreConfigs {
		loader.IdentityStoreConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "IdentityStoreConfigs")
	if err != nil {
		return fmt.Errorf("identity store module configuration failed")
	}
	seen := make(map[string]bool)
	for _, cfg := range config.IdentityStores {
		if cfg != nil {
			seen[cfg.Name] = true
		}
	}
	for i, entry := range loaded.([]any) {
		module, ok := entry.(IdentityStoreBackendModule)
		if !ok {
			return fmt.Errorf("identity store %d has an incompatible module interface", i)
		}
		descriptor, err := module.IdentityStoreConfig()
		if err != nil || descriptor == nil || descriptor.Validate() != nil || seen[descriptor.Name] {
			return fmt.Errorf("identity store %d requires a valid unique runtime binding", i)
		}
		seen[descriptor.Name] = true
		copy := *descriptor
		config.ExternalIdentityStores = append(config.ExternalIdentityStores, &copy)
		app.identityStores = append(app.identityStores, preparedIdentityStore{config: copy, module: module})
	}
	if len(app.identityStores) != 0 {
		for _, portal := range config.AuthenticationPortals {
			if portal == nil {
				return fmt.Errorf("identity store consumer configuration is nil")
			}
			for _, name := range portal.IdentityStores {
				if !seen[name] {
					return fmt.Errorf("portal selects an undeclared identity store")
				}
			}
		}
	}
	app.pluginContext = ctx
	return nil
}

// attachIdentityStores creates private candidate stores before root assembly.
// The caller owns every returned closer, including on partial failure; the root
// borrows the handles and validates their name, realm, kind and readiness.
func (app *App) attachIdentityStores(ctx context.Context) (map[string]ids.IdentityStore, []io.Closer, error) {
	stores := make(map[string]ids.IdentityStore, len(app.identityStores))
	var closers []io.Closer
	for i, binding := range app.identityStores {
		backend, err := binding.module.NewIdentityStore(ctx)
		if closer, ok := backend.(io.Closer); ok {
			closers = append(closers, identityOwnedCloser{closer: closer})
		}
		if err != nil || backend == nil {
			return nil, closers, fmt.Errorf("identity store %d construction failed", i)
		}
		stores[binding.config.Name] = backend
	}
	return stores, closers, nil
}
