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
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// RefreshStoreBackendModule prepares an immutable factory without opening files
// or acquiring resources. Module cleanup never owns returned store handles.
type RefreshStoreBackendModule = plugin.RefreshStoreBackendModule

// RefreshStoreFactory freezes copied configuration and core metadata. Every
// constructor call transfers a fresh store to the app; later module mutations
// cannot change it. A failed constructor returns a safely closable partial
// handle, or real nil after unwinding acquisition. The context applies to setup,
// not runtime lifetime. Optional io.Closer ownership belongs solely to the app.
type RefreshStoreFactory = plugin.RefreshStoreFactory

type preparedRefreshStore struct {
	config  tokenrefresh.ExternalStoreConfig
	factory RefreshStoreFactory
}

func prepareRefreshStoreFactory(module RefreshStoreBackendModule) (factory RefreshStoreFactory, err error) {
	defer func() {
		if recover() != nil {
			factory = nil
			err = fmt.Errorf("refresh store preparation failed")
		}
	}()
	factory, err = module.PrepareRefreshStore()
	if err != nil || factory == nil {
		return nil, fmt.Errorf("refresh store preparation failed")
	}
	return factory, nil
}

func readRefreshStoreConfig(factory RefreshStoreFactory) (config tokenrefresh.ExternalStoreConfig, err error) {
	defer func() {
		if recover() != nil {
			config = tokenrefresh.ExternalStoreConfig{}
			err = fmt.Errorf("refresh store metadata is unavailable")
		}
	}()
	if factory == nil {
		return config, fmt.Errorf("refresh store metadata is unavailable")
	}
	config, err = factory.RefreshStoreConfig()
	if err != nil || config.Validate() != nil {
		return tokenrefresh.ExternalStoreConfig{}, fmt.Errorf("refresh store metadata is invalid")
	}
	return config, nil
}

// prepareRefreshStores checks every selected reference before any constructor.
// Root descriptors are derived only on the app's private resolved config.
func (app *App) prepareRefreshStores(ctx caddy.Context, config *authcrunch.Config) error {
	if config == nil || len(config.ExternalRefreshStores) != 0 {
		return fmt.Errorf("external refresh store descriptors are derived from security refresh store modules")
	}
	loader := &App{RefreshStoreConfigs: make([]json.RawMessage, len(app.RefreshStoreConfigs))}
	for i, raw := range app.RefreshStoreConfigs {
		if !utf8.Valid(raw) {
			return fmt.Errorf("refresh store module configuration is invalid")
		}
		loader.RefreshStoreConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "RefreshStoreConfigs")
	if err != nil {
		return fmt.Errorf("refresh store module configuration failed")
	}
	seen := make(map[string]bool)
	var prepared []preparedRefreshStore
	var descriptors []*tokenrefresh.ExternalStoreConfig
	for i, entry := range loaded.([]any) {
		module, ok := entry.(RefreshStoreBackendModule)
		if !ok {
			return fmt.Errorf("refresh store %d has an incompatible module interface", i)
		}
		factory, err := prepareRefreshStoreFactory(module)
		if err != nil {
			return fmt.Errorf("refresh store %d preparation failed", i)
		}
		descriptor, err := readRefreshStoreConfig(factory)
		if err != nil || seen[descriptor.Name] {
			return fmt.Errorf("refresh store %d requires valid unique metadata", i)
		}
		seen[descriptor.Name] = true
		prepared = append(prepared, preparedRefreshStore{config: descriptor, factory: factory})
		copy := descriptor
		descriptors = append(descriptors, &copy)
	}
	for i, portal := range config.AuthenticationPortals {
		if portal == nil || portal.RefreshTokens != nil && portal.RefreshTokens.Store != "" && !seen[portal.RefreshTokens.Store] {
			return fmt.Errorf("portal %d requires a valid declared refresh store", i)
		}
	}
	config.ExternalRefreshStores = descriptors
	app.refreshStores = prepared
	app.pluginContext = ctx
	return nil
}

// Contain only metadata calls, including arbitrary typed nil implementations.
// Root assembly owns bounded read-only readiness and generation activation.
func refreshStoreMetadataMatches(store tokenrefresh.ManagedStore, config tokenrefresh.ExternalStoreConfig) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("refresh store runtime metadata is unavailable")
		}
	}()
	if store == nil {
		return fmt.Errorf("refresh store runtime metadata is unavailable")
	}
	actual, err := store.Metadata()
	if err != nil || actual.Kind != config.Kind || actual.ConfigDigest != config.ConfigDigest || actual.MaxSessions != config.MaxSessions || actual.MaxRotations != config.MaxRotations {
		return fmt.Errorf("refresh store runtime metadata does not match its declaration")
	}
	return nil
}

// attachRefreshStores transfers exact dynamic instances and every acquired
// closer, even on failure. Root owns readiness and generation activation and
// borrows every store handle.
func (app *App) attachRefreshStores(ctx context.Context) (map[string]tokenrefresh.ManagedStore, []io.Closer, error) {
	stores := make(map[string]tokenrefresh.ManagedStore, len(app.refreshStores))
	var closers []io.Closer
	for i, binding := range app.refreshStores {
		store, err := binding.factory.NewRefreshStore(ctx)
		if closer, ok := store.(io.Closer); ok {
			closers = append(closers, refreshStoreOwnedCloser{closer: closer})
		}
		if err != nil || store == nil {
			return nil, closers, fmt.Errorf("refresh store %d construction failed", i)
		}
		if refreshStoreMetadataMatches(store, binding.config) != nil {
			return nil, closers, fmt.Errorf("refresh store %d has invalid runtime metadata", i)
		}
		stores[binding.config.Name] = store
	}
	return stores, closers, nil
}

type refreshStoreOwnedCloser struct{ closer io.Closer }

func (c refreshStoreOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("refresh store cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("refresh store cleanup failed")
	}
	return nil
}
