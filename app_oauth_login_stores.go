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
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// OAuthLoginStoreConfig identifies an immutable host factory and its runtime.
// ConfigHash is the lowercase SHA-256 of normalized backend configuration. It
// checks factory agreement; it is neither the provider's transaction namespace
// nor an AuthCrunch persistence epoch. Metadata contains no runtime handles.
type OAuthLoginStoreConfig = plugin.OAuthLoginStoreConfig

// OAuthLoginStoreBackendModule prepares a detached immutable factory without
// opening resources. Later changes to the module must not change the factory's
// metadata, storage path or constructor inputs. Module Cleanup must not dispose
// returned runtimes. Backend configuration remains literal at this boundary.
type OAuthLoginStoreBackendModule = plugin.OAuthLoginStoreBackendModule

// OAuthLoginStoreFactory creates a distinct app-owned backend for each call.
// Metadata is copied, and constructors must consume the already-prepared values.
// The context bounds setup only, not runtime lifetime. On failure, return any
// acquired resource as a safely closable partial result or unwind it before
// returning real nil. Neither factories nor modules own the returned backend.
type OAuthLoginStoreFactory = plugin.OAuthLoginStoreFactory

// OAuthLoginStore preserves the upstream transactional interface. Its metadata
// method must attest an initialized, usable, not-closed runtime and return the
// factory's exact copied descriptor. Implement io.Closer when disposal is needed;
// the app invokes it only after consumers drain and the root closes. Never
// publish tentative results or add logical retries around upstream operations.
type OAuthLoginStore = plugin.OAuthLoginStore

type preparedOAuthLoginStore struct {
	config  OAuthLoginStoreConfig
	factory OAuthLoginStoreFactory
}

type oauthLoginStoreMetadataSource interface {
	OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error)
}

// Contain only plugin metadata calls, including a typed nil implementation.
// Backend constructors and transaction methods remain outside panic recovery.
func readOAuthLoginStoreConfig(source oauthLoginStoreMetadataSource) (config OAuthLoginStoreConfig, err error) {
	defer func() {
		if recover() != nil {
			config = OAuthLoginStoreConfig{}
			err = fmt.Errorf("OAuth login store metadata is unavailable")
		}
	}()
	if source == nil {
		return config, fmt.Errorf("OAuth login store metadata is unavailable")
	}
	config, err = source.OAuthLoginStoreConfig()
	if err != nil || config.Validate() != nil {
		return OAuthLoginStoreConfig{}, fmt.Errorf("OAuth login store metadata is invalid")
	}
	return config, nil
}

func prepareOAuthLoginStoreFactory(module OAuthLoginStoreBackendModule) (factory OAuthLoginStoreFactory, err error) {
	// Preparation is a configuration-only plugin boundary. It must not acquire
	// a resource whose ownership could be lost on a metadata panic.
	defer func() {
		if recover() != nil {
			factory = nil
			err = fmt.Errorf("OAuth login store preparation failed")
		}
	}()
	factory, err = module.PrepareOAuthLoginStore()
	if err != nil || factory == nil {
		return nil, fmt.Errorf("OAuth login store preparation failed")
	}
	return factory, nil
}

// validateOAuthLoginStoreParameters preserves resolved reference bytes before
// JSON encoding, which would otherwise replace invalid UTF-8. Only omission
// selects private memory; an explicit null or incomplete reference is invalid.
func validateOAuthLoginStoreParameters(params map[string]any) error {
	raw, present := params["login_store"]
	if !present {
		return nil
	}
	var config oauth.LoginStoreConfig
	switch value := raw.(type) {
	case oauth.LoginStoreConfig:
		config = value
	case *oauth.LoginStoreConfig:
		if value == nil {
			return fmt.Errorf("OAuth login store reference is invalid")
		}
		config = *value
	case map[string]any:
		name, nameOK := value["name"].(string)
		namespace, namespaceOK := value["namespace"].(string)
		if !nameOK || !namespaceOK {
			return fmt.Errorf("OAuth login store reference is invalid")
		}
		config = oauth.LoginStoreConfig{Name: name, Namespace: namespace}
	case map[string]string:
		config = oauth.LoginStoreConfig{Name: value["name"], Namespace: value["namespace"]}
	default:
		return fmt.Errorf("OAuth login store reference is invalid")
	}
	if config.Validate() != nil {
		return fmt.Errorf("OAuth login store reference is invalid")
	}
	return nil
}

// prepareOAuthLoginStores inspects every retained OAuth declaration, including
// unselected providers and configurations declaring no modules. Root assembly
// constructs those providers too. Caddy consumes only copied module JSON.
func (app *App) prepareOAuthLoginStores(ctx caddy.Context, config *authcrunch.Config) error {
	loader := &App{OAuthLoginStoreConfigs: make([]json.RawMessage, len(app.OAuthLoginStoreConfigs))}
	for i, raw := range app.OAuthLoginStoreConfigs {
		loader.OAuthLoginStoreConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "OAuthLoginStoreConfigs")
	if err != nil {
		return fmt.Errorf("OAuth login store module configuration failed")
	}
	seen := make(map[string]bool)
	var prepared []preparedOAuthLoginStore
	for i, entry := range loaded.([]any) {
		module, ok := entry.(OAuthLoginStoreBackendModule)
		if !ok {
			return fmt.Errorf("OAuth login store %d has an incompatible module interface", i)
		}
		factory, err := prepareOAuthLoginStoreFactory(module)
		if err != nil {
			return fmt.Errorf("OAuth login store %d preparation failed", i)
		}
		descriptor, err := readOAuthLoginStoreConfig(factory)
		if err != nil || seen[descriptor.Name] {
			return fmt.Errorf("OAuth login store %d requires valid unique metadata", i)
		}
		seen[descriptor.Name] = true
		prepared = append(prepared, preparedOAuthLoginStore{config: descriptor, factory: factory})
	}
	for i, provider := range config.IdentityProviders {
		if provider == nil {
			return fmt.Errorf("OAuth login store encountered invalid provider %d", i)
		}
		if provider.Kind != "oauth" {
			continue
		}
		if validateOAuthLoginStoreParameters(provider.Params) != nil {
			return fmt.Errorf("OAuth provider %d requires a valid declared login store", i)
		}
		encoded, err := json.Marshal(provider.Params)
		if err != nil {
			return fmt.Errorf("OAuth provider %d configuration is invalid", i)
		}
		var typed oauth.Config
		if err := json.Unmarshal(encoded, &typed); err != nil {
			return fmt.Errorf("OAuth provider %d configuration is invalid", i)
		}
		// Full OAuth validation can read pinned key files. This pure reference
		// check owns only LoginStore; ordinary root validation retains provider
		// defaults and trust validation in its established phase.
		if typed.LoginStore != nil {
			if typed.LoginStore.Validate() != nil || !seen[typed.LoginStore.Name] {
				return fmt.Errorf("OAuth provider %d requires a valid declared login store", i)
			}
		}
	}
	app.oauthLoginStores = prepared
	app.pluginContext = ctx
	return nil
}

// attachOAuthLoginStores transfers every acquired closer to the caller even on
// partial failure. The exact dynamic runtime enters the root options map. Root
// disposal precedes backend disposal; neither failure nor retirement purges data.
func (app *App) attachOAuthLoginStores(ctx context.Context) (map[string]oauth.LoginStore, []io.Closer, error) {
	stores := make(map[string]oauth.LoginStore, len(app.oauthLoginStores))
	var closers []io.Closer
	for i, binding := range app.oauthLoginStores {
		backend, err := binding.factory.NewOAuthLoginStore(ctx)
		if closer, ok := backend.(io.Closer); ok {
			closers = append(closers, oauthLoginStoreOwnedCloser{closer: closer})
		}
		if err != nil || backend == nil {
			return nil, closers, fmt.Errorf("OAuth login store %d construction failed", i)
		}
		actual, err := readOAuthLoginStoreConfig(backend)
		if err != nil || actual != binding.config {
			return nil, closers, fmt.Errorf("OAuth login store %d has invalid runtime metadata or readiness", i)
		}
		stores[binding.config.Name] = backend
	}
	return stores, closers, nil
}

type oauthLoginStoreOwnedCloser struct{ closer io.Closer }

func (c oauthLoginStoreOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("OAuth login store cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("OAuth login store cleanup failed")
	}
	return nil
}
