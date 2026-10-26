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
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// RegistrationWorkflowBackendModule prepares enrollment without opening storage.
// Each factory call receives only its selected, borrowed dependencies and returns
// a fresh provider. On failure return a safely closable partial handle or a real
// nil after unwinding acquisition. Module Cleanup must not dispose the provider.
// Neither factories nor providers may close their borrowed store or messaging
// provider. The app drains requests before closing workflows and dependencies.
type RegistrationWorkflowBackendModule = plugin.RegistrationWorkflowBackendModule

type preparedRegistrationWorkflow struct {
	config      registry.ExternalUserRegistryConfig
	module      RegistrationWorkflowBackendModule
	sqliteFiles []string
}

func (app *App) prepareRegistrationWorkflows(ctx caddy.Context, config *authcrunch.Config) error {
	if len(config.ExternalUserRegistries) != 0 {
		return fmt.Errorf("external user registry descriptors are derived from security registration workflow modules")
	}
	if len(app.RegistrationWorkflowConfigs) > 0 && config.Messaging != nil {
		providers := config.Messaging
		// Host messaging modules are declared now and injected at construction.
		// Validate only present built-ins; an empty list can await a host outbox.
		if len(providers.RawConfigs)+len(providers.EmailProviders)+len(providers.FileProviders) != 0 {
			if err := providers.Validate(); err != nil {
				return fmt.Errorf("registration workflow messaging configuration is invalid")
			}
		}
	}
	loader := &App{RegistrationWorkflowConfigs: make([]json.RawMessage, len(app.RegistrationWorkflowConfigs))}
	for i, raw := range app.RegistrationWorkflowConfigs {
		loader.RegistrationWorkflowConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "RegistrationWorkflowConfigs")
	if err != nil {
		return fmt.Errorf("registration workflow module configuration failed")
	}
	stores := make(map[string]preparedIdentityStore)
	for _, binding := range app.identityStores {
		stores[binding.config.Name] = binding
	}
	providers := make(map[string]preparedMessagingProvider)
	for _, binding := range app.messagingProviders {
		providers[binding.name] = binding
	}
	seen := make(map[string]bool)
	for i, entry := range loaded.([]any) {
		module, ok := entry.(RegistrationWorkflowBackendModule)
		if !ok {
			return fmt.Errorf("registration workflow %d has an incompatible module interface", i)
		}
		descriptor, err := module.RegistrationWorkflowConfig()
		if err != nil || descriptor == nil || descriptor.Validate() != nil || seen[descriptor.Name] {
			return fmt.Errorf("registration workflow %d requires a valid unique runtime binding", i)
		}
		store, ok := stores[descriptor.IdentityStore]
		if !ok || store.config.Realm != descriptor.Realm {
			return fmt.Errorf("registration workflow %d requires a declared identity module in the matching realm", i)
		}
		provider, hasModule := providers[descriptor.EmailProvider]
		if !hasModule && (config.Messaging == nil || !config.Messaging.FindProvider(descriptor.EmailProvider)) {
			return fmt.Errorf("registration workflow %d requires a declared messaging provider", i)
		}
		binding := preparedRegistrationWorkflow{config: *descriptor, module: module}
		if isCompanionModule(module, "security.registration_workflows.sqlite") {
			if !isCompanionModule(store.module, "security.identity_stores.sqlite") || !isCompanionModule(provider.module, "security.messaging.sqlite") {
				return fmt.Errorf("registration workflow %d requires bundled SQLite identity and messaging modules", i)
			}
			workflowPath, err := validatedSQLiteModulePath(module)
			if err != nil {
				return fmt.Errorf("registration workflow %d configuration is invalid", i)
			}
			accountPath, err := validatedSQLiteModulePath(store.module)
			if err != nil {
				return fmt.Errorf("registration workflow %d account configuration is invalid", i)
			}
			outboxPath, err := validatedSQLiteModulePath(provider.module)
			if err != nil {
				return fmt.Errorf("registration workflow %d outbox configuration is invalid", i)
			}
			binding.sqliteFiles = []string{workflowPath, accountPath, outboxPath}
			if workflowPath == accountPath || workflowPath == outboxPath || accountPath == outboxPath {
				return fmt.Errorf("registration workflow %d requires distinct pending, identity and messaging files", i)
			}
		}
		seen[descriptor.Name] = true
		copy := *descriptor
		config.ExternalUserRegistries = append(config.ExternalUserRegistries, &copy)
		app.registrationWorkflows = append(app.registrationWorkflows, binding)
	}
	app.pluginContext = ctx
	return nil
}

// validateRegistrationWorkflowFiles performs read-only alias checks at runtime
// construction, before any database opens. SQLite sharing across app instances
// remains supported; these files never enter exclusive local identity ownership.
func (app *App) validateRegistrationWorkflowFiles() error {
	for i, binding := range app.registrationWorkflows {
		var paths []string
		for _, path := range binding.sqliteFiles {
			canonical, err := identityFilePath(path)
			if err != nil {
				return fmt.Errorf("registration workflow %d storage path is unavailable", i)
			}
			for _, other := range paths {
				if sameIdentityFile(canonical, other) {
					return fmt.Errorf("registration workflow %d requires distinct pending, identity and messaging files", i)
				}
			}
			paths = append(paths, canonical)
		}
	}
	return nil
}

func (app *App) attachRegistrationWorkflows(ctx context.Context, identityStores map[string]ids.IdentityStore, config *authcrunch.Config) (map[string]registry.Provider, []io.Closer, error) {
	workflows := make(map[string]registry.Provider, len(app.registrationWorkflows))
	var closers []io.Closer
	for i, binding := range app.registrationWorkflows {
		store := identityStores[binding.config.IdentityStore]
		var messagingProvider messaging.Provider
		if config.Messaging != nil {
			messagingProvider = config.Messaging.ExtractProvider(binding.config.EmailProvider)
		}
		if store == nil || messagingProvider == nil {
			return nil, closers, fmt.Errorf("registration workflow %d dependencies are unavailable", i)
		}
		provider, err := binding.module.NewRegistrationWorkflow(ctx, store, messagingProvider)
		if closer, ok := provider.(io.Closer); ok {
			closers = append(closers, registrationWorkflowOwnedCloser{closer: closer})
		}
		if err != nil || provider == nil {
			return nil, closers, fmt.Errorf("registration workflow %d construction failed", i)
		}
		workflows[binding.config.Name] = provider
	}
	return workflows, closers, nil
}

type registrationWorkflowOwnedCloser struct{ closer io.Closer }

func (c registrationWorkflowOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("registration workflow cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("registration workflow cleanup failed")
	}
	return nil
}
