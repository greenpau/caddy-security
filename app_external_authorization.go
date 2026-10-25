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
	"github.com/greenpau/go-authcrunch/pkg/authz/external"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ExternalAuthorizationBinding selects one backend and a complete identity binding
// for an existing policy. Only one binding is allowed per policy. BackendRaw is
// decoded by a security.external_authorization.<driver> Caddy module; it is not an
// AuthCrunch registry entry. Runtime objects never enter declarative JSON.
type ExternalAuthorizationBinding struct {
	Policy     string           `json:"policy"`
	Config     *external.Config `json:"config"`
	BackendRaw json.RawMessage  `json:"backend" caddy:"namespace=security.external_authorization inline_key=driver"`
}

// ExternalAuthorizationBackendModule is implemented by Caddy backend factories.
// Provision/Validate must only prepare configuration, without opening runtime
// resources. NewExternalAuthorizationBackend creates a fresh, exclusively app-owned
// backend and checks any backend-specific binding constraints. Its context is
// for construction only; do not retain it as a runtime cancellation signal.
//
// The app calls io.Closer.Close, when implemented by the returned backend, after
// draining requests and closing the AuthCrunch root. Module Cleanup must never
// close that backend. On error, return acquired resources as a closable backend
// or unwind them before returning nil. Return real nil, not a typed nil. Do not
// share a closable backend between calls; each call transfers one ownership.
type ExternalAuthorizationBackendModule = plugin.ExternalAuthorizationBackendModule

type preparedExternalAuthorization struct {
	policy string
	config external.Config
	module ExternalAuthorizationBackendModule
}

// prepareExternalAuthorization runs after core configuration validation. Validate all
// bindings before loading any module, and load copies: LoadModule clears raw JSON.
func (app *App) prepareExternalAuthorization(ctx caddy.Context, config *authcrunch.Config) error {
	bindings := make([]ExternalAuthorizationBinding, 0, len(app.ExternalAuthorization))
	seen := make(map[string]bool)
	policies := make(map[string]bool)
	for _, policy := range config.AuthorizationPolicies {
		policies[policy.Name] = true
	}
	for i, binding := range app.ExternalAuthorization {
		if binding == nil || !policies[binding.Policy] || seen[binding.Policy] || binding.Config == nil || len(binding.BackendRaw) == 0 {
			return fmt.Errorf("external authorization binding %d requires a unique existing policy, config and backend", i)
		}
		copyConfig := *binding.Config
		copyConfig.Attributes = slices.Clone(binding.Config.Attributes)
		if err := copyConfig.Validate(); err != nil {
			return fmt.Errorf("external authorization binding %d is invalid", i)
		}
		bindings = append(bindings, ExternalAuthorizationBinding{
			Policy: binding.Policy, Config: &copyConfig, BackendRaw: slices.Clone(binding.BackendRaw),
		})
		seen[binding.Policy] = true
	}
	for i := range bindings {
		binding := &bindings[i]
		loaded, err := ctx.LoadModule(binding, "BackendRaw")
		if err != nil {
			// Backend errors may contain configuration values or credentials.
			return fmt.Errorf("external authorization binding %d could not load its backend module", i)
		}
		module, ok := loaded.(ExternalAuthorizationBackendModule)
		if !ok {
			return fmt.Errorf("external authorization binding %d module does not implement ExternalAuthorizationBackendModule", i)
		}
		app.externalAuthorization = append(app.externalAuthorization, preparedExternalAuthorization{
			policy: binding.Policy, config: *binding.Config, module: module,
		})
	}
	app.pluginContext = ctx
	return nil
}

// attachExternalAuthorization modifies only a private, fully constructed root. Even
// on failure, the caller owns every returned closer and must close the root first.
func (app *App) attachExternalAuthorization(ctx context.Context, server *authcrunch.Server) ([]io.Closer, error) {
	var closers []io.Closer
	for i, binding := range app.externalAuthorization {
		gate, err := server.GetGatekeeperByName(binding.policy)
		if err != nil {
			return closers, fmt.Errorf("external authorization binding %d policy is unavailable", i)
		}
		moduleConfig := binding.config
		moduleConfig.Attributes = slices.Clone(binding.config.Attributes)
		backend, err := binding.module.NewExternalAuthorizationBackend(ctx, moduleConfig)
		if closer, ok := backend.(io.Closer); ok {
			closers = append(closers, closer)
		}
		if err != nil {
			return closers, fmt.Errorf("external authorization binding %d backend construction failed", i)
		}
		authorizer, err := external.New(&binding.config, backend)
		if err != nil {
			return closers, fmt.Errorf("external authorization binding %d could not construct its authorizer", i)
		}
		if err := gate.SetExternalAuthorizer(authorizer); err != nil {
			return closers, fmt.Errorf("external authorization binding %d could not attach its authorizer", i)
		}
	}
	return closers, nil
}
