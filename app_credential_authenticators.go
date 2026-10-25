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
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// CredentialAuthenticator is an app-owned fresh API-key backend. Basic methods
// exist only for the upstream interface; host bindings never enable them.
// Each lookup receives the protected request's context and bypasses caches.
type CredentialAuthenticator = plugin.CredentialAuthenticator

// CredentialAuthenticatorBackendModule prepares configuration without opening
// runtime resources. Each factory call transfers a distinct backend to the app,
// shared only by that app's matching policies. Setup context is not a shutdown
// signal; module Cleanup must not close the returned handle. On failure return
// a closable partial result or unwind acquisition, using a real nil interface.
type CredentialAuthenticatorBackendModule = plugin.CredentialAuthenticatorBackendModule

type preparedCredentialAuthenticator struct {
	name, realm string
	policies    []*authz.PolicyConfig
	module      CredentialAuthenticatorBackendModule
}

// prepareCredentialAuthenticators runs after policy validation. Keep both the
// declarative module bytes and raw proxy statements; injections belong only to
// this private validated graph and must be restored after every JSON decode.
func (app *App) prepareCredentialAuthenticators(ctx caddy.Context, config *authcrunch.Config) error {
	loader := &App{CredentialAuthenticatorConfigs: make([]json.RawMessage, len(app.CredentialAuthenticatorConfigs))}
	for i, raw := range app.CredentialAuthenticatorConfigs {
		loader.CredentialAuthenticatorConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "CredentialAuthenticatorConfigs")
	if err != nil {
		return fmt.Errorf("credential authenticator module configuration failed")
	}
	seen := make(map[string]bool)
	for _, portal := range config.AuthenticationPortals {
		seen[portal.Name] = true
	}
	var prepared []preparedCredentialAuthenticator
	for i, entry := range loaded.([]any) {
		module, ok := entry.(CredentialAuthenticatorBackendModule)
		if !ok {
			return fmt.Errorf("credential authenticator %d has an incompatible module interface", i)
		}
		name, realm := module.CredentialIdentity()
		if name == "" || realm == "" || strings.TrimSpace(name) != name || strings.TrimSpace(realm) != realm || strings.ContainsAny(name+realm, "\r\n\x00") || strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") || seen[name] {
			return fmt.Errorf("credential authenticator %d requires a unique name distinct from portals and an exact realm", i)
		}
		seen[name] = true
		binding := preparedCredentialAuthenticator{name: name, realm: realm, module: module}
		for _, policy := range config.AuthorizationPolicies {
			if policy.AuthProxyConfig == nil {
				continue
			}
			selected := false
			for realmName, proxy := range policy.AuthProxyConfig.Realms {
				if proxy == nil {
					return fmt.Errorf("credential authenticator %d encountered an invalid policy realm", i)
				}
				if proxy.PortalName != name {
					continue
				}
				if realmName != realm || proxy.IsRemote || !proxy.APIKeyAuthEnabled || proxy.BasicAuthEnabled || proxy.HasAuthenticator() {
					return fmt.Errorf("credential authenticator %d requires an unbound API-key-only policy with the exact realm", i)
				}
				selected = true
			}
			// Shared parsing can overwrite earlier declarations for a realm. Reject
			// ambiguous declarations involving this backend instead of silently rebinding.
			count := 0
			for _, line := range policy.AuthProxyRawConfig {
				raw, err := authproxy.ParseConfig([]string{line})
				if err != nil {
					return fmt.Errorf("credential authenticator %d policy declaration is invalid", i)
				}
				for rawRealm, proxy := range raw.Realms {
					if proxy.PortalName != name && !(selected && rawRealm == realm) {
						continue
					}
					count++
					if !selected || rawRealm != realm || proxy.PortalName != name || proxy.IsRemote || proxy.BasicAuthEnabled || !proxy.APIKeyAuthEnabled || count > 1 {
						return fmt.Errorf("credential authenticator %d has conflicting policy declarations", i)
					}
				}
			}
			if selected {
				binding.policies = append(binding.policies, policy)
			}
		}
		if len(binding.policies) == 0 {
			return fmt.Errorf("credential authenticator %d has no matching API-key policy", i)
		}
		prepared = append(prepared, binding)
	}
	app.credentialAuthenticators = prepared
	app.pluginContext = ctx
	return nil
}

// attachCredentialAuthenticators must precede NewServer: root construction
// checks all auth proxies before returning, so post-root attachment is too late.
// The caller owns every returned closer even when setup fails.
func (app *App) attachCredentialAuthenticators(ctx context.Context) ([]io.Closer, error) {
	var closers []io.Closer
	for i, binding := range app.credentialAuthenticators {
		backend, err := binding.module.NewCredentialAuthenticator(ctx)
		if backend != nil {
			closers = append(closers, backend)
		}
		if err != nil || backend == nil {
			return closers, fmt.Errorf("credential authenticator %d construction failed", i)
		}
		realm, _ := backend.GetConfig()["realm"].(string)
		if backend.GetName() != binding.name || realm != binding.realm || !backend.RequireFreshAuthentication() {
			return closers, fmt.Errorf("credential authenticator %d has an invalid runtime identity or freshness capability", i)
		}
		for _, policy := range binding.policies {
			if err := policy.AuthProxyConfig.AddAuthenticator(binding.name, backend); err != nil {
				return closers, fmt.Errorf("credential authenticator %d could not bind its policy", i)
			}
		}
	}
	return closers, nil
}
