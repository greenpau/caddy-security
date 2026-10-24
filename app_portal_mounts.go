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
	"fmt"
	"net/url"
	"slices"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

type portalMountConstraint struct {
	feature string
	path    string
}

type portalMountBinding struct {
	constraints []portalMountConstraint
	cookies     *cookie.Factory
}

// preparePortalMounts snapshots only resolved mount restrictions. It runs before
// either immediate or deferred root construction, without opening a backend or
// inspecting Caddy's partially provisioned HTTP route tree.
func (app *App) preparePortalMounts(config *authcrunch.Config) error {
	bindings := make(map[string]portalMountBinding, len(config.AuthenticationPortals))
	for _, portal := range config.AuthenticationPortals {
		if portal == nil {
			return fmt.Errorf("portal mount configuration is unavailable")
		}
		cookieConfig := portal.CookieConfig.Clone()
		if cookieConfig == nil {
			cookieConfig = cookie.NewConfig()
		}
		// Portal construction applies this override before factory defaults and
		// collision checks. Native JSON must receive the same effective snapshot.
		if refresh := portal.RefreshTokens; refresh != nil && refresh.Enabled && refresh.CookieName != "" {
			cookieConfig.RefreshTokenCookieName = refresh.CookieName
		}
		factory, err := cookie.NewFactory(cookieConfig)
		if err != nil {
			return fmt.Errorf("portal %q cookie mount configuration is invalid", portal.Name)
		}
		binding := portalMountBinding{cookies: factory}
		if refresh := portal.RefreshTokens; refresh != nil && refresh.Enabled {
			binding.constraints = append(binding.constraints, portalMountConstraint{"token refresh", refresh.BasePath})
		}
		if provider := portal.OIDCProvider; provider != nil && provider.Enabled {
			issuer, err := url.Parse(provider.Issuer)
			if err != nil {
				return fmt.Errorf("portal %q oidc mount configuration is invalid", portal.Name)
			}
			mount := issuer.Path
			if mount == "" {
				mount = "/"
			}
			binding.constraints = append(binding.constraints, portalMountConstraint{"oidc provider", mount})
		}
		// Bundled modules expose their normalized configuration without constructing
		// providers. Opaque third-party descriptors retain their own restrictions.
		for _, prepared := range app.identityProviders {
			if !slices.Contains(portal.IdentityProviders, prepared.config.Name) {
				continue
			}
			if module, ok := prepared.module.(*SQLiteTicketIdentityProvider); ok {
				cfg, err := module.config()
				if err != nil {
					return fmt.Errorf("portal %q ticket mount configuration is invalid", portal.Name)
				}
				binding.constraints = append(binding.constraints, portalMountConstraint{"ticket provider", cfg.BasePath})
			}
		}
		for _, prepared := range app.registrationWorkflows {
			if !slices.Contains(portal.UserRegistries, prepared.config.Name) {
				continue
			}
			if module, ok := prepared.module.(*SQLiteRegistrationWorkflow); ok {
				cfg, err := module.config()
				if err != nil {
					return fmt.Errorf("portal %q registration mount configuration is invalid", portal.Name)
				}
				binding.constraints = append(binding.constraints, portalMountConstraint{"registration workflow", cfg.BasePath})
			}
		}
		bindings[portal.Name] = binding
	}
	app.portalMounts = bindings
	return nil
}

// validatePortalMount reads an immutable snapshot, including before persistent
// App.Start. The declaration selects a boundary; it does not attest Caddy matcher
// coverage or the external origin seen through a proxy.
func (app *App) validatePortalMount(name, basePath string) error {
	binding, ok := app.portalMounts[name]
	if !ok {
		return fmt.Errorf("portal mount configuration for %q is unavailable", name)
	}
	for _, constraint := range binding.constraints {
		if constraint.path != basePath {
			return fmt.Errorf("portal mount conflicts with %s for portal %q", constraint.feature, name)
		}
	}
	if err := binding.cookies.ValidatePortalPath(basePath); err != nil {
		return fmt.Errorf("portal mount conflicts with cookie scope for portal %q", name)
	}
	return nil
}
