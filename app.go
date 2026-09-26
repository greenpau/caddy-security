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
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"

	"go.uber.org/zap"
)

var (
	appName = "security"

	// Interface guards
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.Module       = (*App)(nil)
	_ caddy.App          = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
)

func init() {
	caddy.RegisterModule(&App{})
}

type SecretsManager interface {
	GetConfig(context.Context) map[string]interface{}
	GetSecret(context.Context) (map[string]interface{}, error)
	GetSecretByKey(context.Context, string) (interface{}, error)
}

// App implements security manager.
type App struct {
	Name   string             `json:"-"`
	Config *authcrunch.Config `json:"config,omitempty"`

	OAuthRegistrationStore  *OAuthRegistrationStoreConfig `json:"oauth_registration_store,omitempty"`
	OAuthApplicationSources []*OAuthApplicationSource     `json:"oauth_application_sources,omitempty"`

	// OIDCProviderDirectives preserves complete provider bodies across Caddy JSON.
	// Reattach them after all explicit/stored applications are available, before
	// validating the runtime portal. Declarative JSON omits copied client snapshots.
	OIDCProviderDirectives map[string][]string `json:"oidc_provider_directives,omitempty"`

	// PortalCookieDirectives holds complete cookie snapshots awaiting runtime
	// replacement or a deferred refresh override, keyed by portal name. It replaces
	// that portal's CookieConfig after resolving token refresh configuration.
	PortalCookieDirectives map[string][]string `json:"portal_cookie_directives,omitempty"`

	// PortalTokenRefreshDirectives preserves complete token refresh bodies with
	// runtime references. Resolve and attach before validating runtime portals.
	PortalTokenRefreshDirectives map[string][]string `json:"portal_token_refresh_directives,omitempty"`

	// OAuthProviderDirectives retains complete, validated provider statements
	// with runtime references, keyed by provider name. Reparse after replacement
	// so driver defaults never become part of an unresolved secret lookup.
	OAuthProviderDirectives map[string][]string `json:"oauth_provider_directives,omitempty"`

	SecretsManagerConfigs []json.RawMessage `json:"secrets_managers,omitempty" caddy:"namespace=security.secrets inline_key=driver"`
	secretsManagers       []SecretsManager

	server *authcrunch.Server
	logger *zap.Logger
	// Persistent runtimes are constructed only by Start. Caddy also calls
	// Provision during validation, which must not initialize durable state.
	runtimeConfig *authcrunch.Config

	mu            sync.Mutex
	provisioned   bool
	disposing     bool
	requests      sync.WaitGroup
	cleanupOnce   sync.Once
	cleanupErr    error
	identityFiles []string
}

// CaddyModule returns the Caddy module information.
func (*App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "security",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision validates this Caddy configuration and constructs volatile runtimes.
// Persistent runtimes wait for Start so validation never initializes storage.
func (app *App) Provision(ctx caddy.Context) error {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.provisioned || app.disposing {
		return fmt.Errorf("security app instance cannot be reprovisioned")
	}
	app.provisioned = true
	if app.Config == nil {
		return fmt.Errorf("security app config is nil")
	}
	// Validation, runtime replacement, and NewServer all mutate configuration.
	// Keep the declarative input separate, including nested maps and slices.
	data, err := json.Marshal(app.Config)
	if err != nil {
		return fmt.Errorf("copy security app config: %w", err)
	}
	var config authcrunch.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("copy security app config: %w", err)
	}
	if err := app.resolveOAuthRegistrationConfig(ctx, &config); err != nil {
		return fmt.Errorf("resolve OAuth registrations: %w", err)
	}

	app.Name = appName
	app.logger = ctx.Logger(app)

	app.logger.Info(
		"provisioning app instance",
		zap.String("app", app.Name),
	)

	secretsManagerConfigs, err := ctx.LoadModule(app, "SecretsManagerConfigs")
	if err != nil {
		app.logger.Error(
			"app failed loading secrets manager plugins",
			zap.String("app_name", app.Name),
			zap.Error(err),
		)
		return err
	}

	for _, conf := range secretsManagerConfigs.([]any) {
		secretsManagerPlugin := conf.(SecretsManager)
		app.logger.Info(
			"loaded secrets manager plugin",
			zap.String("app_name", app.Name),
			zap.Any("config", secretsManagerPlugin.GetConfig(ctx)),
		)
		app.secretsManagers = append(app.secretsManagers, secretsManagerPlugin)
	}

	repl := caddy.NewReplacer()
	if err := resolveRuntimeAppConfig(ctx, repl, app.secretsManagers, &config, app.OAuthProviderDirectives, app.PortalTokenRefreshDirectives, app.logger); err != nil {
		return err
	}
	// Apply resolved snapshots last so substituted paths are not expanded twice.
	if err := resolvePortalCookieDirectives(ctx, repl, app.secretsManagers, &config, app.PortalCookieDirectives, app.logger); err != nil {
		return err
	}

	if err := config.Validate(); err != nil {
		app.logger.Error(
			"app failed validating config",
			zap.String("app_name", app.Name),
			zap.Error(err),
		)
		return err
	}

	// Check issuer isolation on the completed config, before construction.
	if err := validateOIDCProviderMounts(&config); err != nil {
		return err
	}
	if config.State != nil {
		// Caddy provisions every candidate before starting any of its apps.
		// Reject persistent-to-persistent replacement at that boundary, before
		// the candidate HTTP app can publish routes. There is no public atomic
		// drain/close/construct/rollback contract for sharing a state directory.
		// The library remains the sole cross-process storage-lock owner.
		if current, err := caddy.ActiveContext().AppIfConfigured(appName); err == nil {
			if old, ok := current.(*App); ok && old != app {
				old.mu.Lock()
				live := old.runtimeConfig != nil && old.server != nil && !old.disposing
				old.mu.Unlock()
				if live {
					return fmt.Errorf("persistent security runtime does not support overlapping reload; stop Caddy and wait for request drain before starting the replacement")
				}
			}
		}
		app.runtimeConfig = &config
		return nil
	}
	return app.constructServer(&config)
}

// constructServer runs with app.mu held, before publishing admission.
func (app *App) constructServer(config *authcrunch.Config) error {
	// Local stores cache independent database snapshots. Until AuthCrunch can
	// coordinate those snapshots, overlapping owners must fail before NewServer
	// can initialize or overwrite users in a file used by the live deployment.
	files, err := reserveIdentityFiles(config)
	if err != nil {
		return err
	}
	app.identityFiles = files

	server, err := authcrunch.NewServer(config, app.logger)
	if err != nil {
		releaseIdentityFiles(app.identityFiles)
		app.identityFiles = nil
		if config.State != nil {
			// Do not put constructor details (possibly containing credentials)
			// into shared Caddy logs or admin API responses.
			return fmt.Errorf("persistent security runtime could not start; ensure the state directory is private and intact and stop its current owner before starting another instance (overlapping reload is unsupported)")
		}
		app.logger.Error(
			"failed provisioning app server instance",
			zap.String("app", app.Name),
			zap.Error(err),
		)
		return err
	}

	app.server = server

	app.logger.Info(
		"provisioned app instance",
		zap.String("app", app.Name),
	)
	return nil
}

// Start starts the App.
func (app *App) Start() error {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.disposing {
		return fmt.Errorf("security app is shutting down")
	}
	if app.runtimeConfig != nil && app.server == nil {
		if err := app.constructServer(app.runtimeConfig); err != nil {
			return err
		}
	}
	app.logger.Debug(
		"started app instance",
		zap.String("app", app.Name),
	)
	return nil
}

// Stop leaves disposal to Cleanup. Caddy stops apps in unspecified order;
// HTTP handlers may still be using this app, even after the HTTP app's Stop.
func (app *App) Stop() error {
	app.logger.Debug(
		"stopped app instance",
		zap.String("app", app.Name),
	)
	return nil
}

// Cleanup prevents new AuthCrunch calls, drains calls already admitted, and
// disposes the runtime once. Caddy invokes it for abandoned candidates as well
// as retired configurations. HTTP shutdown is asynchronous during reload, so
// cancellation of the Caddy module context is not a request-drain guarantee.
// Only this app owns the server; individual route modules never close it.
func (app *App) Cleanup() error {
	app.cleanupOnce.Do(func() {
		app.mu.Lock()
		app.disposing = true
		app.mu.Unlock()
		app.requests.Wait()
		app.cleanupErr = app.server.Close()
		releaseIdentityFiles(app.identityFiles)
	})
	return app.cleanupErr
}

// acquireRequest pins the runtime for one portal/gatekeeper call. Admission and
// WaitGroup.Add share the disposal lock, so no Add can race the cleanup Wait.
func (app *App) acquireRequest() (release func(), ok bool) {
	if app == nil {
		return nil, false
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.disposing || app.server == nil {
		return nil, false
	}
	app.requests.Add(1)
	return app.requests.Done, true
}

func (app *App) getPortal(s string) (*authn.Portal, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if !app.disposing && app.server == nil && app.runtimeConfig != nil {
		for _, p := range app.runtimeConfig.AuthenticationPortals {
			if p.Name == s {
				return nil, nil // Declaration checked; Start has not run yet.
			}
		}
		return nil, fmt.Errorf("authentication portal %q not configured", s)
	}
	if app.disposing || app.server == nil {
		return nil, authcrunch.ErrServerClosed
	}
	return app.server.GetPortalByName(s)
}

func (app *App) getGatekeeper(s string) (*authz.Gatekeeper, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if !app.disposing && app.server == nil && app.runtimeConfig != nil {
		for _, p := range app.runtimeConfig.AuthorizationPolicies {
			if p.Name == s {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("authorization policy %q not configured", s)
	}
	if app.disposing || app.server == nil {
		return nil, authcrunch.ErrServerClosed
	}
	return app.server.GetGatekeeperByName(s)
}
