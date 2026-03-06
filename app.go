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

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"

	"go.uber.org/zap"
)

var (
	appName = "security"

	// Interface guards
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Module      = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)

func init() {
	caddy.RegisterModule(App{})
}

type SecretsManager interface {
	GetSecret(context.Context) (map[string]interface{}, error)
	GetSecretByKey(context.Context, string) (interface{}, error)
}

// App implements security manager.
type App struct {
	Name   string             `json:"-"`
	Config *authcrunch.Config `json:"config,omitempty"`

	SecretsManagersRaw []json.RawMessage `json:"secrets_managers,omitempty" caddy:"namespace=security.secrets inline_key=driver"`
	secretsManagers    []SecretsManager

	server *authcrunch.Server
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "security",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the repo manager.
func (app *App) Provision(ctx caddy.Context) error {
	app.Name = appName
	app.logger = ctx.Logger(app)

	app.logger.Info(
		"provisioning app instance",
		zap.String("app", app.Name),
	)

	secretsManagerMods, err := ctx.LoadModule(app, "SecretsManagersRaw")
	if err != nil {
		app.logger.Error(
			"app failed loading secrets manager plugins",
			zap.String("app_name", app.Name),
			zap.Error(err),
		)
		return err
	}

	for _, mod := range secretsManagerMods.([]any) {
		app.secretsManagers = append(app.secretsManagers, mod.(SecretsManager))
	}

	resolvedConfig, err := resolveRuntimeConfig(app.Config)
	if err != nil {
		app.logger.Error(
			"failed resolving app config placeholders",
			zap.String("app", app.Name),
			zap.Error(err),
		)
		return err
	}

	server, err := authcrunch.NewServer(resolvedConfig, app.logger)
	if err != nil {
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

func resolveRuntimeConfig(cfg *authcrunch.Config) (*authcrunch.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	repl := caddy.NewReplacer()
	resolvedCfg := &authcrunch.Config{}

	var err error
	if resolvedCfg.Credentials, err = cloneResolvedCredentialsConfig(cfg.Credentials, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.Messaging, err = cloneResolvedMessagingConfig(cfg.Messaging, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.AuthenticationPortals, err = cloneResolvedPortalConfigs(cfg.AuthenticationPortals, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.AuthorizationPolicies, err = cloneResolvedPolicyConfigs(cfg.AuthorizationPolicies, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.IdentityStores, err = cloneResolvedIdentityStoreConfigs(cfg.IdentityStores, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.IdentityProviders, err = cloneResolvedIdentityProviderConfigs(cfg.IdentityProviders, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.SingleSignOnProviders, err = cloneResolvedSingleSignOnProviderConfigs(cfg.SingleSignOnProviders, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.UserRegistries, err = cloneResolvedUserRegistryConfigs(cfg.UserRegistries, repl); err != nil {
		return nil, err
	}

	return resolvedCfg, nil
}

// Start starts the App.
func (app App) Start() error {
	app.logger.Debug(
		"started app instance",
		zap.String("app", app.Name),
	)
	return nil
}

// Stop stops the App.
func (app App) Stop() error {
	app.logger.Debug(
		"stopped app instance",
		zap.String("app", app.Name),
	)
	return nil
}

func (app *App) getPortal(s string) (*authn.Portal, error) {
	return app.server.GetPortalByName(s)
}

func (app *App) getGatekeeper(s string) (*authz.Gatekeeper, error) {
	return app.server.GetGatekeeperByName(s)
}
