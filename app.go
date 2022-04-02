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

// App implements security manager.
type App struct {
	Name   string             `json:"-"`
	Config *authcrunch.Config `json:"config,omitempty"`
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

	server, err := authcrunch.NewServer(app.Config, app.logger)
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
