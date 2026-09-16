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
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// resolvePortalTokenRefresh resolves each value once, before portal validation.
// A deferred Caddyfile body and native JSON config are mutually exclusive.
func resolvePortalTokenRefresh(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, config *authcrunch.Config, directives map[string][]string, log *zap.Logger) error {
	portals := make(map[string]*authn.PortalConfig, len(config.AuthenticationPortals))
	for _, portal := range config.AuthenticationPortals {
		if _, exists := portals[portal.Name]; exists {
			return fmt.Errorf("duplicate token refresh portal %q", portal.Name)
		}
		portals[portal.Name] = portal
	}
	for name := range directives {
		if portals[name] == nil {
			return fmt.Errorf("token refresh portal %q not found", name)
		}
	}
	for _, portal := range config.AuthenticationPortals {
		if body, exists := directives[portal.Name]; exists {
			if portal.RefreshTokens != nil {
				return fmt.Errorf("portal %q has both token refresh directives and config", portal.Name)
			}
			// Preserve token boundaries and whitespace through replacement. In
			// particular, a replacement cannot inject another setting or realm.
			resolved := make([]string, 0, len(body))
			for i, statement := range body {
				if strings.ContainsAny(statement, "\r\n") {
					return fmt.Errorf("portal %q: invalid token refresh statement %d", portal.Name, i)
				}
				args, err := cfgutil.DecodeArgs(statement)
				if err != nil || len(args) == 0 {
					return fmt.Errorf("portal %q: invalid token refresh statement %d", portal.Name, i)
				}
				args, err = substituteStrings(ctx, repl, managers, "PortalTokenRefreshDirectives", args, log)
				if err != nil {
					return err
				}
				if err := validateOAuthDirectiveTokens(args); err != nil {
					return fmt.Errorf("portal %q: invalid token refresh argument", portal.Name)
				}
				resolved = append(resolved, encodeOAuthDirective(args))
			}
			if err := configurePortalTokenRefresh(portal, resolved); err != nil {
				return fmt.Errorf("portal %q token refresh: %w", portal.Name, err)
			}
			continue
		}
		cfg := portal.RefreshTokens
		if cfg == nil {
			continue
		}
		for field, value := range map[string]*string{"PublicOrigin": &cfg.PublicOrigin, "BasePath": &cfg.BasePath, "CookieName": &cfg.CookieName} {
			resolved, err := substituteString(ctx, repl, managers, "RefreshTokens."+field, *value, log)
			if err != nil {
				return err
			}
			*value = resolved
		}
		realms := cfg.Realms
		var err error
		if realms != nil {
			realms, err = substituteStrings(ctx, repl, managers, "RefreshTokens.Realms", realms, log)
		}
		if err != nil {
			return err
		}
		cfg.Realms = realms
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("portal %q token refresh: %w", portal.Name, err)
		}
	}
	return nil
}
