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
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// validateRefreshStoreInputText rejects malformed native selector bytes before
// the app's initial JSON snapshot could repair them. This performs no defaults,
// replacement, semantic validation or I/O.
func validateRefreshStoreInputText(config *authcrunch.Config) error {
	if config == nil {
		return fmt.Errorf("refresh storage configuration is unavailable")
	}
	for _, portal := range config.AuthenticationPortals {
		if portal != nil && portal.RefreshTokens != nil && !utf8.ValidString(portal.RefreshTokens.Store) {
			return fmt.Errorf("refresh storage selection text is invalid")
		}
	}
	return nil
}

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
				if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
					return fmt.Errorf("portal %q: invalid token refresh statement %d", portal.Name, i)
				}
				args, err := cfgutil.DecodeArgs(statement)
				if err != nil || len(args) == 0 {
					return fmt.Errorf("portal %q: invalid token refresh statement %d", portal.Name, i)
				}
				// Resolve value positions only. The shared parser owns the
				// complete grammar; store and realms have one-word keywords.
				offset := len(args)
				if len(args) == 1 {
					// The enabled/disabled statement may itself be deferred.
					// Preserve its existing single-token replacement contract.
					offset = 0
				}
				switch args[0] {
				case "realms", "store":
					offset = 1
				case "public", "base", "cookie", "access", "idle", "absolute", "body", "max", "provider":
					if len(args) >= 2 {
						offset = 2
					}
				}
				for index := offset; index < len(args); index++ {
					original := args[index]
					value, err := substituteString(ctx, repl, managers, "PortalTokenRefreshDirectives", original, log)
					if err != nil {
						return err
					}
					if args[0] == "store" && original != "" && value == "" {
						return fmt.Errorf("portal %q refresh storage replacement is invalid", portal.Name)
					}
					args[index] = value
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
		originalStore := cfg.Store
		resolvedStore, err := substituteString(ctx, repl, managers, "RefreshTokens.Store", originalStore, log)
		if err != nil || originalStore != "" && resolvedStore == "" || !utf8.ValidString(resolvedStore) || strings.TrimSpace(resolvedStore) != resolvedStore || strings.ContainsFunc(resolvedStore, unicode.IsControl) {
			return fmt.Errorf("portal %q refresh storage replacement is invalid", portal.Name)
		}
		cfg.Store = resolvedStore
		for field, value := range map[string]*string{"PublicOrigin": &cfg.PublicOrigin, "BasePath": &cfg.BasePath, "CookieName": &cfg.CookieName} {
			resolved, err := substituteString(ctx, repl, managers, "RefreshTokens."+field, *value, log)
			if err != nil {
				return err
			}
			*value = resolved
		}
		realms := cfg.Realms
		if realms != nil {
			realms, err = substituteStrings(ctx, repl, managers, "RefreshTokens.Realms", realms, log)
		}
		if err != nil {
			return err
		}
		cfg.Realms = realms
		for i := range cfg.ProviderRevalidation {
			provider := &cfg.ProviderRevalidation[i]
			for _, field := range []struct {
				name  string
				value *string
			}{{"Realm", &provider.Realm}, {"Mode", &provider.Mode}} {
				path := fmt.Sprintf("RefreshTokens.ProviderRevalidation[%d].%s", i, field.name)
				resolved, err := substituteString(ctx, repl, managers, path, *field.value, log)
				if err != nil {
					return err
				}
				*field.value = resolved
			}
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("portal %q token refresh: %w", portal.Name, err)
		}
	}
	return nil
}
