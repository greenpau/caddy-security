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

// resolvePortalDocuments handles native strings or a complete deferred snapshot,
// before portal validation. Substituted values are never expanded a second time.
func resolvePortalDocuments(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, config *authcrunch.Config, directives map[string][]string, log *zap.Logger) error {
	portals := make(map[string]*authn.PortalConfig, len(config.AuthenticationPortals))
	for _, portal := range config.AuthenticationPortals {
		if portal == nil {
			return fmt.Errorf("documents portal configuration is nil")
		}
		if _, exists := portals[portal.Name]; exists {
			return fmt.Errorf("duplicate documents portal %q", portal.Name)
		}
		portals[portal.Name] = portal
	}
	for name, body := range directives {
		if portals[name] == nil {
			return fmt.Errorf("documents portal %q not found", name)
		}
		if len(body) == 0 {
			return fmt.Errorf("portal %q has an empty documents snapshot", name)
		}
	}
	for _, portal := range config.AuthenticationPortals {
		enabled := portal.API != nil && portal.API.DocumentsEnabled
		if body, exists := directives[portal.Name]; exists {
			if portal.Documents != nil || enabled {
				return fmt.Errorf("portal %q has both documents directives and config", portal.Name)
			}
			resolved := make([]string, 0, len(body))
			for i, statement := range body {
				if strings.ContainsAny(statement, "\r\n") {
					return fmt.Errorf("portal %q: invalid documents statement %d", portal.Name, i)
				}
				args, err := cfgutil.DecodeArgs(statement)
				if err != nil || len(args) == 0 || validateOAuthDirectiveTokens(args) != nil {
					return fmt.Errorf("portal %q: invalid documents statement %d", portal.Name, i)
				}
				args, err = substituteStrings(ctx, repl, managers, "PortalDocumentsDirectives", args, log)
				if err != nil {
					return err
				}
				if validateOAuthDirectiveTokens(args) != nil {
					return fmt.Errorf("portal %q: invalid documents argument", portal.Name)
				}
				resolved = append(resolved, encodeOAuthDirective(args))
			}
			if err := configurePortalDocuments(portal, resolved); err != nil {
				return fmt.Errorf("portal %q documents API: %w", portal.Name, err)
			}
			continue
		}
		if portal.Documents == nil {
			if enabled {
				return fmt.Errorf("portal %q documents API requires storage configuration", portal.Name)
			}
			continue
		}
		storage := *portal.Documents
		for _, field := range []struct {
			name  string
			value *string
		}{{"Database", &storage.Database}, {"PublicOrigin", &storage.PublicOrigin}, {"BasePath", &storage.BasePath}} {
			value, err := substituteString(ctx, repl, managers, "Documents."+field.name, *field.value, log)
			if err != nil {
				return err
			}
			*field.value = value
		}
		if storage.Realms != nil {
			values, err := substituteStrings(ctx, repl, managers, "Documents.Realms", storage.Realms, log)
			if err != nil {
				return err
			}
			storage.Realms = values
		}
		if enabled {
			if err := storage.Validate(); err != nil {
				return fmt.Errorf("portal %q documents API: %w", portal.Name, err)
			}
		}
		portal.Documents = &storage
	}
	return nil
}
