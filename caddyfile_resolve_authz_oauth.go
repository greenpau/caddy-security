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
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// resolveOAuthAuthorization applies complete snapshots before ordinary policy
// defaults. Never resolve derived defaults or substituted tokens a second time.
func resolveOAuthAuthorization(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, config *authcrunch.Config, directives map[string][]string, log *zap.Logger) error {
	policies := make(map[string]*authz.PolicyConfig, len(config.AuthorizationPolicies))
	for _, policy := range config.AuthorizationPolicies {
		if policies[policy.Name] != nil {
			return fmt.Errorf("duplicate authorization policy %q", policy.Name)
		}
		policies[policy.Name] = policy
	}
	for name := range directives {
		if policies[name] == nil {
			return fmt.Errorf("OAuth authorization policy %q not found", name)
		}
	}
	for _, policy := range config.AuthorizationPolicies {
		if body, exists := directives[policy.Name]; exists {
			if policy.OAuth != nil || len(body) == 0 {
				return fmt.Errorf("policy %q requires nonempty OAuth directives without typed OAuth config", policy.Name)
			}
			resolved := make([]string, 0, len(body))
			for i, statement := range body {
				path := fmt.Sprintf("OAuthAuthorizationDirectives[%q][%d]", policy.Name, i)
				if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
					return fmt.Errorf("%s: invalid OAuth authorization statement", path)
				}
				args, err := cfgutil.DecodeArgs(statement)
				if err != nil || len(args) == 0 || validateOAuthDirectiveTokens(args) != nil {
					return fmt.Errorf("%s: invalid OAuth authorization statement", path)
				}
				args, err = substituteStrings(ctx, repl, managers, path, args, log)
				if err != nil {
					return err
				}
				if err := validateOAuthDirectiveTokens(args); err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				resolved = append(resolved, encodeOAuthDirective(args))
			}
			oauth, err := oauthparser.NewOAuthAuthorizationConfigFromDirectives(policy.Name, resolved)
			if err != nil {
				return fmt.Errorf("policy %q: %w", policy.Name, err)
			}
			if err := policy.ConfigureOAuth(oauth); err != nil {
				return fmt.Errorf("policy %q: %w", policy.Name, err)
			}
			continue
		}
		if cfg := policy.OAuth; cfg != nil {
			for field, value := range map[string]*string{
				"IdentityProvider": &cfg.IdentityProvider, "PublicOrigin": &cfg.PublicOrigin,
				"BasePath": &cfg.BasePath, "SessionCookieName": &cfg.SessionCookieName, "LoginCookieName": &cfg.LoginCookieName,
			} {
				resolved, err := substituteString(ctx, repl, managers, "OAuth."+field, *value, log)
				if err != nil {
					return err
				}
				*value = resolved
			}
			if err := cfg.Validate(policy.Name); err != nil {
				return fmt.Errorf("policy %q: %w", policy.Name, err)
			}
		}
	}
	return nil
}
