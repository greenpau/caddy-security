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
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// validateAccessTokenInputText preserves exact native input before the app's JSON
// snapshot can replace malformed UTF-8. It performs no replacement, defaults,
// semantic validation, mutation or I/O; placeholders remain valid input here.
func validateAccessTokenInputText(config *authcrunch.Config) error {
	if config == nil {
		return fmt.Errorf("access token configuration is unavailable")
	}
	check := func(selection string, profile *kms.AccessTokenProfileConfig) bool {
		if !utf8.ValidString(selection) {
			return false
		}
		if profile == nil {
			return true
		}
		if !utf8.ValidString(profile.Issuer) || !utf8.ValidString(profile.Audience) {
			return false
		}
		for _, id := range profile.KeyIDs {
			if !utf8.ValidString(id) {
				return false
			}
		}
		return true
	}
	for _, portal := range config.AuthenticationPortals {
		if portal != nil && !check(portal.AccessSigner, portal.AccessTokenProfile) {
			return fmt.Errorf("portal access token text is invalid")
		}
	}
	for _, policy := range config.AuthorizationPolicies {
		if policy != nil && !check("", policy.AccessTokenProfile) {
			return fmt.Errorf("policy access token text is invalid")
		}
	}
	return nil
}

// resolveAccessTokens handles typed values or complete deferred profiles before
// consumer validation. Backend module configuration remains literal and separate.
func resolveAccessTokens(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, config *authcrunch.Config, portalDirectives, policyDirectives map[string][]string) error {
	if config == nil {
		return fmt.Errorf("access token configuration is unavailable")
	}
	portals, policies := make(map[string]bool), make(map[string]bool)
	for _, portal := range config.AuthenticationPortals {
		if portal == nil || portals[portal.Name] {
			return fmt.Errorf("access token profile requires unique nonnull portals")
		}
		portals[portal.Name] = true
	}
	for _, policy := range config.AuthorizationPolicies {
		if policy == nil || policies[policy.Name] {
			return fmt.Errorf("access token profile requires unique nonnull policies")
		}
		policies[policy.Name] = true
	}
	for name := range portalDirectives {
		if !portals[name] {
			return fmt.Errorf("access token profile portal was not found")
		}
	}
	for name := range policyDirectives {
		if !policies[name] {
			return fmt.Errorf("access token profile policy was not found")
		}
	}
	for i, portal := range config.AuthenticationPortals {
		original := portal.AccessSigner
		selection, err := substituteString(ctx, repl, managers, "AccessSigner", original, zap.NewNop())
		if err != nil || original != "" && selection == "" || !utf8.ValidString(selection) || strings.ContainsFunc(selection, unicode.IsControl) || strings.TrimSpace(selection) != selection {
			return fmt.Errorf("portal %d access signer replacement is invalid", i)
		}
		body, deferred := portalDirectives[portal.Name]
		profile, err := resolveAccessTokenProfile(ctx, repl, managers, portal.AccessTokenProfile, body, deferred)
		if err != nil {
			return fmt.Errorf("portal %d access token profile replacement is invalid", i)
		}
		portal.AccessSigner, portal.AccessTokenProfile = selection, profile
	}
	for i, policy := range config.AuthorizationPolicies {
		body, deferred := policyDirectives[policy.Name]
		profile, err := resolveAccessTokenProfile(ctx, repl, managers, policy.AccessTokenProfile, body, deferred)
		if err != nil {
			return fmt.Errorf("policy %d access token profile replacement is invalid", i)
		}
		policy.AccessTokenProfile = profile
	}
	return nil
}

func resolveAccessTokenProfile(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, native *kms.AccessTokenProfileConfig, statements []string, deferred bool) (*kms.AccessTokenProfileConfig, error) {
	invalid := func() (*kms.AccessTokenProfileConfig, error) {
		return nil, fmt.Errorf("invalid access token profile replacement")
	}
	if deferred {
		if native != nil || len(statements) == 0 {
			return invalid()
		}
		resolved := make([]string, 0, len(statements))
		for _, statement := range statements {
			if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
				return invalid()
			}
			args, err := cfgutil.DecodeArgs(statement)
			if err != nil || len(args) == 0 || validateOAuthDirectiveTokens(args) != nil {
				return invalid()
			}
			// These offsets identify values only. The shared parser still owns
			// complete grammar, arity, duplicate and semantic validation. Unknown
			// keywords stay literal and therefore cannot resolve into a setting.
			offset := len(args)
			switch args[0] {
			case "issuer", "audience":
				offset = 1
			case "key", "max":
				if len(args) >= 2 && (args[0] == "key" && args[1] == "ids" || args[0] == "max" && args[1] == "lifetime") {
					offset = 2
				}
			}
			for i := offset; i < len(args); i++ {
				value, err := substituteString(ctx, repl, managers, "AccessTokenProfile", args[i], zap.NewNop())
				if err != nil {
					return invalid()
				}
				args[i] = value
			}
			if validateOAuthDirectiveTokens(args) != nil {
				return invalid()
			}
			resolved = append(resolved, encodeOAuthDirective(args))
		}
		return parseAccessTokenProfile(resolved)
	}
	if native == nil {
		return nil, nil
	}
	copy := *native
	copy.KeyIDs = slices.Clone(native.KeyIDs)
	values := []*string{&copy.Issuer, &copy.Audience}
	for i := range copy.KeyIDs {
		values = append(values, &copy.KeyIDs[i])
	}
	for _, value := range values {
		resolved, err := substituteString(ctx, repl, managers, "AccessTokenProfile", *value, zap.NewNop())
		if err != nil {
			return invalid()
		}
		*value = resolved
	}
	if copy.Validate() != nil {
		return invalid()
	}
	return &copy, nil
}
