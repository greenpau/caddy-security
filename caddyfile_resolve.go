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

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

func replaceSecretValue(ctx context.Context, secretManagers []SecretsManager, secretPath string) (string, bool, error) {
	if !hasSecretKey(secretPath) {
		return "", false, fmt.Errorf("path has no secrets")
	}
	parts := strings.Split(secretPath, ":")
	secretsManagerID := parts[1]
	secretKey := parts[2]
	for _, secretManager := range secretManagers {
		cfg := secretManager.GetConfig(ctx)
		if cfg == nil {
			continue
		}
		identifier, found := cfg["id"].(string)
		if !found {
			continue
		}
		if identifier == "" {
			continue
		}
		if identifier != secretsManagerID {
			continue
		}
		secretValueRaw, err := secretManager.GetSecretByKey(ctx, secretKey)
		if err != nil {
			return secretPath, false, err
		}
		secretValue, ok := secretValueRaw.(string)
		if !ok {
			return secretPath, false, fmt.Errorf("secret value is not a string")
		}
		return secretValue, true, nil
	}
	return secretPath, false, fmt.Errorf("secret key value was not replaced")
}

func hasSecretKey(s string) bool {

	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") {
		s = strings.Trim(s, "\"")
	}
	parts := strings.Split(s, ":")
	return len(parts) == 3 && parts[0] == "secrets"
}

func substitute(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, data map[string]interface{}, path string, log *zap.Logger) error {
	for key := range data {
		replacedKeyStr, err := substituteString(ctx, repl, secretManagers, path, key, log)
		if err != nil {
			return err
		}
		if key != replacedKeyStr {
			data[replacedKeyStr] = data[key]
			delete(data, key)
		}
	}

	for key, value := range data {
		// Build the path string for clear logging (e.g., "users[0].username")
		currentPath := key
		if path != "" {
			currentPath = fmt.Sprintf("%s.%s", path, key)
		}

		switch v := value.(type) {
		case bool, float32, float64:
			continue
		case string:
			if replacedStr, err := substituteString(ctx, repl, secretManagers, currentPath, v, log); err != nil {
				return err
			} else {
				data[key] = replacedStr
			}
		case []string:
			if replacedStrs, err := substituteStrings(ctx, repl, secretManagers, currentPath, v, log); err != nil {
				return err
			} else {
				data[key] = replacedStrs
			}
		case map[string]interface{}:
			if err := substitute(ctx, repl, secretManagers, v, currentPath, log); err != nil {
				return err
			}
		case []interface{}:
			if len(v) == 0 {
				continue
			}
			// Inspect the first element to determine if this is a list of strings or maps
			switch first := v[0].(type) {
			case bool:
				continue
			case string:
				// Validate that every element in the interface slice is a string
				entries := []string{}
				for i, item := range v {
					vStr, ok := item.(string)
					if !ok {
						log.Error("mixed types in string list",
							zap.String("path", currentPath),
							zap.Int("index", i),
							zap.String("found_type", fmt.Sprintf("%T", item)),
						)
						return fmt.Errorf("found mixed types in list: %s", currentPath)
					}
					entry, err := substituteString(ctx, repl, secretManagers, path, vStr, log)
					if err != nil {
						return err
					}
					entries = append(entries, entry)
				}
				data[key] = entries
			case map[string]interface{}:
				for i, item := range v {
					m, ok := item.(map[string]interface{})
					if !ok {
						return fmt.Errorf("expected object in list: %s[%d]", currentPath, i)
					}
					if err := substitute(ctx, repl, secretManagers, m, fmt.Sprintf("%s[%d]", currentPath, i), log); err != nil {
						return err
					}
				}
			case []interface{}:
				// Detected list of lists, process each sub-list
				for i, item := range v {
					subList, ok := item.([]interface{})
					if !ok {
						log.Error("mixed types in nested list",
							zap.String("path", currentPath),
							zap.Int("index", i),
							zap.String("found_type", fmt.Sprintf("%T", item)),
						)
						return fmt.Errorf("found mixed types in nested list: %s[%d]", currentPath, i)
					}

					// Process the sub-list elements
					for j, subItem := range subList {
						subPath := fmt.Sprintf("%s[%d][%d]", currentPath, i, j)
						switch si := subItem.(type) {
						case string:
							if replaced, err := substituteString(ctx, repl, secretManagers, subPath, si, log); err != nil {
								return err
							} else {
								subList[j] = replaced
							}
						case map[string]interface{}:
							if err := substitute(ctx, repl, secretManagers, si, subPath, log); err != nil {
								return err
							}
						case []interface{}:
							log.Warn("deeply nested list detected, processing limited to 2 levels", zap.String("path", subPath))
						}
					}
				}
			default:
				log.Error("unsupported slice element type",
					zap.String("path", currentPath),
					zap.String("type", fmt.Sprintf("%T", first)),
				)
				return fmt.Errorf("unsupported slice element type: %s", currentPath)
			}
		default:
			log.Error("unexpected field type",
				zap.String("path", currentPath),
				zap.String("type", fmt.Sprintf("%T", v)),
			)
			return fmt.Errorf("unexpected field type: %s", currentPath)
		}
	}
	return nil
}

func substituteString(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, path, value string, log *zap.Logger) (string, error) {
	if replacedValue, _, err := util.FindReplace(repl, value); err == nil {
		if hasSecretKey(replacedValue) {
			replacedSecret, secretReplaced, err := replaceSecretValue(ctx, secretManagers, replacedValue)
			if err != nil {
				log.Error("failed to replaced text",
					zap.String("path", path),
					zap.String("from", replacedValue),
				)
				return "", fmt.Errorf("%s: %v", path, err)
			}
			if secretReplaced {
				// log.Info("replaced text",
				// 	zap.String("path", currentPath),
				// 	zap.String("from", replacedValue),
				// 	zap.String("to", replacedSecret),
				// )
				return replacedSecret, nil
			}
		} else {
			return replacedValue, nil
		}
	} else {
		return "", fmt.Errorf("%s: %v", path, err)
	}

	return value, nil
}

func substituteStrings(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, path string, values []string, log *zap.Logger) ([]string, error) {
	entries := []string{}
	for _, value := range values {
		entry, err := substituteString(ctx, repl, secretManagers, path, value, log)
		if err != nil {
			return entries, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// validateProviderInstructions guards the kind dispatch in AuthCrunch, which
// reads its second argument before the provider-specific parser validates it.
func validateProviderInstructions(path string, instructions []string) error {
	for i, instruction := range instructions {
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", path, i, err)
		}
		if args[0] == "kind" && (len(args) != 2 || args[1] == "") {
			return fmt.Errorf("%s[%d]: kind requires one nonempty argument", path, i)
		}
	}
	return nil
}

// Resolve each encoded argument separately. Replacing an entire statement can
// turn spaces or quotes in a secret into syntax, and hides secret references
// behind the statement's command word.
func resolveConfigInstructions(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, field string, instructions []string, minimumArguments int, log *zap.Logger) ([]string, error) {
	entries := make([]string, 0, len(instructions))
	for i, instruction := range instructions {
		path := fmt.Sprintf("%s[%d]", field, i)
		args, err := cfgutil.DecodeArgs(instruction)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		args, err = substituteStrings(ctx, repl, secretManagers, path, args, log)
		if err != nil {
			return nil, err
		}
		// Guard upstream argument indexing before parsing. EncodeArgs trims
		// trailing empty tokens, so reject them before they can change syntax.
		if len(args) < minimumArguments {
			return nil, fmt.Errorf("%s: requires at least %d arguments", path, minimumArguments)
		}
		for j, arg := range args {
			if arg == "" {
				return nil, fmt.Errorf("%s: argument %d must not be empty", path, j)
			}
		}
		entries = append(entries, cfgutil.EncodeArgs(args))
	}
	return entries, nil
}

// ResolveRuntimeAppConfig uses caddy.Replacer to replace strings in App config.
func ResolveRuntimeAppConfig(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, config *authcrunch.Config, log *zap.Logger) error {
	return resolveRuntimeAppConfig(ctx, repl, secretManagers, config, nil, nil, log)
}

// resolveRuntimeAppConfig also consumes deferred Caddy OAuth and token refresh
// statements. JSON-only AuthCrunch configurations retain typed replacement.
func resolveRuntimeAppConfig(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, config *authcrunch.Config, oauthDirectives, tokenRefreshDirectives map[string][]string, log *zap.Logger) error {
	if config == nil {
		return fmt.Errorf("security app config is nil")
	}
	if err := validateConfigObjects(config); err != nil {
		return err
	}
	if err := resolvePortalTokenRefresh(ctx, repl, secretManagers, config, tokenRefreshDirectives, log); err != nil {
		return err
	}
	// These Validate methods parse raw instructions. Empty or already-parsed
	// sections do not need reparsing, which would reject valid typed configs.
	if config.Credentials != nil && len(config.Credentials.RawCredentialConfigs) > 0 {
		rawCredentialConfigs := [][]string{}
		for i, rawCredentialConfig := range config.Credentials.RawCredentialConfigs {
			path := fmt.Sprintf("RawCredentialConfigs[%d]", i)
			if values, err := resolveConfigInstructions(ctx, repl, secretManagers, path, rawCredentialConfig, 2, log); err == nil {
				rawCredentialConfigs = append(rawCredentialConfigs, values)
			} else {
				return err
			}
		}
		config.Credentials.RawCredentialConfigs = rawCredentialConfigs
		if err := config.Credentials.Validate(); err != nil {
			return err
		}
	}

	if config.Messaging != nil && len(config.Messaging.RawConfigs) > 0 {
		rawMessagingConfigs := [][]string{}
		for i, rawMessagingConfig := range config.Messaging.RawConfigs {
			path := fmt.Sprintf("RawMessagingConfigs[%d]", i)
			if values, err := resolveConfigInstructions(ctx, repl, secretManagers, path, rawMessagingConfig, 1, log); err == nil {
				if err := validateProviderInstructions(path, values); err != nil {
					return err
				}
				rawMessagingConfigs = append(rawMessagingConfigs, values)
			} else {
				return err
			}
		}
		config.Messaging.RawConfigs = rawMessagingConfigs
		if err := config.Messaging.Validate(); err != nil {
			return err
		}
	}

	if config.UserRegistration != nil && len(config.UserRegistration.RawConfigs) > 0 {
		rawUserRegistrationConfigs := [][]string{}
		for i, rawRegistrationConfig := range config.UserRegistration.RawConfigs {
			path := fmt.Sprintf("RawUserRegistrationConfigs[%d]", i)
			if values, err := resolveConfigInstructions(ctx, repl, secretManagers, path, rawRegistrationConfig, 1, log); err == nil {
				if err := validateProviderInstructions(path, values); err != nil {
					return err
				}
				rawUserRegistrationConfigs = append(rawUserRegistrationConfigs, values)
			} else {
				return err
			}
		}
		config.UserRegistration.RawConfigs = rawUserRegistrationConfigs
		if err := config.UserRegistration.Validate(); err != nil {
			return err
		}
	}

	for _, cfg := range config.IdentityStores {
		if err := substitute(ctx, repl, secretManagers, cfg.Params, "", log); err != nil {
			return err
		}
		if err := validateIdentityParameters(cfg.Kind, cfg.Params); err != nil {
			return fmt.Errorf("identity store %q parameters: %w", cfg.Name, err)
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	// A snapshot must identify exactly one OAuth provider. Do not permit JSON
	// snapshots to silently target a missing, duplicate, or different-kind entry.
	for name := range oauthDirectives {
		matches := 0
		for _, cfg := range config.IdentityProviders {
			if cfg.Name == name {
				if cfg.Kind != "oauth" {
					return fmt.Errorf("OAuth directives target a non-OAuth provider %q", name)
				}
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("OAuth directives require exactly one provider named %q", name)
		}
	}
	for _, cfg := range config.IdentityProviders {
		if statements, ok := oauthDirectives[cfg.Name]; ok {
			// Snapshots recompute defaults, not the shared dispatcher's allowlist.
			// A JSON snapshot must not hide unsupported fields in its target map.
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid OAuth snapshot target %q", cfg.Name)
			}
			resolved, err := resolveOAuthProviderDirectives(ctx, repl, secretManagers, cfg.Name, statements, log)
			if err != nil {
				return err
			}
			cfg.Params = resolved.Params
		} else if err := substitute(ctx, repl, secretManagers, cfg.Params, "", log); err != nil {
			return err
		}
		if err := validateIdentityParameters(cfg.Kind, cfg.Params); err != nil {
			return fmt.Errorf("identity provider %q parameters: %w", cfg.Name, err)
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	for _, cfg := range config.SingleSignOnProviders {
		if value, err := substituteString(ctx, repl, secretManagers, "EntityID", cfg.EntityID, log); err == nil {
			cfg.EntityID = value
		} else {
			return err
		}
		if value, err := substituteString(ctx, repl, secretManagers, "CertPath", cfg.CertPath, log); err == nil {
			cfg.CertPath = value
		} else {
			return err
		}
		if value, err := substituteString(ctx, repl, secretManagers, "PrivateKeyPath", cfg.PrivateKeyPath, log); err == nil {
			cfg.PrivateKeyPath = value
		} else {
			return err
		}
		if values, err := substituteStrings(ctx, repl, secretManagers, "Locations", cfg.Locations, log); err == nil {
			cfg.Locations = values
		} else {
			return err
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	for _, cfg := range config.AuthenticationPortals {
		// Crypto configs
		entries, err := resolveConfigInstructions(ctx, repl, secretManagers, "RawCryptoKeyStoreConfigs", cfg.GetRawCryptoKeyStoreConfig(), 2, log)
		if err != nil {
			return fmt.Errorf("portal %q: %w", cfg.Name, err)
		}
		cfg.OverwriteRawCryptoKeyStoreConfig(entries)

		// Claim templates belong to AuthCrunch at login. Preserve that namespace
		// only for transform arguments, without teaching the shared Caddy replacer
		// to accept unknown placeholders elsewhere or expanding inserted data twice.
		transformRepl := caddy.NewEmptyReplacer()
		transformRepl.Map(func(key string) (any, bool) {
			if strings.HasPrefix(key, "claims.") {
				return "{" + key + "}", true
			}
			return repl.Get(key)
		})
		// User Transforms
		for i, trCfg := range cfg.UserTransformerConfigs {
			path := fmt.Sprintf("portal %q transform %d", cfg.Name, i)
			// The shared transform compiler rejects multiline instructions. Check
			// before DecodeArgs, whose CSV reader otherwise discards later records.
			for _, instructions := range [][]string{trCfg.Actions, trCfg.Matchers} {
				for _, instruction := range instructions {
					if strings.ContainsAny(instruction, "\r\n") {
						return fmt.Errorf("%s: user transformer instructions must be single-line", path)
					}
				}
			}
			actions, err := resolveConfigInstructions(ctx, transformRepl, secretManagers, path+" actions", trCfg.Actions, 1, log)
			if err != nil {
				return err
			}
			matchers, err := resolveConfigInstructions(ctx, transformRepl, secretManagers, path+" matchers", trCfg.Matchers, 1, log)
			if err != nil {
				return err
			}
			trCfg.Actions, trCfg.Matchers = actions, matchers
			if _, err := transformparser.CompileUserTransformerConfig(trCfg); err != nil {
				return fmt.Errorf("%s: invalid resolved user transformer configuration", path)
			}
			// ACL conditions join decoded arguments before recognizing match any.
			// Native JSON can encode it as a single quoted argument, including
			// through replacement. Check the same meaning after shared validation.
			matchesAny := slices.ContainsFunc(matchers, func(matcher string) bool {
				args, err := cfgutil.DecodeArgs(matcher)
				return err == nil && strings.Join(args, " ") == "match any"
			})
			// AuthCrunch v1.3.3 implements match any through the exp field, but
			// refresh/OIDC identity checks transform claims before adding exp.
			// Reject that combination instead of silently losing actions/policy.
			if (cfg.RefreshTokens != nil && cfg.RefreshTokens.Enabled || cfg.OIDCProvider != nil && cfg.OIDCProvider.Enabled) && matchesAny {
				return fmt.Errorf("%s: match any transforms are unsupported with portal refresh or OIDC; use an explicit realm matcher", path)
			}
			if matchesAny {
				// Encrypted System API assertions also transform untimed claims.
				// Use the shared key parser to identify usage, including resolved
				// arguments, without mistaking key material for a usage keyword.
				keyStore, err := kms.NewCryptoKeyStoreConfig(entries)
				if err != nil {
					return fmt.Errorf("%s: invalid resolved crypto configuration", path)
				}
				if len(keyStore.RawKeyConfigs) > 0 {
					keys, err := kms.ParseCryptoKeyConfigs(keyStore.RawKeyConfigs)
					if err != nil {
						return fmt.Errorf("%s: invalid resolved crypto key configuration", path)
					}
					if slices.ContainsFunc(keys, func(key *kms.CryptoKeyConfig) bool { return key.Usage == "system" }) {
						return fmt.Errorf("%s: match any transforms are unsupported with System API keys; use an explicit realm matcher", path)
					}
				}
			}
		}

		// Optional settings may be absent in JSON configurations. Leave their
		// defaults to AuthCrunch after resolving the values actually supplied.
		if cfg.UI != nil {
			if value, err := substituteString(ctx, repl, secretManagers, "UI.LogoURL", cfg.UI.LogoURL, log); err == nil {
				cfg.UI.LogoURL = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.LogoDescription", cfg.UI.LogoDescription, log); err == nil {
				cfg.UI.LogoDescription = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.MetaTitle", cfg.UI.MetaTitle, log); err == nil {
				cfg.UI.MetaTitle = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.MetaAuthor", cfg.UI.MetaAuthor, log); err == nil {
				cfg.UI.MetaAuthor = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.MetaDescription", cfg.UI.MetaDescription, log); err == nil {
				cfg.UI.MetaDescription = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.AutoRedirectURL", cfg.UI.AutoRedirectURL, log); err == nil {
				cfg.UI.AutoRedirectURL = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.CustomCSSPath", cfg.UI.CustomCSSPath, log); err == nil {
				cfg.UI.CustomCSSPath = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "UI.CustomJsPath", cfg.UI.CustomJsPath, log); err == nil {
				cfg.UI.CustomJsPath = value
			} else {
				return err
			}

			for k, v := range cfg.UI.Templates {
				if value, err := substituteString(ctx, repl, secretManagers, "UI.Templates."+k, v, log); err == nil {
					cfg.UI.Templates[k] = value
				} else {
					return err
				}
			}

			for i, lnk := range cfg.UI.PrivateLinks {
				if value, err := substituteString(ctx, repl, secretManagers, fmt.Sprintf("UI.PrivateLink[%d].Title", i), lnk.Title, log); err == nil {
					lnk.Title = value
				} else {
					return err
				}
				if value, err := substituteString(ctx, repl, secretManagers, fmt.Sprintf("UI.PrivateLink[%d].Link", i), lnk.Link, log); err == nil {
					lnk.Link = value
				} else {
					return err
				}
			}

			for i, asset := range cfg.UI.StaticAssets {
				if value, err := substituteString(ctx, repl, secretManagers, fmt.Sprintf("UI.StaticAsset[%d].Path", i), asset.Path, log); err == nil {
					asset.Path = value
				} else {
					return err
				}
				if value, err := substituteString(ctx, repl, secretManagers, fmt.Sprintf("UI.StaticAsset[%d].ContentType", i), asset.ContentType, log); err == nil {
					asset.ContentType = value
				} else {
					return err
				}
				if value, err := substituteString(ctx, repl, secretManagers, fmt.Sprintf("UI.StaticAsset[%d].FsPath", i), asset.FsPath, log); err == nil {
					asset.FsPath = value
				} else {
					return err
				}
			}
		}

		if cfg.CookieConfig != nil {
			if value, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Path", cfg.CookieConfig.Path, log); err == nil {
				cfg.CookieConfig.Path = value
			} else {
				return err
			}

			if cfg.CookieConfig.Domains != nil {
				// Rebuild once: rewriting keys during iteration can overwrite another
				// domain or expand newly inserted keys a second time.
				domains := make(map[string]*cookie.DomainConfig, len(cfg.CookieConfig.Domains))
				for domainKey, domain := range cfg.CookieConfig.Domains {
					key, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Domains[].Key", domainKey, log)
					if err != nil {
						return err
					}
					if _, exists := domains[key]; exists {
						return fmt.Errorf("portal %q: duplicate resolved cookie domain", cfg.Name)
					}
					next := *domain
					if next.Domain, err = substituteString(ctx, repl, secretManagers, "CookieConfig.Domains[].Domain", domain.Domain, log); err != nil {
						return err
					}
					if next.Path, err = substituteString(ctx, repl, secretManagers, "CookieConfig.Domains[].Path", domain.Path, log); err != nil {
						return err
					}
					domains[key] = &next
				}
				cfg.CookieConfig.Domains = domains
			}
		}

		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	for _, cfg := range config.AuthorizationPolicies {
		// Pin gatekeeper defaults before NewServer can discover names from
		// unrelated portals. Custom names require an explicit policy list.
		defaults := cookie.NewConfig()
		if cfg.SessionIDCookieName == "" {
			cfg.SessionIDCookieName = defaults.SessionIDCookieName
		}
		if len(cfg.AccessTokenCookieNames) == 0 {
			cfg.AccessTokenCookieNames = []string{defaults.AccessTokenCookieName, "access_token", "jwt_access_token"}
		}
		entries, err := resolveConfigInstructions(ctx, repl, secretManagers, "RawCryptoKeyStoreConfigs", cfg.GetRawCryptoKeyStoreConfig(), 2, log)
		if err != nil {
			return fmt.Errorf("policy %q: %w", cfg.Name, err)
		}
		cfg.OverwriteRawCryptoKeyStoreConfig(entries)
		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func resolvePortalCookieDirectives(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, config *authcrunch.Config, directives map[string][]string, log *zap.Logger) error {
	if err := validateConfigObjects(config); err != nil {
		return err
	}
	for name, statements := range directives {
		var portal *authn.PortalConfig
		for _, candidate := range config.AuthenticationPortals {
			if candidate.Name == name {
				if portal != nil {
					return fmt.Errorf("duplicate cookie portal %q", name)
				}
				portal = candidate
			}
		}
		if portal == nil {
			return fmt.Errorf("cookie portal %q not found", name)
		}
		// Reject extra CSV records before decoding; DecodeArgs reads only the first.
		// Keep replacements as tokens until legacy translation and lossless encoding
		// validate them, so invalid trailing whitespace cannot disappear in between.
		resolved := make([]string, len(statements))
		for i, statement := range statements {
			if strings.ContainsAny(statement, "\r\n") {
				return fmt.Errorf("portal %q: invalid cookie statement %d", name, i)
			}
			args, err := cfgutil.DecodeArgs(statement)
			if err != nil || len(args) < 2 {
				return fmt.Errorf("portal %q: invalid cookie statement %d", name, i)
			}
			args, err = substituteStrings(ctx, repl, managers, "PortalCookieDirectives", args, log)
			if err != nil {
				return fmt.Errorf("portal %q cookies: %w", name, err)
			}
			if args[0] != "cookie" && args[0] != "set" {
				return fmt.Errorf("portal %q: invalid cookie directive", name)
			}
			resolved[i], err = encodePortalCookieDirective(args[0], args[1:], false)
			if err != nil {
				return fmt.Errorf("portal %q cookies: %w", name, err)
			}
		}
		if err := configurePortalCookies(portal, resolved); err != nil {
			return fmt.Errorf("portal %q cookies: %w", name, err)
		}
	}
	return nil
}
