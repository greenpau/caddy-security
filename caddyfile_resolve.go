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
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
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
				for i, item := range v {
					if _, ok := item.(string); !ok {
						log.Error("mixed types in string list",
							zap.String("path", currentPath),
							zap.Int("index", i),
							zap.String("found_type", fmt.Sprintf("%T", item)),
						)
						return fmt.Errorf("found mixed types in list: %s", currentPath)
					}
				}
			case map[string]interface{}:
				for i, item := range v {
					if m, ok := item.(map[string]interface{}); ok {
						if err := substitute(ctx, repl, secretManagers, m, fmt.Sprintf("%s[%d]", currentPath, i), log); err != nil {
							return err
						}
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

// ResolveRuntimeAppConfig uses caddy.Replacer to replace strings in App config.
func ResolveRuntimeAppConfig(ctx context.Context, repl *caddy.Replacer, secretManagers []SecretsManager, config *authcrunch.Config, log *zap.Logger) error {
	if config.Credentials != nil {
		rawCredentialConfigs := [][]string{}
		for _, rawCredentialConfig := range config.Credentials.RawCredentialConfigs {
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawCredentialConfigs", rawCredentialConfig, log); err == nil {
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

	if config.Messaging != nil {
		rawMessagingConfigs := [][]string{}
		for _, rawMessagingConfig := range config.Messaging.RawConfigs {
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawMessagingConfigs", rawMessagingConfig, log); err == nil {
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

	if config.Messaging != nil {
		rawMessagingConfigs := [][]string{}
		for _, rawMessagingConfig := range config.Messaging.RawConfigs {
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawMessagingConfigs", rawMessagingConfig, log); err == nil {
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

	if config.UserRegistration != nil {
		rawUserRegistrationConfigs := [][]string{}
		for _, rawMessagingConfig := range config.UserRegistration.RawConfigs {
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawUserRegistrationConfigs", rawMessagingConfig, log); err == nil {
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
		if err := cfg.Validate(); err != nil {
			return err
		}
	}
	for _, cfg := range config.IdentityProviders {
		if err := substitute(ctx, repl, secretManagers, cfg.Params, "", log); err != nil {
			return err
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
		entries := []string{}

		// Crypto configs
		for _, entry := range cfg.GetRawCryptoKeyStoreConfig() {
			args, err := cfgutil.DecodeArgs(entry)
			if err != nil {
				return fmt.Errorf("failed to decode RawCryptoKeyStoreConfigs: %v", err)
			}
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawCryptoKeyStoreConfigs", args, log); err == nil {
				entries = append(entries, cfgutil.EncodeArgs(values))
			} else {
				return err
			}
		}
		cfg.OverwriteRawCryptoKeyStoreConfig(entries)

		// User Transforms
		for _, trCfg := range cfg.UserTransformerConfigs {
			actions := []string{}
			for _, action := range trCfg.Actions {
				args, err := cfgutil.DecodeArgs(action)
				if err != nil {
					return fmt.Errorf("failed to decode UserTransformerConfigs.Action: %v", err)
				}
				if values, err := substituteStrings(ctx, repl, secretManagers, "UserTransformerConfig.Action", args, log); err == nil {
					actions = append(actions, cfgutil.EncodeArgs(values))
				} else {
					return err
				}
			}
			trCfg.Actions = actions

			matchers := []string{}
			for _, action := range trCfg.Matchers {
				args, err := cfgutil.DecodeArgs(action)
				if err != nil {
					return fmt.Errorf("failed to decode UserTransformerConfigs.Matcher: %v", err)
				}
				if values, err := substituteStrings(ctx, repl, secretManagers, "UserTransformerConfig.Matcher", args, log); err == nil {
					matchers = append(matchers, cfgutil.EncodeArgs(values))
				} else {
					return err
				}
			}
			trCfg.Matchers = matchers
		}

		// UI
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

		if value, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Path", cfg.CookieConfig.Path, log); err == nil {
			cfg.CookieConfig.Path = value
		} else {
			return err
		}

		for domainKey, domain := range cfg.CookieConfig.Domains {
			if value, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Domains[].Key", domainKey, log); err == nil {
				if value != domainKey {
					cfg.CookieConfig.Domains[value] = domain
					delete(cfg.CookieConfig.Domains, domainKey)
				}
			} else {
				return err
			}
		}

		for domainKey, domain := range cfg.CookieConfig.Domains {
			if value, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Domains["+domainKey+"].Domain", domain.Domain, log); err == nil {
				domain.Domain = value
			} else {
				return err
			}
			if value, err := substituteString(ctx, repl, secretManagers, "CookieConfig.Domains["+domainKey+"].Path", domain.Path, log); err == nil {
				domain.Path = value
			} else {
				return err
			}
		}

		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	for _, cfg := range config.AuthorizationPolicies {
		entries := []string{}
		for _, entry := range cfg.GetRawCryptoKeyStoreConfig() {
			args, err := cfgutil.DecodeArgs(entry)
			if err != nil {
				return fmt.Errorf("failed to decode RawCryptoKeyStoreConfigs: %v", err)
			}
			if values, err := substituteStrings(ctx, repl, secretManagers, "RawCryptoKeyStoreConfigs", args, log); err == nil {
				entries = append(entries, cfgutil.EncodeArgs(values))
			} else {
				return err
			}
		}
		cfg.OverwriteRawCryptoKeyStoreConfig(entries)
		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	return nil
}
