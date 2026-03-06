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
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
)

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

func cloneResolvedRuleConfigurations(cfgs []*acl.RuleConfiguration, repl *caddy.Replacer) ([]*acl.RuleConfiguration, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*acl.RuleConfiguration, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		comment, err := resolveRuntimeString(cfg.Comment, repl)
		if err != nil {
			return nil, err
		}
		conditions, err := cloneResolvedStringSlice(cfg.Conditions, repl)
		if err != nil {
			return nil, err
		}
		action, err := resolveRuntimeString(cfg.Action, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &acl.RuleConfiguration{
			Comment:    comment,
			Conditions: conditions,
			Action:     action,
		})
	}
	return clones, nil
}

func cloneResolvedStringSlice(values []string, repl *caddy.Replacer) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make([]string, 0, len(values))
	for _, value := range values {
		resolvedValue, err := resolveRuntimeString(value, repl)
		if err != nil {
			return nil, err
		}
		clone = append(clone, resolvedValue)
	}
	return clone, nil
}

func cloneResolvedStringMap(values map[string]string, repl *caddy.Replacer) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make(map[string]string, len(values))
	for key, value := range values {
		resolvedValue, err := resolveRuntimeString(value, repl)
		if err != nil {
			return nil, err
		}
		clone[key] = resolvedValue
	}
	return clone, nil
}

func cloneResolvedInterfaceMap(values map[string]interface{}, repl *caddy.Replacer) (map[string]interface{}, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make(map[string]interface{}, len(values))
	for key, value := range values {
		resolvedValue, err := cloneResolvedDynamicValue(value, repl)
		if err != nil {
			return nil, err
		}
		clone[key] = resolvedValue
	}
	return clone, nil
}

func cloneResolvedDynamicValue(value interface{}, repl *caddy.Replacer) (interface{}, error) {
	switch v := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v, nil
	case string:
		return resolveRuntimeString(v, repl)
	case []string:
		return cloneResolvedStringSlice(v, repl)
	case []interface{}:
		clone := make([]interface{}, 0, len(v))
		for _, entry := range v {
			resolvedEntry, err := cloneResolvedDynamicValue(entry, repl)
			if err != nil {
				return nil, err
			}
			clone = append(clone, resolvedEntry)
		}
		return clone, nil
	case []map[string]interface{}:
		clone := make([]map[string]interface{}, 0, len(v))
		for _, entry := range v {
			resolvedEntry, err := cloneResolvedInterfaceMap(entry, repl)
			if err != nil {
				return nil, err
			}
			clone = append(clone, resolvedEntry)
		}
		return clone, nil
	case map[string]interface{}:
		return cloneResolvedInterfaceMap(v, repl)
	default:
		return nil, fmt.Errorf("failed cloning config value of type %T", value)
	}
}

func cloneStringBoolMap(values map[string]bool) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]bool, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneInterfaceBoolMap(values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]interface{}, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func resolveRuntimeString(s string, repl *caddy.Replacer) (string, error) {
	if !containsPlaceholderCandidate(s) {
		return s, nil
	}

	resolvedString := s
	for {
		nextResolvedString := repl.ReplaceKnown(resolvedString, "")
		if nextResolvedString == resolvedString {
			break
		}
		resolvedString = nextResolvedString
	}

	if unresolvedPlaceholder := findPlaceholderCandidate(resolvedString); unresolvedPlaceholder != "" {
		return "", fmt.Errorf("failed resolving placeholder in %q: unknown placeholder %q", s, unresolvedPlaceholder)
	}

	return resolvedString, nil
}

func containsPlaceholderCandidate(s string) bool {
	return findPlaceholderCandidate(s) != ""
}

func findPlaceholderCandidate(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		if i > 0 && s[i-1] == '\\' {
			continue
		}

		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return ""
		}
		end += i + 1

		candidate := s[i : end+1]
		if len(candidate) > 2 && isPlaceholderNameStart(candidate[1]) {
			return candidate
		}
	}
	return ""
}

func isPlaceholderNameStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}
