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
	"reflect"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/mitchellh/copystructure"
)

func resolveRuntimeConfig(cfg *authcrunch.Config) (*authcrunch.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	clonedCfg, err := copystructure.Copy(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed copying config: %w", err)
	}

	resolvedCfg, ok := clonedCfg.(*authcrunch.Config)
	if !ok {
		return nil, fmt.Errorf("failed copying config: unexpected type %T", clonedCfg)
	}

	if err := resolveRuntimeValue(reflect.ValueOf(resolvedCfg), caddy.NewReplacer()); err != nil {
		return nil, err
	}

	return resolvedCfg, nil
}

func resolveRuntimeValue(v reflect.Value, repl *caddy.Replacer) error {
	if !v.IsValid() {
		return nil
	}

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return resolveRuntimeValue(v.Elem(), repl)
	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		resolvedValue, err := cloneAndResolveValue(v.Elem(), repl)
		if err != nil {
			return err
		}
		if v.CanSet() {
			v.Set(resolvedValue)
		}
		return nil
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if !field.CanSet() {
				continue
			}
			if err := resolveRuntimeValue(field, repl); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := resolveRuntimeValue(v.Index(i), repl); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		for _, key := range v.MapKeys() {
			resolvedValue, err := cloneAndResolveValue(v.MapIndex(key), repl)
			if err != nil {
				return err
			}
			v.SetMapIndex(key, resolvedValue)
		}
		return nil
	case reflect.String:
		if !v.CanSet() {
			return nil
		}
		resolvedString, err := resolveRuntimeString(v.String(), repl)
		if err != nil {
			return err
		}
		v.SetString(resolvedString)
		return nil
	default:
		return nil
	}
}

func cloneAndResolveValue(v reflect.Value, repl *caddy.Replacer) (reflect.Value, error) {
	if !v.IsValid() {
		return v, nil
	}

	clonedValue := reflect.New(v.Type()).Elem()
	clonedValue.Set(v)
	if err := resolveRuntimeValue(clonedValue, repl); err != nil {
		return reflect.Value{}, err
	}
	return clonedValue, nil
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
