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

	"github.com/greenpau/go-authcrunch/pkg/authn"
	cookieparser "github.com/greenpau/go-authcrunch/pkg/authn/cookie/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// encodePortalCookieDirective only translates legacy Caddy spellings. The shared
// parser owns grammar, aliases, duplicate detection, defaults, and validation.
func encodePortalCookieDirective(keyword string, args []string, deferPlaceholders bool) (string, error) {
	args = append([]string(nil), args...)
	for _, arg := range args {
		// EncodeArgs trims trailing empty fields; reject them before encoding.
		if strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\r\n") {
			return "", fmt.Errorf("empty or multiline cookie argument")
		}
	}
	// After runtime replacement, braces can be literal data in a path. Always
	// translate the resolved statement instead of treating its value as syntax.
	if deferPlaceholders && cookieDirectivesNeedResolution(args) {
		return cfgutil.EncodeArgs(append([]string{keyword}, args...)), nil
	}
	if keyword == "set" {
		if len(args) != 4 || args[1] != "cookie" || args[2] != "name" {
			// The legacy prefix form has different keyword positions.
			if len(args) != 4 || args[0] != "cookie" || args[1] != "name" || args[2] != "prefix" {
				return "", fmt.Errorf("unsupported cookie set directive")
			}
			args = []string{"prefix", strings.ToUpper(args[3])}
		} else {
			roles := map[string]string{"session_id": "session id", "redirect_url": "referer", "sandbox_id": "sandbox id", "id_token": "identity token", "access_token": "access token", "refresh_token": "refresh token"}
			role, ok := roles[args[0]]
			if !ok {
				return "", fmt.Errorf("unsupported cookie role")
			}
			args = append(strings.Fields(role), "name", args[3])
		}
	} else {
		// Legacy per-domain syntax: cookie example.com path /app.
		// Do not reinterpret malformed modern role/attribute keywords as domains.
		legacyDomain := false
		if len(args) == 3 {
			switch args[0] {
			case "domain", "prefix", "path", "lifetime", "samesite", "same", "insecure", "strip", "guess", "session", "referer", "redirect", "sandbox", "identity", "id", "access", "refresh", "oidc":
			default:
				legacyDomain = true
			}
		}
		if legacyDomain {
			switch args[1] {
			case "path", "lifetime", "samesite", "insecure", "strip":
				if args[0] == "default" {
					args = args[1:]
				} else {
					args = append([]string{"domain"}, args...)
				}
			}
		}
		start := 0
		if len(args) >= 2 && args[0] == "domain" {
			start = 2
		}
		attribute := args[start:]
		if len(attribute) == 2 {
			switch {
			case (attribute[0] == "strip" || attribute[0] == "guess") && attribute[1] == "domain":
				args = append(args, "enabled")
			case attribute[0] == "insecure" && attribute[1] != "enabled" && attribute[1] != "disabled":
				state, err := cfgutil.ParseBoolArg(attribute[1])
				if err != nil {
					return "", fmt.Errorf("invalid cookie insecure state")
				}
				args[len(args)-1] = "disabled"
				if state {
					args[len(args)-1] = "enabled"
				}
			}
		}
	}
	return cfgutil.EncodeArgs(append([]string{"cookie"}, args...)), nil
}

func configurePortalCookies(portal *authn.PortalConfig, statements []string) error {
	config, err := cookieparser.NewCookieConfigFromDirectives(statements)
	if err != nil {
		return err
	}
	return portal.ConfigureCookies(config)
}

func cookieDirectivesNeedResolution(statements []string) bool {
	for _, statement := range statements {
		if strings.Contains(statement, "{") || strings.Contains(statement, "secrets:") {
			return true
		}
	}
	return false
}
