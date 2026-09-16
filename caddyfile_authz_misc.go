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
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileAuthorizationMisc parses policy options. Raw auth proxy lines
// are validated by go-authcrunch/pkg/authproxy during policy validation.
// Caddy does not resolve runtime placeholders in raw auth proxy statements.
//
// Syntax:
//
//	enable <js redirect|strip token|additional scopes>
//	enable login hint [with <validator> [<validator>...]]
//	disable <auth redirect query|auth redirect>
//	validate <path acl|source address|bearer header>
//	set session_id cookie name <name>
//	set access_token cookie name <name> [<name>...]
//	set token sources <cookie|header|query> [<cookie|header|query>...]
//	set auth url <url>
//	set forbidden url <url>
//	set redirect query parameter <name>
//	set redirect status <300-308>
//	set user identity <field>
//	with basic auth portal <name_or_url> realm <realm>
//	with api key auth portal <name_or_url> realm <realm>
//	with api key header name <header>
//	with auth realm header name <header>
//
// A session cookie name setting takes one value; multiple access cookie names
// belong on a single line. Cookie names and repeated settings must be unique.
// Coordinate explicit names with portals using a custom cookie prefix.
// validate path acl checks both policy rules and token path claims at every
// decoded/cleaned path interpretation. Claims use literal paths with * and **
// wildcards, not regular expressions; * stays in one segment, ** spans slashes,
// and both require at least one allowed character. The library rejects ambiguous
// encodings instead of rewriting the downstream request to grant access.
func parseCaddyfileAuthorizationMisc(h *caddyfile.Dispenser, p *authz.PolicyConfig, rootDirective, k string, args []string) error {
	v := strings.Join(args, " ")
	v = strings.TrimSpace(v)
	switch k {
	case "enable":
		switch {
		case v == "js redirect":
			p.RedirectWithJavascript = true
		case v == "strip token":
			p.StripTokenEnabled = true
		case v == "additional scopes":
			p.AdditionalScopes = true
		case strings.HasPrefix(v, "login hint"):
			remainingArguments := strings.TrimPrefix(v, "login hint ")
			switch {
			case strings.HasPrefix(remainingArguments, "with"):
				remainingArguments = strings.TrimPrefix(remainingArguments, "with ")
				validationArguments := strings.Split(remainingArguments, " ")
				p.LoginHintValidators = validationArguments
			default:
				p.LoginHintValidators = []string{"email", "phone", "alphanumeric"}
			}
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	case "validate":
		switch {
		case v == "path acl":
			p.ValidateAccessListPathClaim = true
			p.ValidateMethodPath = true
		case v == "source address":
			p.ValidateSourceAddress = true
		case v == "bearer header":
			p.ValidateBearerHeader = true
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	case "disable":
		switch {
		case v == "auth redirect query":
			p.AuthRedirectQueryDisabled = true
		case v == "auth redirect":
			p.AuthRedirectDisabled = true
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	case "set":
		switch {
		case len(args) >= 3 && args[1] == "cookie" && args[2] == "name":
			if len(args) < 4 {
				return h.Errf("%s cookie name requires a value", rootDirective)
			}
			seen := make(map[string]bool)
			for _, name := range args[3:] {
				if (&http.Cookie{Name: name}).Valid() != nil || seen[name] {
					return h.Errf("%s has an invalid or duplicate cookie name", rootDirective)
				}
				seen[name] = true
			}
			switch args[0] {
			case "session_id":
				if len(args) != 4 || p.SessionIDCookieName != "" {
					return h.Errf("%s requires one session cookie name setting", rootDirective)
				}
				p.SessionIDCookieName = args[3]
			case "access_token":
				if len(p.AccessTokenCookieNames) != 0 {
					return h.Errf("%s has duplicate access cookie name settings", rootDirective)
				}
				p.AccessTokenCookieNames = args[3:]
			default:
				return h.Errf("%s has unsupported cookie role", rootDirective)
			}
		case strings.HasPrefix(v, "token sources "):
			p.AllowedTokenSources = strings.Split(strings.TrimPrefix(v, "token sources "), " ")
		case strings.HasPrefix(v, "auth url "):
			p.AuthURLPath = strings.TrimPrefix(v, "auth url ")
		case strings.HasPrefix(v, "forbidden url "):
			p.ForbiddenURL = strings.TrimPrefix(v, "forbidden url ")
		case strings.HasPrefix(v, "redirect query parameter "):
			p.AuthRedirectQueryParameter = strings.TrimPrefix(v, "redirect query parameter ")
		case strings.HasPrefix(v, "redirect status "):
			n, err := strconv.Atoi(strings.TrimPrefix(v, "redirect status "))
			if err != nil {
				return h.Errf("%s %s directive failed: %v", rootDirective, v, err)
			}
			if n < 300 || n > 308 {
				return h.Errf("%s %s directive contains invalid value", rootDirective, v)
			}
			p.AuthRedirectStatusCode = n
		case strings.HasPrefix(v, "user identity "):
			p.UserIdentityField = strings.TrimPrefix(v, "user identity ")
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	case "with":
		switch {
		case strings.HasPrefix(v, "basic auth"):
			p.AddAuthProxyRawConfig(cfgutil.EncodeArgs(args))
		case strings.HasPrefix(v, "api key auth"):
			p.AddAuthProxyRawConfig(cfgutil.EncodeArgs(args))
		case strings.HasPrefix(v, "api key header name ") && len(args) == 5:
			p.SetAPIKeyHeaderName(args[4])
		case strings.HasPrefix(v, "auth realm header name ") && len(args) == 5:
			p.SetAuthRealmHeaderName(args[4])
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	}
	return nil
}
