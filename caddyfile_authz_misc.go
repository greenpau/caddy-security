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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strconv"
	"strings"
)

func parseCaddyfileAuthorizationMisc(h *caddyfile.Dispenser, repl *caddy.Replacer, p *authz.PolicyConfig, rootDirective, k string, args []string) error {
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
				break
			default:
				p.LoginHintValidators = []string{"email", "phone", "alphanumeric"}
				break
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
			p.AddRawIdpConfig(cfgutil.EncodeArgs(args))
		case strings.HasPrefix(v, "api key auth"):
			p.AddRawIdpConfig(cfgutil.EncodeArgs(args))
		case v == "":
			return h.Errf("%s directive has no value", rootDirective)
		default:
			return h.Errf("unsupported directive for %s: %s", rootDirective, v)
		}
	}
	return nil
}
