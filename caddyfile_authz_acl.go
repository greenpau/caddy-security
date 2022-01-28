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
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strings"
)

func parseCaddyfileAuthorizationACL(h *caddyfile.Dispenser, repl *caddy.Replacer, p *authz.PolicyConfig, rootDirective string, args []string) error {
	if len(args) == 0 {
		return h.Errf("%s directive has no value", rootDirective)
	}
	switch args[0] {
	case "rule":
		if len(args) > 1 {
			return h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
		}
		rule := &acl.RuleConfiguration{}
		for subNesting := h.Nesting(); h.NextBlock(subNesting); {
			k := h.Val()
			rargs := h.RemainingArgs()
			if len(rargs) == 0 {
				return h.Errf("%s %s directive %v has no values", rootDirective, args[0], k)
			}
			rargs = append([]string{k}, rargs...)
			switch k {
			case "comment":
				rule.Comment = cfgutil.EncodeArgs(rargs)
			case "allow", "deny":
				rule.Action = cfgutil.EncodeArgs(rargs)
			default:
				rule.Conditions = append(rule.Conditions, cfgutil.EncodeArgs(rargs))
			}
		}
		p.AccessListRules = append(p.AccessListRules, rule)
	case "default":
		if len(args) != 2 {
			return h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
		}
		rule := &acl.RuleConfiguration{
			Conditions: []string{"match any"},
		}
		switch args[1] {
		case "allow", "deny":
			rule.Action = args[1]
		default:
			return h.Errf("%s directive %q must have either allow or deny", rootDirective, strings.Join(args, " "))
		}
		p.AccessListRules = append(p.AccessListRules, rule)
	default:
		return h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
	}
	return nil
}
