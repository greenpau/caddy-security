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

func parseCaddyfileAuthorizationACLShortcuts(h *caddyfile.Dispenser, repl *caddy.Replacer, p *authz.PolicyConfig, rootDirective, k string, args []string) error {
	if len(args) == 0 {
		return h.Errf("%s directive has no value", rootDirective)
	}
	if len(args) < 2 {
		return h.Errf("%s directive %q is too short", rootDirective, strings.Join(args, " "))
	}
	rule := &acl.RuleConfiguration{}
	mode := "field"
	var cond []string
	var matchMethod, matchPath string
	var matchAlways bool
	for _, arg := range args {
		switch arg {
		case "with":
			mode = "method"
			continue
		case "to":
			mode = "path"
			continue
		}
		switch mode {
		case "field":
			if arg == "*" || arg == "any" {
				matchAlways = true
			}
			cond = append(cond, arg)
		case "method":
			matchMethod = strings.ToUpper(arg)
			mode = "path"
		case "path":
			matchPath = arg
			mode = "complete"
		default:
			return h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
		}
	}
	if matchAlways {
		rule.Conditions = append(rule.Conditions, cfgutil.EncodeArgs([]string{"field", cond[0], "exists"}))
	} else {
		rule.Conditions = append(rule.Conditions, cfgutil.EncodeArgs(append([]string{"match"}, cond...)))
	}
	if matchMethod != "" {
		rule.Conditions = append(rule.Conditions, cfgutil.EncodeArgs([]string{"match", "method", matchMethod}))
		p.ValidateMethodPath = true
	}
	if matchPath != "" {
		rule.Conditions = append(rule.Conditions, cfgutil.EncodeArgs([]string{"partial", "match", "path", matchPath}))
		p.ValidateMethodPath = true
	}
	switch k {
	case "allow":
		rule.Action = cfgutil.EncodeArgs([]string{k, "log", "debug"})
	case "deny":
		rule.Action = cfgutil.EncodeArgs([]string{k, "stop", "log", "warn"})
	}
	p.AccessListRules = append(p.AccessListRules, rule)
	return nil
}
