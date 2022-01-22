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
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func parseCaddyfileAuthorizationHeaderInjection(h *caddyfile.Dispenser, repl *caddy.Replacer, p *authz.PolicyConfig, rootDirective string, args []string) error {
	if len(args) == 0 {
		return h.Errf("%s directive has no value", rootDirective)
	}
	switch {
	case cfgutil.EncodeArgs(args) == "headers with claims":
		p.PassClaimsWithHeaders = true
	case args[0] == "header":
		if len(args) != 4 {
			return h.Errf("%s directive %q is invalid", rootDirective, cfgutil.EncodeArgs(args))
		}
		if args[2] != "from" {
			return h.Errf("%s directive %q has invalid syntax", rootDirective, cfgutil.EncodeArgs(args))
		}
		cfg := &injector.Config{
			Header: args[1],
			Field:  args[3],
		}
		if err := cfg.Validate(); err != nil {
			return h.Errf("%s %s erred: %v", rootDirective, cfgutil.EncodeArgs(args), err)
		}
		p.HeaderInjectionConfigs = append(p.HeaderInjectionConfigs, cfg)
	default:
		return h.Errf("unsupported directive for %s: %s", rootDirective, cfgutil.EncodeArgs(args))
	}
	return nil
}
