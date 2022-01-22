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
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func parseCaddyfileAuthorizationBypass(h *caddyfile.Dispenser, repl *caddy.Replacer, p *authz.PolicyConfig, rootDirective string, args []string) error {
	if len(args) == 0 {
		return h.Errf("%s directive has no value", rootDirective)
	}
	if len(args) != 3 {
		return h.Errf("%s %s is invalid", rootDirective, cfgutil.EncodeArgs(args))
	}
	if args[0] != "uri" {
		return h.Errf("%s %s is invalid", rootDirective, cfgutil.EncodeArgs(args))
	}
	bc := &bypass.Config{
		MatchType: args[1],
		URI:       args[2],
	}
	if err := bc.Validate(); err != nil {
		return h.Errf("%s %s erred: %v", rootDirective, cfgutil.EncodeArgs(args), err)
	}
	p.BypassConfigs = append(p.BypassConfigs, bc)
	return nil
}
