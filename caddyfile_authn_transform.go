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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"strings"
)

func parseCaddyfileAuthPortalTransform(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string, rootArgs []string) error {
	args := strings.Join(rootArgs, " ")
	switch args {
	case "user", "users":
		tc := &transformer.Config{}
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			trKey := h.Val()
			trArgs := h.RemainingArgs()
			trArgs = append([]string{trKey}, trArgs...)
			encodedArgs := cfgutil.EncodeArgs(trArgs)
			var matchArgs bool
			for _, arg := range trArgs {
				if arg == "match" {
					matchArgs = true
					break
				}
			}
			if matchArgs {
				if trArgs[0] == "match" {
					trArgs = append([]string{"exact"}, trArgs...)
					encodedArgs = cfgutil.EncodeArgs(trArgs)
				}
				tc.Matchers = append(tc.Matchers, encodedArgs)
			} else {
				tc.Actions = append(tc.Actions, encodedArgs)
			}
		}
		portal.UserTransformerConfigs = append(portal.UserTransformerConfigs, tc)
	default:
		return h.Errf("unsupported directive for %s: %s", rootDirective, args)
	}

	return nil
}
