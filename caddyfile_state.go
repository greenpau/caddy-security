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
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	stateparser "github.com/greenpau/go-authcrunch/pkg/state/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileState adapts one optional root security block:
//
//	state {
//		directory <absolute-private-directory>
//	}
//
// The shared state parser owns the directory grammar and normalizes paths
// without filesystem IO. Caddy's {$ENV} substitution runs before tokenization;
// {env.*} and secrets references resolve in the private provisioning copy.
// Quote paths containing spaces. Omission retains volatile runtime behavior.
func parseCaddyfileState(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	if len(d.RemainingArgs()) != 0 {
		return d.Errf("security state takes no arguments")
	}
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return d.Errf("security state requires a block")
	}
	d.Prev()
	nesting := d.Nesting()
	var statements []string
	var deferredDirectory string
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 || d.Val() == "{" || d.Val() == "}" {
			return d.Errf("invalid security state block structure")
		}
		args := []string{d.Val()}
		for d.NextArg() {
			if d.Val() == "}" && !d.Token().Quoted() {
				return d.Errf("invalid security state block structure")
			}
			args = append(args, d.Val())
		}
		if d.Next() {
			if d.Val() == "{" {
				return d.Errf("nested security state blocks are unsupported")
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return d.Errf("security state closing brace must be unquoted")
				}
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return d.Errf("security state closing brace must end its line")
				}
			}
			d.Prev()
		}
		// Validate deferred statements with the same parser and token boundaries.
		// This stand-in is never stored or opened. Keep the original value in
		// Config.State and validate its replacement again during provisioning.
		for i := 1; i < len(args); i++ {
			if strings.Contains(args[i], "{") || hasSecretKey(args[i]) {
				deferredDirectory = args[i]
				args[i] = "/__caddy_deferred_state_directory"
			}
		}
		statements = append(statements, cfgutil.EncodeArgs(args))
	}
	if d.Nesting() != nesting {
		return d.Errf("unterminated security state block")
	}
	c, err := stateparser.NewStateConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("security state: %v", err)
	}
	if deferredDirectory != "" {
		c.Directory = deferredDirectory
	}
	cfg.State = c
	return nil
}
