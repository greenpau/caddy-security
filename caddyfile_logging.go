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
	"slices"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch"
	loggingparser "github.com/greenpau/go-authcrunch/pkg/logging/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileLogging adapts one optional root security block:
//
//	logging {
//		skip <exact|partial|prefix|suffix|regex> text <value>
//	}
//
// Each leaf has four tokens. Rules append (OR); duplicate blocks are rejected
// by the caller. The shared parser owns validation and case-sensitive matching.
// Omission and an empty block skip nothing. Values remain literal, including
// regex escapes and braces; runtime secret/placeholder expansion is not applied.
// NewServer filters AuthCrunch components only. Caddy v2.11.4 does not expose a
// wrapper for its independent authentication middleware logger; see the logging
// configuration skill before claiming host diagnostics are suppressed.
func parseCaddyfileLogging(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	if len(d.RemainingArgs()) != 0 {
		return d.Errf("security logging takes no arguments")
	}
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return d.Errf("security logging requires a block")
	}
	d.Prev()
	nesting := d.Nesting()
	var statements []string
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 || d.Val() == "{" || d.Val() == "}" {
			return d.Errf("invalid security logging block structure")
		}
		args := []string{d.Val()}
		for d.NextArg() {
			if d.Val() == "}" && !d.Token().Quoted() {
				return d.Errf("invalid security logging block structure")
			}
			args = append(args, d.Val())
		}
		// Inspect the boundary before NextBlock can consume an empty nested
		// block or mistake a quoted closing brace for this block's delimiter.
		if d.Next() {
			if d.Val() == "{" {
				return d.Errf("nested security logging blocks are unsupported")
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return d.Errf("security logging closing brace must be unquoted")
				}
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return d.Errf("security logging closing brace must end its line")
				}
			}
			d.Prev()
		}
		if slices.Contains(args, "") {
			return d.Errf("security logging arguments must not be empty")
		}
		statements = append(statements, cfgutil.EncodeArgs(args))
	}
	if d.Nesting() != nesting {
		return d.Errf("unterminated security logging block")
	}
	config, err := loggingparser.NewLoggingConfigFromDirectives(statements)
	if err != nil {
		return d.Errf("security logging: %v", err)
	}
	cfg.Logging = config
	return nil
}
