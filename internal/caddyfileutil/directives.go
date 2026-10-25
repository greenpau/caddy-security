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

package caddyfileutil

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// ReadFlatBlock preserves Caddy argument and block boundaries before
// forwarding encoded statements to a shared AuthCrunch parser.
func ReadFlatBlock(d *caddyfile.Dispenser, kind string) ([][]string, error) {
	if !d.Next() || d.Val() != "{" || d.Token().Quoted() {
		return nil, d.Errf("expected unquoted %s block", kind)
	}
	d.Prev()
	nesting := d.Nesting()
	var body [][]string
	for d.NextBlock(nesting) {
		if d.Nesting() != nesting+1 {
			return nil, d.Errf("nested %s blocks are unsupported", kind)
		}
		args, err := Args(d)
		if err != nil {
			return nil, err
		}
		if err := ValidateTokens(args); err != nil {
			return nil, d.Errf("invalid %s argument", kind)
		}
		body = append(body, args)
		if d.Next() {
			if d.Val() == "{" {
				return nil, d.Errf("nested %s blocks are unsupported", kind)
			}
			if d.Val() == "}" {
				if d.Token().Quoted() {
					return nil, d.Errf("%s closing brace must be unquoted", kind)
				}
				if d.NextLine() {
					d.Prev()
				} else if d.Next() {
					return nil, d.Errf("%s closing brace must end its line", kind)
				}
			}
			d.Prev()
		}
	}
	if d.Nesting() != nesting {
		return nil, d.Errf("unterminated %s block", kind)
	}
	return body, nil
}

// ValidateTokens rejects arguments the shared directive codec cannot preserve.
func ValidateTokens(args []string) error {
	for _, arg := range args {
		// EncodeArgs can trim a trailing empty token; validate before encoding.
		if !utf8.ValidString(arg) || strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("empty or invalid OAuth directive argument")
		}
	}
	return nil
}

// EncodeDirective preserves validated Caddy tokens through the shared CSV
// codec. EncodeArgs and DecodeArgs trim record-edge whitespace, while the CSV
// writer does not quote every trailing Unicode space (for example a tab or NBSP).
// If the normal encoding changes a token, quote every field explicitly using
// CSV escaping. Issuers, audiences, secrets, and key paths must remain exact.
func EncodeDirective(args []string) string {
	encoded := cfgutil.EncodeArgs(args)
	if decoded, err := cfgutil.DecodeArgs(encoded); err == nil && slices.Equal(args, decoded) {
		return encoded
	}
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = `"` + strings.ReplaceAll(arg, `"`, `""`) + `"`
	}
	return strings.Join(quoted, " ")
}

// Args preserves lexical quoting while rejecting an unexpected closing brace.
func Args(d *caddyfile.Dispenser) ([]string, error) {
	args := []string{d.Val()}
	for d.NextArg() {
		if d.Val() == "}" && !d.Token().Quoted() {
			return nil, d.Errf("unexpected closing brace in oauth application directive")
		}
		args = append(args, d.Val())
	}
	return args, nil
}
