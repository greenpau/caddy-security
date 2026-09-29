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
	"fmt"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	aclparser "github.com/greenpau/go-authcrunch/pkg/acl/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileAuthorizationACL adapts fields, conditions and actions for go-authcrunch/pkg/acl.
//
// Syntax:
//
//	acl field <name> {
//		claim <literal-top-level-key>
//		type string [list]
//	}
//
//	acl rule {
//		comment <text> [<text>...]
//		[no] [exact|partial|prefix|suffix|regex] match [any] <field> <value> [<value>...]
//		match any
//		field <field> [not] exists
//		<allow|deny> [any] [stop] [log [debug|info|warn|error]] [counter] [tag <value>]
//	}
//	acl default <allow|deny>
//
// Catalogue alternatives are separate rules as needed. The Caddy wrapper requires
// at least one argument on every line inside acl rule; use allow stop (or another
// action option) there, or acl default allow for a bare default action. Full
// conditions, field aliases, and actions are owned by the upstream ACL parser.
// amr is a list of verified methods: pwd (password), otp (TOTP), hwk (WebAuthn).
// Match role and amr in the same rule when both identity and factor are required.
// Fields require exactly one flat block, one claim and one type, in either order.
// The shared parser owns names, reserved aliases, types and setting validation.
// Claim keys stay literal, including punctuation and runtime placeholder text.
// The caller collects fields and applies them once before compiling policy rules.
func parseCaddyfileAuthorizationACL(h *caddyfile.Dispenser, p *authz.PolicyConfig, rootDirective string, args []string) (*acl.FieldConfig, error) {
	if len(args) == 0 {
		return nil, h.Errf("%s directive has no value", rootDirective)
	}
	switch args[0] {
	case "field":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return nil, h.Errf("authorization policy %q: acl field requires one name and a block", p.Name)
		}
		body, err := readFlatDirectiveBlock(h, "ACL field")
		if err != nil {
			return nil, fmt.Errorf("authorization policy %q: %w", p.Name, err)
		}
		if h.Next() {
			if h.Val() == "{" {
				return nil, h.Errf("authorization policy %q: acl field requires exactly one block", p.Name)
			}
			h.Prev()
		}
		statements := make([]string, 0, len(body))
		for _, statement := range body {
			encoded := cfgutil.EncodeArgs(statement)
			// The shared codec trims record-edge whitespace. Reject any lossy
			// encoding instead of silently changing a literal key or keyword.
			decoded, err := cfgutil.DecodeArgs(encoded)
			if err != nil || !slices.Equal(statement, decoded) {
				return nil, h.Errf("authorization policy %q: invalid ACL field argument encoding", p.Name)
			}
			statements = append(statements, encoded)
		}
		field, err := aclparser.NewACLFieldConfigFromDirectives(args[1], statements)
		if err != nil {
			return nil, h.Errf("authorization policy %q: %v", p.Name, err)
		}
		return field, nil
	case "rule":
		if len(args) > 1 {
			return nil, h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
		}
		rule := &acl.RuleConfiguration{}
		for subNesting := h.Nesting(); h.NextBlock(subNesting); {
			k := h.Val()
			rargs := h.RemainingArgs()
			if len(rargs) == 0 {
				return nil, h.Errf("%s %s directive %v has no values", rootDirective, args[0], k)
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
			return nil, h.Errf("%s directive %q is too long", rootDirective, strings.Join(args, " "))
		}
		rule := &acl.RuleConfiguration{
			Conditions: []string{"match any"},
		}
		switch args[1] {
		case "allow", "deny":
			rule.Action = args[1]
		default:
			return nil, h.Errf("%s directive %q must have either allow or deny", rootDirective, strings.Join(args, " "))
		}
		p.AccessListRules = append(p.AccessListRules, rule)
	default:
		return nil, h.Errf("%s directive value of %q is unsupported", rootDirective, strings.Join(args, " "))
	}
	return nil, nil
}
