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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	transformparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileAuthPortalTransform forwards a complete block to the shared
// go-authcrunch/pkg/authn/transformer/parser, which validates ACL matchers,
// actions, custom claim types, and conditional authentication requirements.
//
// Syntax:
//
//	transform <user|users> {
//		[no] [exact|partial|prefix|suffix|regex] match [any] <field> <value> [<value>...]
//		match any
//		field <field> [not] exists
//		[action] add <field> <value> [<value>...]
//		[action] overwrite <known_field> <value> [<value>...]
//		[action] delete <field>
//		[action] drop matched role
//		[action] add <custom_field> <value> as string
//		[action] add <custom_field> <value> [<value>...] as <list|string_list|string list>
//		[action] add nested <key> [<key>...] with <value> [<value>...] as <string|list|string_list|string list>
//		[action] add nested <key> [<key>...] as map
//		require <password|mfa|totp|u2f>
//		require auth challenges <method> [<method>...] [if <method> [and <method>...] not available]
//		require auth challenges <method> [or <method>...] [if <method> [and <method>...] not available]
//		<block|deny>
//		ui link <title> <url> [icon <class>] [target_blank]
//	}
//
// Blocks require a matcher and an action. Ordinary bare match retains the
// historical exact spelling in JSON; match any stays an unconditional matcher.
// Repeated rules/actions preserve order. Conditional methods are password,
// totp, u2f and mfa; email checkpoints are unsupported. The first eligible rule
// across matching transforms replaces backend challenges; legacy require actions
// remain additive. A matched policy with no eligible rule denies authentication.
// Availability comes from registered credentials, never transformed claims.
// Quote multiword values. Action {claims.*} expands at login, independently of Caddy
// runtime placeholders. Custom scalar values require one token; nested values
// remain literal. In v1.3.3, match any depends on an exp claim missing during
// refresh/OIDC identity checks and System API assertions. Caddy rejects those
// combinations at provisioning;
// use explicit realm matchers with those features until upstream is corrected.
// AMR is verified authentication evidence, not a grant that a
// transform can fabricate. Parsers start no workers or network/file activity.
// See .codex/skills/configuration-authentication-user-transforms/SKILL.md.
func parseCaddyfileAuthPortalTransform(h *caddyfile.Dispenser, portal *authn.PortalConfig, rootDirective string, rootArgs []string) error {
	args := strings.Join(rootArgs, " ")
	switch args {
	case "user", "users":
		body, err := readFlatDirectiveBlock(h, "user transform")
		if err != nil {
			return err
		}
		statements := make([]string, 0, len(body))
		for _, trArgs := range body {
			if trArgs[0] == "match" && !(len(trArgs) == 2 && trArgs[1] == "any") {
				trArgs = append([]string{"exact"}, trArgs...)
			}
			statements = append(statements, cfgutil.EncodeArgs(trArgs))
		}
		tc, err := transformparser.NewUserTransformerConfigFromDirectives(statements)
		if err != nil {
			return h.Errf("%s: %v", rootDirective, err)
		}
		portal.UserTransformerConfigs = append(portal.UserTransformerConfigs, tc)
	default:
		return h.Errf("%s requires user or users", rootDirective)
	}

	return nil
}
