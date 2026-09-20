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
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileOAuthIdentityProvider collects the whole upstream provider body.
// Only legacy Caddy spellings are translated here; go-authcrunch/pkg/idp/parser
// reuses pkg/idp/oauth/parser for field matching, aliases, and defaults, then
// preserves shared-dispatcher validation. This is not downstream pkg/oidc syntax.
//
// Syntax (field catalogue; configure only the fields needed by the driver):
//
//	oauth identity provider <name> {
//		realm <realm>
//		driver <driver>
//		domain_name <domain>
//		client_id <client_id>
//		client_secret <client_secret>
//		server_id <server_id>
//		tenant_id <tenant_id>
//		user_pool_id <user_pool_id>
//		region <region>
//		issuer <exact_issuer>
//		access_token_audience <audience>
//		base_auth_url <url>
//		metadata_url <url>
//		authorization_url <url>
//		token_url <url>
//		logout_url <logout_url>
//		identity_token_cookie_name <name>
//		identity_token_field_name <name>
//		user_info_roles_field_name <name>
//		scopes <value> [<value>...]
//		required_token_fields <value> [<value>...]
//		response_type <value> [<value>...]
//		user_group_filters <value> [<value>...]
//		user_org_filters <value> [<value>...]
//		user_info_fields <value> [<value>...]
//		delay_start <integer>
//		retry_attempts <integer>
//		retry_interval <integer>
//		<metadata discovery|key verification|pass grant type|response type parameter|scope|nonce|pkce|accept header|js callback|logout|identity token cookie|email claim check|tls verification> <enabled|disabled>
//		login icon <class_name|color|background_color|text|text_color|text_background_color> <value>
//		login icon priority <integer>
//		jwks key <kid> <public_PEM_path>
//		disabled
//	}
//
// Scalar/list/integer field names and login icon field names also accept fully
// spaced aliases, such as access token audience. Scalars take exactly one value.
// State keywords use separate words and enabled/disabled, not JSON booleans.
// Repeat jwks key for multiple pins. Duplicate settings, including aliases across
// the entire block, fail; repeated legacy scopes, response_type,
// user_group_filters, and user_org_filters lines append for compatibility.
//
// logout_url is recognized by the typed OAuth parser but rejected by the shared
// IdP validator in go-authcrunch v1.3.3. Keep it visible as restricted syntax;
// never drop it from input to make validation succeed. enable logout is separate.
//
// Compatible Caddy forms are translated before shared parsing:
//
//	oauth identity provider <github|google|facebook> <client_id> <client_secret>
//	disable <metadata discovery|key verification|pass grant type|response type|scope|nonce|pkce|email claim check|tls verification>
//	enable <accept header|js callback|logout>
//	enable id token cookie [<field_name> [<cookie_name>]]
//	extract <field> [<field>...] from userinfo
//	icon <text> [<class> [<color> [<background>]]] [text <color> [<background>]] [priority <integer>]
//
// Legacy icon text and priority modifiers may appear in either order; missing
// or surplus values fail, and repeated fields remain visible to shared validation.
// Legacy switches also accept underscores between words. extract all from
// userinfo selects all fields. See the compatibility inventory in
// .codex/skills/configuration-oauth-providers/references/shared-parser.md.
//
// Explicit issuer is exact and overrides discovery; base_auth_url is not an
// issuer fallback. access_token_audience applies to the supplemental JWT access
// token; identity tokens still require the client ID. Invalid identity tokens
// reject login; invalid optional access JWTs contribute no claims. Parsing may
// validate static PEM files, but must not start workers or fetch discovery.
// Statements with runtime references are retained on App and reparsed after
// replacing their original arguments once. Derived defaults must not rewrite
// secret lookup keys before provisioning (for example Google's client-ID suffix).
func parseCaddyfileOAuthIdentityProvider(d *caddyfile.Dispenser, app *App, name string, shortcuts []string) error {
	cfg := app.Config
	var lines [][]string
	if len(shortcuts) > 0 {
		if !slices.Contains([]string{"github", "google", "facebook"}, name) || len(shortcuts) != 2 {
			return d.Errf("unsupported OAuth provider shortcut or argument count")
		}
		lines = append(lines, []string{"realm", name}, []string{"driver", name}, []string{"client_id", shortcuts[0]}, []string{"client_secret", shortcuts[1]})
	}
	disabled := false
	lists := make(map[string]int)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		if d.Nesting() != nesting+1 {
			return d.Errf("nested OAuth provider blocks are unsupported")
		}
		args := append([]string{d.Val()}, d.RemainingArgs()...)
		// RemainingArgs stops before an opening brace. Check it explicitly so
		// even an empty nested block cannot be mistaken for a scalar statement.
		if d.Next() {
			if d.Val() == "{" {
				return d.Errf("nested OAuth provider blocks are unsupported")
			}
			d.Prev()
		}
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return d.Errf("%v", err)
		}
		if args[0] == "disabled" {
			if len(args) != 1 || disabled {
				return d.Errf("invalid or duplicate OAuth disabled directive")
			}
			disabled = true
			continue
		}
		// These four old list directives appended across repeated lines. Coalesce
		// only identical legacy spellings; a spaced alias stays separate so the
		// shared parser rejects ambiguity anywhere in the complete block.
		switch args[0] {
		case "scopes", "user_group_filters", "user_org_filters", "response_type":
			if len(args) < 2 {
				return d.Errf("OAuth list directive requires values")
			}
			if index, ok := lists[args[0]]; ok {
				lines[index] = append(lines[index], args[1:]...)
				continue
			}
			lists[args[0]] = len(lines)
		}
		translated, err := translateOAuthDirective(args)
		if err != nil {
			return d.Errf("%v", err)
		}
		lines = append(lines, translated...)
	}
	// A disabled provider is a registration marker and need not have credentials.
	// Nonempty definitions still pass through shared validation before being omitted.
	if disabled && len(lines) == 0 {
		cfg.AddDisabledIdentityProvider(name)
		return nil
	}
	statements := make([]string, 0, len(lines))
	for _, args := range lines {
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return d.Errf("%v", err)
		}
		statements = append(statements, encodeOAuthDirective(args))
	}
	result, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives(name, statements)
	if err != nil {
		return d.Errf("%v", err)
	}
	if disabled {
		cfg.AddDisabledIdentityProvider(name)
		return nil
	}
	if err := cfg.AddIdentityProvider(result.Name, result.Kind, result.Params); err != nil {
		return err
	}
	for _, statement := range statements {
		if strings.Contains(statement, "{") || strings.Contains(statement, "secrets:") {
			if app.OAuthProviderDirectives == nil {
				app.OAuthProviderDirectives = make(map[string][]string)
			}
			app.OAuthProviderDirectives[name] = statements
			break
		}
	}
	return nil
}

func validateOAuthDirectiveTokens(args []string) error {
	for _, arg := range args {
		// EncodeArgs can trim a trailing empty token; validate before encoding.
		if !utf8.ValidString(arg) || strings.TrimSpace(arg) == "" || strings.ContainsAny(arg, "\r\n\x00") {
			return fmt.Errorf("empty or invalid OAuth directive argument")
		}
	}
	return nil
}

// encodeOAuthDirective preserves validated Caddy tokens through the shared CSV
// codec. EncodeArgs and DecodeArgs trim record-edge whitespace, while the CSV
// writer does not quote every trailing Unicode space (for example a tab or NBSP).
// If the normal encoding changes a token, quote every field explicitly using
// CSV escaping. Issuers, audiences, secrets, and key paths must remain exact.
func encodeOAuthDirective(args []string) string {
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

func translateOAuthDirective(args []string) ([][]string, error) {
	switch args[0] {
	case "enable", "disable":
		state := "enabled"
		if args[0] == "disable" {
			state = "disabled"
		}
		// The documented cookie form has positional field/name arguments.
		if args[0] == "enable" && len(args) >= 4 && slices.Equal(args[1:4], []string{"id", "token", "cookie"}) {
			if len(args) > 6 {
				return nil, fmt.Errorf("invalid OAuth id token cookie argument count")
			}
			lines := [][]string{{"identity", "token", "cookie", state}}
			if len(args) >= 5 {
				lines = append(lines, []string{"identity_token_field_name", args[4]})
			}
			if len(args) == 6 {
				lines = append(lines, []string{"identity_token_cookie_name", args[5]})
			}
			return lines, nil
		}
		// Legacy switches accepted both underscores and separate keyword tokens.
		words := make([]string, 0, len(args))
		for _, arg := range args[1:] {
			words = append(words, strings.Split(arg, "_")...)
		}
		key := strings.Join(words, " ")
		allowed := false
		if args[0] == "disable" {
			allowed = slices.Contains([]string{"metadata discovery", "key verification", "pass grant type", "response type", "scope", "nonce", "pkce", "email claim check", "tls verification"}, key)
		} else {
			allowed = slices.Contains([]string{"accept header", "js callback", "logout"}, key)
		}
		// Reject grouped keyword tokens; splitting underscores is the only alias.
		for _, arg := range args[1:] {
			if strings.ContainsAny(arg, " \t") {
				allowed = false
			}
		}
		if !allowed {
			return nil, fmt.Errorf("unsupported OAuth enable/disable directive")
		}
		if key == "response type" {
			words = append(words, "parameter")
		}
		return [][]string{append(words, state)}, nil
	case "extract":
		if len(args) < 4 || !slices.Equal(args[len(args)-2:], []string{"from", "userinfo"}) {
			return nil, fmt.Errorf("expected OAuth extract fields from userinfo")
		}
		return [][]string{append([]string{"user_info_fields"}, args[1:len(args)-2]...)}, nil
	case "icon":
		return translateOAuthIcon(args[1:])
	default:
		return [][]string{args}, nil
	}
}

// translateOAuthIcon expands positional icon fields without collapsing them
// into a map. The legacy icons.Parse drops surplus values and overwrites repeated
// modifiers, which would hide duplicates from shared validation. Keep each value
// as a statement, including priority zero and integers larger than float64 can
// represent exactly; the shared parser owns value and duplicate validation.
func translateOAuthIcon(args []string) ([][]string, error) {
	fields := []string{"text", "class_name", "color", "background_color"}
	var lines [][]string
	for len(args) > 0 {
		switch args[0] {
		case "text":
			fields = []string{"text_color", "text_background_color"}
			args = args[1:]
		case "priority":
			fields = []string{"priority"}
			args = args[1:]
		}
		if len(args) == 0 || len(fields) == 0 || args[0] == "text" || args[0] == "priority" {
			return nil, fmt.Errorf("invalid OAuth login icon argument count")
		}
		lines = append(lines, []string{"login", "icon", fields[0], args[0]})
		fields, args = fields[1:], args[1:]
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty OAuth login icon")
	}
	return lines, nil
}
