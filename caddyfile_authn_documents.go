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
	documentsparser "github.com/greenpau/go-authcrunch/pkg/authn/documents/parser"
)

// isDocumentsAPIDirective identifies the owned statement before argument
// collection, preserving structural closing braces and quoted value boundaries.
func isDocumentsAPIDirective(d *caddyfile.Dispenser) bool {
	keyword := d.Val()
	if strings.HasPrefix(keyword, "documents") || ((strings.HasPrefix(keyword, "enable") || strings.HasPrefix(keyword, "disable")) && strings.Contains(keyword, "documents")) {
		return true
	}
	if keyword != "enable" && keyword != "disable" {
		return false
	}
	if !d.NextArg() {
		return false
	}
	documents := strings.HasPrefix(d.Val(), "documents")
	d.Prev()
	return documents
}

// readCaddyfileDocumentsAPI retains complete statements for the shared parser.
// Documents is disabled unless explicitly enabled, independently of Admin and
// Profile. Storage-only settings remain disabled. Every setting occurs once,
// including opposing enable/disable statements and settings expanded by import.
// There is no Documents block; collect statements across the whole portal.
//
// Syntax:
//
//	<enable|disable> documents api
//	documents api database <absolute-private-database-path>
//	documents api public origin <canonical-https-origin>
//	documents api base path <canonical-portal-mount>
//	documents api realms <realm> [<realm>...]
//	documents api max file bytes <integer>
//	documents api max user bytes <integer>
//	documents api max total bytes <integer>
//	documents api max user files <integer>
//	documents api max total files <integer>
//	documents api max keys <integer>
//	documents api max recipients <integer>
//	documents api upload ttl seconds <integer>
//
// The shared parser owns defaults, bounds and duplicates. Numeric zero selects
// defaults; quotas count ciphertext including tags and pending uploads. The
// database parent must exist privately at runtime; adaptation performs no I/O.
// Preserve runtime-backed collections as whole snapshots, resolving each token
// once before shared validation and keeping other portal API flags intact.
func readCaddyfileDocumentsAPI(d *caddyfile.Dispenser) (string, error) {
	args, err := oauthApplicationArgs(d)
	if err != nil || validateOAuthDirectiveTokens(args) != nil {
		return "", d.Errf("invalid documents API argument")
	}
	if d.Next() {
		hasBlock := d.Val() == "{" && !d.Token().Quoted()
		d.Prev()
		if hasBlock {
			return "", d.Errf("documents API directives do not accept blocks")
		}
	}
	return encodeOAuthDirective(args), nil
}

func configurePortalDocuments(portal *authn.PortalConfig, statements []string) error {
	settings, err := documentsparser.NewDocumentsAPIConfigFromDirectives(statements)
	if err != nil {
		return err
	}
	return portal.ConfigureDocumentsAPI(settings)
}
