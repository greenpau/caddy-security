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

import "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

// readCaddyfileOIDCProvider collects the optional provider body without parsing
// fields, resolving applications, reading keys, or generating credentials.
// Config.ConfigureOIDCProvider owns the field grammar and reference validation.
//
// Syntax (inside an authentication portal; every setting occurs at most once):
//
//	oidc provider {
//		<enabled|disabled>
//		issuer <canonical-https-url-including-mount>
//		realms <realm> [<realm>...]
//		signing key files <absolute-private-pem> [<absolute-private-pem>...]
//		applications <nickname> [<nickname>...]
//		session lifetime <seconds>
//		token lifetime <seconds>
//		max sessions <count>
//		max pending requests <count>
//		max grants <count>
//	}
//
// Multiword keywords are separate tokens; lists occupy one line. Quote paths
// containing spaces. State is standalone and defaults to enabled. Zero integers
// retain library defaults. An absent block stays nil; disabled needs no issuer,
// keys, realms, or clients, but syntax and explicit application references still
// validate. A second block fails even when both are disabled. Selected realms
// must each identify exactly one attached local store and no upstream provider
// at runtime. The first dedicated RSA key signs; all keys publish. Runtime key
// checks require clean absolute paths, private 0700 directories and 0600 files.
func readCaddyfileOIDCProvider(d *caddyfile.Dispenser, args []string) ([]string, error) {
	if len(args) != 1 || args[0] != "provider" {
		return nil, d.Errf("expected oidc provider block")
	}
	body, err := readRegistrationBlock(d)
	if err != nil {
		return nil, err
	}
	// Non-nil also records the presence of an empty block, so it cannot be
	// mistaken for an absent provider or silently replaced by a second block.
	statements := make([]string, 0, len(body))
	for _, args := range body {
		statements = append(statements, encodeOAuthDirective(args))
	}
	return statements, nil
}
