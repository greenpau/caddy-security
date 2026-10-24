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

// readCaddyfileIdentityAttachment preserves a complete shared-parser statement,
// including quoted names, without consuming a structural enclosing brace.
func readCaddyfileIdentityAttachment(d *caddyfile.Dispenser) (string, error) {
	args, err := oauthApplicationArgs(d)
	if err != nil || validateOAuthDirectiveTokens(args) != nil {
		return "", d.Errf("invalid identity attachment argument")
	}
	if d.Next() {
		nested := d.Val() == "{" && !d.Token().Quoted()
		d.Prev()
		if nested {
			return "", d.Errf("identity attachments do not accept blocks")
		}
	}
	return encodeOAuthDirective(args), nil
}

// Params have passed through the app's JSON snapshot before runtime resolution.
// Preserve the distinction between an omitted/empty native attachment and a
// named binding whose environment/secret reference resolves to an empty string.
func identityAttachmentName(params map[string]any) string {
	config, ok := params["attachment"].(map[string]any)
	if !ok {
		return ""
	}
	name, _ := config["local_identity_store"].(string)
	return name
}
