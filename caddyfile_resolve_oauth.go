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
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"go.uber.org/zap"
)

// Resolve each original argument once, then let the shared parser recompute
// defaults and validate the whole provider. Normalized maps can contain derived
// URLs or a Google client-ID suffix appended to an unresolved secret reference.
// Do not resolve that map or expand substituted values a second time.
func resolveOAuthProviderDirectives(ctx context.Context, repl *caddy.Replacer, managers []SecretsManager, name string, statements []string, log *zap.Logger) (*idp.IdentityProviderConfig, error) {
	resolved := make([]string, 0, len(statements))
	for i, statement := range statements {
		path := fmt.Sprintf("OAuthProviderDirectives[%q][%d]", name, i)
		// DecodeArgs only reads one CSV record. Reject ignored trailing records in
		// JSON-supplied snapshots just as the shared parser rejects literal input.
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n\x00") {
			return nil, fmt.Errorf("%s: invalid OAuth directive", path)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 || validateOAuthDirectiveTokens(args) != nil {
			return nil, fmt.Errorf("%s: invalid OAuth directive", path)
		}
		args, err = substituteStrings(ctx, repl, managers, path, args, log)
		if err != nil {
			return nil, err
		}
		if err := validateOAuthDirectiveTokens(args); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		resolved = append(resolved, encodeOAuthDirective(args))
	}
	provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives(name, resolved)
	if err != nil {
		return nil, fmt.Errorf("OAuth provider %q: %w", name, err)
	}
	return provider, nil
}
