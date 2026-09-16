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
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	tokenrefreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// readCaddyfileTokenRefresh collects a single flat portal refresh block. The
// shared parser owns fields, duplicates, defaults and semantic validation.
//
// Syntax (inside an authentication portal; settings occur at most once):
//
//	token refresh {
//	    <enabled|disabled>
//	    realms <realm> [<realm>...]
//	    public origin <canonical-https-origin>
//	    base path <absolute-mount-path>
//	    cookie name <name>
//	    access lifetime <seconds>
//	    idle timeout <seconds>
//	    absolute timeout <seconds>
//	    body transport <enabled|disabled>
//	    max sessions <count>
//	    max rotations <count>
//	}
//
// This configures rotating portal sessions, independently of upstream provider
// refresh or OIDC refresh grants. Enabled is the default when the block exists
// and requires realms, public origin and base path. No block leaves the config
// nil; disabled opts out. Both preserve ordinary access-only lifetimes. An empty
// block is invalid. Disabled settings still require valid directive grammar.
//
// realms selects realm names from attached local identity stores, not store
// nicknames. Each must identify exactly one supported store; there is no implicit
// all-realms selection. Other realms and unsupported login kinds remain
// access-only. Password/MFA completion supplies the required login evidence.
//
// public origin pins the actual HTTPS origin, including any nondefault port,
// without a path. base path pins the unstripped portal mount and refresh-cookie
// path; use / for a root mount. These bindings prevent using a refresh credential
// at another origin or mount. Caddy passes the original URL to Portal.ServeHTTP.
// A coexisting OIDC issuer must equal origin plus mount (omit the root slash).
//
// cookie name inherits the shared cookie prefix/refresh-token name when omitted.
// An explicit enabled override applies before collision validation; a disabled
// override cannot rename cookies. Refresh cookies are host-only, Secure, HttpOnly
// and SameSite=Lax, independently of ordinary access-cookie attributes. A
// __Host- refresh name requires base path /.
//
// access lifetime bounds each access token issued by a participating refresh
// login or rotation (default 300 seconds). The signing key's lifetime and the
// family's remaining absolute lifetime can shorten it further. Shorter access
// lifetimes require more frequent renewal for continuous access.
//
// idle timeout bounds the time until the next successful rotation (default 1800
// seconds). Issuance and successful rotation set a new idle deadline, capped by
// the absolute deadline. Ordinary access requests and session probes do not
// extend it. absolute timeout caps the family from its original authentication
// time (default 28800 seconds); rotations never move that deadline. Expiry
// requires a fresh login. Access and idle lifetimes must not exceed the absolute
// timeout, which cannot exceed 2592000 seconds (30 days).
//
// body transport permits explicit native JSON transport (default disabled).
// Native clients select refresh_transport: body at every login checkpoint and
// send no Cookie, Origin or Sec-Fetch headers. Credentials arrive in JSON without
// cookies; subsequent refresh/logout requests carry refresh_token in the body.
// Cookie transport remains the default even when body transport is enabled:
// browsers use HttpOnly cookies and the required origin/refresh-header checks.
// Families are bound to their chosen transport. Enabling body transport does not
// grant arbitrary CORS access or expose browser refresh credentials in JSON.
//
// max sessions caps live refresh families across this portal's selected realms
// and both transports (default 10000), rather than users, tabs or HTTP requests.
// A family is one login session and its chain of rotated credentials; independent
// logins by the same user can occupy several slots. An additional independent
// login at capacity returns 503 without evicting an existing live family.
// Expired/revoked families release capacity; a fresh browser login can atomically
// replace a presented family with the same binding. This is a memory bound, not a
// rate limit. The portal owns a separate in-memory store that is lost on runtime
// replacement or restart; this block cannot configure a distributed store.
//
// max rotations caps successful rotations per family (default 1024); initial
// issuance does not count. The next attempt beyond the limit revokes the family,
// returns 401 and requires fresh login. Spent credential hashes are retained
// while the family lives so replay can revoke its current descendant. Together,
// the limits bound storage to max sessions * (max rotations + 1) credential
// hashes plus session metadata. Lower limits can require earlier reauthentication.
//
// Durations are integer seconds and counts are integers; omitted/zero numeric
// settings select library defaults, not unlimited operation. State arguments are
// enabled/disabled, never true/false/0/1. Every setting occurs at most once,
// including through imports. For request details and configuration examples, see
// .codex/skills/configuration-authentication/references/token-refresh.md.
func readCaddyfileTokenRefresh(d *caddyfile.Dispenser, args []string) ([]string, error) {
	if len(args) != 1 || args[0] != "refresh" {
		return nil, d.Errf("expected token refresh block")
	}
	body, err := readFlatDirectiveBlock(d, "token refresh")
	if err != nil {
		return nil, err
	}
	statements := make([]string, 0, len(body))
	for _, args := range body {
		statements = append(statements, encodeOAuthDirective(args))
	}
	return statements, nil
}

func configurePortalTokenRefresh(portal *authn.PortalConfig, body []string) error {
	config, err := tokenrefreshparser.NewTokenRefreshConfigFromDirectives(body)
	if err != nil {
		return err
	}
	portal.RefreshTokens = config
	return nil
}

// tokenRefreshCookieDirectives applies the enabled override before the shared
// cookie parser validates collisions. Keep every statement (including duplicate
// name settings) so the parser still owns grammar and duplicate detection. Only
// canonical, complete refresh-name statements may be overlaid; their original
// names must remain valid HTTP tokens even though their effective name changes.
// Legacy spellings have already been translated by encodePortalCookieDirective.
func tokenRefreshCookieDirectives(refresh *authn.TokenRefreshConfig, statements []string) ([]string, error) {
	if refresh == nil || !refresh.Enabled || refresh.CookieName == "" {
		return statements, nil
	}
	result := slices.Clone(statements)
	nameDirective := []string{"cookie", "refresh", "token", "name"}
	override := encodeOAuthDirective(append(nameDirective, refresh.CookieName))
	found := false
	for i, statement := range result {
		if !utf8.ValidString(statement) || strings.ContainsAny(statement, "\r\n") {
			return nil, fmt.Errorf("invalid cookie directive at line %d", i+1)
		}
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil {
			return nil, fmt.Errorf("invalid cookie directive at line %d", i+1)
		}
		if len(args) != 5 || !slices.Equal(args[:4], nameDirective) {
			continue
		}
		if (&http.Cookie{Name: args[4]}).Valid() != nil {
			return nil, fmt.Errorf("invalid refresh cookie name at line %d", i+1)
		}
		result[i], found = override, true
	}
	if !found {
		result = append(result, override)
	}
	return result, nil
}
