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
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// normalizeSecurityMetadata applies Caddy's edge trust decision before
// AuthCrunch's address and URL helpers read forwarded metadata. Caddy resolves
// the client address using client_ip_headers and trusted_proxies_strict; parsing
// that chain again here would silently introduce a different trust policy.
func normalizeSecurityMetadata(r *http.Request) {
	trusted, _ := caddyhttp.GetVar(r.Context(), caddyhttp.TrustedProxyVarKey).(bool)
	for _, name := range []string{"X-Forwarded-Host", "X-Forwarded-Proto"} {
		values := r.Header.Values(name)
		if trusted && len(values) > 0 {
			// Match Caddy reverse_proxy: the last header field wins. A comma
			// list stays a list and remains subject to library validation.
			r.Header.Set(name, values[len(values)-1])
		} else {
			r.Header.Del(name)
		}
	}
	// These alternative hints have no Caddy origin/mount trust contract.
	// In particular, X-Real-IP must not override Caddy's resolved client IP.
	for _, name := range []string{"Forwarded", "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Port", "X-Forwarded-Prefix"} {
		r.Header.Del(name)
	}
	// Direct peers already have an authoritative RemoteAddr. Keep that native
	// representation (including bracketed IPv6) instead of feeding it through
	// the library's forwarded-address parser unnecessarily.
	if clientIP, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); trusted && ok && clientIP != "" {
		r.Header.Set("X-Forwarded-For", clientIP)
	}
}
