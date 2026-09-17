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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/go-cmp/cmp"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

func TestSecurityRequestMetadata(t *testing.T) {
	for _, tc := range []struct {
		name         string
		vars         map[string]any
		host, source string
		peer         string
	}{
		{"no Caddy context", nil, "portal.example.test", "192.0.2.1", "192.0.2.1:1234"},
		{"untrusted", map[string]any{caddyhttp.TrustedProxyVarKey: false, caddyhttp.ClientIPVarKey: "192.0.2.1"}, "portal.example.test", "192.0.2.1", "192.0.2.1:1234"},
		{"direct IPv6", map[string]any{caddyhttp.TrustedProxyVarKey: false, caddyhttp.ClientIPVarKey: "2001:db8:1:2:3:4:5:6"}, "portal.example.test", "2001:db8:1:2:3:4:5:6", "[2001:db8:1:2:3:4:5:6]:1234"},
		{"trusted", map[string]any{caddyhttp.TrustedProxyVarKey: true, caddyhttp.ClientIPVarKey: "198.51.100.2"}, "public.example.test", "198.51.100.2", "127.0.0.1:1234"},
		{"trusted IPv6", map[string]any{caddyhttp.TrustedProxyVarKey: true, caddyhttp.ClientIPVarKey: "2001:db8::1"}, "public.example.test", "2001:db8::1", "127.0.0.1:1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://portal.example.test/tenant/auth/api/refresh_token?x=%2F", nil)
			r.RemoteAddr = tc.peer
			r.Header = http.Header{
				"X-Forwarded-Host":  {"hostile.example", "public.example.test"},
				"X-Forwarded-Proto": {"http", "https"},
				"X-Forwarded-For":   {"203.0.113.66, 198.51.100.2"}, "X-Real-Ip": {"203.0.113.66"},
				"X-Forwarded-Port": {"9999"}, "X-Forwarded-Prefix": {"/hostile"}, "Forwarded": {"host=hostile.example;proto=http"},
				"Origin": {"https://public.example.test"}, "Cookie": {"a=b"},
			}
			if tc.vars != nil {
				r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, tc.vars))
			}
			originalURL, originalURI, originalTLS := *r.URL, r.RequestURI, r.TLS
			normalizeSecurityMetadata(r)
			if addrutil.GetSourceHost(r) != tc.host || addrutil.GetSourceAddress(r) != tc.source {
				t.Fatal("library did not consume Caddy's origin/address decision")
			}
			wantForwarded := http.Header{}
			if tc.vars[caddyhttp.TrustedProxyVarKey] == true {
				wantForwarded.Set("X-Forwarded-For", tc.source)
				wantForwarded.Set("X-Forwarded-Host", "public.example.test")
				wantForwarded.Set("X-Forwarded-Proto", "https")
			}
			for _, name := range []string{"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-For"} {
				if diff := cmp.Diff(wantForwarded.Values(name), r.Header.Values(name)); diff != "" {
					t.Fatalf("%s values: %s", name, diff)
				}
			}
			for _, name := range []string{"Forwarded", "X-Real-IP", "X-Forwarded-Port", "X-Forwarded-Prefix"} {
				if r.Header.Get(name) != "" {
					t.Fatalf("retained unsupported hint %s", name)
				}
			}
			if *r.URL != originalURL || r.RequestURI != originalURI || r.TLS != originalTLS || r.RemoteAddr != tc.peer || r.Header.Get("Origin") != "https://public.example.test" || r.Header.Get("Cookie") != "a=b" {
				t.Fatal("normalization changed protocol evidence")
			}
			first := r.Header.Clone()
			normalizeSecurityMetadata(r)
			if diff := cmp.Diff(first, r.Header); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}
