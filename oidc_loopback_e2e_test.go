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
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (f *oidcRPFixture) testLoopback(t *testing.T) {
	for _, tc := range []struct{ network, host, client string }{{"tcp4", "127.0.0.1", "native4"}, {"tcp6", "[::1]", "native6"}} {
		t.Run(tc.network, func(t *testing.T) {
			listener, err := net.Listen(tc.network, tc.host+":0")
			if err != nil {
				t.Fatal("required native loopback listener unavailable", err)
			}
			received := make(chan url.Values, 1)
			callback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/callback" {
					http.NotFound(w, r)
					return
				}
				select {
				case received <- r.URL.Query():
				default:
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			callback.Listener.Close()
			callback.Listener = listener
			callback.Start()
			t.Cleanup(callback.Close)
			actual := callback.URL + "/callback?registered=yes"
			registered := "http://" + tc.host + ":1/callback?registered=yes"
			if actual == registered {
				t.Fatal("ephemeral listener did not vary the registered port")
			}
			f.newBrowser(t)
			f.login(t)
			params := f.authorization(tc.client)
			for _, wrong := range []string{
				strings.Replace(actual, "/callback", "/other", 1),
				strings.Replace(actual, "/callback", "/%63allback", 1),
				actual + "&extra=yes", strings.Replace(actual, "registered=yes", "registered=%79es", 1),
				"http://localhost:43112/callback?registered=yes",
				"http://127.1:43112/callback?registered=yes",
				"http://[::ffff:127.0.0.1]:43112/callback?registered=yes",
				"com.example.app:/callback", "http://*.example.test/callback",
				strings.Replace(actual, "http://", "https://", 1),
			} {
				params.Set("redirect_uri", wrong)
				r := f.authorize(t, params)
				r.requireStatus(t, 400)
				if r.header.Get("Location") != "" {
					t.Fatal("unsafe native callback received a redirect")
				}
			}
			params.Set("redirect_uri", actual)
			response := f.authorize(t, params)
			code := f.callback(t, response, params, "")
			// Deliver the actual OP redirect to a real native ephemeral listener.
			native := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			r, err := http.NewRequestWithContext(t.Context(), "GET", response.header.Get("Location"), nil)
			if err != nil {
				t.Fatal(err)
			}
			delivered, err := native.Do(r)
			if err != nil {
				t.Fatal("native callback delivery failed")
			}
			delivered.Body.Close()
			if delivered.StatusCode != 204 {
				t.Fatal("native listener rejected callback")
			}
			select {
			case values := <-received:
				if values.Get("code") != code || values.Get("state") != params.Get("state") || values.Get("iss") != f.issuer || values.Get("registered") != "yes" {
					t.Fatal("native callback lost protocol binding")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("native callback was not received")
			}
			// Only authorization may vary the port. Redemption is byte-exact.
			f.exchange(t, tc.client, code, registered, oidcRPVerifier).failure(t, 400, "invalid_grant")
			tokens, claims := f.tokens(t, f.exchange(t, tc.client, code, actual, oidcRPVerifier), params)
			f.userinfo(t, tokens, claims, "alice@example.test")
			f.exchange(t, tc.client, code, actual, oidcRPVerifier).failure(t, 400, "invalid_grant")
			// The callback port exception does not authorize arbitrary browser origins.
			preflight := f.request(t, "OPTIONS", f.endpoint(t, "token_endpoint"), nil, http.Header{"Origin": {callback.URL}, "Access-Control-Request-Method": {"POST"}})
			preflight.requireStatus(t, 403)
			if preflight.header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("native callback port exception expanded CORS")
			}
		})
	}
}
