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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"gopkg.in/yaml.v3"
)

func TestAuthenticationClientConfigAdapter(t *testing.T) {
	base := "base_url: https://auth.example.test/tenant/auth/\nrealm: local\n"
	for _, tc := range []struct {
		name, body string
		want       authclient.Config
	}{
		{"defaults", "username: alice\npassword: ''\ntotp_code_length: 0\ntotp_code_lifetime: 0\nrefresh_transport: ''\n", authclient.Config{Username: "alice", RefreshTransport: "cookie", TOTPCodeLength: 6, TOTPCodeLifetime: 30, AccessTokenName: authclient.DefaultAccessTokenName}},
		{"all password fields", "username: ' alice '\npassword: 'quoted \"secret\" with spaces ☃'\ntotp_secret: 'raw secret'\ntotp_code_length: 8\ntotp_code_lifetime: 45\naccess_token_name: CUSTOM_ACCESS\nrefresh_transport: body\n", authclient.Config{Username: "alice", Password: "quoted \"secret\" with spaces ☃", TOTPSecret: "raw secret", TOTPCodeLength: 8, TOTPCodeLifetime: 45, AccessTokenName: "CUSTOM_ACCESS", RefreshTransport: "body"}},
		{"API key", "api_key: synthetic-api-key\nrefresh_transport: cookie\n", authclient.Config{APIKey: "synthetic-api-key", RefreshTransport: "cookie", TOTPCodeLength: 6, TOTPCodeLifetime: 30, AccessTokenName: authclient.DefaultAccessTokenName}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseSecurityLocalConfig([]byte(base + tc.body + "token_path: private/token.json\ncookie_name: legacy\n"))
			if err != nil {
				t.Fatal(err)
			}
			tc.want.BaseURL, tc.want.Realm = "https://auth.example.test/tenant/auth", "local"
			if !cmp.Equal(tc.want, cfg.Config) || cfg.TokenPath != "private/token.json" || cfg.CookieName != "legacy" {
				t.Fatal("shared parser lost login settings or CLI-owned fields")
			}
			data, err := json.Marshal(cfg.Config)
			if err != nil {
				t.Fatal(err)
			}
			var restored authclient.Config
			if err := json.Unmarshal(data, &restored); err != nil || !cmp.Equal(restored, tc.want) {
				t.Fatal("typed authentication config failed JSON restoration")
			}
		})
	}
	for _, body := range []string{
		"username: alice\nrefresh_transport: native\n",
		"username: alice\nrefresh_transport: body\nrefresh_transport: cookie\n",
		"username: alice\ntotp_code_length: 3\n",
		"username: alice\ntotp_code_lifetime: -1\n",
		"username: alice\ntotp_code_lifetime: 999999999999999999999999\n",
		"username: alice\npassword: '   '\n",
		"username: alice\npassword: \"synthetic-secret\\nsecond-line\"\n",
		"username: alice\napi_key: synthetic-secret\n",
		"api_key: synthetic-secret\npassword: synthetic-secret\n",
		"api_key: synthetic-secret\ntotp_secret: synthetic-secret\n",
		"api_key: synthetic-secret\nrefresh_transport: body\n",
		"username: alice\naccess_token_name: 'bad name'\n",
	} {
		if _, err := parseSecurityLocalConfig([]byte(base + body)); err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid login config accepted or credentials disclosed")
		}
	}
}

func TestAuthenticationClientConfigWhitespace(t *testing.T) {
	for _, suffix := range []string{"\t", "\v", "\f", "\u0085", "\u00a0", "\u2003", "\u3000"} {
		t.Run(fmt.Sprintf("trailing U+%04X", []rune(suffix)[0]), func(t *testing.T) {
			secret := "synthetic-secret" + suffix
			for _, apiKey := range []bool{false, true} {
				want := authclient.Config{BaseURL: "https://auth.example.test", Realm: "local", Username: "alice", Password: secret, TOTPSecret: secret}
				if apiKey {
					want.Username, want.Password, want.TOTPSecret, want.APIKey = "", "", "", secret
				}
				data, err := yaml.Marshal(want)
				if err != nil {
					t.Fatal(err)
				}
				got, err := parseSecurityLocalConfig(data)
				if err != nil || got.Password != want.Password || got.TOTPSecret != want.TOTPSecret || got.APIKey != want.APIKey {
					t.Fatal("YAML adapter changed credential bytes", err)
				}
			}
		})
	}
	for _, field := range []string{"base_url", "refresh_transport", "access_token_name"} {
		t.Run("invalid "+field, func(t *testing.T) {
			values := map[string]string{"base_url": "https://auth.example.test", "realm": "local", "username": "alice", "refresh_transport": "body", "access_token_name": "CUSTOM"}
			values[field] += "\t"
			data, err := yaml.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseSecurityLocalConfig(data); err == nil {
				t.Fatal("invalid setting became valid after whitespace loss")
			}
		})
	}
}

// Emulate an older portal's strict schema. Real password/TOTP verification is
// covered separately through Caddy TLS; this checks the backwards-compatible
// wire envelope rather than relying on a modern server ignoring new fields.
func TestAuthenticationClientLegacyWire(t *testing.T) {
	for _, mode := range []string{"", authclient.RefreshTransportCookie} {
		t.Run("mode="+mode, func(t *testing.T) {
			var count atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Username          string `json:"username"`
					Realm             string `json:"realm"`
					SandboxID         string `json:"sandbox_id"`
					SandboxSecret     string `json:"sandbox_secret"`
					ChallengeKind     string `json:"challenge_kind"`
					ChallengeResponse string `json:"challenge_response"`
				}
				d := json.NewDecoder(r.Body)
				d.DisallowUnknownFields()
				if err := d.Decode(&request); err != nil || r.Method != "POST" || r.URL.Path != "/auth/login" {
					t.Error("client sent an unsupported legacy login request")
					w.WriteHeader(400)
					return
				}
				switch count.Add(1) {
				case 1:
					fmt.Fprint(w, `{"sandbox_id":"sandbox","sandbox_secret":"first","next_challenge":"password"}`)
				case 2:
					if request.SandboxSecret != "first" || request.ChallengeKind != "password" {
						t.Error("password checkpoint lost sandbox state")
					}
					fmt.Fprint(w, `{"sandbox_id":"sandbox","sandbox_secret":"second","next_challenge":"totp"}`)
				case 3:
					if request.SandboxSecret != "second" || request.ChallengeKind != "totp" {
						t.Error("TOTP checkpoint reused old sandbox state")
					}
					fmt.Fprint(w, `{"authenticated":true,"access_token":"synthetic-access-token"}`)
				default:
					t.Error("client retried completed login")
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			httpClient := server.Client()
			httpClient.Timeout = 5 * time.Second
			client, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + "/auth", Realm: "local", Username: "alice", Password: lifecyclePassword, TOTPSecret: "raw-totp-secret", RefreshTransport: mode}, authclient.Options{HTTPClient: httpClient})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			if err != nil || credentials == nil || credentials.RefreshToken != "" || count.Load() != 3 {
				t.Fatal("default/cookie mode broke strict-schema access-only login", err)
			}
		})
	}
}

func TestAuthenticationClientUnsupportedChallenge(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		fmt.Fprint(w, `{"sandbox_id":"sandbox","sandbox_secret":"secret","next_challenge":"mfa:u2f:e30="}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 5 * time.Second
	client, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL, Realm: "local", Username: "alice"}, authclient.Options{HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if credentials != nil || !errors.Is(err, authclient.ErrUnsupportedChallenge) || count.Load() != 1 {
		t.Fatal("unsupported assertion returned credentials or retried", err)
	}
}
