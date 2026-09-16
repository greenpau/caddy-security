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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"gopkg.in/yaml.v3"
)

func (f *authenticationClientFixture) passwordJourneys(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		name, username, subject        string
		configuredTOTP, promptPassword bool
		prompts                        []authclient.PromptKind
	}{
		{name: "configured password", username: "alice", subject: "alice"},
		{name: "email alias", username: "alice@example.test", subject: "alice"},
		{name: "case alias", username: "ALICE", subject: "alice"},
		{name: "prompted password", username: "alice", subject: "alice", promptPassword: true, prompts: []authclient.PromptKind{authclient.PromptPassword}},
		{name: "configured TOTP with email alias", username: "totpuser@example.test", subject: "totpuser", configuredTOTP: true},
		{name: "prompted TOTP", username: "totpuser", subject: "totpuser", prompts: []authclient.PromptKind{authclient.PromptTOTP}},
		{name: "configured combined MFA", username: "mfauser", subject: "mfauser", configuredTOTP: true},
		{name: "configured credentials with trailing whitespace", username: "whitespace", subject: "whitespace", configuredTOTP: true},
		{name: "prompted combined MFA", username: "MFAUSER", subject: "mfauser", prompts: []authclient.PromptKind{authclient.PromptMFA, authclient.PromptTOTP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authclient.Config{BaseURL: f.base + f.mount, Realm: "local", Username: tc.username, Password: lifecyclePassword, AccessTokenName: "unused_client_fallback"}
			if f.refresh {
				cfg.RefreshTransport = authclient.RefreshTransportBody
			}
			if tc.promptPassword {
				cfg.Password = ""
			}
			if tc.configuredTOTP {
				cfg.TOTPSecret = authenticationClientTOTPSecret
			}
			if tc.subject == "whitespace" {
				cfg.Password, cfg.TOTPSecret = authenticationClientWhitespacePassword, authenticationClientWhitespaceTOTPSecret
			}
			// Exercise the existing host config adapter, which delegates all login
			// settings to the public authclient parser and returns its typed Config.
			data, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parseSecurityLocalConfig(data)
			if err != nil {
				t.Fatal(err)
			}
			var prompts []authclient.PromptKind
			var prompt authclient.PromptFunc
			if len(tc.prompts) > 0 {
				prompt = func(ctx context.Context, kind authclient.PromptKind) (string, error) {
					if err := ctx.Err(); err != nil {
						return "", err
					}
					prompts = append(prompts, kind)
					switch kind {
					case authclient.PromptPassword:
						return lifecyclePassword, nil
					case authclient.PromptTOTP:
						return authenticationClientTOTP(), nil
					case authclient.PromptMFA:
						return "totp", nil
					default:
						return "", authclient.ErrUnsupportedChallenge
					}
				}
			}
			client, wire, jar := f.loginClient(t, parsed.Config, prompt)
			// Compare against the original YAML input, before the host adapter.
			wire.password = cfg.Password
			result, err := client.Authenticate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			want := 2
			if tc.subject != "alice" {
				want = 3
			}
			if wire.requests != want || len(wire.responses) != want || !slices.Equal(prompts, tc.prompts) {
				t.Fatal("login skipped checkpoints, retried or prompted unexpectedly")
			}
			if result.AccessTokenName != f.accessName {
				t.Fatal("portal token name did not override client fallback")
			}
			last := wire.responses[len(wire.responses)-1]
			if result.AccessToken != last.AccessToken || result.RefreshToken != last.RefreshToken || result.SessionID != last.SessionID || result.AccessExpiresAt != last.AccessExpiresAt || result.RefreshExpiresAt != last.RefreshExpiresAt || result.SessionExpiresAt != last.SessionExpiresAt {
				t.Fatal("client discarded response credentials or metadata")
			}
			if f.refresh {
				if result.RefreshToken == "" || result.SessionID == "" || result.RefreshTokenName != f.refreshName || result.AccessExpiresAt <= 0 || result.RefreshExpiresAt < result.AccessExpiresAt || result.SessionExpiresAt < result.RefreshExpiresAt {
					t.Fatal("native success omitted tokens, SID, names or deadlines")
				}
				u, _ := url.Parse(f.base + f.mount + "/")
				if cookies := jar.Cookies(u); len(cookies) != 1 || cookies[0].Name != "BROWSER_SENTINEL" {
					t.Fatal("native client modified a supplied browser jar")
				}
			} else if result.RefreshToken != "" || result.SessionID != "" {
				t.Fatal("legacy login acquired refresh authority")
			}
			f.credentialAccess(t, result, tc.subject)
			if tc.name == "configured password" {
				// A legacy JWT may be identical when claims and issuance seconds
				// match. A fresh exchange is established by its login checkpoints.
				fresh, err := client.Authenticate(t.Context())
				if err != nil || wire.requests != 2*want || len(wire.responses) != 2*want {
					t.Fatal("Authenticate did not perform a new login", err)
				}
				if f.refresh && (fresh.SessionID == result.SessionID || fresh.RefreshToken == result.RefreshToken || fresh.AccessToken == result.AccessToken) {
					t.Fatal("fresh login reused an existing native family")
				}
				f.credentialAccess(t, fresh, tc.subject)
			}
		})
	}
	for _, tc := range []struct {
		name, user, password, answer string
		wanted                       error
		status, calls                int
	}{
		{name: "wrong password", user: "alice", password: "Wrong-password-123", status: 401, calls: 2},
		{name: "wrong TOTP", user: "totpuser", password: lifecyclePassword, answer: "000", status: 401, calls: 3},
		{name: "missing TOTP", user: "totpuser", password: lifecyclePassword, wanted: authclient.ErrInputRequired, calls: 2},
		{name: "unenrolled WebAuthn selection", user: "mfauser", password: lifecyclePassword, answer: "webauthn", status: 401, calls: 3},
		{name: "canceled prompt", user: "alice", wanted: context.Canceled, calls: 1},
		{name: "canceled TOTP input", user: "totpuser", password: lifecyclePassword, wanted: context.Canceled, calls: 2},
		{name: "canceled before request", user: "alice", password: lifecyclePassword, wanted: context.Canceled, calls: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authclient.Config{Username: tc.user, Password: tc.password}
			if f.refresh {
				cfg.RefreshTransport = authclient.RefreshTransportBody
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var prompt authclient.PromptFunc
			if tc.wanted == context.Canceled && tc.calls > 0 {
				prompt = func(received context.Context, _ authclient.PromptKind) (string, error) {
					cancel()
					<-received.Done()
					return "", received.Err()
				}
			} else if tc.answer != "" {
				prompt = func(context.Context, authclient.PromptKind) (string, error) { return tc.answer, nil }
			}
			if tc.calls == 0 {
				cancel()
			}
			client, wire, _ := f.loginClient(t, cfg, prompt)
			result, err := client.Authenticate(ctx)
			if result != nil || err == nil || wire.requests != tc.calls || len(wire.responses) != tc.calls {
				t.Fatal("failed login returned credentials, retried or ignored cancellation")
			}
			if tc.wanted != nil {
				if !errors.Is(err, tc.wanted) {
					t.Fatalf("wrong login error: %v", err)
				}
			} else {
				assertAuthenticationClientStatus(t, err, tc.status)
			}
		})
	}
}

func assertAuthenticationClientStatus(t *testing.T, err error, status int) {
	t.Helper()
	var response *authclient.HTTPError
	if !errors.As(err, &response) || response.StatusCode != status {
		t.Fatalf("expected public HTTPError status %d, got %v", status, err)
	}
}

func (f *authenticationClientFixture) transportBoundaries(t *testing.T) {
	t.Helper()
	if !f.body {
		t.Run("native opt-in unavailable", func(t *testing.T) {
			client, wire, _ := f.loginClient(t, authclient.Config{Username: "alice", Password: lifecyclePassword, RefreshTransport: authclient.RefreshTransportBody}, nil)
			credentials, err := client.Authenticate(t.Context())
			assertAuthenticationClientStatus(t, err, 400)
			if credentials != nil || wire.requests != 1 || len(wire.responses) != 1 {
				t.Fatal("unavailable native transport retried or returned credentials")
			}
		})
	}
	if f.refresh {
		t.Run("cookie metadata requires native opt-in", func(t *testing.T) {
			client, wire, _ := f.loginClient(t, authclient.Config{Username: "alice", Password: lifecyclePassword}, nil)
			credentials, err := client.Authenticate(t.Context())
			if credentials != nil || !errors.Is(err, authclient.ErrNativeTransportRequired) || wire.requests != 2 || len(wire.responses) != 2 {
				t.Fatal("metadata-only completion was retried or mistaken for native success")
			}
			last := wire.responses[1]
			if !last.Authenticated || last.SessionID == "" || last.AccessToken != "" || last.RefreshToken != "" || last.AccessExpiresAt <= 0 {
				t.Fatal("browser response exposed credentials or omitted metadata")
			}
		})
	}
}

func (f *authenticationClientFixture) apiKeyJourneys(t *testing.T, keys map[string]string) {
	t.Helper()
	t.Run("API key trailing whitespace is not repaired", func(t *testing.T) {
		data, err := yaml.Marshal(authclient.Config{BaseURL: f.base + f.mount, Realm: "local", APIKey: keys["alice"] + "\t"})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := parseSecurityLocalConfig(data)
		if err != nil {
			t.Fatal(err)
		}
		client, wire, _ := f.loginClient(t, cfg.Config, nil)
		credentials, err := client.Authenticate(t.Context())
		assertAuthenticationClientStatus(t, err, 401)
		if credentials != nil || wire.requests != 1 || len(wire.responses) != 1 {
			t.Fatal("invalid API-key bytes were repaired or retried")
		}
	})
	for _, name := range []string{"alice", "totpuser", "mfauser", "expiredkey", "revokedkey", "disabledkey", "disableduser"} {
		t.Run("API key "+name, func(t *testing.T) {
			client, wire, jar := f.loginClient(t, authclient.Config{APIKey: keys[name]}, func(context.Context, authclient.PromptKind) (string, error) {
				t.Error("API-key login prompted for password/MFA")
				return "", authclient.ErrInputRequired
			})
			credentials, err := client.Authenticate(t.Context())
			if wire.requests != 1 || len(wire.responses) != 1 {
				t.Fatal("API-key login retried or entered sandbox authentication")
			}
			if strings.HasPrefix(name, "expired") || strings.HasPrefix(name, "revoked") || strings.HasPrefix(name, "disabled") {
				assertAuthenticationClientStatus(t, err, 401)
				if credentials != nil {
					t.Fatal("denied API key returned credentials")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if credentials.RefreshToken != "" || credentials.SessionID != "" || credentials.AccessTokenName != f.accessName {
				t.Fatal("API-key login acquired refresh authority or lost custom name")
			}
			u, _ := url.Parse(f.base + f.mount + "/")
			if len(jar.Cookies(u)) != 0 {
				t.Fatal("API key established browser state")
			}
			f.credentialAccess(t, credentials, name)
		})
	}
	for _, body := range []map[string]string{
		{"api_key": keys["alice"], "username": "alice"},
		{"api_key": keys["alice"], "challenge_kind": "password", "challenge_response": lifecyclePassword},
		{"api_key": keys["alice"], "sandbox_id": "old", "sandbox_secret": "old"},
		{"api_key": keys["alice"], "refresh_transport": "body"},
	} {
		body["realm"] = "local"
		response := f.jsonRequest(t, "POST", "/login", body, nil)
		if response.status != 400 || response.header.Get("Cache-Control") != "no-store" {
			t.Fatal("mixed credentials or body-mode API key did not fail closed")
		}
		var result authclient.Credentials
		if response.readError != nil || json.Unmarshal(response.body, &result) != nil || result.AccessToken != "" || result.RefreshToken != "" || result.SessionID != "" {
			t.Fatal("rejected login returned credential authority")
		}
	}
}

func (f *authenticationClientFixture) cliConnect(t *testing.T, cert string) {
	t.Helper()
	t.Run("existing CLI native configuration", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "client.yaml")
		token := filepath.Join(dir, "private", "token.json")
		data := fmt.Sprintf("base_url: %q\nrealm: local\nusername: whitespace\npassword: %q\ntotp_secret: %q\nrefresh_transport: body\ntoken_path: %q\n", f.base+f.mount, authenticationClientWhitespacePassword, authenticationClientWhitespaceTOTPSecret, token)
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		var previous *authclient.Credentials
		for range 2 {
			output, err := securityCommand(t, "security", "local", "connect", "--config", path, "--ca-file", cert)
			if err != nil {
				t.Fatalf("native CLI login failed: %v\n%s", err, output)
			}
			var summary struct {
				Status    string `json:"status"`
				TokenPath string `json:"token_path"`
			}
			physical, pathErr := filepath.EvalSymlinks(token)
			if json.Unmarshal(output, &summary) != nil || summary.Status != "success" || pathErr != nil || summary.TokenPath != physical {
				t.Fatal("connect did not report private credential path")
			}
			store, err := authclient.NewFileTokenStore(token)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if credentials.RefreshToken == "" || credentials.SessionID == "" || (previous != nil && (previous.SessionID == credentials.SessionID || previous.RefreshToken == credentials.RefreshToken)) {
				t.Fatal("connect did not persist fresh native credentials")
			}
			for _, secret := range []string{authenticationClientWhitespacePassword, authenticationClientWhitespaceTOTPSecret, credentials.AccessToken, credentials.RefreshToken} {
				if strings.Contains(string(output), secret) {
					t.Fatal("connect disclosed credentials")
				}
			}
			f.credentialAccess(t, credentials, "whitespace")
			previous = credentials
		}
	})
}
