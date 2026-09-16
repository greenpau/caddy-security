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

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func cacheTestJWT(t *testing.T, expires time.Time) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expires),
	}).SignedString([]byte("synthetic-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestCredentialExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	aliasJWT := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"Ed25519"}`)) + "." + strings.Split(cacheTestJWT(t, now), ".")[1] + ".opaque"
	for _, tc := range []struct {
		name  string
		token string
		meta  int64
		want  time.Time
	}{
		{"metadata", "opaque", now.Unix(), now},
		{"jwt", cacheTestJWT(t, now), 0, now},
		{"algorithm-independent expiry", aliasJWT, 0, now},
		{"earlier jwt", cacheTestJWT(t, now), now.Add(time.Hour).Unix(), now},
		{"earlier metadata", cacheTestJWT(t, now.Add(time.Hour)), now.Unix(), now},
		{"missing", "opaque", 0, time.Time{}},
		{"malformed jwt", "bad.jwt.value", 0, time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expires, err := credentialExpiry(&authclient.Credentials{AccessToken: tc.token, AccessExpiresAt: tc.meta})
			if tc.want.IsZero() {
				if err == nil || !strings.Contains(err.Error(), "--force") {
					t.Fatal("unknown expiration did not require explicit reauthentication")
				}
			} else if err != nil || !expires.Equal(tc.want) {
				t.Fatal("incorrect cached credential expiration")
			}
		})
	}
}

func TestCLICachedLogin(t *testing.T) {
	for _, mode := range []string{"valid", "near expiry", "expired", "forced", "unknown expiry"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/login" {
					t.Error("unexpected request for cached login")
				}
				json.NewEncoder(w).Encode(apiauth.AuthResponse{Authenticated: true, AccessToken: "fresh-token", AccessExpiresAt: time.Now().Add(time.Hour).Unix()})
			}))
			defer server.Close()
			home := filepath.Join(t.TempDir(), "state")
			configureTest(t, home, "default", server.URL)
			expires := time.Now().Add(time.Hour)
			if mode == "near expiry" {
				expires = time.Now().Add(time.Minute)
			} else if mode == "expired" {
				expires = time.Now().Add(-time.Minute)
			}
			token := cacheTestJWT(t, expires)
			if mode == "unknown expiry" {
				token = "opaque-without-expiry"
			}
			path := filepath.Join(home, "profiles", "default", "token.jwt")
			store, _ := authclient.NewFileTokenStore(path)
			if err := store.Save(&authclient.Credentials{AccessToken: token}); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			args := []string{"login"}
			if mode == "forced" {
				args = append(args, "--force")
			} else if mode == "valid" || mode == "near expiry" {
				// Reusing a token must not even open a supplied password file.
				args = append(args, "--password-file", filepath.Join(home, "absent-secret"))
			}
			out, _, err := cli(t, home, "", args...)
			after, _ := os.ReadFile(path)
			if mode == "unknown expiry" {
				if err == nil || !strings.Contains(err.Error(), "--force") {
					t.Fatal("unknown expiry did not require explicit login")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if mode == "expired" || mode == "forced" {
				if requests.Load() != 1 || bytes.Equal(before, after) {
					t.Fatal("fresh authentication did not replace cached credentials")
				}
			} else if requests.Load() != 0 || !bytes.Equal(before, after) {
				t.Fatal("cached login contacted the portal or changed credentials")
			}
			if mode == "near expiry" && !strings.Contains(out, "no refresh credential") {
				t.Fatal("refresh unavailability was not reported")
			}
		})
	}
}

func refreshTestCredentials() *authclient.Credentials {
	now := time.Now()
	return &authclient.Credentials{
		AccessToken: "old-access", AccessTokenName: "custom_access",
		RefreshToken: "old-refresh", RefreshTokenName: "CUSTOM_REFRESH", SessionID: "session",
		AccessExpiresAt: now.Add(time.Minute).Unix(), RefreshExpiresAt: now.Add(time.Hour).Unix(),
		SessionExpiresAt: now.Add(2 * time.Hour).Unix(),
	}
}

func refreshTestResponse(cached *authclient.Credentials) apiauth.AuthResponse {
	return apiauth.AuthResponse{
		Authenticated: true, AccessToken: "new-access", AccessTokenName: "CUSTOM_ACCESS",
		RefreshToken: "new-refresh", RefreshTokenName: "CUSTOM_REFRESH", SessionID: cached.SessionID,
		AccessExpiresAt: time.Now().Add(10 * time.Minute).Unix(), RefreshExpiresAt: cached.RefreshExpiresAt,
		SessionExpiresAt: cached.SessionExpiresAt,
	}
}

func TestCLIRefreshRequiresNativeConfiguration(t *testing.T) {
	for _, missing := range []string{"body transport", "session metadata"} {
		t.Run(missing, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Error(w, "must not be contacted", 500)
			}))
			defer server.Close()
			home := filepath.Join(t.TempDir(), "state")
			transport := "body"
			cached := refreshTestCredentials()
			if missing == "body transport" {
				transport = "cookie"
			} else {
				cached.SessionID = ""
			}
			configureTest(t, home, "default", server.URL, "--refresh-transport", transport)
			store, _ := authclient.NewFileTokenStore(filepath.Join(home, "profiles", "default", "token.jwt"))
			if err := store.Save(cached); err != nil {
				t.Fatal(err)
			}
			if _, _, err := cli(t, home, "", "login"); err == nil || !strings.Contains(err.Error(), "native body transport") || requests.Load() != 0 {
				t.Fatal("refresh ignored required native configuration")
			}
			if _, err := os.Stat(filepath.Join(home, "profiles", "default", "refresh.pending")); !os.IsNotExist(err) {
				t.Fatal("preflight failure marked an unsent refresh as pending")
			}
		})
	}
}

func TestCLINativeRefresh(t *testing.T) {
	for _, mode := range []string{"success", "unauthorized", "bad json", "wrong session", "unchanged refresh", "expired response", "invalid token", "truncated", "redirect", "save failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			cached := refreshTestCredentials()
			var requests atomic.Int32
			home := filepath.Join(t.TempDir(), "state")
			path := filepath.Join(home, "profiles", "default", "token.jwt")
			pending := filepath.Join(home, "profiles", "default", "refresh.pending")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/auth/login" {
					result := refreshTestResponse(cached)
					result.AccessToken, result.RefreshToken, result.SessionID = "forced-access", "forced-refresh", "fresh-family"
					json.NewEncoder(w).Encode(result)
					return
				}
				if r.Method != "POST" || r.URL.Path != "/auth/api/refresh_token" || r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("incorrect native refresh request")
				}
				for _, header := range []string{"Cookie", "Origin", "Authorization", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
					if r.Header.Get(header) != "" {
						t.Error("native refresh sent browser or access credentials")
					}
				}
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["refresh_token"] != cached.RefreshToken {
					t.Error("incorrect refresh credential body")
				}
				if _, err := os.Stat(pending); err != nil {
					t.Error("refresh was sent without a pending marker")
				}
				result := refreshTestResponse(cached)
				switch mode {
				case "timeout":
					<-r.Context().Done()
					return
				case "unauthorized":
					http.Error(w, "private-server-error", 401)
					return
				case "bad json":
					io.WriteString(w, "private-server-error")
					return
				case "wrong session":
					result.SessionID = "unrelated-session"
				case "unchanged refresh":
					result.RefreshToken = cached.RefreshToken
				case "expired response":
					result.AccessExpiresAt = time.Now().Add(-time.Minute).Unix()
				case "invalid token":
					result.AccessToken = "invalid\nprivate-server-error"
				case "truncated":
					w.Header().Set("Content-Length", "4096")
					io.WriteString(w, "{")
					return
				case "redirect":
					http.Redirect(w, r, "/must-not-follow", 307)
					return
				case "save failure":
					if err := os.Remove(path); err != nil {
						t.Error(err)
					}
					if err := os.Mkdir(path, 0700); err != nil {
						t.Error(err)
					}
				}
				json.NewEncoder(w).Encode(result)
			}))
			defer server.Close()
			configureTest(t, home, "default", server.URL+"/auth", "--refresh-transport", "body")
			store, _ := authclient.NewFileTokenStore(path)
			if err := store.Save(cached); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			args := []string{"login"}
			if mode == "timeout" {
				args = append(args, "--timeout", "100ms")
			}
			out, diagnostics, err := cli(t, home, "", args...)
			if mode == "success" {
				if err != nil || !strings.Contains(out, "Refreshed.") {
					t.Fatal("refresh did not succeed:", err)
				}
				after, err := store.Load()
				if err != nil || after.AccessToken != "new-access" || after.RefreshToken != "new-refresh" || after.AccessTokenName != "custom_access" || after.SessionID != cached.SessionID || after.SessionExpiresAt != cached.SessionExpiresAt || after.CreatedAt == "" {
					t.Fatal("refresh lost credentials or metadata")
				}
				if _, err := os.Stat(pending); !os.IsNotExist(err) {
					t.Fatal("successful refresh retained its pending marker")
				}
				mustCLI(t, home, "", "login")
			} else {
				if err == nil || !strings.Contains(err.Error(), "--force") || strings.Contains(fmt.Sprint(err)+diagnostics, "private-server-error") {
					t.Fatal("failed refresh did not stop with redacted recovery guidance")
				}
				if mode == "save failure" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, before, 0600); err != nil {
						t.Fatal(err)
					}
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("failed refresh changed the cached token")
				}
				if _, _, err := cli(t, home, "", "login"); err == nil || !strings.Contains(err.Error(), "previous refresh") {
					t.Fatal("uncertain refresh was not blocked across commands")
				}
			}
			if requests.Load() != 1 {
				t.Fatal("refresh retried, followed a redirect or performed a fresh login")
			}
			logs, err := os.ReadFile(filepath.Join(home, "profiles", "default", "auth.log"))
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{cached.AccessToken, cached.RefreshToken, "new-access", "new-refresh", "private-server-error"} {
				if bytes.Contains(logs, []byte(secret)) || strings.Contains(out+diagnostics, secret) {
					t.Fatal("refresh leaked sensitive values")
				}
			}
			if mode != "success" {
				mustCLI(t, home, "", "login", "--force")
				fresh, err := store.Load()
				if err != nil || fresh.SessionID != "fresh-family" || requests.Load() != 2 {
					t.Fatal("forced login did not recover from uncertain refresh")
				}
				if _, err := os.Stat(pending); !os.IsNotExist(err) {
					t.Fatal("forced login retained the old refresh marker")
				}
			}
			// Clear is explicit local recovery; it removes both cached files.
			mustCLI(t, home, "", "clear")
			for _, file := range []string{path, pending} {
				if _, err := os.Stat(file); !os.IsNotExist(err) {
					t.Fatal("clear retained cached refresh state")
				}
			}
		})
	}
}
