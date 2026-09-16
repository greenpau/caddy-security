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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/spf13/cobra"
)

// Expiry is only a local cache scheduling hint, never authentication evidence.
// Native responses supply metadata; legacy JWT files carry exp in their claims.
// When both exist, use the earlier value. Resources still verify signed tokens.
func credentialExpiry(credentials *authclient.Credentials) (time.Time, error) {
	var expires time.Time
	if credentials.AccessExpiresAt > 0 {
		expires = time.Unix(credentials.AccessExpiresAt, 0)
	}
	// Reading exp does not depend on a registered signing algorithm (portals
	// also issue JWTs with the Ed25519 alias). No signature is verified here.
	parts := strings.Split(credentials.AccessToken, ".")
	if len(parts) == 3 {
		var claims struct {
			ExpiresAt *jwt.NumericDate `json:"exp"`
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil && json.Unmarshal(payload, &claims) == nil && claims.ExpiresAt != nil {
			if expires.IsZero() || claims.ExpiresAt.Before(expires) {
				expires = claims.ExpiresAt.Time
			}
		}
	}
	if expires.IsZero() {
		return time.Time{}, errors.New("cached token has no readable expiration; use login --force to authenticate again")
	}
	return expires, nil
}

func refreshProfile(cmd *cobra.Command, s *state, p profile, store *authclient.FileTokenStore, cached *authclient.Credentials) error {
	info, err := checkFile(s.pendingPath(), true, true)
	if err != nil {
		return err
	}
	if info != nil {
		return errors.New("previous refresh may have consumed its credential; use login --force to authenticate again")
	}
	cfg, err := p.config()
	if err != nil {
		return err
	}
	if cfg.RefreshTransport != authclient.RefreshTransportBody || cached.SessionID == "" {
		return errors.New("cached refresh requires native body transport and session metadata; use login --force to authenticate again")
	}
	hc, cleanup, err := profileHTTPClient(cmd, s, p, cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	data, err := json.Marshal(struct {
		Token string `json:"refresh_token"`
	}{cached.RefreshToken})
	if err != nil || len(data) > 1024 {
		return errors.New("invalid cached refresh credential; use login --force")
	}
	request, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, cfg.BaseURL+"/api/refresh_token", bytes.NewReader(data))
	if err != nil {
		return errors.New("cannot create refresh request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "caddy-authenticator")
	if err := cmd.Context().Err(); err != nil {
		return err
	}
	// A rotation may commit before its response is lost. Persist the marker
	// before sending, under the state lock, so later commands cannot replay it.
	// Only saving fresh credentials or clearing local state removes the marker.
	if err := atomicWrite(s.pendingPath(), []byte("Refresh may have consumed its credential. Use login --force to authenticate again.\n")); err != nil {
		return err
	}
	response, err := hc.Do(request)
	if err != nil {
		if cmd.Context().Err() != nil {
			return fmt.Errorf("refresh interrupted; use login --force to authenticate again: %w", cmd.Context().Err())
		}
		return errors.New("refresh response unavailable; use login --force to authenticate again")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed (HTTP %d); cached token retained; use login --force to authenticate again", response.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, maxFileSize+1))
	if err != nil || len(data) > maxFileSize || !utf8.Valid(data) {
		return errors.New("refresh response incomplete or invalid; use login --force to authenticate again")
	}
	var result apiauth.AuthResponse
	if json.Unmarshal(data, &result) != nil || !result.Authenticated || result.SessionID != cached.SessionID ||
		result.AccessToken == "" || result.AccessToken == cached.AccessToken || result.AccessTokenName == "" ||
		result.RefreshToken == "" || result.RefreshToken == cached.RefreshToken || result.RefreshTokenName == "" ||
		result.AccessExpiresAt <= time.Now().Unix() || result.RefreshExpiresAt <= time.Now().Unix() ||
		result.SessionExpiresAt <= time.Now().Unix() || result.AccessExpiresAt > result.SessionExpiresAt ||
		result.RefreshExpiresAt > result.SessionExpiresAt ||
		(cached.SessionExpiresAt != 0 && result.SessionExpiresAt != cached.SessionExpiresAt) {
		return errors.New("refresh response has invalid credentials or session metadata; use login --force to authenticate again")
	}
	credentials := &authclient.Credentials{
		AccessToken: result.AccessToken, AccessTokenName: strings.ToLower(result.AccessTokenName),
		RefreshToken: result.RefreshToken, RefreshTokenName: result.RefreshTokenName,
		SessionID: result.SessionID, AccessExpiresAt: result.AccessExpiresAt,
		RefreshExpiresAt: result.RefreshExpiresAt, SessionExpiresAt: result.SessionExpiresAt,
	}
	if expires, err := credentialExpiry(credentials); err != nil || !expires.After(time.Now()) {
		return errors.New("refresh returned expired credentials; use login --force to authenticate again")
	}
	if err := store.Save(credentials); err != nil {
		return errors.New("refresh completed, but could not save token.jwt; use login --force to authenticate again")
	}
	if err := removePrivate(s.pendingPath()); err != nil {
		return errors.New("refreshed and saved token.jwt, but could not clear refresh.pending")
	}
	return nil
}
