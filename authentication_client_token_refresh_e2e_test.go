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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

type authenticationClientHTTPResponse struct {
	status    int
	header    http.Header
	body      []byte
	readError error
}

// Explicit native protocol requests are deliberately separate from authclient:
// Authenticate performs fresh login and does not manage refresh/logout retries.
func (f *authenticationClientFixture) jsonRequest(t *testing.T, method, path string, body any, headers http.Header) authenticationClientHTTPResponse {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequestWithContext(t.Context(), method, f.base+f.mount+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	for name, values := range headers {
		r.Header[name] = values
	}
	response, err := f.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	return authenticationClientHTTPResponse{status: response.StatusCode, header: response.Header, body: data, readError: err}
}

func (r authenticationClientHTTPResponse) native(t *testing.T, status int) apiauth.AuthResponse {
	t.Helper()
	if r.readError != nil {
		t.Fatal(r.readError)
	}
	if r.status != status {
		t.Fatalf("native protocol status %d, want %d", r.status, status)
	}
	if len(r.header.Values("Set-Cookie")) != 0 || r.header.Get("Cache-Control") != "no-store" || r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("native protocol changed cookie, cache or CORS contract")
	}
	var result apiauth.AuthResponse
	if json.Unmarshal(r.body, &result) != nil {
		t.Fatal("native response was not JSON")
	}
	return result
}

func (f *authenticationClientFixture) nativeProtocol(t *testing.T) {
	t.Helper()
	t.Run("explicit native rotation and logout", func(t *testing.T) {
		client, wire, _ := f.loginClient(t, authclient.Config{Username: "alice", Password: lifecyclePassword, RefreshTransport: authclient.RefreshTransportBody}, nil)
		first, err := client.Authenticate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		request := map[string]string{"refresh_token": first.RefreshToken}
		// Native state cannot be introspected with the browser-only lookup.
		f.jsonRequest(t, "POST", "/api/refresh_session", request, nil).native(t, 403)
		rotated := f.jsonRequest(t, "POST", "/api/refresh_token", request, nil).native(t, 200)
		if rotated.SessionID != first.SessionID || rotated.RefreshToken == "" || rotated.RefreshToken == first.RefreshToken || rotated.AccessToken == "" || rotated.AccessToken == first.AccessToken || rotated.SessionExpiresAt != first.SessionExpiresAt || rotated.RefreshTokenName != f.refreshName {
			t.Fatal("rotation lost family binding, tokens, names or absolute deadline")
		}
		// Match authclient's login conversion: the portal advertises the cookie
		// name, while named Authorization values use its lower-case header name.
		credentials := &authclient.Credentials{AccessToken: rotated.AccessToken, AccessTokenName: strings.ToLower(rotated.AccessTokenName), RefreshToken: rotated.RefreshToken, RefreshTokenName: rotated.RefreshTokenName, SessionID: rotated.SessionID, AccessExpiresAt: rotated.AccessExpiresAt, RefreshExpiresAt: rotated.RefreshExpiresAt, SessionExpiresAt: rotated.SessionExpiresAt}
		f.credentialAccess(t, credentials, "alice")
		request["refresh_token"] = rotated.RefreshToken
		logout := f.jsonRequest(t, "POST", "/api/logout", request, nil)
		logout.native(t, 200)
		var result struct {
			LoggedOut bool `json:"logged_out"`
		}
		if json.Unmarshal(logout.body, &result) != nil || !result.LoggedOut {
			t.Fatal("native logout was not confirmed")
		}
		f.jsonRequest(t, "POST", "/api/refresh_token", request, nil).native(t, 401)
		if wire.requests != 2 || len(wire.responses) != 2 {
			t.Fatal("protocol operations triggered an automatic login")
		}
	})
	t.Run("committed native response loss has no retry", func(t *testing.T) {
		client, wire, _ := f.loginClient(t, authclient.Config{Username: "alice", Password: lifecyclePassword, RefreshTransport: authclient.RefreshTransportBody}, nil)
		first, err := client.Authenticate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		f.probe.mu.Lock()
		beforeRequests, beforeRotations := f.probe.rotationRequests, f.probe.rotations
		f.probe.cutNext = true
		f.probe.mu.Unlock()
		lost := f.jsonRequest(t, "POST", "/api/refresh_token", map[string]string{"refresh_token": first.RefreshToken}, nil)
		if lost.status != 200 || !errors.Is(lost.readError, io.ErrUnexpectedEOF) || len(lost.header.Values("Set-Cookie")) != 0 {
			t.Fatal("fault did not lose an already-committed native response")
		}
		// Recovery is a separate, explicit fresh login. Never replay the spent
		// credential to discover whether the interrupted operation committed.
		fresh, err := client.Authenticate(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if fresh.SessionID == first.SessionID || fresh.RefreshToken == first.RefreshToken || wire.requests != 4 || len(wire.responses) != 4 {
			t.Fatal("fresh authentication was mistaken for renewal")
		}
		f.probe.mu.Lock()
		requests, rotations := f.probe.rotationRequests-beforeRequests, f.probe.rotations-beforeRotations
		f.probe.mu.Unlock()
		if requests != 1 || rotations != 1 {
			t.Fatal("uncertain native rotation retried")
		}
		f.credentialAccess(t, fresh, "alice")
		f.jsonRequest(t, "POST", "/api/logout", map[string]string{"refresh_token": first.RefreshToken}, nil).native(t, 200)
		// Revoking the uncertain old family must leave the explicitly created
		// replacement usable. This is a deliberate rotation of the new family.
		replacement := f.jsonRequest(t, "POST", "/api/refresh_token", map[string]string{"refresh_token": fresh.RefreshToken}, nil).native(t, 200)
		if replacement.SessionID != fresh.SessionID || replacement.RefreshToken == "" || replacement.RefreshToken == fresh.RefreshToken {
			t.Fatal("old-family logout damaged the fresh family")
		}
		f.jsonRequest(t, "POST", "/api/logout", map[string]string{"refresh_token": replacement.RefreshToken}, nil).native(t, 200)
	})
}
