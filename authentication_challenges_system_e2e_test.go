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
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/system"
)

func testCaddySystemChallengePolicy(t *testing.T, cert, tlsKey string, roots *x509.CertPool) {
	f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", mfa: true}, cert, tlsKey, roots)
	const keyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	f.input = challengePolicyInput(f.input, "transform user {\nmatch realm local\nrequire auth challenges password\nadd label system-policy as string\n}")
	f.input = strings.Replace(f.input, "authentication portal myportal {", "authentication portal myportal {\ncrypto key internal system "+keyHex, 1)
	challengeRestart(t, f)
	key, err := system.ParseKeyFromString(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := system.NewEncryptor("internal", key)
	if err != nil {
		t.Fatal(err)
	}
	authenticate := func(status int) {
		t.Helper()
		encoded, err := encryptor.EncryptMessage(&system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "local", Username: "alice", Password: lifecyclePassword, Address: "198.51.100.10"})
		if err != nil {
			t.Fatal("cannot encrypt synthetic System API request")
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/api/system", strings.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "text/plain; charset=UTF-8")
		response, err := f.plain.Do(request)
		if err != nil {
			t.Fatal("System API TLS request failed")
		}
		defer response.Body.Close()
		if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatal("System API omitted verified TLS")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 {
			t.Fatal("invalid System API response size")
		}
		if response.StatusCode != status {
			t.Fatalf("System API HTTP %d, want %d", response.StatusCode, status)
		}
		if status != http.StatusOK {
			if _, err := encryptor.DecryptMessage(string(body)); err == nil {
				t.Fatal("rejected password issued an authentication assertion")
			}
			return
		}
		message, err := encryptor.DecryptMessage(string(body))
		if err != nil {
			t.Fatal("cannot verify encrypted authentication assertion")
		}
		result, ok := message.(*system.AuthResponseMessage)
		if !ok || !result.Authenticated || result.UserData["sub"] != "alice" || result.UserData["label"] != "system-policy" {
			t.Fatal("System API lost identity or realm transform")
		}
		if diff := cmp.Diff([]any{"pwd"}, result.UserData["amr"]); diff != "" {
			t.Fatal(diff)
		}
	}
	authenticate(http.StatusOK)
	candidate := strings.Replace(f.input, "match realm local", "match any", 1)
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(candidate), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(config, true); err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported with System API keys") {
		t.Fatal("unsafe System API replacement escaped provisioning guard")
	}
	for _, matcher := range []string{`"match any"`, "{env.CHALLENGE_NATIVE_MATCHER}"} {
		t.Setenv("CHALLENGE_NATIVE_MATCHER", "match any")
		candidate := challengeNativeMatcher(t, config, matcher)
		if err := caddy.Load(candidate, true); err == nil || !strings.Contains(err.Error(), "match any transforms are unsupported with System API keys") {
			t.Fatal("encoded native JSON matcher bypassed System API guard")
		}
		authenticate(http.StatusOK)
	}
	authenticate(http.StatusOK)
	f.input = strings.Replace(f.input, "require auth challenges password", "require auth challenges totp", 1)
	challengeRestart(t, f)
	authenticate(http.StatusForbidden)
}
