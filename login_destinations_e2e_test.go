// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestCaddyLoginDestinationsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLoginDestinationsProcess$", "-test.v", "-test.timeout=170s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_DESTINATIONS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy login destinations: %v\n%s", err, output)
	}
}

type destinationSandbox struct{ location, name, proof string }

func destinationStart(t *testing.T, f *localIdentityFixture, username, query string) destinationSandbox {
	t.Helper()
	target := "/login?" + query
	providerDestinationRequest(t, f.oidcRPFixture, "GET", target, nil, nil).requireStatus(t, 200)
	r := providerDestinationRequest(t, f.oidcRPFixture, "POST", target, url.Values{"username": {username}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
	r.requireStatus(t, 303)
	location := r.header.Get("Location")
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.Host != strings.TrimPrefix(f.base, "https://") || !strings.HasPrefix(u.Path, f.mount+"/sandbox/") || u.RawQuery != "" {
		t.Fatal("login did not create a mounted sandbox")
	}
	name := "AUTHP_SANDBOX_ID_" + strings.TrimPrefix(u.Path, f.mount+"/sandbox/")
	proof := providerDestinationProof(t, f.oidcRPFixture, name)
	f.secrets = append(f.secrets, strings.TrimPrefix(proof, name+"="))
	found := false
	for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
		if cookie.Name == name {
			found = true
			path := f.mount
			if path == "" {
				path = "/"
			}
			if cookie.Path != path || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
				t.Fatal("independent proof lost its host, mount, or lifetime boundary")
			}
		}
	}
	if !found {
		t.Fatal("login omitted independent proof")
	}
	providerDestinationRequest(t, f.oidcRPFixture, "GET", location, nil, nil).requireStatus(t, 200)
	return destinationSandbox{location, name, proof}
}

func destinationPassword(t *testing.T, f *localIdentityFixture, s destinationSandbox, password string) {
	t.Helper()
	// Neither the checkpoint URL nor its form may replace the start's choice.
	tampered := providerDestinationURL(f.base, "/resource", "tampered")
	r := providerDestinationRequest(t, f.oidcRPFixture, "POST", s.location+"?redirect_url="+url.QueryEscape(tampered), url.Values{"secret": {password}, "redirect_url": {tampered}}, http.Header{"Origin": {f.base}})
	r.requireStatus(t, 303)
}

func destinationFinish(t *testing.T, f *localIdentityFixture, s destinationSandbox, target string, methods ...string) map[string]any {
	t.Helper()
	r := providerDestinationRequest(t, f.oidcRPFixture, "GET", s.location, nil, nil)
	providerDestinationLocation(t, r, target)
	if f.cookie(s.name) != "" {
		t.Fatal("completed flow retained its proof cookie")
	}
	token := f.cookie("AUTHP_ACCESS_TOKEN")
	f.secrets = append(f.secrets, token, f.cookie("AUTHP_REFRESH_TOKEN"))
	claims := challengeClaims(t, f, token, methods...)
	f.assertResource(t, token)
	replay := providerDestinationRequest(t, providerDestinationReplayBrowser(f.oidcRPFixture), "GET", s.location, nil, http.Header{"Cookie": {s.proof}})
	replay.requireStatus(t, 401)
	providerDestinationNoIssuance(t, replay)
	return claims
}

func TestCaddyLoginDestinationsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_DESTINATIONS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	t.Run("destination_boundaries", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/tenant/auth", configure: func(input string) string { return providerDestinationLocalConfig(t, input) }}, cert, key, roots)
		valid := providerDestinationURL(f.base, "/resource", "original")
		long := f.base + "/resource?q=" + strings.Repeat("x", 8192)
		for _, tc := range []struct{ name, query, want string }{
			{"encoded", "redirect_url=" + url.QueryEscape(valid), valid},
			{"query_canonicalization", "redirect_url=" + url.QueryEscape(f.base+"/resource?tab=original&path=%2Fone%2Ftwo&literal=one%26two#part%202"), valid},
			{"long_cookie_free", "redirect_url=" + url.QueryEscape(long), long},
			{"empty_first", "redirect_url=&redirect_url=" + url.QueryEscape(valid), ""},
			{"untrusted", "redirect_url=" + url.QueryEscape("https://outside.invalid/resource"), ""},
			{"malformed_first", "redirect_url=%zz&redirect_url=" + url.QueryEscape(valid), ""},
			{"too_long", "redirect_url=" + url.QueryEscape(f.base+"/resource?q="+strings.Repeat("x", 16*1024)), ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f.newBrowser(t)
				s := destinationStart(t, f, "alice", tc.query)
				if tc.name == "long_cookie_free" && f.cookie("AUTHP_REDIRECT_URL") != "" {
					t.Fatal("long destination was put in a cookie")
				}
				competing := providerDestinationURL(f.base, "/resource", "later_visit")
				providerDestinationRequest(t, f.oidcRPFixture, "GET", "/login?redirect_url="+url.QueryEscape(competing), nil, nil).requireStatus(t, 200)
				if f.cookie("AUTHP_REDIRECT_URL") == "" {
					t.Fatal("competing login page did not establish legacy cookie")
				}
				destinationPassword(t, f, s, lifecyclePassword)
				want := tc.want
				if want == "" {
					want = f.issuer + "/portal?redirect_url="
				}
				destinationFinish(t, f, s, want, "pwd")
				if tc.want != "" {
					providerDestinationResource(t, f.oidcRPFixture, want, "identity resource")
				}
			})
		}
	})
	t.Run("browser_capacity", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/tenant/auth"}, cert, key, roots)
		var flows []destinationSandbox
		for range 16 {
			flows = append(flows, destinationStart(t, f, "alice", "redirect_url="))
		}
		r := providerDestinationRequest(t, f.oidcRPFixture, "POST", "/login?redirect_url=", url.Values{"username": {"alice"}, "realm": {"local"}}, http.Header{"Origin": {f.base}})
		r.requireStatus(t, 429)
		providerDestinationNoIssuance(t, r)
		for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
			if strings.HasPrefix(cookie.Name, "AUTHP_SANDBOX_ID") {
				t.Fatal("capacity refusal changed a proof cookie")
			}
		}
		providerDestinationLocation(t, providerDestinationRequest(t, f.oidcRPFixture, "GET", flows[0].location+"/terminate", nil, nil), f.issuer+"/login?redirect_url=")
		if f.cookie(flows[0].name) != "" || f.cookie(flows[1].name) == "" {
			t.Fatal("termination did not clear exactly one flow")
		}
		_ = destinationStart(t, f, "alice", "redirect_url=")
		destinationPassword(t, f, flows[1], lifecyclePassword)
		destinationFinish(t, f, flows[1], f.issuer+"/portal?redirect_url=", "pwd")
	})
	t.Run("MFA_refresh_overlap", func(t *testing.T) {
		const bobSecret = "DifferentFixtureTOTPSecretForBob42"
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/tenant/auth", refreshRealm: "local", mfa: true, seed: func(t *testing.T, database string) {
			db, err := identity.NewDatabase(database)
			if err != nil {
				t.Fatal("cannot open fixture identity store")
			}
			r := &requests.Request{User: requests.User{Username: "bob", Email: "bob@example.test", Challenges: []string{"password totp"}}, MfaToken: requests.MfaToken{Type: "totp", Secret: bobSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}}
			if db.AddMfaToken(r) != nil || db.OverwriteUserAuthChallengeRules(r) != nil {
				t.Fatal("cannot seed independent Bob factor")
			}
		}, configure: func(input string) string { return providerDestinationLocalConfig(t, input) }}, cert, key, roots)
		f.secrets = append(f.secrets, bobSecret)
		destinations := []string{providerDestinationURL(f.base, "/resource", "alice"), providerDestinationURL(f.base, "/resource", "bob")}
		flows := []destinationSandbox{destinationStart(t, f, "alice", "redirect_url="+url.QueryEscape(destinations[0])), destinationStart(t, f, "bob", "redirect_url="+url.QueryEscape(destinations[1]))}
		destinationPassword(t, f, flows[0], lifecyclePassword)
		destinationPassword(t, f, flows[1], localIdentityBobPassword)
		f.noCredentials(t)
		for _, index := range []int{1, 0} {
			secret := authenticationClientTOTPSecret
			if index == 1 {
				secret = bobSecret
			}
			providerDestinationRequest(t, f.oidcRPFixture, "GET", flows[index].location, nil, nil).requireStatus(t, 200)
			providerDestinationRequest(t, f.oidcRPFixture, "POST", flows[index].location, url.Values{"passcode": {destinationTOTP(secret)}}, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
			claims := destinationFinish(t, f, flows[index], destinations[index], "pwd", "otp")
			if claims["sub"] != []string{"alice", "bob"}[index] {
				t.Fatal("MFA completion issued the other tab's principal")
			}
			providerDestinationResource(t, f.oidcRPFixture, destinations[index], "identity resource")
			if index == 1 && f.cookie(flows[0].name) == "" {
				t.Fatal("refresh issuance removed the other tab's proof")
			}
		}
	})
	t.Run("native_proof_rotation", func(t *testing.T) {
		f := newLocalIdentityFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local", mfa: true}, cert, key, roots)
		req := apiauth.AuthRequest{Username: "alice", Realm: "local", RefreshTransport: "body"}
		start := localIdentityAuth(t, f.json(t, f.plain, "/login", req, ""))
		f.secrets = append(f.secrets, start.SandboxSecret)
		// Browser starts use separate cookies and cannot overwrite body proof.
		_ = destinationStart(t, f, "bob", "redirect_url=")
		req.SandboxID, req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = start.SandboxID, start.SandboxSecret, "password", lifecyclePassword
		r := f.json(t, f.plain, "/login", req, "")
		next := localIdentityAuth(t, r)
		f.secrets = append(f.secrets, next.SandboxSecret)
		if next.Authenticated || next.NextChallenge != "totp" || next.SandboxSecret == "" || next.SandboxSecret == start.SandboxSecret {
			t.Fatal("native checkpoint did not rotate its body proof")
		}
		for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
			if strings.HasPrefix(cookie.Name, "AUTHP_SANDBOX_ID") {
				t.Fatal("native body proof was placed in a cookie")
			}
		}
		localIdentityRejectedAuth(t, f.json(t, f.plain, "/login", req, ""), 400)
		req.SandboxSecret, req.ChallengeKind, req.ChallengeResponse = next.SandboxSecret, "totp", authenticationClientTOTP()
		done := localIdentityAuth(t, f.json(t, f.plain, "/login", req, ""))
		if !done.Authenticated || done.AccessToken == "" || done.RefreshToken == "" {
			t.Fatal("fresh native proof failed after stale-proof rejection")
		}
		f.secrets = append(f.secrets, done.AccessToken, done.RefreshToken)
		challengeClaims(t, f, done.AccessToken, "pwd", "otp")
		f.assertResource(t, done.AccessToken)
	})
}

func destinationTOTP(secret string) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
