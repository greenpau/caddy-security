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
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/system"
)

func TestCaddyAccessSignerE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAccessSignerProcess$", "-test.v", "-test.timeout=400s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_ACCESS_SIGNER_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy selected access signing: %v\n%s", err, output)
	}
}

func TestCaddyAccessSignerProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_ACCESS_SIGNER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("cannot load fixture TLS key")
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal("cannot initialize system TLS roots")
	}
	oauthE2ESystemRoots = roots
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run("local"+strings.ReplaceAll(mount, "/", "_"), func(t *testing.T) {
			f := newAccessSignerFixture(t, accessSignerOptions{mount: mount, maximum: 180, lifetime: 120, transform: "transform user {\nmatch any\nadd original_issuer {claims.iss} as string\n}\n"}, cert, key, roots)
			token := f.formLogin(t, "alice", lifecyclePassword, false)
			claims := f.verify(t, token)
			if claims["id"] != localIdentityRecord(t, f.database, "alice").ID || claims["original_issuer"] == f.issuer || !strings.HasPrefix(fmt.Sprint(claims["original_issuer"]), f.issuer+"/sandbox/") || accessSignerNumber(t, claims, "nbf") != accessSignerNumber(t, claims, "iat") {
				t.Fatal("selected form issuance lost identity, request policy context or normalized time")
			}
			f.consumers(t, token, true)
			jsonLogin, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "", false)
			f.verify(t, jsonLogin.AccessToken)
			f.consumers(t, jsonLogin.AccessToken, true)
			basic := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("alice:"+lifecyclePassword))}}
			status, headers, body := registrationHTTP(t, f.plain, "GET", f.issuer+"/basic/login/local", nil, basic)
			r := oidcRPResponse{status, headers, body}
			accessSignerCapture(f.localIdentityFixture, r)
			r.requireStatus(t, 303)
			f.verify(t, accessSignerCookie(t, r, f.cookie).Value)
			bad := basic.Clone()
			bad.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:incorrect")))
			status, headers, body = registrationHTTP(t, f.plain, "GET", f.issuer+"/basic/login/local", nil, bad)
			providerDestinationNoIssuance(t, oidcRPResponse{status, headers, body})
			if status == 200 || status == 303 {
				t.Fatal("wrong Basic credential acquired selected access")
			}
			admin := &caddyAdminFixture{client: f.plain, base: f.base, mount: f.mount}
			published := fetchCaddyJWKS(t, admin, 1)
			discoveryStatus, discoveryHeaders, discoveryBody := jwksHTTPRequest(t, admin, "GET", f.mount+adminJWKSPath, nil)
			newOpenAPIContracts(t).AssertResponse(t, "GET", "/.well-known/jwks.json", discoveryStatus, discoveryHeaders, discoveryBody)
			accessSignerVerify(t, token, f.issuer, accessSignerAudience, f.kid, f.maximum, published)
			if mount != "" {
				status, _, _ := registrationHTTP(t, f.plain, "GET", f.base+adminJWKSPath, nil, nil)
				if status != 404 {
					t.Fatal("selected JWKS escaped its declared portal mount")
				}
			}
			untrusted := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}, Timeout: 5 * time.Second}
			defer untrusted.CloseIdleConnections()
			if response, err := untrusted.Get(f.issuer + adminJWKSPath); err == nil {
				response.Body.Close()
				t.Fatal("untrusted TLS root unexpectedly reached signer discovery")
			}
			if mount != "" {
				testAccessSignerStrictConsumers(t, f, jsonLogin.AccessToken)
			}
		})
	}
	t.Run("MFA", func(t *testing.T) {
		apiKey := "000000000000000000000025" + strings.Repeat("M", 40)
		f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", mfa: true, seed: func(t *testing.T, path string) { accessSignerSeedAPIKey(t, path, apiKey) }}, cert, key, roots)
		f.secrets = append(f.secrets, apiKey)
		denied := f.json(t, f.plain, "/login", apiauth.AuthRequest{Realm: "local", APIKey: apiKey}, "")
		accessSignerCapture(f.localIdentityFixture, denied)
		localIdentityRejectedAuth(t, denied, 401)
		providerDestinationNoIssuance(t, denied)
		owner, err := caddy.ActiveContext().App("security")
		if err != nil {
			t.Fatal("factor fixture runtime unavailable")
		}
		app := owner.(*App)
		release, ok := app.acquireRequest()
		if !ok {
			t.Fatal("factor fixture request lease unavailable")
		}
		func() {
			defer release()
			portal, err := app.getPortal("myportal")
			if err != nil {
				t.Fatal("factor fixture portal unavailable")
			}
			request := &authproxy.Request{Realm: "local", Address: "127.0.0.1", Secret: base64.StdEncoding.EncodeToString([]byte("alice:" + lifecyclePassword))}
			f.secrets = append(f.secrets, request.Secret)
			err = portal.BasicAuth(request)
			f.secrets = append(f.secrets, request.Response.Payload)
			if err == nil || request.Response.Payload != "" {
				t.Fatal("direct password bypassed required local factor")
			}
		}()
		response, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "", true)
		claims := f.verify(t, response.AccessToken)
		methods, ok := claims["amr"].([]any)
		if !ok || !slices.Contains(methods, any("pwd")) || !slices.Contains(methods, any("otp")) {
			t.Fatal("selected signer lost completed local factors")
		}
		f.consumers(t, response.AccessToken, true)
	})
	t.Run("direct_credentials", func(t *testing.T) { testAccessSignerDirect(t, cert, key, roots) })
	t.Run("delivery", func(t *testing.T) { testAccessSignerDelivery(t, cert, key, roots) })
	t.Run("refresh", func(t *testing.T) { testAccessSignerRefresh(t, cert, key, roots) })
	t.Run("audience_policy", func(t *testing.T) { testAccessSignerAudiencePolicy(t, cert, key, roots) })
	t.Run("connected", func(t *testing.T) { testAccessSignerConnected(t, cert, key, roots, pair) })
	t.Run("OP_and_private_export", func(t *testing.T) { testAccessSignerAuthority(t, cert, key, roots) })
	t.Run("rollover_and_rejected_candidates", func(t *testing.T) { testAccessSignerRollover(t, cert, key, roots) })
	t.Run("legacy_provider_transfer", func(t *testing.T) { testAccessSignerLegacyProvider(t, cert, key, roots, pair) })
	t.Run("staged_signer_failures", func(t *testing.T) { testAccessSignerStaging(t, cert, key, roots) })
}

func testAccessSignerStrictConsumers(t *testing.T, f *accessSignerFixture, valid string) {
	t.Helper()
	claims := f.verify(t, valid)
	header := map[string]any{"alg": "PS256", "kid": f.kid, "typ": "authcrunch-access+jwt"}
	foreign := newJWKSKeyFiles(t, "RSA", "foreign")
	// Warm both independent consumer caches before every malformed credential.
	for _, name := range []string{"RS256", "wrong_purpose", "missing_purpose", "missing_kid", "unknown_kid", "foreign_key", "issuer", "missing_issuer", "missing_audience", "wrong_audience", "extra_audience", "duplicate_audience", "missing_subject", "empty_subject", "numeric_subject", "missing_iat", "missing_nbf", "missing_exp", "string_iat", "fractional_iat", "overflow_iat", "zero_nbf", "future_iat", "future_nbf", "expired", "backwards", "overlong", "duplicate_header", "duplicate_claim", "crit", "jku", "jwk", "x5u", "salt31", "salt33", "saltmax", "wrong_hash", "PS384", "oversize", "depth", "tampered"} {
		t.Run(name, func(t *testing.T) {
			f.consumers(t, valid, true)
			h, c := maps.Clone(header), maps.Clone(claims)
			key, algorithm, hash, salt := f.key, "PS256", crypto.SHA256, 32
			switch name {
			case "RS256":
				h["alg"], algorithm = "RS256", "RS256"
			case "wrong_purpose":
				h["typ"] = "JWT"
			case "missing_purpose":
				delete(h, "typ")
			case "missing_kid":
				delete(h, "kid")
			case "unknown_kid":
				h["kid"] = "unconfigured"
			case "foreign_key":
				key = foreign
			case "issuer":
				c["iss"] = f.base + "/wrong"
			case "missing_issuer":
				delete(c, "iss")
			case "missing_audience":
				delete(c, "aud")
			case "wrong_audience":
				c["aud"] = "different"
			case "extra_audience":
				c["aud"] = []string{accessSignerAudience, "different"}
			case "duplicate_audience":
				c["aud"] = []string{accessSignerAudience, accessSignerAudience}
			case "missing_subject":
				delete(c, "sub")
			case "empty_subject":
				c["sub"] = ""
			case "numeric_subject":
				c["sub"] = 42
			case "missing_iat":
				delete(c, "iat")
			case "missing_nbf":
				delete(c, "nbf")
			case "missing_exp":
				delete(c, "exp")
			case "string_iat":
				c["iat"] = fmt.Sprint(c["iat"])
			case "fractional_iat":
				c["iat"] = json.Number(fmt.Sprint(c["iat"]) + ".5")
			case "overflow_iat":
				c["iat"] = json.Number("9223372036854775808")
			case "zero_nbf":
				c["nbf"] = 0
			case "future_iat":
				c["iat"] = time.Now().Unix() + 30
			case "future_nbf":
				c["nbf"] = time.Now().Unix() + 30
			case "expired":
				c["exp"] = time.Now().Unix() - 1
			case "backwards":
				c["nbf"] = accessSignerNumber(t, claims, "iat") - 1
			case "overlong":
				c["exp"] = accessSignerNumber(t, claims, "iat") + f.maximum + 1
			case "crit":
				h["crit"] = []string{"unknown"}
			case "jku", "x5u":
				h[name] = f.base + "/untrusted-key"
			case "jwk":
				h["jwk"] = map[string]string{"kty": "RSA"}
			case "salt31":
				salt = 31
			case "salt33":
				salt = 33
			case "saltmax":
				salt = rsa.PSSSaltLengthAuto
			case "wrong_hash":
				hash = crypto.SHA384
			case "PS384":
				h["alg"], hash, salt = "PS384", crypto.SHA384, 48
			case "oversize":
				c["custom"] = strings.Repeat("x", 66<<10)
			case "depth":
				var nested any = "leaf"
				for range 20 {
					nested = map[string]any{"child": nested}
				}
				c["custom"] = nested
			}
			hb, cb := accessSignerJSON(t, h), accessSignerJSON(t, c)
			if name == "duplicate_header" {
				hb = append([]byte(`{"alg":"PS256",`), hb[1:]...)
			}
			if name == "duplicate_claim" {
				cb = append([]byte(`{"sub":"alice",`), cb[1:]...)
			}
			token := accessSignerRawToken(t, key, hb, cb, algorithm, hash, salt)
			if name == "tampered" {
				parts := strings.Split(token, ".")
				c["sub"] = "tampered"
				token = parts[0] + "." + base64.RawURLEncoding.EncodeToString(accessSignerJSON(t, c)) + "." + parts[2]
			}
			if name == "oversize" {
				f.oversizedHeaders(t, token)
			} else {
				f.consumers(t, token, false)
			}
			f.consumers(t, valid, true)
		})
	}
	// Independently signed exact numbers survive both live consumer paths.
	precise := maps.Clone(claims)
	precise["custom_exact"] = json.Number("9007199254740993")
	precise["iat"], precise["nbf"], precise["exp"] = time.Now().Unix(), time.Now().Unix(), time.Now().Unix()+3
	token := accessSignerRawToken(t, f.key, accessSignerJSON(t, header), accessSignerJSON(t, precise), "PS256", crypto.SHA256, 32)
	f.consumers(t, token, true)
	status, _, body := registrationHTTP(t, f.plain, "GET", f.issuer+"/whoami", nil, http.Header{"Accept": {"application/json"}, "Authorization": {"Bearer " + token}})
	if status != 200 || !bytes.Contains(body, []byte("9007199254740993")) {
		t.Fatal("portal consumer rounded an exact custom number")
	}
	accessSignerWait(t, time.Unix(precise["exp"].(int64), 0).Add(50*time.Millisecond))
	f.consumers(t, token, false)
	// An explicitly usable extra verifier is still outside this consumer's
	// selected profile. No legacy key search may rescue its valid signature.
	candidate := accessSignerMemoryCandidate(f.input)
	candidate = strings.ReplaceAll(candidate, f.key.verifier(f.kid), f.key.verifier(f.kid)+"\n"+foreign.verifier("unprofiled"))
	if accessSignerLoad(candidate) != nil {
		t.Fatal("cannot install unrelated verifier control")
	}
	f.client.CloseIdleConnections()
	header["kid"] = "unprofiled"
	claims["iat"], claims["nbf"], claims["exp"] = time.Now().Unix(), time.Now().Unix(), time.Now().Unix()+30
	outside := accessSignerRawToken(t, foreign, accessSignerJSON(t, header), accessSignerJSON(t, claims), "PS256", crypto.SHA256, 32)
	f.consumers(t, outside, false)
	newLogin, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "", false)
	f.consumers(t, newLogin.AccessToken, true)
	fetchCaddyJWKS(t, &caddyAdminFixture{client: f.plain, base: f.base, mount: f.mount}, 1)
}

func accessSignerSeedAPIKey(t *testing.T, path, key string) {
	t.Helper()
	db, err := identity.NewDatabase(path)
	if err != nil || db.AddAPIKey(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: key, Usage: "api", Comment: "Selected signer fixture"}}) != nil {
		t.Fatal("cannot seed selected signer API credential")
	}
}

func testAccessSignerDirect(t *testing.T, cert, tlsKey string, roots *x509.CertPool) {
	key := "000000000000000000000024" + strings.Repeat("D", 40)
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", tokenLabel: "logical_access", cookie: "DIRECT_ACCESS", seed: func(t *testing.T, path string) {
		accessSignerSeedAPIKey(t, path, key)
	}, configure: func(input string) string {
		// The common signer fixture already wraps global and site encoders.
		// Caddy does not redact custom credential headers by default; retain
		// DEBUG evidence and delete this field from both request-log copies.
		input = strings.Replace(input, "level INFO", "level DEBUG", 1)
		input = strings.ReplaceAll(input, "resp_headers>Location delete", "resp_headers>Location delete\nrequest>headers>X-Api-Key delete")
		return strings.Replace(input, "validate bearer header", "validate bearer header\nwith basic auth portal myportal realm local\nwith api key auth portal myportal realm local\nwith api key header name X-Api-Key", 1)
	}}, cert, tlsKey, roots)
	f.secrets = append(f.secrets, key)
	raw := f.json(t, f.plain, "/login", apiauth.AuthRequest{Realm: "local", APIKey: key}, "")
	accessSignerCapture(f.localIdentityFixture, raw)
	response := localIdentityAuth(t, raw)
	if !response.Authenticated || response.AccessToken == "" || response.AccessTokenName != "DIRECT_ACCESS" {
		t.Fatal("API credential lost selected HTTP token name")
	}
	f.verify(t, response.AccessToken)
	wrong := f.json(t, f.plain, "/login", apiauth.AuthRequest{Realm: "local", APIKey: key[:len(key)-1] + "E"}, "")
	accessSignerCapture(f.localIdentityFixture, wrong)
	localIdentityRejectedAuth(t, wrong, 401)
	for _, cookie := range (&http.Response{Header: wrong.header}).Cookies() {
		if cookie.Name == f.cookie && authenticationEventLiveCookie(cookie) {
			t.Fatal("rejected API credential published access")
		}
	}
	app, err := caddy.ActiveContext().App("security")
	if err != nil {
		t.Fatal("cannot access active Caddy security runtime")
	}
	owner := app.(*App)
	release, ok := owner.acquireRequest()
	if !ok {
		t.Fatal("active Caddy runtime rejected direct credential lease")
	}
	defer release()
	portal, err := owner.getPortal("myportal")
	if err != nil || portal == nil {
		t.Fatal("active Caddy portal unavailable")
	}
	for _, kind := range []string{"basic", "api_key"} {
		r := &authproxy.Request{Realm: "local", Address: "127.0.0.1", Secret: key}
		headers := http.Header{"X-Api-Key": {key}}
		if kind == "basic" {
			r.Secret = base64.StdEncoding.EncodeToString([]byte("alice:" + lifecyclePassword))
			headers = http.Header{"Authorization": {"Basic " + r.Secret}}
			err = portal.BasicAuth(r)
		} else {
			err = portal.APIKeyAuth(r)
		}
		f.secrets = append(f.secrets, r.Secret, r.Response.Payload)
		if err != nil || r.Response.Name != "logical_access" || r.Response.IsPlainPayload {
			t.Fatal("direct Caddy-owned credential issuer changed token contract")
		}
		f.verify(t, r.Response.Payload)
		// The HTTP credential protocol selects the same public realm as the
		// direct request above through its dedicated realm header.
		headers.Set("X-Auth-Realm", "local")
		status, _, _ := registrationHTTP(t, f.plain, "GET", f.base+"/resource", nil, headers)
		if status != 200 {
			t.Fatalf("real %s authorization failed: HTTP %d", kind, status)
		}
	}
}

func testAccessSignerDelivery(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, lifetime := range []int{0, 5, 600} {
		t.Run(fmt.Sprintf("cookie_%d", lifetime), func(t *testing.T) {
			f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", cookie: "CUSTOM_ACCESS", tokenLabel: "logical_access", cookieLifetime: lifetime, lifetime: 20, refresh: true, configure: func(input string) string {
				return strings.Replace(input, "realms local\npublic origin", "realms excluded\npublic origin", 1)
			}}, cert, key, roots)
			for _, flow := range []string{"form", "browser_JSON"} {
				t.Run(flow, func(t *testing.T) {
					var raw oidcRPResponse
					if flow == "form" {
						sandbox := f.formPassword(t, "alice", lifecyclePassword, 303)
						raw = f.request(t, "GET", sandbox, nil, nil)
						accessSignerCapture(f.localIdentityFixture, raw)
						raw.requireStatus(t, 303)
					} else {
						client := accessSignerBrowser(t, f.plain)
						_, prior := accessSignerNativeRealm(t, f.localIdentityFixture, client, "excluded", "alice", "", false)
						accessSignerCookie(t, prior, "AUTHP_REFRESH_TOKEN")
						var login apiauth.AuthResponse
						login, raw = accessSignerNative(t, f.localIdentityFixture, client, "alice", "", false)
						if login.AccessTokenName != "CUSTOM_ACCESS" || login.RefreshToken != "" || login.SessionID != "" {
							t.Fatal("access-only browser replacement retained renewable authority or logical token label")
						}
					}
					cookie := accessSignerCookie(t, raw, f.cookie)
					claims := f.verify(t, cookie.Value)
					if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
						t.Fatal("selected delivery changed cookie scope/security")
					}
					if lifetime == 0 {
						if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
							t.Fatal("selected signer made a session cookie persistent")
						}
					} else if cookie.MaxAge <= 0 || cookie.MaxAge > lifetime || int64(cookie.MaxAge) > accessSignerNumber(t, claims, "exp")-time.Now().Unix()+1 || cookie.Expires.Unix() > accessSignerNumber(t, claims, "exp") {
						t.Fatal("selected cookie exceeded configured or signed lifetime")
					}
					f.consumers(t, cookie.Value, true)
				})
			}
		})
	}
}

func testAccessSignerRefresh(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", refresh: true, lifetime: 30}, cert, key, roots)
	for _, transport := range []string{"body", "cookie"} {
		t.Run(transport, func(t *testing.T) {
			client, selection := f.plain, "body"
			if transport == "cookie" {
				client, selection = accessSignerBrowser(t, f.plain), ""
			}
			login, raw := accessSignerNative(t, f.localIdentityFixture, client, "alice", selection, false)
			access, refresh := login.AccessToken, login.RefreshToken
			if transport == "cookie" {
				access, refresh = accessSignerCookie(t, raw, f.cookie).Value, accessSignerCookie(t, raw, "AUTHP_REFRESH_TOKEN").Value
				if login.AccessToken != "" || login.RefreshToken != "" {
					t.Fatal("selected browser renewal disclosed credentials")
				}
			}
			before := f.verify(t, access)
			if login.AccessExpiresAt != accessSignerNumber(t, before, "exp") || accessSignerNumber(t, before, "exp")-accessSignerNumber(t, before, "iat") > 30 || login.SessionID == "" {
				t.Fatal("selected initial renewable metadata diverged from signed grant")
			}
			payload, headers := map[string]string{"refresh_token": refresh}, http.Header{}
			if transport == "cookie" {
				payload = map[string]string{}
				headers.Set("Origin", f.base)
				headers.Set("X-Authcrunch-Refresh", "1")
			}
			raw = f.json(t, client, "/api/refresh_token", payload, "", headers)
			accessSignerCapture(f.localIdentityFixture, raw)
			rotated := localIdentityAuth(t, raw)
			access = rotated.AccessToken
			if transport == "cookie" {
				access = accessSignerCookie(t, raw, f.cookie).Value
			}
			after := f.verify(t, access)
			if after["jti"] == before["jti"] || after["sid"] != before["sid"] || after["auth_time"] != before["auth_time"] || rotated.AccessExpiresAt != accessSignerNumber(t, after, "exp") || rotated.SessionID != login.SessionID {
				t.Fatal("selected rotation changed proof or returned inaccurate expiry")
			}
			if transport == "cookie" {
				cookie := accessSignerCookie(t, raw, f.cookie)
				if cookie.Expires.Unix() != rotated.AccessExpiresAt || cookie.MaxAge <= 0 {
					t.Fatal("renewable cookie disagreed with selected signed expiry")
				}
			}
			f.consumers(t, access, true)
		})
	}
}

func testAccessSignerAudiencePolicy(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, action := range []string{"delete aud", "overwrite aud signer-resource extra", "overwrite aud different"} {
		t.Run(strings.ReplaceAll(action, " ", "_"), func(t *testing.T) {
			f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", transform: "transform user {\nmatch any\naction " + action + "\n}\n"}, cert, key, roots)
			start := f.json(t, f.plain, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local"}, "")
			accessSignerCapture(f.localIdentityFixture, start)
			identified := localIdentityAuth(t, start)
			raw := f.json(t, f.plain, "/login", apiauth.AuthRequest{Username: "alice", Realm: "local", SandboxID: identified.SandboxID, SandboxSecret: identified.SandboxSecret, ChallengeKind: "password", ChallengeResponse: lifecyclePassword}, "")
			accessSignerCapture(f.localIdentityFixture, raw)
			providerDestinationNoIssuance(t, raw)
			if raw.status == 200 {
				t.Fatal("selected signer repaired an unapproved audience")
			}
		})
	}
	t.Run("renewal_cannot_restore_removed_grant", func(t *testing.T) {
		f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", refresh: true, configure: func(input string) string {
			grant := "action overwrite aud " + accessSignerAudience + "\n}\n"
			return strings.Replace(input, grant, grant+"transform user {\nsuffix match iss /api/refresh_token\naction delete aud\n}\n", 1)
		}}, cert, key, roots)
		login, _ := accessSignerNative(t, f.localIdentityFixture, f.plain, "alice", "body", false)
		f.verify(t, login.AccessToken)
		raw := f.json(t, f.plain, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, "")
		accessSignerCapture(f.localIdentityFixture, raw)
		providerDestinationNoIssuance(t, raw)
		if raw.status == 200 {
			t.Fatal("renewal restored an audience removed by current request policy")
		}
	})
}

func testAccessSignerConnected(t *testing.T, cert, tlsKey string, roots *x509.CertPool, pair tls.Certificate) {
	key := newJWKSKeyFiles(t, "RSA", "connected-selected")
	options := accessSignerOptions{mount: "/tenant/auth", maximum: 60, lifetime: 30}
	f := newCaddyConnectedAccountsFixture(t, connectedAccountsOptions{mount: options.mount, providerRefresh: true, configure: func(input string) string { return accessSignerConfigure(t, options, key, "selected", input) }}, cert, tlsKey, roots, pair)
	accessSignerCaptureCookies(f.localIdentityFixture)
	private, err := os.ReadFile(key.private)
	if err != nil {
		t.Fatal("cannot inventory connected signing key")
	}
	f.secrets = append(f.secrets, string(private))
	verify := func(token string) map[string]any {
		f.secrets = append(f.secrets, token)
		return accessSignerVerify(t, token, f.issuer, accessSignerAudience, "selected", 60, f.keys)
	}
	client := f.browser(t)
	f.login(t, client, "upstream", 303)
	initial := verify(connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
	if initial["id"] == localIdentityRecord(t, f.database, "alice").ID {
		t.Fatal("provider display email selected the local account")
	}
	// Reuse the real operation steps but not the legacy RS512-only verifier.
	o := connectedAccountsBegin(t, f.localIdentityFixture, client)
	sandbox := connectedAccountsStartLocal(t, f.localIdentityFixture, client, o.loginURL, "alice")
	finish := connectedAccountsFinishLocal(t, f.localIdentityFixture, client, sandbox, "alice")
	if finish.header.Get("Location") != o.endpoint {
		t.Fatal("selected local proof lost its bound connection operation")
	}
	review := connectedAccountsOperationForm(t, f.localIdentityFixture, connectedAccountsSend(t, f.localIdentityFixture, client, "GET", o.endpoint, nil, nil))
	verify(connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
	connectedAccountsPage(t, connectedAccountsForm(t, f.localIdentityFixture, client, review.endpoint, url.Values{"csrf": {review.csrf}, "action": {"connect"}}))
	f.login(t, client, "upstream", 303)
	before := verify(connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
	if before["id"] != localIdentityRecord(t, f.database, "alice").ID {
		t.Fatal("selected connected issuance lost local immutable identity")
	}
	f.upstream.mu.Lock()
	counts := [2]int{f.upstream.exchanges, f.upstream.userInfos}
	f.upstream.mu.Unlock()
	raw := f.send(t, client, "POST", "/api/refresh_token", strings.NewReader(`{}`), http.Header{"Content-Type": {"application/json"}, "Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}})
	accessSignerCapture(f.localIdentityFixture, raw)
	localIdentityAuth(t, raw)
	after := verify(connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
	f.upstream.mu.Lock()
	nextCounts := [2]int{f.upstream.exchanges, f.upstream.userInfos}
	f.upstream.mu.Unlock()
	if counts != nextCounts || before["id"] != after["id"] || before["sid"] != after["sid"] || before["jti"] == after["jti"] {
		t.Fatal("selected provider renewal replaced proof or contacted the upstream")
	}
	f.assertResource(t, connectedAccountsCookie(t, f.localIdentityFixture, client, "AUTHP_ACCESS_TOKEN"))
}

func testAccessSignerAuthority(t *testing.T, cert, key string, roots *x509.CertPool) {
	const systemKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", oidc: true, configure: func(input string) string {
		return strings.Replace(input, "enable admin api", "crypto key internal system "+systemKey+"\nenable admin api\nenable admin api private key export", 1)
	}}, cert, key, roots)
	f.secrets = append(f.secrets, systemKey)
	parsedKey, err := system.ParseKeyFromString(systemKey)
	if err != nil {
		t.Fatal("cannot parse fixture System key")
	}
	encryptor, err := system.NewEncryptor("internal", parsedKey)
	if err != nil {
		t.Fatal("cannot construct fixture System encryption")
	}
	encoded, err := encryptor.EncryptMessage(&system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "local", Username: "alice", Password: lifecyclePassword, Address: "127.0.0.1"})
	if err != nil {
		t.Fatal("cannot encrypt fixture System request")
	}
	f.secrets = append(f.secrets, encoded)
	systemResponse := connectedAccountsSend(t, f.localIdentityFixture, f.plain, "POST", "/api/system", strings.NewReader(encoded), http.Header{"Content-Type": {"text/plain; charset=UTF-8"}})
	f.secrets = append(f.secrets, string(systemResponse.body))
	systemResponse.requireStatus(t, 200)
	message, err := encryptor.DecryptMessage(string(systemResponse.body))
	assertion, ok := message.(*system.AuthResponseMessage)
	if err != nil || !ok || !assertion.Authenticated || assertion.UserData["sub"] != "alice" {
		t.Fatal("access signer changed independent System encryption")
	}
	providerDestinationNoIssuance(t, systemResponse)
	access := f.formLogin(t, "alice", lifecyclePassword, false)
	f.verify(t, access)
	params := f.authorization("trusted")
	f.secrets = append(f.secrets, params.Get("state"), params.Get("nonce"))
	code := f.callback(t, f.authorize(t, params), params, "")
	f.secrets = append(f.secrets, code)
	raw := f.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier)
	var issued oidcRPTokens
	_ = json.Unmarshal(raw.body, &issued)
	f.secrets = append(f.secrets, issued.Access, issued.ID)
	tokens, _ := f.tokens(t, raw, params)
	parts := strings.Split(tokens.ID, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if !bytes.Contains(header, []byte(`"RS256"`)) || bytes.Contains(header, []byte(`authcrunch-access+jwt`)) {
		t.Fatal("access signer changed the independent OP signing boundary")
	}
	f.consumers(t, tokens.ID, false)
	admin := f.formLogin(t, "admin", lifecyclePassword, false)
	f.verify(t, admin)
	status, headers, body := registrationHTTP(t, f.plain, "GET", f.issuer+adminExportPath, nil, http.Header{"Authorization": {"Bearer " + admin}})
	if status != 404 {
		t.Fatalf("private export separation returned HTTP %d", status)
	}
	assertAdminRedacted(t, body, []string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"})
	if bytes.Contains(body, []byte(`"d"`)) || bytes.Contains(body, []byte(`"p"`)) || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("external access signer exported private RSA material")
	}
}

func accessSignerMemoryCandidate(input string) string {
	var lines []string
	for line := range strings.SplitSeq(input, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "path ") {
			line = "path :memory:"
		}
		lines = append(lines, line)
	}
	return strings.Replace(strings.Join(lines, "\n"), "local identity store localdb {", "local identity store localdb {\nuser alice {\nemail alice@example.test\npassword "+lifecyclePassword+"\nroles authp/user alice\n}\n", 1)
}

func testAccessSignerRollover(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth"}, cert, key, roots)
	old := f.formLogin(t, "alice", lifecyclePassword, false)
	f.verify(t, old)
	f.consumers(t, old, true)
	next := newJWKSKeyFiles(t, "RSA", "next-selected")
	original := accessSignerMemoryCandidate(f.input)
	for _, kind := range []string{"private_missing", "public_missing", "key_mismatch", "late_route"} {
		candidate := original
		switch kind {
		case "private_missing":
			candidate = strings.Replace(candidate, f.key.private, f.key.private+".missing", 1)
		case "public_missing":
			candidate = strings.ReplaceAll(candidate, f.key.public, f.key.public+".missing")
		case "key_mismatch":
			candidate = strings.Replace(candidate, f.key.private, next.private, 1)
		case "late_route":
			candidate = strings.Replace(candidate, "authenticate with myportal", "authenticate with absentportal", 1)
		}
		if accessSignerLoad(candidate) == nil {
			t.Fatalf("invalid %s candidate published", kind)
		}
		f.plain.CloseIdleConnections()
		f.consumers(t, old, true)
		f.verify(t, f.formLogin(t, "alice", lifecyclePassword, false))
	}
	overlap := strings.Replace(original, f.key.private, next.private, 1)
	overlap = strings.Replace(overlap, "key id selected", "key id next", 1)
	overlap = strings.ReplaceAll(overlap, "key ids selected", "key ids selected next")
	overlap = strings.ReplaceAll(overlap, f.key.verifier("selected"), f.key.verifier("selected")+"\n"+next.verifier("next"))
	if accessSignerLoad(overlap) != nil {
		t.Fatal("cannot publish selected signer overlap")
	}
	f.client.CloseIdleConnections()
	f.kid, f.key = "next", next
	f.keys = fetchCaddyJWKS(t, &caddyAdminFixture{client: f.plain, base: f.base, mount: f.mount}, 2)
	f.consumers(t, old, true)
	f.verify(t, f.formLogin(t, "alice", lifecyclePassword, false))
	retired := strings.ReplaceAll(overlap, "key ids selected next", "key ids next")
	for line := range strings.SplitSeq(original, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "crypto key selected verify") {
			retired = strings.ReplaceAll(retired, line, "")
		}
	}
	if accessSignerLoad(retired) != nil {
		t.Fatal("cannot retire old selected access trust")
	}
	f.client.CloseIdleConnections()
	f.keys = fetchCaddyJWKS(t, &caddyAdminFixture{client: f.plain, base: f.base, mount: f.mount}, 1)
	f.consumers(t, old, false)
	f.verify(t, f.formLogin(t, "alice", lifecyclePassword, false))
}
