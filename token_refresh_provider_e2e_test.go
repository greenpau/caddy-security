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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
)

func TestCaddyProviderRefreshE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyProviderRefreshProcess$", "-test.v", "-test.timeout=165s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_PROVIDER_REFRESH_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS provider renewal: %v\n%s", err, output)
	}
}

type caddyProviderRefreshOptions struct {
	mount                  string
	access, idle, absolute int
	unselected, authority  bool
	policy                 string
}

type caddyProviderRefreshFixture struct {
	local    *localIdentityFixture
	upstream *oauthE2EUpstream
	mu       sync.Mutex
	secrets  []string
}

type caddyProviderRefreshTokens struct {
	access, refresh *http.Cookie
	claims          map[string]any
	metadata        apiauth.AuthResponse
}

func newCaddyProviderRefreshFixture(t *testing.T, options caddyProviderRefreshOptions, cert, key string, roots *x509.CertPool, pair tls.Certificate) *caddyProviderRefreshFixture {
	t.Helper()
	if options.access == 0 {
		options.access = 60
	}
	if options.idle == 0 {
		options.idle = 120
	}
	if options.absolute == 0 {
		options.absolute = 240
	}
	u := newOAuthE2EUpstream(t, pair, "EdDSA")
	u.fixedSubject, u.accessMode = "provider-snapshot-user", "userinfo"
	u.upstreamRefreshToken = "synthetic-provider-refresh-credential"
	u.identityClaims = map[string]any{"sid": "untrusted-provider-sid", "auth_time": 1, "amr": []string{"mfa"}, "acr": "untrusted-high"}
	u.userInfoClaims = map[string]any{"tenant": "captured", "nested": map[string]any{"label": "retained"}}
	if !options.unselected {
		u.userInfoClaims["nested"].(map[string]any)["access_token"] = "synthetic-nested-provider-credential"
	}
	f := &caddyProviderRefreshFixture{upstream: u, secrets: []string{oauthE2ESecret, u.upstreamRefreshToken, "synthetic-nested-provider-credential"}}
	local := localIdentityOptions{mount: options.mount, refreshRealm: "local"}
	if options.authority {
		local.oidcRealm = "local"
	}
	local.configure = func(input string) string {
		var base string
		for line := range strings.SplitSeq(input, "\n") {
			if strings.HasPrefix(line, "https://") {
				base = strings.Fields(line)[0]
			}
		}
		if base == "" {
			t.Fatal("provider renewal fixture has no TLS origin")
		}
		u.mu.Lock()
		u.callback = base + options.mount + "/oauth2/upstream/authorization-code-callback"
		u.mu.Unlock()
		provider := fmt.Sprintf(`oauth identity provider upstream {
 driver generic
 realm upstream
 client_id %s
 client_secret %s
 base_auth_url %s
 metadata_url %s/metadata
 scopes openid profile email
 user_info_fields all
 attach to local identity store localdb
}
`, oauthE2EClient, oauthE2ESecret, u.server.URL, u.server.URL)
		input = strings.Replace(input, "authentication portal myportal {", provider+`authentication portal myportal {
 enable identity provider upstream
 transform user {
  match realm upstream
  action add role authp/user
  action overwrite sub attempted-subject-rewrite
  add provider_name {claims.name} as string
  add request_issuer {claims.iss} as string
 }
`+options.policy, 1)
		if !options.unselected {
			input = strings.Replace(input, "realms local\npublic origin", "realms local upstream\nprovider revalidation upstream snapshot\npublic origin", 1)
		}
		input = strings.Replace(input, "access lifetime 600", fmt.Sprintf("access lifetime %d\nidle timeout %d\nabsolute timeout %d\nmax sessions 4", options.access, options.idle, options.absolute), 1)
		mount := options.mount
		if mount == "" {
			mount = "/"
		}
		input = strings.Replace(input, "authenticate with myportal", "authenticate with myportal at "+mount, 1)
		// Both independent Caddy encoders must discard redirect-bearing URIs.
		input = strings.Replace(input, "level DEBUG", "level INFO", 1)
		input = strings.Replace(input, "format json", "format filter {\nwrap json\nfields {\nresp_headers>Location delete\n}\n}", 1)
		return strings.ReplaceAll(input, "resp_headers>Location delete", "resp_headers>Location delete\nrequest>uri delete")
	}
	f.local = newLocalIdentityFixture(t, local, cert, key, roots)
	// Runs before the local fixture stops Caddy and scans both nonempty logs.
	t.Cleanup(func() {
		f.mu.Lock()
		f.local.secrets = append(f.local.secrets, f.secrets...)
		f.mu.Unlock()
		u.mu.Lock()
		f.local.secrets = append(f.local.secrets, u.issuedSecrets...)
		u.mu.Unlock()
	})
	return f
}

func (f *caddyProviderRefreshFixture) browser(t *testing.T) *http.Client {
	t.Helper()
	return crossDeviceBrowser(t, f.local.oidcRPFixture).client
}

func (f *caddyProviderRefreshFixture) capture(response oidcRPResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cookie := range (&http.Response{Header: response.header}).Cookies() {
		// The legacy session cookie is the documented diagnostic correlation
		// value. OAuth replay retains it separately; it is not a redaction oracle.
		if cookie.Name != "AUTHP_SESSION_ID" && cookie.Value != "" && cookie.MaxAge >= 0 {
			f.secrets = append(f.secrets, cookie.Value)
		}
	}
	var body apiauth.AuthResponse
	if json.Unmarshal(response.body, &body) == nil {
		f.secrets = append(f.secrets, body.SandboxSecret, body.AccessToken, body.RefreshToken)
	}
}

// This intentionally accepts explicit Cookie headers on jar-free requests so
// replay tests retain the original proof without restoring or corrupting a jar.
func (f *caddyProviderRefreshFixture) send(t *testing.T, client *http.Client, method, target string, body any, headers http.Header) oidcRPResponse {
	t.Helper()
	if strings.HasPrefix(target, "/") {
		target = f.local.issuer + target
	}
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal("cannot encode provider renewal request")
		}
		input = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, input)
	if err != nil {
		t.Fatal("cannot construct provider renewal request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
	}
	maps.Copy(req.Header, headers)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("verified provider renewal TLS request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 || resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		t.Fatal("provider renewal response lacked bounded verified TLS")
	}
	r := oidcRPResponse{resp.StatusCode, resp.Header.Clone(), raw}
	f.capture(r)
	return r
}

func (f *caddyProviderRefreshFixture) noProviderSecrets(t *testing.T, r oidcRPResponse) {
	t.Helper()
	f.upstream.mu.Lock()
	secrets := append([]string{oauthE2ESecret, "synthetic-nested-provider-credential"}, f.upstream.issuedSecrets...)
	f.upstream.mu.Unlock()
	assertAdminRedacted(t, r.body, secrets)
	assertAdminRedacted(t, fmt.Append(nil, r.header), secrets)
}

func (f *caddyProviderRefreshFixture) login(t *testing.T, client *http.Client, status int) (oidcRPResponse, string, string) {
	t.Helper()
	start := f.send(t, client, "GET", "/oauth2/upstream", nil, nil)
	start.requireStatus(t, 302)
	location, err := url.Parse(start.header.Get("Location"))
	if err != nil || location.Scheme+"://"+location.Host != f.upstream.server.URL || location.Path != "/authorize" {
		t.Fatal("provider authorization left the pinned issuer")
	}
	f.mu.Lock()
	f.secrets = append(f.secrets, location.Query().Get("state"), location.Query().Get("nonce"))
	f.mu.Unlock()
	callback := f.send(t, client, "GET", location.String(), nil, nil)
	callback.requireStatus(t, 302)
	location, err = url.Parse(callback.header.Get("Location"))
	if err != nil || location.Scheme+"://"+location.Host != f.local.base || location.Path != f.local.mount+"/oauth2/upstream/authorization-code-callback" {
		t.Fatal("provider callback left the pinned portal")
	}
	proof := providerDestinationProof(t, &oidcRPFixture{client: client, issuer: f.local.issuer}, "AUTHP_SESSION_ID")
	result := f.send(t, client, "GET", location.String(), nil, http.Header{"Sec-Fetch-Site": {"cross-site"}, "Sec-Fetch-Mode": {"navigate"}, "Sec-Fetch-Dest": {"document"}})
	f.noProviderSecrets(t, result)
	result.requireStatus(t, status)
	result.noStore(t)
	if status != 303 {
		providerDestinationNoIssuance(t, result)
	}
	return result, location.String(), proof
}

func (f *caddyProviderRefreshFixture) tokens(t *testing.T, r oidcRPResponse, refresh bool) caddyProviderRefreshTokens {
	t.Helper()
	f.noProviderSecrets(t, r)
	cookies := (&http.Response{Header: r.header}).Cookies()
	result := caddyProviderRefreshTokens{access: tokenRefreshActiveCookie(t, cookies, "AUTHP_ACCESS_TOKEN")}
	result.claims = verifyCaddyJWKSSignature(t, f.local.keys, result.access.Value, "RS512", "access")
	if !result.access.Secure || !result.access.HttpOnly || result.access.Domain != "" {
		t.Fatal("provider access cookie lost its private TLS scope")
	}
	if refresh {
		result.refresh = tokenRefreshActiveCookie(t, cookies, "AUTHP_REFRESH_TOKEN")
		mount := f.local.mount
		if mount == "" {
			mount = "/"
		}
		if result.refresh.Domain != "" || result.refresh.Path != mount || !result.refresh.Secure || !result.refresh.HttpOnly || result.refresh.SameSite != http.SameSiteLaxMode || result.refresh.Expires.IsZero() || r.header.Get("Authorization") != "" {
			t.Fatal("provider refresh delivery escaped the cookie transport contract")
		}
		if result.claims["sub"] != f.upstream.fixedSubject || result.claims["id"] == "" || result.claims["id"] == nil || result.claims["sid"] == nil || result.claims["sid"] == "untrusted-provider-sid" || result.claims["auth_time"].(float64) <= 1 || fmt.Sprint(result.claims["amr"]) != "[federated]" || result.claims["acr"] != nil {
			t.Fatal("provider claims replaced portal-owned identity or authentication evidence")
		}
		if r.status == 200 {
			if json.Unmarshal(r.body, &result.metadata) != nil || !result.metadata.Authenticated || result.metadata.AccessToken != "" || result.metadata.RefreshToken != "" || result.metadata.SessionID != result.claims["sid"] || result.metadata.AccessExpiresAt != int64(result.claims["exp"].(float64)) || result.metadata.RefreshExpiresAt <= 0 || result.metadata.SessionExpiresAt <= 0 {
				t.Fatal("cookie renewal exposed credentials or inconsistent metadata")
			}
		}
	}
	// Inspect decoded claims too: encoding a nested credential into a signed JWT
	// must not evade the public response's literal-value scan.
	encoded, err := json.Marshal(result.claims)
	if err != nil {
		t.Fatal("cannot inspect signed provider claims")
	}
	f.noProviderSecrets(t, oidcRPResponse{header: make(http.Header), body: encoded})
	return result
}

func (f *caddyProviderRefreshFixture) renew(t *testing.T, client *http.Client, cookie *http.Cookie, status int) oidcRPResponse {
	t.Helper()
	headers := http.Header{"Origin": {f.local.base}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"}}
	if cookie != nil {
		client = f.local.plain
		headers.Set("Cookie", cookie.Name+"="+cookie.Value)
	}
	r := f.send(t, client, "POST", "/api/refresh_token", map[string]any{}, headers)
	r.requireStatus(t, status)
	r.noStore(t)
	f.noProviderSecrets(t, r)
	if status != 200 {
		providerDestinationNoIssuance(t, r)
		localIdentityRejectedAuth(t, r, status)
	}
	return r
}

func (f *caddyProviderRefreshFixture) counts() [2]int {
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	return [2]int{f.upstream.exchanges, f.upstream.userInfos}
}

func (f *caddyProviderRefreshFixture) resource(t *testing.T, access *http.Cookie, status int) {
	t.Helper()
	r := f.send(t, f.local.plain, "GET", f.local.base+"/resource", nil, http.Header{"Cookie": {access.Name + "=" + access.Value}})
	r.requireStatus(t, status)
	if status == 200 && string(r.body) != "identity resource" {
		t.Fatal("signed provider access missed the protected application")
	}
}

func providerRefreshWait(t *testing.T, deadline time.Time) {
	t.Helper()
	if delay := time.Until(deadline) + 30*time.Millisecond; delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-t.Context().Done():
			t.Fatal("provider deadline wait exceeded the test bound")
		}
	}
}

func TestCaddyProviderRefreshProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_PROVIDER_REFRESH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Fatal(err)
	}
	oauthE2ESystemRoots = roots
	fixture := func(t *testing.T, options caddyProviderRefreshOptions) *caddyProviderRefreshFixture {
		return newCaddyProviderRefreshFixture(t, options, cert, key, roots, pair)
	}
	t.Run("snapshot_and_authority", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth", access: 2, authority: true})
		browser := f.browser(t)
		response, callback, proof := f.login(t, browser, 303)
		first := f.tokens(t, response, true)
		f.resource(t, first.access, 200)
		if first.claims["provider_name"] != "External User" || first.claims["request_issuer"] != f.local.issuer+"/oauth2/upstream/" || !slices.Contains(first.claims["roles"].([]any), any("userinfo/user")) {
			t.Fatal("callback lost the verified provider profile or current request transform")
		}
		replay := f.send(t, f.local.plain, "GET", callback, nil, http.Header{"Cookie": {proof}})
		replay.requireStatus(t, 401)
		providerDestinationNoIssuance(t, replay)
		// The gatekeeper's public Claims.Valid/cache boundary is inclusive at
		// the JWT's Unix second: expiry is rejected once now.Unix() exceeds exp.
		providerRefreshWait(t, time.Unix(int64(first.claims["exp"].(float64))+1, 0))
		f.resource(t, first.access, 302)
		f.upstream.mu.Lock()
		f.upstream.deactivated = true
		f.upstream.userInfoClaims["roles"] = []string{"changed/upstream"}
		f.upstream.userInfoClaims["tenant"] = "changed"
		f.upstream.mu.Unlock()
		before := f.counts()
		next := f.tokens(t, f.renew(t, browser, nil, 200), true)
		for _, name := range []string{"id", "sub", "sid", "auth_time", "amr", "provider_name"} {
			if fmt.Sprint(first.claims[name]) != fmt.Sprint(next.claims[name]) {
				t.Fatal("renewal changed captured identity or original proof", name)
			}
		}
		if next.access.Value == first.access.Value || next.refresh.Value == first.refresh.Value || next.claims["jti"] == first.claims["jti"] || next.claims["exp"].(float64) <= first.claims["exp"].(float64) || next.claims["request_issuer"] != f.local.issuer+"/api/refresh_token" || next.claims["iss"] != f.local.issuer {
			t.Fatal("renewal failed to rotate or rerun the current request transform")
		}
		roles := next.claims["roles"].([]any)
		if !slices.Contains(roles, any("userinfo/user")) || slices.Contains(roles, any("changed/upstream")) || f.counts() != before {
			t.Fatal("snapshot renewal observed or contacted the changed upstream")
		}
		f.resource(t, next.access, 200)
		profile := f.send(t, browser, "POST", "/api/profile", map[string]any{"kind": "fetch_user_api_keys"}, http.Header{"Origin": {f.local.base}})
		profile.requireStatus(t, 501)
		providerDestinationNoIssuance(t, profile)
		f.local.client = browser
		params := f.local.authorization("trusted")
		params.Set("prompt", "none")
		f.local.callback(t, f.local.authorize(t, params), params, "login_required")
		// A real fresh callback observes the enabled fixture rejection switch.
		f.login(t, f.browser(t), 401)
		if f.counts()[0] != before[0]+1 {
			t.Fatal("unavailable upstream control never reached the real token endpoint")
		}
		f.upstream.mu.Lock()
		f.upstream.deactivated = false
		f.upstream.mu.Unlock()
		freshResponse, _, _ := f.login(t, f.browser(t), 303)
		fresh := f.tokens(t, freshResponse, true)
		if fresh.claims["id"] != first.claims["id"] || !slices.Contains(fresh.claims["roles"].([]any), any("changed/upstream")) {
			t.Fatal("fresh callback did not preserve attachment and observe changed provider roles")
		}
		f.renew(t, browser, first.refresh, 401)
		f.renew(t, browser, next.refresh, 401)
	})
	t.Run("root_selected", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{})
		browser := f.browser(t)
		r, _, _ := f.login(t, browser, 303)
		first := f.tokens(t, r, true)
		next := f.tokens(t, f.renew(t, browser, nil, 200), true)
		if first.claims["id"] != next.claims["id"] || first.claims["sid"] != next.claims["sid"] {
			t.Fatal("root-mounted renewal lost its attachment or family")
		}
		f.resource(t, next.access, 200)
	})
	for _, kind := range []string{"roles", "disable", "factor"} {
		t.Run("local_"+kind, func(t *testing.T) {
			f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth"})
			admin := f.local.formLogin(t, "admin", lifecyclePassword, false)
			browser := f.browser(t)
			r, _, _ := f.login(t, browser, 303)
			first := f.tokens(t, r, true)
			data, err := os.ReadFile(f.local.database)
			var database struct{ Users []*identity.User }
			if err != nil || json.Unmarshal(data, &database) != nil {
				t.Fatal("cannot inspect attached identity record")
			}
			var account *identity.User
			for _, candidate := range database.Users {
				if candidate.ID == first.claims["id"] {
					account = candidate
				}
			}
			if account == nil || !account.ExternallyProvisioned || account.Username == f.upstream.fixedSubject || len(account.EmailAddresses) != 0 {
				t.Fatal("signed attachment did not identify a distinct provider-only local account")
			}
			fields := map[string]any{"username": account.Username, "email": ""}
			operation := "disable"
			switch kind {
			case "roles":
				operation, fields["roles"] = "overwrite_roles", []string{"local/current"}
			case "factor":
				if slices.Contains(account.GetRegisteredAuthMethods(), "totp") {
					t.Fatal("unavailable-factor fixture unexpectedly has an enrolled TOTP")
				}
				operation, fields["challenges"] = "overwrite_auth_challenges", []string{"totp"}
			}
			f.local.admin(t, admin, operation, fields)
			before := f.counts()
			f.renew(t, browser, first.refresh, 401)
			if f.counts() != before {
				t.Fatal("local invalidation contacted the provider")
			}
			switch kind {
			case "roles":
				freshResponse, _, _ := f.login(t, f.browser(t), 303)
				fresh := f.tokens(t, freshResponse, true)
				if fresh.claims["id"] != first.claims["id"] || !slices.Contains(fresh.claims["roles"].([]any), any("local/current")) {
					t.Fatal("fresh callback missed the current attached local roles")
				}
			case "factor":
				// No registered local method satisfies this explicit rule. The
				// identity backend refuses it before creating a factor sandbox;
				// the issuer's asserted MFA cannot satisfy that missing method.
				f.login(t, f.browser(t), 401)
				if f.counts() != [2]int{before[0] + 1, before[1] + 1} {
					t.Fatal("missing-factor denial did not follow a real fresh provider exchange")
				}
			default:
				f.login(t, f.browser(t), 401)
			}
		})
	}
	t.Run("current_request_policy", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth", policy: "transform user {\nregex match iss /api/refresh_token$\nrequire totp\n}\n"})
		browser := f.browser(t)
		r, _, _ := f.login(t, browser, 303)
		first := f.tokens(t, r, true)
		before := f.counts()
		f.renew(t, browser, nil, 401)
		f.renew(t, browser, first.refresh, 401)
		if f.counts() != before {
			t.Fatal("request-dependent policy denial contacted upstream")
		}
	})
	t.Run("concurrency_logout_replacement", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth"})
		browser := f.browser(t)
		r, _, _ := f.login(t, browser, 303)
		first := f.tokens(t, r, true)
		results := make(chan oidcRPResponse, 2)
		var workers sync.WaitGroup
		for range 2 {
			workers.Go(func() {
				results <- f.send(t, f.local.plain, "POST", "/api/refresh_token", map[string]any{}, http.Header{"Origin": {f.local.base}, "X-Authcrunch-Refresh": {"1"}, "Cookie": {first.refresh.Name + "=" + first.refresh.Value}})
			})
		}
		workers.Wait()
		close(results)
		var descendant *http.Cookie
		counts := map[int]int{}
		for response := range results {
			counts[response.status]++
			response.noStore(t)
			if response.status == 200 {
				descendant = f.tokens(t, response, true).refresh
			} else {
				providerDestinationNoIssuance(t, response)
			}
		}
		if counts[200] != 1 || counts[401] != 1 {
			t.Fatal("concurrent strict reuse did not produce one rotation and one rejection")
		}
		f.renew(t, browser, descendant, 401)
		// Fresh callback replaces the revoked cookie still retained by this jar.
		r, _, _ = f.login(t, browser, 303)
		fresh := f.tokens(t, r, true)
		logout := f.send(t, browser, "POST", "/api/logout", map[string]any{}, http.Header{"Origin": {f.local.base}, "X-Authcrunch-Refresh": {"1"}})
		logout.requireStatus(t, 200)
		logout.noStore(t)
		providerDestinationNoIssuance(t, logout)
		f.renew(t, browser, fresh.refresh, 401)
		r, _, _ = f.login(t, browser, 303)
		external := f.tokens(t, r, true)
		local := caddyTokenRefreshFixture{base: f.local.base, mount: f.local.mount, client: f.local.plain, inspectResponse: func(_ *testing.T, status int, raw []byte, cookies []*http.Cookie) {
			header := make(http.Header)
			for _, cookie := range cookies {
				header.Add("Set-Cookie", cookie.String())
			}
			f.capture(oidcRPResponse{status, header, raw})
		}}
		_, cookies := local.login(t, browser, "local", "", 200)
		localAccess := tokenRefreshActiveCookie(t, cookies, "AUTHP_ACCESS_TOKEN")
		claims := verifyCaddyJWKSSignature(t, f.local.keys, localAccess.Value, "RS512", "access")
		if claims["sub"] != "alice" || fmt.Sprint(claims["amr"]) != "[pwd]" {
			t.Fatal("local replacement retained federated authentication evidence")
		}
		f.renew(t, browser, external.refresh, 401)
		f.renew(t, browser, nil, 200)
	})
	t.Run("unselected_and_body_transport", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth", unselected: true})
		browser := f.browser(t)
		r, _, _ := f.login(t, browser, 303)
		access := f.tokens(t, r, false).access
		for _, cookie := range (&http.Response{Header: r.header}).Cookies() {
			if cookie.Name == "AUTHP_REFRESH_TOKEN" && cookie.Value != "" && cookie.MaxAge >= 0 {
				t.Fatal("unselected provider gained a renewal family")
			}
		}
		f.resource(t, access, 200)
		for _, headers := range []http.Header{
			{"Cookie": {access.Name + "=" + access.Value}},
			{"Authorization": {"Bearer " + access.Value}},
		} {
			headers.Set("Origin", f.local.base)
			headers.Set("X-Authcrunch-Refresh", "1")
			denied := f.send(t, f.local.plain, "POST", "/api/refresh_token", map[string]any{}, headers)
			localIdentityRejectedAuth(t, denied, 401)
			denied.noStore(t)
			providerDestinationNoIssuance(t, denied)
		}
		body := map[string]any{"refresh_token": access.Value}
		encoded, err := json.Marshal(body)
		if err != nil || len(encoded) <= 1024 {
			t.Fatal("access-as-refresh body no longer exercises the documented request bound")
		}
		// This real signed access JWT exceeds the refresh endpoint's 1024-byte
		// JSON limit. It is rejected by request parsing before credential lookup.
		oversized := f.send(t, f.local.plain, "POST", "/api/refresh_token", body, nil)
		localIdentityRejectedAuth(t, oversized, 400)
		oversized.noStore(t)
		providerDestinationNoIssuance(t, oversized)
	})
	t.Run("cookie_cannot_become_body", func(t *testing.T) {
		f := fixture(t, caddyProviderRefreshOptions{mount: "/tenant/auth"})
		browser := f.browser(t)
		r, _, _ := f.login(t, browser, 303)
		first := f.tokens(t, r, true)
		denied := f.send(t, f.local.plain, "POST", "/api/refresh_token", map[string]any{"refresh_token": first.refresh.Value}, nil)
		denied.requireStatus(t, 401)
		providerDestinationNoIssuance(t, denied)
	})
	for _, absolute := range []bool{false, true} {
		name := "idle_deadline"
		if absolute {
			name = "absolute_deadline"
		}
		t.Run(name, func(t *testing.T) {
			options := caddyProviderRefreshOptions{mount: "/tenant/auth", access: 1, idle: 2, absolute: 8}
			if absolute {
				options.idle, options.absolute = 3, 4
			}
			f := fixture(t, options)
			browser := f.browser(t)
			r, _, _ := f.login(t, browser, 303)
			first := f.tokens(t, r, true)
			before := f.counts()
			if !absolute {
				providerRefreshWait(t, first.refresh.Expires)
				f.renew(t, browser, first.refresh, 401)
			} else {
				current := f.tokens(t, f.renew(t, browser, nil, 200), true)
				end := time.Unix(current.metadata.SessionExpiresAt, 0)
				if end.Before(time.Now()) || time.Until(end) > 5*time.Second {
					t.Fatal("missing or unbounded public absolute deadline")
				}
				for time.Until(end) > 600*time.Millisecond {
					providerRefreshWait(t, time.Now().Add(400*time.Millisecond))
					response := f.send(t, browser, "POST", "/api/refresh_token", map[string]any{}, http.Header{"Origin": {f.local.base}, "X-Authcrunch-Refresh": {"1"}})
					response.noStore(t)
					if response.status == 401 && !time.Now().Before(end) {
						providerDestinationNoIssuance(t, response)
						break
					}
					response.requireStatus(t, 200)
					current = f.tokens(t, response, true)
					if current.metadata.SessionExpiresAt != end.Unix() || current.claims["auth_time"] != first.claims["auth_time"] || int64(current.claims["exp"].(float64)) > end.Unix() {
						t.Fatal("active rotation extended the absolute authentication boundary")
					}
				}
				providerRefreshWait(t, end)
				f.renew(t, browser, current.refresh, 401)
			}
			if f.counts() != before {
				t.Fatal("deadline handling contacted the provider")
			}
		})
	}
}
