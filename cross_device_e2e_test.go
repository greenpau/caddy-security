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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestCaddyCrossDeviceE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCrossDeviceProcess$", "-test.v", "-test.timeout=9m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CROSS_DEVICE_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy cross-device TLS flow: %v\n%s", err, output)
	}
}

type crossDeviceInteraction struct {
	Code     string `json:"code"`
	Secret   string `json:"secret"`
	URI      string `json:"verification_uri"`
	Display  string `json:"display_code"`
	QR       string `json:"qr"`
	Interval int    `json:"interval"`
	Expires  int    `json:"expires_in"`
}

func (i crossDeviceInteraction) values() url.Values {
	return url.Values{"code": {i.Code}, "secret": {i.Secret}}
}

func crossDeviceBrowser(t *testing.T, f *oidcRPFixture) *oidcRPFixture {
	t.Helper()
	b := *f
	client := *f.client
	b.client = &client
	b.newBrowser(t)
	return &b
}
func crossDeviceCookie(f *oidcRPFixture, name string) string {
	u, _ := url.Parse(f.issuer + "/portal")
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
func crossDevicePost(t *testing.T, b *oidcRPFixture, route string, form url.Values) oidcRPResponse {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	return b.request(t, "POST", "/cross-device/"+route, form, http.Header{"Origin": {b.base}})
}
func crossDeviceStart(t *testing.T, b *oidcRPFixture) crossDeviceInteraction {
	t.Helper()
	r := crossDevicePost(t, b, "start", nil)
	r.requireStatus(t, 200)
	r.noStore(t)
	var i crossDeviceInteraction
	if json.Unmarshal(r.body, &i) != nil || i.Code == "" || i.Secret == "" || i.Code == i.Secret || i.Display == "" || i.Interval != 2 || i.Expires != 300 {
		t.Fatal("invalid cross-device start contract")
	}
	u, err := url.Parse(i.URI)
	if err != nil || u.Scheme+"://"+u.Host != b.base || u.Path != b.mount+"/cross-device/activate" || len(u.Query()) != 1 || u.Query().Get("code") != i.Code || strings.Contains(i.URI, i.Secret) {
		t.Fatal("activation link scope or capability leaked")
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(i.QR, "data:image/png;base64,"))
	if err != nil {
		t.Fatal("invalid QR data")
	}
	dimensions, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || dimensions.Width != 256 || dimensions.Height != 256 {
		t.Fatal("invalid QR image")
	}
	if r.header.Get("Referrer-Policy") != "strict-origin" || r.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("cross-device HTTP policy changed")
	}
	return i
}
func crossDeviceBegin(t *testing.T, b *oidcRPFixture, i crossDeviceInteraction) {
	t.Helper()
	r := b.request(t, "GET", i.URI, nil, nil)
	r.requireStatus(t, 200)
	if !bytes.Contains(r.body, []byte(i.Display)) {
		t.Fatal("activation omitted matching code")
	}
	form := oidcRPForm(t, r.body)
	begun := b.request(t, "POST", crossDeviceAction(t, b, form.action), form.values, http.Header{"Origin": {b.base}})
	begun.requireStatus(t, 303)
	if begun.header.Get("Location") != b.mount+"/login?fresh=1" {
		t.Fatal("activation did not require fresh login")
	}
	b.request(t, "GET", b.base+begun.header.Get("Location"), nil, nil).requireStatus(t, 200)
}
func crossDeviceLogin(t *testing.T, b *oidcRPFixture, username, password string, mfa bool, database string) oidcRPResponse {
	t.Helper()
	headers := http.Header{"Origin": {b.base}}
	start := b.request(t, "POST", "/login", url.Values{"username": {username}, "realm": {"local"}}, headers)
	start.requireStatus(t, 303)
	sandbox := start.header.Get("Location")
	b.request(t, "POST", sandbox, url.Values{"secret": {password}}, headers).requireStatus(t, 303)
	if mfa {
		b.request(t, "GET", "/cross-device/confirm", nil, nil).requireStatus(t, 410)
		waitForFreshFixtureTOTP(t, database, username)
		b.request(t, "POST", sandbox, url.Values{"passcode": {authenticationClientTOTP()}}, headers).requireStatus(t, 303)
	}
	done := b.request(t, "GET", sandbox, nil, nil)
	done.requireStatus(t, 303)
	if done.header.Get("Location") != b.mount+"/cross-device/confirm" {
		t.Fatal("HTML login lost the pending approval")
	}
	confirmation := b.request(t, "GET", "/cross-device/confirm", nil, nil)
	confirmation.requireStatus(t, 200)
	if !bytes.Contains(confirmation.body, []byte(username+"@example.test")) {
		t.Fatal("confirmation omitted approving account")
	}
	return confirmation
}
func crossDeviceDecision(t *testing.T, b *oidcRPFixture, r oidcRPResponse, decision string) oidcRPResponse {
	t.Helper()
	if r.header.Get("Referrer-Policy") != "strict-origin" {
		t.Fatal("confirmation would lose browser Origin")
	}
	form := oidcRPForm(t, r.body)
	form.values.Set("decision", decision)
	return b.request(t, "POST", crossDeviceAction(t, b, form.action), form.values, http.Header{"Origin": {b.base}})
}
func crossDeviceNoCredentials(t *testing.T, b *oidcRPFixture, r oidcRPResponse) {
	t.Helper()
	for _, name := range []string{"AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"} {
		if crossDeviceCookie(b, name) != "" {
			t.Fatal("unfinished transfer published credentials")
		}
	}
	if r.header.Get("Authorization") != "" || bytes.Contains(r.body, []byte("access_token")) || bytes.Contains(r.body, []byte("refresh_token")) {
		t.Fatal("transfer exposed bearer material")
	}
}
func crossDeviceFixture(t *testing.T, options localIdentityOptions, extra, cert, key string, roots *x509.CertPool) *localIdentityFixture {
	t.Helper()
	configure := options.configure
	options.configure = func(input string) string {
		if configure != nil {
			input = configure(input)
		}
		input = strings.Replace(input, "authentication portal myportal {", "authentication portal myportal {\n"+extra, 1)
		// Keep a single local realm, including the UI's hidden ordinary links case.
		return strings.Replace(input, "enable identity stores localdb excludeddb", "enable identity store localdb", 1)
	}
	return newLocalIdentityFixture(t, options, cert, key, roots)
}

func TestCaddyCrossDeviceProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CROSS_DEVICE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct {
		name, mount  string
		mfa, refresh bool
	}{
		{"root", "", false, false}, {"nested", "/tenant/auth", false, false},
		{"substring mount", "/cross-device-team/auth", false, false},
		{"MFA refresh OIDC", "/auth", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := localIdentityOptions{mount: tc.mount, mfa: tc.mfa}
			if tc.refresh {
				options.refreshRealm = "local"
				options.oidcRealm = "local"
			}
			f := crossDeviceFixture(t, options, "enable cross-device login", cert, key, roots)
			requester, approver := crossDeviceBrowser(t, f.oidcRPFixture), crossDeviceBrowser(t, f.oidcRPFixture)
			login := requester.request(t, "GET", "/login", nil, nil)
			login.requireStatus(t, 200)
			if !bytes.Contains(login.body, []byte("Sign in on another device")) {
				t.Fatal("missing opt-in link")
			}
			i := crossDeviceStart(t, requester)
			f.secrets = append(f.secrets, i.Secret)
			wrong := i.values()
			wrong.Set("secret", i.Code)
			denied := crossDevicePost(t, requester, "poll", wrong)
			denied.requireStatus(t, 410)
			crossDeviceNoCredentials(t, requester, denied)
			crossDeviceBegin(t, approver, i)
			approver.request(t, "GET", "/cross-device/confirm", nil, nil).requireStatus(t, 410)
			confirmation := crossDeviceLogin(t, approver, "alice", lifecyclePassword, tc.mfa, f.database)
			pending := crossDevicePost(t, requester, "poll", i.values())
			pending.requireStatus(t, 200)
			if !bytes.Contains(pending.body, []byte(`"pending"`)) {
				t.Fatal("sign-in implicitly approved")
			}
			crossDeviceNoCredentials(t, requester, pending)
			crossDevicePost(t, requester, "poll", i.values()).requireStatus(t, 429)
			crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
			time.Sleep(2 * time.Second)
			redeemed := crossDevicePost(t, requester, "poll", i.values())
			redeemed.requireStatus(t, 200)
			if !bytes.Contains(redeemed.body, []byte(`"approved"`)) || bytes.Contains(redeemed.body, []byte("access_token")) {
				t.Fatal("wrong redemption response")
			}
			token := crossDeviceCookie(requester, "AUTHP_ACCESS_TOKEN")
			if token == "" || token == crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN") {
				t.Fatal("devices shared credentials")
			}
			f.secrets = append(f.secrets, token, crossDeviceCookie(approver, "AUTHP_ACCESS_TOKEN"))
			methods := []string{"pwd"}
			if tc.mfa {
				methods = append(methods, "otp")
			}
			claims := challengeClaims(t, f, token, methods...)
			if claims["email"] != "alice@example.test" {
				t.Fatal("transfer lost identity")
			}
			f.assertResource(t, token)
			crossDevicePost(t, requester, "poll", i.values()).requireStatus(t, 410)
			if tc.refresh {
				for _, name := range []string{"AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"} {
					own, remote := crossDeviceCookie(requester, name), crossDeviceCookie(approver, name)
					if own == "" || remote == "" || own == remote {
						t.Fatal("devices shared refresh/OP sessions")
					}
					f.secrets = append(f.secrets, own, remote)
				}
				headers := http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}}
				f.json(t, requester.client, "/api/refresh_token", struct{}{}, "", headers).requireStatus(t, 200)
				params := requester.authorization("trusted")
				code := requester.callback(t, requester.authorize(t, params), params, "")
				requester.tokens(t, requester.exchange(t, "trusted", code, oidcRPCallback, oidcRPVerifier), params)
			}
		})
	}
	for _, directive := range []string{"", "disable cross-device login"} {
		t.Run("disabled/"+directive, func(t *testing.T) {
			f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth"}, directive, cert, key, roots)
			r := f.request(t, "GET", "/login", nil, nil)
			r.requireStatus(t, 200)
			if bytes.Contains(r.body, []byte("Sign in on another device")) {
				t.Fatal("disabled login link visible")
			}
			for _, route := range []string{"", "/start", "/activate?code=unused", "/begin", "/confirm", "/poll", "/cancel"} {
				for _, method := range []string{"GET", "POST"} {
					f.request(t, method, "/cross-device"+route, nil, nil).requireStatus(t, 404)
				}
			}
		})
	}
	t.Run("HTTP boundaries", func(t *testing.T) { testCaddyCrossDeviceHTTP(t, cert, key, roots) })
	t.Run("approval decisions", func(t *testing.T) { testCaddyCrossDeviceDecisions(t, cert, key, roots) })
	t.Run("family lifecycle", func(t *testing.T) { testCaddyCrossDeviceFamilies(t, cert, key, roots) })
	t.Run("host lifecycle", func(t *testing.T) { testCaddyCrossDeviceLifecycle(t, cert, key, roots) })
	t.Run("completion rollback", func(t *testing.T) { testCaddyCrossDeviceRollback(t, cert, key, roots) })
	t.Run("fresh HTML required", func(t *testing.T) {
		f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth"}, "enable cross-device login", cert, key, roots)
		b := crossDeviceBrowser(t, f.oidcRPFixture)
		crossDeviceJSONLogin(t, f, b, "alice", lifecyclePassword)
		i := crossDeviceStart(t, f.oidcRPFixture)
		b.request(t, "GET", i.URI, nil, nil).requireStatus(t, 200)
		b.request(t, "GET", "/cross-device/confirm", nil, nil).requireStatus(t, 410)
		crossDeviceBegin(t, b, i)
		crossDeviceJSONLogin(t, f, b, "alice", lifecyclePassword)
		b.request(t, "GET", "/cross-device/confirm", nil, nil).requireStatus(t, 410)
		pending := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
		pending.requireStatus(t, 200)
		crossDeviceNoCredentials(t, f.oidcRPFixture, pending)
	})
	t.Run("expired approver", func(t *testing.T) {
		f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth", configure: func(input string) string {
			return strings.Replace(input, "crypto default token lifetime 600", "crypto default token lifetime 2", 1)
		}}, "enable cross-device login", cert, key, roots)
		b := crossDeviceBrowser(t, f.oidcRPFixture)
		i := crossDeviceStart(t, f.oidcRPFixture)
		crossDeviceBegin(t, b, i)
		confirmation := crossDeviceLogin(t, b, "alice", lifecyclePassword, false, f.database)
		crossDeviceDecision(t, b, confirmation, "approve").requireStatus(t, 200)
		time.Sleep(2 * time.Second)
		r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
		r.requireStatus(t, 410)
		crossDeviceNoCredentials(t, f.oidcRPFixture, r)
	})
	for _, protocol := range []string{"Basic", "API key"} {
		t.Run("non-HTML/"+protocol, func(t *testing.T) {
			apiKey := strings.Repeat("C", 24) + strings.Repeat("D", 40)
			options := localIdentityOptions{mount: "/auth", seed: func(t *testing.T, path string) {
				db, err := identity.NewDatabase(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := db.AddAPIKey(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test"}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "Synthetic cross-device isolation key"}}); err != nil {
					t.Fatal(err)
				}
			}}
			f := crossDeviceFixture(t, options, "enable cross-device login", cert, key, roots)
			f.secrets = append(f.secrets, apiKey)
			b := crossDeviceBrowser(t, f.oidcRPFixture)
			i := crossDeviceStart(t, f.oidcRPFixture)
			crossDeviceBegin(t, b, i)
			var token string
			if protocol == "Basic" {
				credential := base64.StdEncoding.EncodeToString([]byte("alice:" + lifecyclePassword))
				f.secrets = append(f.secrets, credential)
				b.request(t, "GET", "/basic/login/local", nil, http.Header{"Authorization": {"Basic " + credential}}).requireStatus(t, 303)
				token = crossDeviceCookie(b, "AUTHP_ACCESS_TOKEN")
			} else {
				result := localIdentityAuth(t, f.json(t, b.client, "/login", apiauth.AuthRequest{Realm: "local", APIKey: apiKey}, ""))
				if !result.Authenticated {
					t.Fatal("valid API key failed")
				}
				token = result.AccessToken
			}
			if token == "" {
				t.Fatal("non-HTML login did not issue access")
			}
			f.assertResource(t, token)
			b.request(t, "GET", "/cross-device/confirm", nil, http.Header{"Authorization": {"Bearer " + token}}).requireStatus(t, 410)
			pending := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
			pending.requireStatus(t, 200)
			crossDeviceNoCredentials(t, f.oidcRPFixture, pending)
		})
	}
	t.Run("binding cookie prefix scope", func(t *testing.T) {
		for _, mount := range []string{"", "/auth"} {
			t.Run(mount, func(t *testing.T) {
				f := crossDeviceFixture(t, localIdentityOptions{mount: mount}, "enable cross-device login", cert, key, roots)
				f.input = strings.Replace(f.input, "enable cross-device login", "enable cross-device login\ncookie cross-device session id name __Host-DEVICE", 1)
				if err := caddy.Stop(); err != nil {
					t.Fatal(err)
				}
				f.load(t)
				f.client.CloseIdleConnections()
				if mount != "" {
					f.request(t, "POST", "/cross-device/start", url.Values{}, http.Header{"Origin": {f.base}}).requireStatus(t, 500)
					return
				}
				i := crossDeviceStart(t, f.oidcRPFixture)
				r := f.request(t, "GET", i.URI, nil, nil)
				r.requireStatus(t, 200)
				for _, c := range (&http.Response{Header: r.header}).Cookies() {
					if c.Name == "__Host-DEVICE" && c.Secure && c.Domain == "" && c.Path == "/" && c.HttpOnly && c.SameSite == http.SameSiteNoneMode {
						return
					}
				}
				t.Fatal("root binding omitted required __Host- attributes")
			})
		}
	})
}

// Exercise the published five-minute request lifetime through real TLS and
// the host's source-address normalization; no library clock/store internals.
func TestCaddyCrossDeviceExpirationE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyCrossDeviceExpirationProcess$", "-test.v", "-test.timeout=6m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_CROSS_DEVICE_EXPIRATION_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy cross-device expiry: %v\n%s", err, output)
	}
}

func TestCaddyCrossDeviceExpirationProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_CROSS_DEVICE_EXPIRATION_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth"}, "enable cross-device login", cert, key, roots)
	i := crossDeviceStart(t, f.oidcRPFixture)
	deadline := time.Now().Add(time.Duration(i.Expires)*time.Second + 250*time.Millisecond)
	for range 7 {
		crossDeviceStart(t, f.oidcRPFixture)
	}
	for _, forged := range []string{"192.0.2.1", "192.0.2.2"} {
		r := f.request(t, "POST", "/cross-device/start", url.Values{}, http.Header{"Origin": {f.base}, "X-Forwarded-For": {forged}})
		r.requireStatus(t, 429)
		crossDeviceNoCredentials(t, f.oidcRPFixture, r)
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("expiry fixture canceled")
	}
	r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
	r.requireStatus(t, 410)
	crossDeviceNoCredentials(t, f.oidcRPFixture, r)
	f.request(t, "GET", i.URI, nil, nil).requireStatus(t, 410)
	crossDeviceStart(t, f.oidcRPFixture)
}

// Called by the built-command persistence suite to cross an actual OS-process
// restart with durable state enabled, in addition to in-process host reloads.
func testPersistentCrossDevice(t *testing.T, binary string) {
	cert, key, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	database := filepath.Join(f.workspace, "users.json")
	seedLocalIdentity(t, database, false)
	config := fmt.Sprintf(`local identity store localdb {
 realm local
 path %q
}
authentication portal myportal {
 enable identity store localdb
 enable cross-device login
 crypto key sign-verify %s
}`, database, oauthE2EPortalKey)
	f.write(t, f.input(config, "route /auth/* {\nauthenticate with myportal\n}", cert, key))
	f.start(t)
	b := crossDeviceBrowser(t, &oidcRPFixture{client: f.client, base: f.base, mount: "/auth", issuer: f.base + "/auth"})
	i := crossDeviceStart(t, b)
	f.restart(t)
	b.client.CloseIdleConnections()
	r := crossDevicePost(t, b, "poll", i.values())
	r.requireStatus(t, 410)
	crossDeviceNoCredentials(t, b, r)
	b.request(t, "GET", i.URI, nil, nil).requireStatus(t, 410)
	crossDeviceStart(t, b)
}

func testCaddyCrossDeviceLifecycle(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, scenario := range []string{"reload", "restart", "persistent restart", "disabled JSON"} {
		t.Run(scenario, func(t *testing.T) {
			options := localIdentityOptions{mount: "/auth"}
			if scenario == "persistent restart" {
				stateDir := filepath.Join(t.TempDir(), "state")
				options.configure = func(input string) string {
					return strings.Replace(input, "security {", "security {\nstate {\ndirectory "+stateDir+"\n}\n", 1)
				}
			}
			f := crossDeviceFixture(t, options, "enable cross-device login", cert, key, roots)
			i := crossDeviceStart(t, f.oidcRPFixture)
			if scenario == "reload" || scenario == "disabled JSON" {
				// File stores deliberately reject overlapping owners. A candidate
				// using separate copies permits an actual host reload without weakening
				// that ownership contract or changing the running portal's mount.
				for _, old := range []string{f.database, filepath.Join(filepath.Dir(f.database), "excluded.json")} {
					data, err := os.ReadFile(old)
					if err != nil {
						t.Fatal(err)
					}
					next := old + ".reload"
					if err := os.WriteFile(next, data, 0600); err != nil {
						t.Fatal(err)
					}
					f.input = strings.ReplaceAll(f.input, old, next)
				}
			} else if err := caddy.Stop(); err != nil {
				t.Fatal(err)
			}
			if scenario == "disabled JSON" {
				config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(f.input), nil)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(config, []byte(`"cross_device_login":{"enabled":true}`)) {
					t.Fatal("missing JSON setting")
				}
				config = bytes.ReplaceAll(config, []byte(`"cross_device_login":{"enabled":true}`), []byte(`"cross_device_login":{"enabled":false}`))
				if err := caddy.Load(config, true); err != nil {
					t.Fatal(err)
				}
				f.client.CloseIdleConnections()
				f.request(t, "GET", "/cross-device", nil, nil).requireStatus(t, 404)
				login := f.request(t, "GET", "/login", nil, nil)
				login.requireStatus(t, 200)
				if bytes.Contains(login.body, []byte("Sign in on another device")) {
					t.Fatal("JSON reload retained login action")
				}
				return
			}
			f.load(t)
			f.client.CloseIdleConnections()
			r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
			r.requireStatus(t, 410)
			crossDeviceNoCredentials(t, f.oidcRPFixture, r)
			f.request(t, "GET", i.URI, nil, nil).requireStatus(t, 410)
			crossDeviceStart(t, f.oidcRPFixture)
		})
	}
}

func testCaddyCrossDeviceRollback(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local", oidcRealm: "local", configure: func(input string) string {
		input = strings.Replace(input, "body transport enabled", "body transport enabled\nmax sessions 2", 1)
		return strings.Replace(input, "applications trusted", "applications trusted\nmax sessions 1", 1)
	}}, "enable cross-device login", cert, key, roots)
	b := crossDeviceBrowser(t, f.oidcRPFixture)
	i := crossDeviceStart(t, f.oidcRPFixture)
	crossDeviceBegin(t, b, i)
	confirmation := crossDeviceLogin(t, b, "alice", lifecyclePassword, false, f.database)
	crossDeviceDecision(t, b, confirmation, "approve").requireStatus(t, 200)
	// The approver occupies the sole OP slot; failure after refresh issuance
	// must release the undelivered family as well as suppress every credential.
	r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
	r.requireStatus(t, 401)
	crossDeviceNoCredentials(t, f.oidcRPFixture, r)
	if r.header.Get("Location") != "" {
		t.Fatal("failed completion redirected")
	}
	crossDevicePost(t, f.oidcRPFixture, "poll", i.values()).requireStatus(t, 410)
	f.json(t, b.client, "/api/logout", struct{}{}, "", http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}}).requireStatus(t, 200)
	for range 2 {
		result := f.jsonPassword(t, f.plain, "alice", lifecyclePassword, "body")
		if result.SessionID == "" {
			t.Fatal("undelivered refresh family leaked capacity")
		}
	}
}

func testCaddyCrossDeviceDecisions(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, scenario := range []string{"deny", "cancel", "concurrent", "logout", "requester policy", "password reset"} {
		t.Run(scenario, func(t *testing.T) {
			extra := "enable cross-device login"
			if scenario == "requester policy" {
				extra += "\ntransform user {\nregex match iss /cross-device/poll$\nrequire totp\n}"
			}
			f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth"}, extra, cert, key, roots)
			b := crossDeviceBrowser(t, f.oidcRPFixture)
			i := crossDeviceStart(t, f.oidcRPFixture)
			crossDeviceBegin(t, b, i)
			confirmation := crossDeviceLogin(t, b, "alice", lifecyclePassword, false, f.database)
			decision := "approve"
			if scenario == "deny" {
				decision = "deny"
			}
			crossDeviceDecision(t, b, confirmation, decision).requireStatus(t, 200)
			if scenario == "cancel" {
				crossDevicePost(t, f.oidcRPFixture, "cancel", i.values()).requireStatus(t, 200)
			}
			if scenario == "logout" {
				b.request(t, "GET", "/logout", nil, nil).requireStatus(t, 302)
			}
			if scenario == "password reset" {
				admin := crossDeviceBrowser(t, f.oidcRPFixture)
				result := crossDeviceJSONLogin(t, f, admin, "admin", lifecyclePassword)
				reset := f.admin(t, result.AccessToken, "reset_password", nil)
				password, _ := reset["password"].(string)
				if password == "" {
					t.Fatal("password reset did not complete")
				}
				f.secrets = append(f.secrets, password)
			}
			if scenario == "concurrent" {
				var passed atomic.Int32
				var wg sync.WaitGroup
				// Give each HTTP caller a separate jar so only server-side single use is shared.
				for range 8 {
					caller := crossDeviceBrowser(t, f.oidcRPFixture)
					wg.Go(func() {
						r := crossDevicePost(t, caller, "poll", i.values())
						if r.status == 200 {
							passed.Add(1)
						} else if r.status != 410 {
							t.Errorf("unexpected concurrent status %d", r.status)
						}
					})
				}
				wg.Wait()
				if passed.Load() != 1 {
					t.Fatal("approval was not consumed exactly once")
				}
				return
			}
			r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
			want := 410
			if scenario == "requester policy" || scenario == "password reset" {
				want = 401
			}
			r.requireStatus(t, want)
			crossDeviceNoCredentials(t, f.oidcRPFixture, r)
		})
	}
}

func testCaddyCrossDeviceFamilies(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, scenario := range []string{"rotation", "logout after rotation", "logout without access", "replay", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth", refreshRealm: "local"}, "enable cross-device login", cert, key, roots)
			b := crossDeviceBrowser(t, f.oidcRPFixture)
			i := crossDeviceStart(t, f.oidcRPFixture)
			crossDeviceBegin(t, b, i)
			confirmation := crossDeviceLogin(t, b, "alice", lifecyclePassword, false, f.database)
			crossDeviceDecision(t, b, confirmation, "approve").requireStatus(t, 200)
			headers := http.Header{"Origin": {f.base}, "X-Authcrunch-Refresh": {"1"}}
			old := crossDeviceCookie(b, "AUTHP_REFRESH_TOKEN")
			switch scenario {
			case "rotation", "logout after rotation", "replay":
				f.json(t, b.client, "/api/refresh_token", struct{}{}, "", headers).requireStatus(t, 200)
				if scenario == "logout after rotation" {
					f.json(t, b.client, "/api/logout", struct{}{}, "", headers).requireStatus(t, 200)
				}
				if scenario == "replay" {
					h := headers.Clone()
					h.Set("Cookie", "AUTHP_REFRESH_TOKEN="+old)
					f.json(t, f.plain, "/api/refresh_token", struct{}{}, "", h).requireStatus(t, 401)
				}
			case "logout without access":
				b.request(t, "GET", "/login?fresh=1", nil, nil).requireStatus(t, 200)
				if crossDeviceCookie(b, "AUTHP_ACCESS_TOKEN") != "" {
					t.Fatal("fresh login retained access cookie")
				}
				f.json(t, b.client, "/api/logout", struct{}{}, "", headers).requireStatus(t, 200)
			case "replacement":
				crossDeviceJSONLogin(t, f, b, "bob", localIdentityBobPassword)
			}
			r := crossDevicePost(t, f.oidcRPFixture, "poll", i.values())
			if scenario == "rotation" {
				r.requireStatus(t, 200)
				f.assertResource(t, crossDeviceCookie(f.oidcRPFixture, "AUTHP_ACCESS_TOKEN"))
				return
			}
			if r.status != 410 && r.status != 401 {
				t.Fatalf("retired family authorized transfer: HTTP %d", r.status)
			}
			crossDeviceNoCredentials(t, f.oidcRPFixture, r)
		})
	}
}

func testCaddyCrossDeviceHTTP(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := crossDeviceFixture(t, localIdentityOptions{mount: "/auth"}, "enable cross-device login\ncookie prefix TRANSFER\ncookie cross-device session id name DEVICE_BINDING", cert, key, roots)
	for _, path := range []string{"/cross-device", "/cross-device/activate"} {
		r := f.request(t, "POST", path, url.Values{}, http.Header{"Origin": {f.base}})
		r.requireStatus(t, 405)
		if r.header.Get("Allow") != "GET" {
			t.Fatal("page omitted GET allowance")
		}
	}
	for _, route := range []string{"start", "begin", "poll", "cancel"} {
		r := f.request(t, "GET", "/cross-device/"+route, nil, nil)
		r.requireStatus(t, 405)
		if r.header.Get("Allow") != "POST" {
			t.Fatal("wrong method allowance")
		}
		for _, headers := range []http.Header{{}, {"Origin": {"null"}}, {"Origin": {"https://attacker.example"}}, {"Origin": {f.base, f.base}}, {"Origin": {f.base + ", " + f.base}}, {"Origin": {f.base}, "Sec-Fetch-Site": {"cross-site"}}} {
			f.request(t, "POST", "/cross-device/"+route, url.Values{}, headers).requireStatus(t, 403)
		}
	}
	r := f.request(t, "PUT", "/cross-device/confirm", nil, nil)
	r.requireStatus(t, 405)
	if r.header.Get("Allow") != "GET, POST" {
		t.Fatal("confirmation omitted supported method")
	}
	for _, tc := range []struct {
		size   int
		types  []string
		status int
	}{
		{4096, []string{"application/x-www-form-urlencoded; charset=UTF-8"}, 200},
		{4097, []string{"application/x-www-form-urlencoded"}, 413},
		{8, []string{"application/json"}, 415},
		{8, []string{"application/x-www-form-urlencoded", "application/x-www-form-urlencoded"}, 400},
		{8, []string{"application/x-www-form-urlencoded; charset="}, 400},
	} {
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+"/cross-device/start", io.NopCloser(strings.NewReader("padding="+strings.Repeat("x", tc.size-8))))
		if err != nil {
			t.Fatal(err)
		}
		req.ContentLength = -1
		req.Header = http.Header{"Origin": {f.base}, "Content-Type": tc.types}
		response, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil || response.StatusCode != tc.status {
			t.Fatalf("streamed form: %d, want %d (%v)", response.StatusCode, tc.status, err)
		}
	}
	i := crossDeviceStart(t, f.oidcRPFixture)
	for _, body := range []string{"code=%zz", "code=" + i.Code + "&secret=" + i.Secret + "&bad=%"} {
		req, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+"/cross-device/poll", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = http.Header{"Origin": {f.base}, "Content-Type": {"application/x-www-form-urlencoded"}}
		r, err := f.client.Do(req)
		if err != nil {
			t.Fatal("malformed form TLS request failed")
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if readErr != nil || r.StatusCode != 400 {
			t.Fatal("malformed URL encoding did not return 400")
		}
	}
	for _, field := range []string{"code", "secret"} {
		values := i.values()
		values.Add(field, values.Get(field))
		crossDevicePost(t, f.oidcRPFixture, "poll", values).requireStatus(t, 400)
	}
	for _, path := range []string{"/cross-device/unknown", "/cross-device/api/logout", "/cross-device/oauth2/cross-device", "/cross-device/assets/test.js", "/cross-device/%61ctivate?code=" + i.Code} {
		f.request(t, "GET", path, nil, nil).requireStatus(t, 404)
	}
	b := crossDeviceBrowser(t, f.oidcRPFixture)
	page := b.request(t, "GET", i.URI, nil, nil)
	page.requireStatus(t, 200)
	form := oidcRPForm(t, page.body)
	cookies := (&http.Response{Header: page.header}).Cookies()
	var binding *http.Cookie
	for _, c := range cookies {
		if c.Name == "DEVICE_BINDING" {
			binding = c
		}
	}
	if binding == nil || !binding.Secure || !binding.HttpOnly || binding.Domain != "" || binding.Path != "/auth" || binding.SameSite != http.SameSiteNoneMode || binding.MaxAge != 300 {
		t.Fatal("unsafe approving browser cookie")
	}
	wrong := form.values.Encode()
	values, _ := url.ParseQuery(wrong)
	values.Set("csrf", "wrong")
	b.request(t, "POST", crossDeviceAction(t, b, form.action), values, http.Header{"Origin": {f.base}}).requireStatus(t, 403)
	duplicate := crossDeviceBrowser(t, f.oidcRPFixture)
	duplicate.request(t, "POST", crossDeviceAction(t, duplicate, form.action), form.values, http.Header{"Origin": {f.base}, "Cookie": {"DEVICE_BINDING=" + binding.Value + "; DEVICE_BINDING=" + binding.Value}}).requireStatus(t, 403)
	b.request(t, "POST", crossDeviceAction(t, b, form.action), form.values, http.Header{"Origin": {f.base}}).requireStatus(t, 303)
	confirmation := crossDeviceLogin(t, b, "alice", lifecyclePassword, false, f.database)
	crossDeviceDecision(t, b, confirmation, "approve").requireStatus(t, 200)
	crossDevicePost(t, f.oidcRPFixture, "poll", i.values()).requireStatus(t, 200)
	if crossDeviceCookie(f.oidcRPFixture, "TRANSFER_ACCESS_TOKEN") == "" {
		t.Fatal("custom cookie role lost")
	}
}

func crossDeviceJSONLogin(t *testing.T, f *localIdentityFixture, b *oidcRPFixture, username, password string) apiauth.AuthResponse {
	t.Helper()
	request := apiauth.AuthRequest{Username: username, Realm: "local"}
	start := localIdentityAuth(t, f.json(t, b.client, "/login", request, ""))
	if start.Authenticated || start.NextChallenge != "password" || start.SandboxID == "" || start.SandboxSecret == "" {
		t.Fatal("missing password challenge")
	}
	request.SandboxID, request.SandboxSecret = start.SandboxID, start.SandboxSecret
	request.ChallengeKind, request.ChallengeResponse = "password", password
	result := localIdentityAuth(t, f.json(t, b.client, "/login", request, ""))
	if !result.Authenticated {
		t.Fatal("fresh JSON login did not complete")
	}
	return result
}

// Form actions are origin-relative URLs, while the fixture's convenience paths
// are portal-relative. Resolve the browser action exactly once.
func crossDeviceAction(t *testing.T, b *oidcRPFixture, action string) string {
	t.Helper()
	base, err := url.Parse(b.issuer + "/cross-device")
	if err != nil {
		t.Fatal(err)
	}
	target, err := base.Parse(action)
	if err != nil || target.Scheme+"://"+target.Host != b.base {
		t.Fatal("form left the portal origin")
	}
	return target.String()
}
