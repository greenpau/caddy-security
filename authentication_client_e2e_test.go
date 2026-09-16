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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const (
	authenticationClientTOTPSecret           = "0123456789abcdef0123456789abcdef"
	authenticationClientWhitespacePassword   = lifecyclePassword + "\t"
	authenticationClientWhitespaceTOTPSecret = authenticationClientTOTPSecret + "\u2003"
)

type authenticationClientFixture struct {
	base, mount, accessName, refreshName string
	refresh, body, oidc                  bool
	http                                 *http.Client
	probe                                *tokenRefreshBrowserState
}

// All identity and enrollment data is created before Caddy owns the database.
// No management API or constructed authentication evidence is involved.
func authenticationClientDatabase(t *testing.T) (string, map[string]string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]string)
	for i, name := range []string{"alice", "totpuser", "mfauser", "whitespace", "expiredkey", "revokedkey", "disabledkey", "disableduser"} {
		r := &requests.Request{User: requests.User{Username: name, Email: name + "@example.test", Password: lifecyclePassword, Roles: []string{"authp/user"}}}
		if name == "whitespace" {
			r.User.Password = authenticationClientWhitespacePassword
		}
		if err := db.AddUser(r); err != nil {
			t.Fatal(err)
		}
		if name == "totpuser" || name == "mfauser" || name == "whitespace" {
			r.MfaToken = requests.MfaToken{Type: "totp", Secret: authenticationClientTOTPSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
			if name == "whitespace" {
				r.MfaToken.Secret = authenticationClientWhitespaceTOTPSecret
			}
			if err := db.AddMfaToken(r); err != nil {
				t.Fatal(err)
			}
			if name == "mfauser" || name == "whitespace" {
				r.User.Challenges = []string{"password mfa"}
				if err := db.OverwriteUserAuthChallengeRules(r); err != nil {
					t.Fatal(err)
				}
			}
		}
		keys[name] = fmt.Sprintf("%024d", i+1) + strings.Repeat("A", 40)
		r.Key = requests.Key{Payload: keys[name], Usage: "api", Comment: "Synthetic interoperability key", Disabled: name == "disabledkey"}
		if err := db.AddAPIKey(r); err != nil {
			t.Fatal(err)
		}
		if name == "expiredkey" || name == "revokedkey" {
			if err := db.GetAPIKeys(r); err != nil {
				t.Fatal(err)
			}
			key := r.Response.Payload.(*identity.APIKeyBundle).Get()[0]
			if name == "expiredkey" {
				key.Expired, key.ExpiredAt = true, time.Now().Add(-time.Hour)
				if err := db.Save(); err != nil {
					t.Fatal(err)
				}
			} else {
				r.Key.ID, r.Key.Prefix = key.ID, key.Prefix
				if err := db.DeleteAPIKey(r); err != nil {
					t.Fatal(err)
				}
			}
		}
		if name == "disableduser" {
			if err := db.DisableUser(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	return path, keys
}

func newAuthenticationClientFixture(t *testing.T, mount, database, cert, key string, roots *x509.CertPool, refresh, body, custom, oidc bool, accessLifetimeSeconds ...int) *authenticationClientFixture {
	t.Helper()
	f := &authenticationClientFixture{base: "https://" + lifecycleAddress(t), mount: mount, refresh: refresh, body: body, oidc: oidc, accessName: "authp_access_token", refreshName: "AUTHP_REFRESH_TOKEN"}
	accessKey := newJWKSKeyFiles(t, "RSA", "access")
	cookies, policyNames, refreshBlock, oidcBlock, applications := "", "", "", "", ""
	if custom {
		cookies = "cookie access token name INTEROP_ACCESS\ncookie refresh token name INTEROP_REFRESH"
		policyNames = "set access_token cookie name INTEROP_ACCESS"
		f.accessName, f.refreshName = "interop_access", "INTEROP_REFRESH"
	}
	if refresh {
		state, basePath := "disabled", mount
		if body {
			state = "enabled"
		}
		if basePath == "" {
			basePath = "/"
		}
		lifetime := 60
		if len(accessLifetimeSeconds) > 0 {
			lifetime = accessLifetimeSeconds[0]
		}
		refreshBlock = fmt.Sprintf("token refresh {\nrealms local\npublic origin %s\nbase path %s\nbody transport %s\naccess lifetime %d\n}\n", f.base, basePath, state, lifetime)
	}
	if oidc {
		opKey := newOIDCRPKey(t, "op")
		applications = fmt.Sprintf("oauth application website {\nclient_id interop-rp\nclient_secret %s\nredirect_uri https://rp.example.test/callback\nskip_consent on\n}\n", applicationTestSecret)
		oidcBlock = fmt.Sprintf("oidc provider {\nissuer %s%s\nrealms local\nsigning key files %q\napplications website\n}\n", f.base, mount, opKey.private)
	}
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  %s
  local identity store localdb {
   realm local
   path %q
  }
  authentication portal myportal {
   enable identity store localdb
   disable admin api
   %s
   %s
   %s
   %s
  }
  authorization policy resource_policy {
   %s
   %s
   set auth url %s%s/login
   disable auth redirect
   validate bearer header
   allow roles authp/user
  }
 }
}
%s {
 tls %q %q
 route {
  route /resource {
   authorize with resource_policy
   respond "protected interoperability resource"
  }
  route %s/* {
   authenticate with myportal
  }
 }
}`, applications, database, accessKey.signer("access"), cookies, refreshBlock, oidcBlock, accessKey.verifier("access"), policyNames, f.base, mount, f.base, cert, key, mount)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	// ProfileEnabled is typed JSON configuration; there is no Caddyfile profile
	// toggle. Disable it explicitly before provisioning instead of assuming the
	// Caddyfile default is off or adding a new unrelated directive.
	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	var apps map[string]json.RawMessage
	if err := json.Unmarshal(config["apps"], &apps); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(apps["security"], &app); err != nil {
		t.Fatal(err)
	}
	app.Config.AuthenticationPortals[0].API = &authn.APIConfig{}
	apps["security"], err = json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	config["apps"], err = json.Marshal(apps)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	f.probe = &tokenRefreshBrowserState{}
	currentTokenRefreshBrowserProbe.Store(f.probe)
	data = tokenRefreshBrowserAdapter(t, mount)(data)
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	f.http = &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}

// Inspect the public client's real wire requests and server responses without
// changing them. Keep secrets out of diagnostics, including comparison diffs.
type authenticationClientWire struct {
	t          *testing.T
	next       http.RoundTripper
	path, mode string
	password   string
	key        bool
	requests   int
	responses  []apiauth.AuthResponse
}

func (tr *authenticationClientWire) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.requests++
	if r.Method != "POST" || r.URL.Path != tr.path || r.URL.RawQuery != "" {
		tr.t.Error("authentication used an endpoint other than JSON login")
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if tr.password != "" && string(fields["challenge_kind"]) == `"password"` {
		var password string
		if json.Unmarshal(fields["challenge_response"], &password) != nil || password != tr.password {
			tr.t.Error("configured password changed before reaching the portal")
		}
	}
	if tr.mode == authclient.RefreshTransportBody {
		if string(fields["refresh_transport"]) != `"body"` {
			tr.t.Error("native checkpoint lost body transport")
		}
		for _, name := range []string{"Cookie", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
			if len(r.Header.Values(name)) != 0 {
				tr.t.Error("native login carried browser state")
			}
		}
	} else if _, exists := fields["refresh_transport"]; exists {
		tr.t.Error("cookie-mode wire broke the legacy schema")
	}
	response, err := tr.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK && (tr.mode == authclient.RefreshTransportBody || tr.key) && len(response.Cookies()) != 0 {
		tr.t.Error("native/API-key response created cookies")
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		tr.t.Error("JSON login permitted caching")
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	var result apiauth.AuthResponse
	if err := json.Unmarshal(data, &result); err != nil {
		tr.t.Error("login response was not JSON")
	}
	tr.responses = append(tr.responses, result)
	return response, nil
}

func (f *authenticationClientFixture) loginClient(t *testing.T, cfg authclient.Config, prompt authclient.PromptFunc) (*authclient.Client, *authenticationClientWire, http.CookieJar) {
	t.Helper()
	cfg.BaseURL, cfg.Realm = f.base+f.mount, "local"
	wire := &authenticationClientWire{t: t, next: f.http.Transport, path: f.mount + "/login", mode: cfg.RefreshTransport, key: cfg.APIKey != ""}
	hc := *f.http
	hc.Transport = wire
	hc.Jar, _ = cookiejar.New(nil)
	if cfg.RefreshTransport == authclient.RefreshTransportBody {
		u, _ := url.Parse(f.base + f.mount + "/")
		hc.Jar.SetCookies(u, []*http.Cookie{{Name: "BROWSER_SENTINEL", Value: "must-not-leave-jar", Path: "/"}})
	}
	client, err := authclient.NewClient(&cfg, authclient.Options{HTTPClient: &hc, Prompt: prompt, UserAgent: "caddy-security-interop-test"})
	if err != nil {
		t.Fatal(err)
	}
	if wire.requests != 0 {
		t.Fatal("constructing the client performed login")
	}
	return client, wire, hc.Jar
}

func authenticationClientTOTP() string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, []byte(authenticationClientTOTPSecret))
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func (f *authenticationClientFixture) credentialAccess(t *testing.T, credentials *authclient.Credentials, username string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "credentials.json")
	store, err := authclient.NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credentials); err != nil {
		t.Fatal(err)
	}
	reopened, err := authclient.NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	expected := *credentials
	if expected.CreatedAt == "" {
		// Save supplies creation metadata for explicitly managed protocol results.
		if _, err := time.Parse(time.RFC3339Nano, loaded.CreatedAt); err != nil {
			t.Fatal("credential store omitted creation time")
		}
		expected.CreatedAt = loaded.CreatedAt
	}
	if !cmp.Equal(&expected, loaded) {
		t.Fatal("credential persistence lost login metadata")
	}
	if runtime.GOOS != "windows" {
		for _, entry := range []struct {
			path string
			mode os.FileMode
		}{{path, 0600}, {filepath.Dir(path), 0700}} {
			info, err := os.Stat(entry.path)
			if err != nil || info.Mode().Perm() != entry.mode {
				t.Fatal("credential storage is not private")
			}
		}
	}
	header, err := loaded.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	// A distinct resource consumer has no authenticator or login cookies.
	consumer := *f.http
	consumer.Jar = nil
	status, _, body := registrationHTTP(t, &consumer, "GET", f.base+"/resource", nil, http.Header{"Authorization": {header}})
	if status != 200 || string(body) != "protected interoperability resource" {
		t.Fatalf("persisted credentials did not authorize the resource: %d", status)
	}
	status, _, _ = registrationHTTP(t, &consumer, "GET", f.base+"/resource", nil, nil)
	if status != 401 {
		t.Fatalf("resource accepted missing credentials: %d", status)
	}
	status, _, body = registrationHTTP(t, &consumer, "GET", f.base+f.mount+"/whoami?probe=true", nil, http.Header{"Authorization": {header}, "Accept": {"application/json"}})
	var identity struct {
		Authenticated bool     `json:"authenticated"`
		Subject       string   `json:"sub"`
		Email         string   `json:"email"`
		Roles         []string `json:"roles"`
		ExpiresIn     int64    `json:"expires_in"`
		SID           string   `json:"sid"`
	}
	if status != 200 || json.Unmarshal(body, &identity) != nil || !identity.Authenticated || identity.Subject != username || identity.Email != username+"@example.test" || !slices.Equal(identity.Roles, []string{"authp/user"}) || identity.ExpiresIn <= 0 || identity.SID != loaded.SessionID {
		t.Fatal("persisted credentials lost identity, roles or lifetime")
	}
	parts := strings.Split(loaded.AccessToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatal("access token is not a signed JWT")
	}
	replacement := "A"
	if parts[2][0] == 'A' {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	status, _, _ = registrationHTTP(t, &consumer, "GET", f.base+"/resource", nil, http.Header{"Authorization": {loaded.AccessTokenName + "=" + strings.Join(parts, ".")}})
	if status != 401 {
		t.Fatal("resource accepted a tampered signature")
	}
	for _, api := range []struct{ method, path string }{{"GET", "/api/server/metadata"}, {"POST", "/api/profile"}} {
		status = f.jsonRequest(t, api.method, api.path, map[string]string{"kind": "fetch_user_info"}, http.Header{"Authorization": {header}}).status
		if status != 400 {
			t.Fatalf("management/profile API was not disabled: %s %d", api.path, status)
		}
	}
	if f.oidc {
		f.noOIDCSession(t, &consumer, loaded)
	}
}

func (f *authenticationClientFixture) noOIDCSession(t *testing.T, client *http.Client, credentials *authclient.Credentials) {
	t.Helper()
	query := url.Values{"client_id": {"interop-rp"}, "redirect_uri": {"https://rp.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}, "code_challenge_method": {"S256"}, "code_challenge": {strings.Repeat("A", 43)}}
	for _, header := range []string{"Bearer " + credentials.AccessToken, credentials.AccessTokenName + "=" + credentials.AccessToken} {
		status, headers, _ := registrationHTTP(t, client, "GET", f.base+f.mount+"/oidc/authorize?"+query.Encode(), nil, http.Header{"Authorization": {header}})
		target, err := url.Parse(headers.Get("Location"))
		if err != nil || status != 302 || target.Host != "rp.example.test" || target.Query().Get("error") != "login_required" || target.Query().Get("code") != "" {
			t.Fatal("native access credential became OIDC browser authentication")
		}
	}
}

func TestCaddyAuthenticationClientE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 600*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthenticationClientProcess$", "-test.v", "-test.timeout=570s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_AUTHCLIENT_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("authentication client through Caddy TLS: %v\n%s", err, output)
	}
}

func TestCaddyAuthenticationClientProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_AUTHCLIENT_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	database, keys := authenticationClientDatabase(t)
	for _, tc := range []struct {
		name, mount                 string
		refresh, body, custom, oidc bool
	}{
		{"legacy root", "", false, false, false, false},
		{"legacy nested custom", "/tenant/auth", false, false, true, false},
		{"native root", "", true, true, false, false},
		{"native nested custom with OIDC", "/tenant/auth", true, true, true, true},
		{"body disabled", "/auth", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuthenticationClientFixture(t, tc.mount, database, cert, key, roots, tc.refresh, tc.body, tc.custom, tc.oidc)
			if !tc.refresh || tc.body {
				f.passwordJourneys(t)
			}
			f.transportBoundaries(t)
			f.apiKeyJourneys(t, keys)
			if tc.body {
				f.nativeProtocol(t)
				f.cliConnect(t, cert)
			}
		})
	}
}
