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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"golang.org/x/net/html"
)

const authenticationEventSuccess = "user was successfully authenticated"
const authenticationEventWrongPassword = "IncorrectEventPassword42!"

// This passes the browser's 4-8 digit form validation and deterministically
// fails the six-digit token's backend validation, without a wall-clock race.
const authenticationEventWrongTOTP = "7149263"

type authenticationEventSecrets struct {
	path   string
	values []string
}

func (s *authenticationEventSecrets) add(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" {
			s.values = append(s.values, value)
		}
	}
	data, err := json.Marshal(s.values)
	if err != nil || os.WriteFile(s.path, data, 0600) != nil {
		t.Fatal("cannot preserve private event-test credential inventory")
	}
}

func authenticationEventRedacted(t *testing.T, data []byte, secrets []string) {
	t.Helper()
	assertAdminRedacted(t, data, secrets)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		encoded, _ := json.Marshal(secret)
		for _, value := range []string{string(encoded[1 : len(encoded)-1]), url.QueryEscape(secret)} {
			if bytes.Contains(data, []byte(value)) {
				t.Fatal("encoded sensitive value appeared in event-test output")
			}
		}
	}
}

func TestCaddyAuthenticationEventsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
	defer cancel()
	inventory := filepath.Join(t.TempDir(), "credentials.json")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthenticationEventsProcess$", "-test.v", "-test.timeout=165s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_EVENTS_CHILD=1", "CADDY_SECURITY_EVENTS_INVENTORY="+inventory, "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	var secrets []string
	data, readErr := os.ReadFile(inventory)
	if readErr != nil || json.Unmarshal(data, &secrets) != nil {
		// Without the private inventory, child output is not safe to publish.
		t.Fatal("authentication-event child did not preserve its credential inventory")
	}
	authenticationEventRedacted(t, output, secrets)
	if err != nil {
		t.Fatalf("Caddy authentication events: %v\n%s", err, output)
	}
}

type authenticationEventWant struct {
	message, username, checkpoint string
	count                         int
}

type authenticationEventFixture struct {
	f        *localIdentityFixture
	secrets  *authenticationEventSecrets
	want     map[string]authenticationEventWant
	sequence int
	debug    bool
	refresh  bool
}

func newAuthenticationEventFixture(t *testing.T, cert, key string, roots *x509.CertPool, secrets *authenticationEventSecrets, debug, refresh bool, skip string, seed func(*testing.T, string)) *authenticationEventFixture {
	t.Helper()
	e := &authenticationEventFixture{secrets: secrets, want: make(map[string]authenticationEventWant), debug: debug, refresh: refresh}
	options := localIdentityOptions{mount: "/tenant/auth", mfa: true, seed: seed}
	if refresh {
		options.refreshRealm = "local"
	}
	options.configure = func(input string) string {
		if !debug {
			input = strings.Replace(input, "level DEBUG", "level INFO", 1)
		}
		input = strings.Replace(input, "validate bearer header", "validate bearer header\n   disable auth redirect", 1)
		if skip != "" {
			input = strings.Replace(input, " security {", " security {\n logging {\n skip exact text "+strconv.Quote(skip)+"\n }", 1)
		}
		// Capture the actual signing key before provisioning can emit diagnostics.
		for line := range strings.SplitSeq(input, "\n") {
			const prefix = "crypto key access sign-verify from file "
			line = strings.TrimSpace(line)
			if quotedPath, ok := strings.CutPrefix(line, prefix); ok {
				path, err := strconv.Unquote(quotedPath)
				if err != nil {
					t.Fatal("invalid fixture signing-key declaration")
				}
				authenticationEventCapturePEM(t, secrets, path)
			}
		}
		return input
	}
	e.f = newLocalIdentityFixture(t, options, cert, key, roots)
	e.capture(t, e.f.secrets...)
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error("cannot stop event-test Caddy instance")
		}
		e.checkLogs(t)
	})
	return e
}

func authenticationEventCapturePEM(t *testing.T, secrets *authenticationEventSecrets, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	block, _ := pem.Decode(data)
	if err != nil || block == nil {
		t.Fatal("cannot capture private fixture key")
	}
	secrets.add(t, string(data), base64.StdEncoding.EncodeToString(block.Bytes))
}

func (e *authenticationEventFixture) capture(t *testing.T, values ...string) {
	t.Helper()
	e.secrets.add(t, values...)
	e.f.secrets = append(e.f.secrets, values...)
}

func (e *authenticationEventFixture) expect(id, message, username, checkpoint string, count int) {
	e.want[id] = authenticationEventWant{message, username, checkpoint, count}
}

func authenticationEventStatus(t *testing.T, r oidcRPResponse, want int, stage string) {
	t.Helper()
	if r.status != want {
		t.Fatalf("%s: HTTP status %d, want %d", stage, r.status, want)
	}
}

func authenticationEventCookieSecret(name string) bool {
	switch name {
	case "AUTHP_SANDBOX_ID", "AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_ID_TOKEN", "AUTHP_OIDC_SESSION_ID":
		return true
	}
	return false
}

func authenticationEventLiveCookie(c *http.Cookie) bool {
	return c.Value != "" && c.MaxAge >= 0 && (c.Expires.IsZero() || c.Expires.After(time.Now()))
}

// Capture returned credentials before any status, cache, schema or TLS assertion.
// No request/response body, cookie or server error is printed on failure.
func (e *authenticationEventFixture) request(t *testing.T, client *http.Client, method, target, media string, body []byte, hints bool) (oidcRPResponse, string) {
	t.Helper()
	e.sequence++
	id := fmt.Sprintf("authentication-event-%d", e.sequence)
	req, err := http.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal("cannot construct event-test request")
	}
	req.Header.Set("X-Request-Id", id)
	if method == http.MethodPost {
		// Native body refresh is deliberately not a browser request. The form
		// and access-only WebAuthn journeys still present the real TLS Origin.
		if !(e.refresh && client == e.f.plain && media == "application/json") {
			req.Header.Set("Origin", e.f.base)
		}
		req.Header.Set("Content-Type", media)
	}
	if media == "application/json" {
		req.Header.Set("Accept", media)
	}
	if hints {
		req.Header.Set("X-Real-IP", "198.51.100.42")
		req.Header.Set("X-Forwarded-For", "203.0.113.24")
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal("event-test TLS request failed")
	}
	defer response.Body.Close()
	for _, c := range response.Cookies() {
		if authenticationEventCookieSecret(c.Name) && authenticationEventLiveCookie(c) {
			e.capture(t, c.Value)
		}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	var auth apiauth.AuthResponse
	if json.Unmarshal(data, &auth) == nil {
		e.capture(t, auth.SandboxSecret, auth.AccessToken, auth.RefreshToken)
	}
	if err != nil || len(data) > 1<<20 {
		t.Fatal("invalid event-test response body")
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatal("event-test request did not use verified TLS")
	}
	return oidcRPResponse{response.StatusCode, response.Header.Clone(), data}, id
}

func (e *authenticationEventFixture) json(t *testing.T, request *apiauth.AuthRequest, hints bool) (oidcRPResponse, apiauth.AuthResponse, string) {
	t.Helper()
	if request.ChallengeResponse != "webauthn" {
		e.capture(t, request.ChallengeResponse)
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal("cannot encode event-test login")
	}
	r, id := e.request(t, e.f.plain, http.MethodPost, e.f.issuer+"/login", "application/json", data, hints)
	r.noStore(t)
	var auth apiauth.AuthResponse
	if json.Unmarshal(r.body, &auth) != nil {
		t.Fatal("event-test login returned invalid JSON")
	}
	if auth.SandboxID != "" {
		request.SandboxID, request.SandboxSecret = auth.SandboxID, auth.SandboxSecret
	}
	return r, auth, id
}

func (e *authenticationEventFixture) identify(t *testing.T, username string) apiauth.AuthRequest {
	t.Helper()
	req := apiauth.AuthRequest{Username: username, Realm: "local"}
	if e.refresh {
		req.RefreshTransport = "body"
	}
	r, auth, _ := e.json(t, &req, false)
	authenticationEventStatus(t, r, 200, "JSON identification")
	e.unfinished(t, r, e.f.plain)
	if auth.NextChallenge != "password" || auth.SandboxID == "" || auth.SandboxSecret == "" {
		t.Fatal("identification omitted password checkpoint or proof")
	}
	return req
}

func (e *authenticationEventFixture) unfinished(t *testing.T, r oidcRPResponse, client *http.Client) {
	t.Helper()
	for _, c := range (&http.Response{Header: r.header}).Cookies() {
		if authenticationEventCookieSecret(c.Name) && c.Name != "AUTHP_SANDBOX_ID" && authenticationEventLiveCookie(c) {
			t.Fatal("unfinished authentication issued a credential cookie")
		}
	}
	if strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
		var auth apiauth.AuthResponse
		if json.Unmarshal(r.body, &auth) != nil || auth.Authenticated || auth.AccessToken != "" || auth.RefreshToken != "" || auth.SessionID != "" {
			t.Fatal("unfinished authentication issued JSON credentials")
		}
	}
	if client.Jar != nil {
		u, _ := url.Parse(e.f.issuer + "/portal")
		for _, c := range client.Jar.Cookies(u) {
			if authenticationEventCookieSecret(c.Name) && c.Name != "AUTHP_SANDBOX_ID" && c.Value != "" {
				t.Fatal("unfinished authentication populated a credential jar")
			}
		}
	}
	denied, _ := e.request(t, client, http.MethodGet, e.f.base+"/resource", "", nil, false)
	authenticationEventStatus(t, denied, http.StatusUnauthorized, "unfinished login resource denial")
}

func (e *authenticationEventFixture) jsonPasswordFailure(t *testing.T, username, canonical string, count int, hints bool) {
	t.Helper()
	req := e.identify(t, username)
	req.ChallengeKind, req.ChallengeResponse = "password", authenticationEventWrongPassword
	r, _, id := e.json(t, &req, hints)
	e.expect(id, "password authentication failed", canonical, "password", count)
	authenticationEventStatus(t, r, 401, "JSON wrong password")
	e.unfinished(t, r, e.f.plain)
}

func (e *authenticationEventFixture) jsonFactorStart(t *testing.T, username, kind string) apiauth.AuthRequest {
	t.Helper()
	req := e.identify(t, username)
	req.ChallengeKind, req.ChallengeResponse = "password", lifecyclePassword
	r, auth, _ := e.json(t, &req, false)
	authenticationEventStatus(t, r, 200, "JSON password before "+kind)
	e.unfinished(t, r, e.f.plain)
	if auth.NextChallenge != kind {
		t.Fatal("password completion did not retain the required factor")
	}
	return req
}

func (e *authenticationEventFixture) jsonTOTPFailure(t *testing.T, count int) {
	t.Helper()
	req := e.jsonFactorStart(t, "ALICE@EXAMPLE.TEST", "totp")
	req.ChallengeKind, req.ChallengeResponse = "totp", authenticationEventWrongTOTP
	r, _, id := e.json(t, &req, false)
	e.expect(id, "totp passcode authentication failed", "alice", "totp", count)
	authenticationEventStatus(t, r, 401, "JSON invalid TOTP")
	e.unfinished(t, r, e.f.plain)
}

func (e *authenticationEventFixture) jsonSuccess(t *testing.T) {
	t.Helper()
	req := e.identify(t, "BOB@EXAMPLE.TEST")
	req.ChallengeKind, req.ChallengeResponse = "password", localIdentityBobPassword
	r, auth, id := e.json(t, &req, false)
	e.expect(id, authenticationEventSuccess, "bob", "", 1)
	authenticationEventStatus(t, r, 200, "JSON final password completion")
	if !auth.Authenticated || auth.AccessToken == "" || (e.refresh && (auth.RefreshToken == "" || auth.SessionID == "")) {
		t.Fatal("completed JSON login omitted its credentials")
	}
	claims := verifyCaddyJWKSSignature(t, e.f.keys, auth.AccessToken, "RS512", "access")
	if claims["sub"] != "bob" {
		t.Fatal("completed JSON login changed canonical subject")
	}
	e.f.assertResource(t, auth.AccessToken)
}

func (e *authenticationEventFixture) form(t *testing.T, method, target string, form url.Values) (oidcRPResponse, string) {
	t.Helper()
	for _, field := range []string{"secret", "passcode", "webauthn_request"} {
		e.capture(t, form.Get(field))
	}
	return e.request(t, e.f.client, method, target, "application/x-www-form-urlencoded", []byte(form.Encode()), false)
}

func (e *authenticationEventFixture) sandboxURL(t *testing.T, value string) string {
	t.Helper()
	u, err := url.Parse(value)
	base, _ := url.Parse(e.f.issuer + "/")
	if err != nil {
		t.Fatal("invalid event-test sandbox URL")
	}
	u = base.ResolveReference(u)
	if u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, e.f.mount+"/sandbox/") {
		t.Fatal("event-test sandbox left the mounted TLS portal")
	}
	return u.String()
}

func (e *authenticationEventFixture) formStart(t *testing.T, username string) string {
	t.Helper()
	e.f.newBrowser(t)
	r, _ := e.form(t, http.MethodPost, e.f.issuer+"/login", url.Values{"username": {username}, "realm": {"local"}})
	authenticationEventStatus(t, r, 303, "form identification")
	e.unfinished(t, r, e.f.client)
	return e.sandboxURL(t, r.header.Get("Location"))
}

// Read the real browser form's action without applying the OP-only parser's
// restrictions on external scripts. Form paths remain explicitly pinned here.
func (e *authenticationEventFixture) factorAction(t *testing.T, body []byte, sandbox, suffix string) string {
	t.Helper()
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		t.Fatal("invalid event-test factor HTML")
	}
	var actions []string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			var action, method string
			for _, attr := range node.Attr {
				switch attr.Key {
				case "action":
					action = attr.Val
				case "method":
					method = attr.Val
				}
			}
			if strings.HasSuffix(action, "/"+suffix) && strings.EqualFold(method, "POST") {
				actions = append(actions, e.sandboxURL(t, action))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if len(actions) != 1 || actions[0] != sandbox+"/"+suffix {
		t.Fatal("factor page omitted its exact mounted form action")
	}
	return actions[0]
}

func (e *authenticationEventFixture) formPasswordFailure(t *testing.T) {
	t.Helper()
	sandbox := e.formStart(t, "BOB@EXAMPLE.TEST")
	r, id := e.form(t, http.MethodPost, sandbox, url.Values{"secret": {authenticationEventWrongPassword}})
	e.expect(id, "password authentication failed", "bob", "password", 1)
	authenticationEventStatus(t, r, 401, "form wrong password")
	e.unfinished(t, r, e.f.client)
}

func (e *authenticationEventFixture) formFactorStart(t *testing.T, username, suffix string) (string, oidcRPResponse) {
	t.Helper()
	sandbox := e.formStart(t, username)
	r, _ := e.form(t, http.MethodPost, sandbox, url.Values{"secret": {lifecyclePassword}})
	authenticationEventStatus(t, r, 303, "form password before "+suffix)
	e.unfinished(t, r, e.f.client)
	r, _ = e.form(t, http.MethodGet, sandbox, nil)
	authenticationEventStatus(t, r, 200, "form factor page "+suffix)
	e.unfinished(t, r, e.f.client)
	return e.factorAction(t, r.body, sandbox, suffix), r
}

func (e *authenticationEventFixture) formTOTPFailure(t *testing.T) {
	t.Helper()
	action, _ := e.formFactorStart(t, "ALICE@EXAMPLE.TEST", "mfa-app-auth")
	r, id := e.form(t, http.MethodPost, action, url.Values{"passcode": {authenticationEventWrongTOTP}})
	e.expect(id, "totp passcode authentication failed", "alice", "totp", 1)
	// Backend MFA denial renders an error view with HTTP 200, not a grant.
	authenticationEventStatus(t, r, 200, "form invalid TOTP")
	e.unfinished(t, r, e.f.client)
}

func (e *authenticationEventFixture) assertion(t *testing.T, key *ecdsa.PrivateKey, credentialID, challenge string) string {
	t.Helper()
	value := challengeWebAuthnAssertion(t, key, credentialID, "127.0.0.1", challenge, e.f.base)
	e.capture(t, value)
	data, err := base64.StdEncoding.DecodeString(value)
	var assertion identity.WebAuthnAuthenticateRequest
	if err != nil || json.Unmarshal(data, &assertion) != nil {
		t.Fatal("cannot inspect synthetic signed assertion")
	}
	e.capture(t, assertion.SignatureEncoded)
	return value
}

func (e *authenticationEventFixture) webAuthnFailures(t *testing.T, key *ecdsa.PrivateKey, credentialID string) {
	t.Helper()
	req := e.jsonFactorStart(t, "ADMIN@EXAMPLE.TEST", "u2f")
	req.ChallengeKind, req.ChallengeResponse = "u2f", "webauthn"
	r, auth, _ := e.json(t, &req, false)
	authenticationEventStatus(t, r, 200, "JSON WebAuthn server challenge")
	e.unfinished(t, r, e.f.plain)
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth.NextChallenge, "mfa:u2f:"))
	var challenge struct{ Challenge string }
	if !strings.HasPrefix(auth.NextChallenge, "mfa:u2f:") || err != nil || json.Unmarshal(data, &challenge) != nil || challenge.Challenge == "" {
		t.Fatal("JSON WebAuthn checkpoint omitted the server challenge")
	}
	req.ChallengeResponse = e.assertion(t, key, credentialID, challenge.Challenge)
	r, _, id := e.json(t, &req, false)
	e.expect(id, "u2f authentication failed", "admin", "u2f", 1)
	authenticationEventStatus(t, r, 401, "JSON WebAuthn wrong signature")
	e.unfinished(t, r, e.f.plain)

	action, page := e.formFactorStart(t, "ADMIN@EXAMPLE.TEST", "mfa-u2f-auth")
	matches := regexp.MustCompile(`challenge: "([^"]+)"`).FindAllSubmatch(page.body, -1)
	if len(matches) != 1 || len(matches[0]) != 2 {
		t.Fatal("browser WebAuthn checkpoint omitted its unique server challenge")
	}
	assertion := e.assertion(t, key, credentialID, string(matches[0][1]))
	r, id = e.form(t, http.MethodPost, action, url.Values{"webauthn_request": {assertion}})
	e.expect(id, "u2f authentication failed", "admin", "u2f", 1)
	// Unlike TOTP consumption, the local WebAuthn verifier sets the response
	// code to 400. The browser error view preserves that backend failure code.
	authenticationEventStatus(t, r, 400, "form WebAuthn wrong signature")
	e.unfinished(t, r, e.f.client)
}

func authenticationEventStrings(t *testing.T, value any, secrets []string) {
	t.Helper()
	switch v := value.(type) {
	case string:
		authenticationEventRedacted(t, []byte(v), secrets)
	case map[string]any:
		for _, child := range v {
			authenticationEventStrings(t, child, secrets)
		}
	case []any:
		for _, child := range v {
			authenticationEventStrings(t, child, secrets)
		}
	}
}

func (e *authenticationEventFixture) checkLogs(t *testing.T) {
	t.Helper()
	counts := make(map[string]int)
	debugCount, accessCount := 0, 0
	for _, name := range []string{"runtime.jsonl", "access.jsonl"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(e.f.database), name))
		if err != nil || len(data) == 0 {
			t.Errorf("missing %s event evidence", name)
			continue
		}
		authenticationEventRedacted(t, data, e.secrets.values)
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		for {
			var entry map[string]any
			err := decoder.Decode(&entry)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("invalid structured %s event evidence", name)
			}
			authenticationEventStrings(t, entry, e.secrets.values)
			if name == "access.jsonl" {
				accessCount++
				continue
			}
			if entry["level"] == "debug" {
				debugCount++
			}
			message, _ := entry["msg"].(string)
			switch message {
			case "password authentication failed", "totp passcode authentication failed", "u2f authentication failed", authenticationEventSuccess:
			default:
				continue
			}
			id, _ := entry["request_id"].(string)
			want, exists := e.want[id]
			if !exists || message != want.message {
				t.Error("unexpected final-success or factor-failure event for an unfinished request")
				continue
			}
			counts[id]++
			for key, value := range map[string]string{"logger": "security", "username": want.username, "realm": "local", "portal_name": "myportal", "request_id": id} {
				if entry[key] != value {
					t.Errorf("authentication event lost canonical %s", key)
				}
			}
			if session, ok := entry["session_id"].(string); !ok || session == "" {
				t.Error("authentication event omitted session correlation")
			}
			if message == authenticationEventSuccess {
				if entry["level"] != "info" || entry["authentication_flow"] != "api" {
					t.Error("completed JSON login lost INFO/API event contract")
				}
				continue
			}
			for key, value := range map[string]string{"level": "warn", "checkpoint_type": want.checkpoint, "src_ip": "127.0.0.1", "src_conn_ip": "127.0.0.1"} {
				if entry[key] != value {
					t.Errorf("failed-factor event lost %s", key)
				}
			}
			checkpointID, ok := entry["checkpoint_id"].(json.Number)
			if _, err := checkpointID.Int64(); !ok || err != nil {
				t.Error("failed-factor event omitted numeric checkpoint ID")
			}
			if checkpoint, ok := entry["checkpoint_name"].(string); !ok || checkpoint == "" {
				t.Error("failed-factor event omitted checkpoint name")
			}
		}
	}
	for id, want := range e.want {
		if counts[id] != want.count {
			t.Errorf("event %q count %d, want %d", want.message, counts[id], want.count)
		}
	}
	if accessCount == 0 || (!e.debug && debugCount != 0) || (e.debug && debugCount == 0) {
		t.Error("fixture log level or independent access evidence did not match configuration")
	}
}

func TestCaddyAuthenticationEventsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_EVENTS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	secrets := &authenticationEventSecrets{path: os.Getenv("CADDY_SECURITY_EVENTS_INVENTORY")}
	secrets.add(t, lifecyclePassword, localIdentityBobPassword, authenticationClientTOTPSecret, applicationTestSecret, authenticationEventWrongPassword, authenticationEventWrongTOTP)
	cert, key, roots := cookieTLSCertificate(t)
	authenticationEventCapturePEM(t, secrets, key)
	t.Run("info_factor_events", func(t *testing.T) {
		registration, enrolledKey, credentialID := challengeWebAuthnRegistration(t, "127.0.0.1")
		wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal("cannot generate synthetic assertion key")
		}
		for _, key := range []*ecdsa.PrivateKey{enrolledKey, wrongKey} {
			private, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal("cannot capture synthetic assertion private material")
			}
			scalar, err := key.Bytes()
			if err != nil {
				t.Fatal("cannot encode synthetic assertion private material")
			}
			secrets.add(t, base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(scalar))
		}
		seed := func(t *testing.T, path string) {
			db, err := identity.NewDatabase(path)
			if err != nil {
				t.Fatal("cannot open fixture enrollment database")
			}
			r := &requests.Request{User: requests.User{Username: "admin", Email: "admin@example.test", Challenges: []string{"password u2f"}}, MfaToken: requests.MfaToken{Type: "u2f", Comment: "authentication event signature fixture"}, WebAuthn: registration}
			if err := db.AddMfaToken(r); err != nil {
				t.Fatal("cannot enroll event-test credential")
			}
			if err := db.OverwriteUserAuthChallengeRules(r); err != nil {
				t.Fatal("cannot require event-test hardware factor")
			}
		}
		e := newAuthenticationEventFixture(t, cert, key, roots, secrets, false, false, "", seed)
		e.jsonPasswordFailure(t, "BOB@EXAMPLE.TEST", "bob", 1, true)
		e.formPasswordFailure(t)
		e.jsonTOTPFailure(t, 1)
		e.formTOTPFailure(t)
		e.webAuthnFailures(t, wrongKey, credentialID)
		e.jsonSuccess(t)
	})
	t.Run("exact_message_filter", func(t *testing.T) {
		e := newAuthenticationEventFixture(t, cert, key, roots, secrets, false, false, "totp passcode authentication failed", nil)
		e.jsonTOTPFailure(t, 0)
		e.jsonPasswordFailure(t, "bob", "bob", 1, false)
	})
	t.Run("exact_field_value_filter", func(t *testing.T) {
		e := newAuthenticationEventFixture(t, cert, key, roots, secrets, false, false, "alice", nil)
		e.jsonPasswordFailure(t, "ALICE@EXAMPLE.TEST", "alice", 0, false)
		e.jsonPasswordFailure(t, "bob", "bob", 1, false)
	})
	t.Run("debug_credential_redaction", func(t *testing.T) {
		e := newAuthenticationEventFixture(t, cert, key, roots, secrets, true, true, "", nil)
		e.jsonPasswordFailure(t, "bob", "bob", 1, false)
		e.jsonSuccess(t)
	})
}
