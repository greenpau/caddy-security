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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
)

const (
	sqliteTicketPassword = "Synthetic-trusted-issuer-password-2026!"
	sqliteTicketSigning  = "synthetic-ticket-caddy-signing-secret-0123456789"
	sqliteTicketCookie   = "APP_TICKET_BINDING"
	sqliteTicketAccess   = "TICKET_ACCESS_TOKEN"
)

// Issuance belongs to a separate authenticated application. Only its public
// backend API touches tickets; every consumer operation crosses real Caddy TLS.
func TestCaddySQLiteTicketE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cgo-free Caddy: %v\n%s", err, output)
	}
	for _, mount := range []string{"/tenant/auth", "/"} {
		name := "nested_mount"
		if mount == "/" {
			name = "root_mount"
		}
		t.Run(name, func(t *testing.T) { testSQLiteTicketJourney(t, binary, mount) })
	}
	t.Run("concurrent_issuance_and_consumption", func(t *testing.T) { testSQLiteTicketConcurrency(t, binary) })
	t.Run("replacement_policy_and_outage", func(t *testing.T) { testSQLiteTicketLifecycle(t, binary) })
}

type sqliteTicketFixture struct {
	*persistentCaddy
	issuer              *httptest.Server
	issuers             [2]*tickets.Provider
	backendConfig       tickets.Config
	source, mount, cert string
	issueCalls, issued  atomic.Int64
	issueUncertain      atomic.Int64
	issueErrorResult    atomic.Bool
	issuerGate          sync.RWMutex
	mu                  sync.Mutex
	secrets             []string
	secretKinds         map[string]string
}

func newSQLiteTicketFixture(t *testing.T, binary, mount string) *sqliteTicketFixture {
	t.Helper()
	cert, key, roots := cookieTLSCertificate(t, "localhost")
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal("load fixture TLS certificate")
	}
	private := registrationTestDirectory(t)
	f := &sqliteTicketFixture{persistentCaddy: newPersistentCaddy(t, binary, cert, key, roots), mount: mount, cert: cert,
		secrets:     []string{sqliteTicketPassword, sqliteTicketSigning},
		secretKinds: map[string]string{sqliteTicketPassword: "issuer_password", sqliteTicketSigning: "signing_key"}}
	f.client.Timeout = 12 * time.Second
	f.issuer = httptest.NewUnstartedServer(http.HandlerFunc(f.serveIssuer))
	f.issuer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	f.issuer.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.issuer.Config.ReadHeaderTimeout = 5 * time.Second
	f.issuer.Config.ReadTimeout = 10 * time.Second
	f.issuer.Config.WriteTimeout = 10 * time.Second
	f.issuer.StartTLS()
	// Separate host names exercise cross-site top-level Lax return without
	// leaking the portal's host-only credentials to the trusted issuer.
	f.issuer.URL = strings.Replace(f.issuer.URL, "127.0.0.1", "localhost", 1)
	t.Cleanup(f.issuer.Close)
	f.backendConfig = tickets.Config{Name: "tickets", Realm: "application", Path: filepath.Join(private, "tickets.db"),
		Timeout: "5s", PublicOrigin: f.base, IssuerURL: f.issuer.URL + "/login", BasePath: mount, CookieName: sqliteTicketCookie}
	t.Cleanup(func() {
		f.issuerGate.Lock()
		defer f.issuerGate.Unlock()
		for _, provider := range f.issuers {
			if provider != nil {
				if err := provider.Close(); err != nil {
					t.Error("close trusted issuer handle", err)
				}
			}
		}
	})
	for i := range f.issuers {
		f.issuers[i], err = tickets.New(t.Context(), &f.backendConfig)
		if err != nil {
			t.Fatal("open independent trusted issuer handle", err)
		}
	}
	host := strings.TrimPrefix(f.base, "https://")
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatal(err)
	}
	// Caddy clones request URI before portal delegation and logs response headers
	// independently. Delete URI and redirect Location in both sinks: initiation
	// redirects carry request state even before a callback carries the ticket.
	f.source = fmt.Sprintf(`{
 admin %s
 persist_config off
 auto_https off
 storage file_system %q
 log {
  level DEBUG
  format filter {
   wrap json
   fields {
    request>uri delete
    resp_headers>Location delete
   }
  }
 }
 security {
  identity provider sqlite tickets {
   realm application
   path %q
   public_origin %s
   issuer_url %s
   base_path %s
   cookie_name %s
   timeout 5s
  }
  authentication portal ticketportal {
   enable identity provider tickets
   crypto key sign-verify %s
   crypto default token lifetime 120
   cookie prefix TICKET
   trust login redirect uri domain exact %s path prefix /resource
   transform user {
    match realm application
    action add role app/verified
   }
  }
  authorization policy ticketpolicy {
   crypto key verify %s
   set access_token cookie name %s
   validate bearer header
   allow roles app/verified
   disable auth redirect
  }
 }
}
https://:%s {
 bind 127.0.0.1
 tls %q %q
 log {
  format filter {
   wrap json
   fields {
    request>uri delete
    resp_headers>Location delete
   }
  }
 }
 route /ready {
  respond "ready"
 }
 route /resource* {
  authorize with ticketpolicy
  respond "ticket resource"
 }
 route %s/* {
  authenticate with ticketportal
 }
 respond unmatched 404
}`, f.admin, filepath.Join(private, "storage"), f.backendConfig.Path, f.base, f.backendConfig.IssuerURL, mount,
		sqliteTicketCookie, sqliteTicketSigning, host, sqliteTicketSigning, sqliteTicketAccess, port, cert, key, strings.TrimSuffix(mount, "/"))
	f.write(t, f.source)
	t.Cleanup(func() {
		f.kill(t)
		data, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
		if err != nil {
			t.Error("read ticket Caddy diagnostics", err)
			return
		}
		f.mu.Lock()
		secrets := append([]string(nil), f.secrets...)
		kinds := make(map[string]string, len(f.secretKinds))
		for value, category := range f.secretKinds {
			kinds[value] = category
		}
		f.mu.Unlock()
		sqliteTicketLogEvidence(t, data, secrets, kinds)
		assertAdminRedacted(t, data, secrets)
		if regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).Match(data) {
			t.Error("ticket Caddy diagnostics exposed a browser access JWT")
		}
		// Redaction must retain actual access records, rather than disabling logs.
		if !bytes.Contains(data, []byte(`"logger":"http.log.access`)) {
			t.Error("ticket access-log evidence is absent")
		}
	})
	f.startTicket(t)
	return f
}

func (f *sqliteTicketFixture) record(category string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, value := range values {
		if value != "" {
			f.secrets = append(f.secrets, value)
			f.secretKinds[value] = category
		}
	}
}

// Preserve a failing private log and report only category, structural key and
// byte offset. Never print the matching value, URL, header or log record.
func sqliteTicketLogEvidence(t *testing.T, data []byte, secrets []string, kinds map[string]string) {
	t.Helper()
	count := 0
	seen := make(map[string]bool)
	for _, secret := range secrets {
		if secret == "" || seen[secret] {
			continue
		}
		seen[secret] = true
		offset := bytes.Index(data, []byte(secret))
		if offset < 0 {
			continue
		}
		if count < 8 {
			start := bytes.LastIndexByte(data[:offset], '\n') + 1
			end := bytes.IndexByte(data[offset:], '\n')
			if end < 0 {
				end = len(data) - offset
			}
			var record map[string]any
			field := "unparsed"
			if json.Unmarshal(data[start:offset+end], &record) == nil {
				field = sqliteTicketSecretField(record, secret, "")
			}
			if !regexp.MustCompile(`^[A-Za-z0-9_>.\[\]-]{1,160}$`).MatchString(field) {
				field = "unclassified"
			}
			t.Logf("ticket log leak category=%s key=%s byte_offset=%d", kinds[secret], field, offset)
		}
		count++
	}
	if count == 0 {
		return
	}
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Error("prepare private ticket failure evidence", err)
		return
	}
	directory, err := os.MkdirTemp("tmp", "sqlite-ticket-failure-")
	if err != nil {
		t.Error("prepare private ticket failure evidence", err)
		return
	}
	if err := os.WriteFile(filepath.Join(directory, "process.log"), data, 0600); err != nil {
		t.Error("retain private ticket failure evidence", err)
		return
	}
	t.Logf("private ticket failure log retained at %s/process.log", directory)
}

func sqliteTicketSecretField(value any, secret, path string) string {
	switch value := value.(type) {
	case string:
		if strings.Contains(value, secret) {
			return path
		}
	case []any:
		for _, item := range value {
			if field := sqliteTicketSecretField(item, secret, path+"[]"); field != "" {
				return field
			}
		}
	case map[string]any:
		for name, item := range value {
			if field := sqliteTicketSecretField(item, secret, strings.TrimPrefix(path+">"+name, ">")); field != "" {
				return field
			}
		}
	}
	return ""
}

// This deliberately test-only application authenticates a password, then chooses
// all identity fields itself. The caller's callback, subject, role and MFA claims
// are never trusted. The fixture sends neither tickets nor identities on failure.
func (f *sqliteTicketFixture) serveIssuer(w http.ResponseWriter, r *http.Request) {
	f.issuerGate.RLock()
	defer f.issuerGate.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path != "/login" || r.TLS == nil || r.Host != strings.TrimPrefix(f.issuer.URL, "https://") {
		http.Error(w, "issuer request denied", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		// Keep the form POST's Origin usable for the exact CSRF check below,
		// while stripping request identifiers from the browser's Referer header.
		w.Header().Set("Referrer-Policy", "strict-origin")
		request := r.URL.Query().Get("request")
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(request) {
			http.Error(w, "issuer request denied", http.StatusBadRequest)
			return
		}
		// GET only renders the application login; it has no issuance authority.
		_, _ = fmt.Fprintf(w, `<!doctype html><title>Trusted application</title><form method="post" action="/login"><input type="hidden" name="request" value="%s"><label>User<input name="username" autocomplete="username"></label><label>Password<input name="password" type="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>`, html.EscapeString(request))
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Origin") != f.issuer.URL {
		http.Error(w, "issuer authentication denied", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm["username"]) != 1 || len(r.PostForm["password"]) != 1 ||
		r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != sqliteTicketPassword {
		http.Error(w, "issuer authentication denied", http.StatusUnauthorized)
		return
	}
	if len(r.PostForm["request"]) != 1 {
		http.Error(w, "issuer request denied", http.StatusBadRequest)
		return
	}
	request := r.PostForm.Get("request")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	backend := f.issuers[(f.issueCalls.Add(1)-1)%2]
	ticket, err := backend.Issue(ctx, request, &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice Ticket", Roles: []string{"app/issued"}})
	if err != nil {
		if errors.Is(err, tickets.ErrCommitUncertain) {
			f.issueUncertain.Add(1)
		}
		if ticket != "" {
			f.issueErrorResult.Store(true)
		}
		http.Error(w, "issuer request denied", http.StatusUnauthorized)
		return
	}
	f.issued.Add(1)
	f.record("request_state", request)
	f.record("ticket", ticket)
	callback, err := url.Parse(backend.CallbackURL())
	if err != nil {
		http.Error(w, "issuer unavailable", http.StatusServiceUnavailable)
		return
	}
	callback.RawQuery = url.Values{"state": {request}, "ticket": {ticket}}.Encode()
	http.Redirect(w, r, callback.String(), http.StatusSeeOther)
}

func (f *sqliteTicketFixture) endpoint(path string) string {
	return f.base + strings.TrimSuffix(f.mount, "/") + path
}

func (f *sqliteTicketFixture) startTicket(t *testing.T) {
	t.Helper()
	f.start(t)
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("mounted ticket portal did not become ready")
		case <-tick.C:
			response, err := f.client.Get(f.endpoint("/login"))
			if err != nil {
				continue
			}
			response.Body.Close()
			if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("ticket fixture did not verify TLS")
			}
			if response.StatusCode == http.StatusOK {
				return
			}
		}
	}
}

func (f *sqliteTicketFixture) stopTicket(t *testing.T) {
	t.Helper()
	(&sqliteMessagingFixture{persistentCaddy: f.persistentCaddy}).stopMessaging(t)
}

// Reconciliation is explicit: drain both applications, retire every connection
// which could retain an uncertain transaction, and reopen compatible handles.
// The caller must start a fresh request when no ticket was safely published.
func (f *sqliteTicketFixture) reopenAfterUncertainIssue(t *testing.T) {
	t.Helper()
	f.stopTicket(t)
	func() {
		f.issuerGate.Lock()
		defer f.issuerGate.Unlock()
		for i, provider := range f.issuers {
			if err := provider.Close(); err != nil {
				t.Fatal("close uncertain issuer handle", err)
			}
			f.issuers[i] = nil
		}
		for i := range f.issuers {
			provider, err := tickets.New(t.Context(), &f.backendConfig)
			if err != nil {
				t.Fatal("reopen reconciled issuer handle", err)
			}
			f.issuers[i] = provider
		}
	}()
	f.startTicket(t)
}

func sqliteTicketHTTP(ctx context.Context, client *http.Client, method, target string, form url.Values, headers http.Header, host string) (oidcRPResponse, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("create ticket request")
	}
	if headers != nil {
		r.Header = headers.Clone()
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if host != "" {
		r.Host = host
	}
	response, err := client.Do(r)
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("ticket transport failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return oidcRPResponse{}, fmt.Errorf("read ticket response")
	}
	return oidcRPResponse{response.StatusCode, response.Header.Clone(), data}, nil
}

func (f *sqliteTicketFixture) request(t *testing.T, client *http.Client, method, target string, form url.Values, headers http.Header, host string) oidcRPResponse {
	t.Helper()
	response, err := sqliteTicketHTTP(t.Context(), client, method, target, form, headers, host)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func sqliteTicketStatus(t *testing.T, response oidcRPResponse, status int) {
	t.Helper()
	if response.status != status {
		t.Fatalf("ticket HTTP status: got %d, want %d", response.status, status)
	}
}

func sqliteTicketBinding(t *testing.T, cookies []*http.Cookie) string {
	t.Helper()
	var binding string
	for _, cookie := range cookies {
		if cookie.Name != sqliteTicketCookie {
			continue
		}
		if binding != "" || cookie.Value == "" {
			t.Fatal("ticket replay requires one nonempty browser binding")
		}
		binding = cookie.Value
	}
	if binding == "" {
		t.Fatal("ticket replay requires one nonempty browser binding")
	}
	return binding
}

func sqliteTicketNoCredentials(t *testing.T, response oidcRPResponse) {
	t.Helper()
	if response.header.Get("Authorization") != "" {
		t.Fatal("ticket rejection or initiation published an access credential")
	}
	for _, c := range (&http.Response{Header: response.header}).Cookies() {
		if c.Value != "" && !sqliteTicketDeletionCookie(c) && (c.Name == sqliteTicketAccess || c.Name == "TICKET_REFRESH_TOKEN" || c.Name == "TICKET_OIDC_SESSION_ID" || c.Name == "AUTHP_ACCESS_TOKEN") {
			t.Fatal("ticket rejection or initiation published a credential cookie")
		}
	}
}

// The shared portal factory uses the literal tombstone "delete", negative
// Max-Age and epoch Expires. A nonempty expired credential is still rejected.
func sqliteTicketDeletionCookie(cookie *http.Cookie) bool {
	return cookie.Value == "delete" && cookie.MaxAge == -1 && cookie.Expires.Equal(time.Unix(0, 0))
}

func sqliteTicketPrivate(t *testing.T, response oidcRPResponse) {
	t.Helper()
	if response.header.Get("Cache-Control") != "no-store" || response.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("ticket response omitted its cache or referrer boundary")
	}
}

func (f *sqliteTicketFixture) begin(t *testing.T, client *http.Client) string {
	t.Helper()
	response := f.request(t, client, http.MethodGet, f.endpoint("/provider/application"), nil, nil, "")
	sqliteTicketStatus(t, response, http.StatusFound)
	sqliteTicketPrivate(t, response)
	sqliteTicketNoCredentials(t, response)
	target, err := url.Parse(response.header.Get("Location"))
	if err != nil || target.Scheme+"://"+target.Host+target.Path != f.backendConfig.IssuerURL || len(target.Query()) != 2 || target.Query().Get("callback") != f.issuers[0].CallbackURL() {
		t.Fatal("ticket begin changed the trusted issuer or pinned callback")
	}
	f.record("request_state", target.Query().Get("request"))
	count := 0
	for _, c := range (&http.Response{Header: response.header}).Cookies() {
		if c.Name != sqliteTicketCookie {
			continue
		}
		count++
		if c.Value == "" || !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != strings.TrimSuffix(f.mount, "/")+"/provider/application" || c.SameSite != http.SameSiteLaxMode || c.MaxAge != 300 {
			t.Fatal("ticket binding cookie attributes changed")
		}
		f.record("browser_binding", c.Value)
	}
	if count != 1 {
		t.Fatal("ticket begin did not issue exactly one independent binding cookie")
	}
	return target.String()
}

func (f *sqliteTicketFixture) issuerForm(t *testing.T, target, password string) url.Values {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal("parse trusted issuer request")
	}
	return url.Values{"request": {u.Query().Get("request")}, "username": {"alice"}, "password": {password},
		"callback": {"https://attacker.example.test/callback"}, "subject": {"attacker"}, "roles": {"authp/admin"}, "amr": {"mfa"}}
}

func (f *sqliteTicketFixture) issue(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	response := f.request(t, client, http.MethodPost, f.backendConfig.IssuerURL, f.issuerForm(t, target, sqliteTicketPassword), http.Header{"Origin": {f.issuer.URL}}, "")
	sqliteTicketStatus(t, response, http.StatusSeeOther)
	sqliteTicketPrivate(t, response)
	sqliteTicketNoCredentials(t, response)
	u, err := url.Parse(response.header.Get("Location"))
	if err != nil || u.Scheme+"://"+u.Host+u.Path != f.issuers[0].CallbackURL() || len(u.Query()) != 2 || u.Query().Get("ticket") == "" || u.Query().Get("state") == "" {
		t.Fatal("trusted issuance did not use its pinned callback")
	}
	return u.String()
}

func (f *sqliteTicketFixture) deny(t *testing.T, client *http.Client, callback string, headers http.Header, host string) {
	t.Helper()
	response := f.request(t, client, http.MethodGet, callback, nil, headers, host)
	sqliteTicketStatus(t, response, http.StatusUnauthorized)
	sqliteTicketPrivate(t, response)
	sqliteTicketNoCredentials(t, response)
	if response.header.Get("Location") != "" {
		t.Fatal("denied callback redirected")
	}
}

func (f *sqliteTicketFixture) verify(t *testing.T, response oidcRPResponse) jwt.MapClaims {
	t.Helper()
	sqliteTicketStatus(t, response, http.StatusSeeOther)
	sqliteTicketPrivate(t, response)
	raw := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
	return f.verifyToken(t, raw)
}

func (f *sqliteTicketFixture) verifyToken(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	f.record("access_jwt", raw)
	parsed, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(sqliteTicketSigning), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid {
		t.Fatal("ticket portal JWT failed independent signature or temporal validation")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	identifier, _ := claims["id"].(string)
	nonce, _ := claims["nonce"].(string)
	if identifier == "" || identifier == "alice" || claims["sub"] != "alice" || claims["origin"] != "application" || claims["email"] != "alice@example.test" || claims["name"] != "Alice Ticket" || nonce == "" {
		t.Fatal("ticket JWT lost its verified identity, implicit local ID or nonce")
	}
	methods, ok := claims["amr"].([]any)
	if !ok || len(methods) != 1 || methods[0] != "federated" {
		t.Fatal("ticket asserted unverified local authentication factors")
	}
	roles, ok := claims["roles"].([]any)
	if !ok || len(roles) != 2 || !sqliteTicketHasClaim(roles, "app/issued") || !sqliteTicketHasClaim(roles, "app/verified") {
		t.Fatal("ticket roles bypassed the issuer or current portal transform")
	}
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		t.Fatal("ticket JWT omitted issuance time")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil || exp.Sub(iat.Time) <= 0 || exp.Sub(iat.Time) > 121*time.Second {
		t.Fatal("ticket JWT ignored configured lifetime")
	}
	authenticated, ok := claims["auth_time"].(float64)
	if !ok || authenticated < float64(time.Now().Add(-2*time.Minute).Unix()) || authenticated > float64(time.Now().Add(time.Second).Unix()) {
		t.Fatal("ticket JWT omitted fresh server authentication evidence")
	}
	resource := f.request(t, f.client, http.MethodGet, f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + raw}}, "")
	sqliteTicketStatus(t, resource, http.StatusOK)
	if string(resource.body) != "ticket resource" {
		t.Fatal("verified ticket did not reach the Caddy protected route")
	}
	return claims
}

func sqliteTicketHasClaim(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func (f *sqliteTicketFixture) complete(t *testing.T, client *http.Client, callback string) jwt.MapClaims {
	t.Helper()
	response := f.request(t, client, http.MethodGet, callback, nil, http.Header{"Accept": {"application/json"}}, "")
	claims := f.verify(t, response)
	bindingRemoved, access := false, false
	for _, c := range (&http.Response{Header: response.header}).Cookies() {
		switch c.Name {
		case sqliteTicketCookie:
			bindingRemoved = c.Value == "" && c.MaxAge == -1 && c.Path == strings.TrimSuffix(f.mount, "/")+"/provider/application" && c.Secure && c.HttpOnly && c.Domain == "" && c.SameSite == http.SameSiteLaxMode
		case sqliteTicketAccess:
			access = c.Value != "" && c.Secure && c.HttpOnly
		case "TICKET_REFRESH_TOKEN", "TICKET_OIDC_SESSION_ID":
			if c.Value != "" && !sqliteTicketDeletionCookie(c) {
				t.Fatal("ticket login unexpectedly created refresh or OP authority")
			}
		}
	}
	if !bindingRemoved || !access {
		t.Fatal("ticket completion did not clear exact binding scope or issue protected access cookie")
	}
	return claims
}

func testSQLiteTicketJourney(t *testing.T, binary, mount string) {
	f := newSQLiteTicketFixture(t, binary, mount)
	client := f.browser(t)
	destination := f.base + "/resource?source=ticket&x=one%26two"
	login := f.endpoint("/login") + "?redirect_url=" + url.QueryEscape(destination)
	response := f.request(t, client, http.MethodGet, login, nil, nil, "")
	sqliteTicketStatus(t, response, http.StatusOK)
	link := regexp.MustCompile(`<a href="(provider/application[^"]*)"`).FindSubmatch(response.body)
	if len(link) != 2 || string(link[1]) != "provider/application" {
		t.Fatal("ticket login icon added query parameters or omitted the selected provider")
	}
	start := f.begin(t, client)
	before := f.issueCalls.Load()
	for _, password := range []string{"", "incorrect-issuer-password"} {
		denied := f.request(t, client, http.MethodPost, f.backendConfig.IssuerURL, f.issuerForm(t, start, password), http.Header{"Origin": {f.issuer.URL}}, "")
		sqliteTicketStatus(t, denied, http.StatusUnauthorized)
		sqliteTicketNoCredentials(t, denied)
		if denied.header.Get("Location") != "" || f.issueCalls.Load() != before {
			t.Fatal("anonymous or wrong issuer credentials crossed trusted issuance")
		}
	}
	for _, headers := range []http.Header{nil, {"Origin": {"https://attacker.example.test"}}} {
		denied := f.request(t, client, http.MethodPost, f.backendConfig.IssuerURL, f.issuerForm(t, start, sqliteTicketPassword), headers, "")
		sqliteTicketStatus(t, denied, http.StatusUnauthorized)
		sqliteTicketNoCredentials(t, denied)
		if denied.header.Get("Location") != "" || f.issueCalls.Load() != before {
			t.Fatal("untrusted issuer origin crossed trusted issuance")
		}
	}
	wrongIssuerHost := f.request(t, client, http.MethodPost, f.backendConfig.IssuerURL, f.issuerForm(t, start, sqliteTicketPassword), http.Header{"Origin": {f.issuer.URL}}, "attacker.example.test")
	sqliteTicketStatus(t, wrongIssuerHost, http.StatusBadRequest)
	sqliteTicketNoCredentials(t, wrongIssuerHost)
	if f.issueCalls.Load() != before {
		t.Fatal("untrusted issuer Host crossed trusted issuance")
	}
	callback := f.issue(t, client, start)
	u, _ := url.Parse(callback)
	binding := sqliteTicketBinding(t, client.Jar.Cookies(u))
	f.deny(t, f.browser(t), callback, nil, "")
	f.deny(t, client, callback, nil, "attacker.example.test")
	// Query parsing and browser binding failures do not consume a valid ticket.
	for _, suffix := range []string{"&format=json", "&state=" + u.Query().Get("state"), "&ticket=" + u.Query().Get("ticket"), "&extra=value", "&bad=%zz", ";bad"} {
		f.deny(t, client, callback+suffix, http.Header{"Accept": {"application/json"}}, "")
	}
	for _, target := range []string{f.endpoint("/provider/application") + "?", f.endpoint("/provider/application") + "?ticket=malformed&state=malformed", strings.Replace(callback, "/provider/application?", "/provider/application/?", 1), strings.Replace(callback, "/provider/application?", "/provider/%61pplication?", 1)} {
		r := f.request(t, client, http.MethodGet, target, nil, nil, "")
		if r.status != http.StatusBadRequest && r.status != http.StatusUnauthorized {
			t.Fatalf("malformed ticket callback was accepted: HTTP %d", r.status)
		}
		sqliteTicketNoCredentials(t, r)
	}
	plaintext := f.request(t, f.client, http.MethodGet, strings.Replace(callback, "https://", "http://", 1), nil, nil, "")
	sqliteTicketStatus(t, plaintext, http.StatusBadRequest)
	sqliteTicketNoCredentials(t, plaintext)
	duplicate := http.Header{"Cookie": {sqliteTicketCookie + "=" + binding + "; " + sqliteTicketCookie + "=" + binding}}
	f.deny(t, f.client, callback, duplicate, "")
	f.deny(t, f.client, callback, http.Header{"Cookie": {sqliteTicketCookie + "=malformed"}}, "")
	method := f.request(t, client, http.MethodPost, f.endpoint("/provider/application"), nil, nil, "")
	sqliteTicketStatus(t, method, http.StatusMethodNotAllowed)
	sqliteTicketNoCredentials(t, method)
	if method.header.Get("Allow") != "GET" {
		t.Fatal("ticket callback omitted method restriction")
	}
	response = f.request(t, client, http.MethodGet, callback, nil, nil, "")
	first := f.verify(t, response)
	if response.header.Get("Location") != destination {
		t.Fatal("ticket login lost its trusted tab destination")
	}
	// Replay the original valid binding without restoring cookies whose Path
	// attributes were intentionally omitted by the browser jar's Cookies method.
	f.deny(t, f.client, callback, http.Header{"Cookie": {sqliteTicketCookie + "=" + binding}}, "")
	second := f.complete(t, client, f.issue(t, client, f.begin(t, client)))
	if first["id"] != second["id"] || first["nonce"] == second["nonce"] {
		t.Fatal("same live provider changed implicit identity or reused its nonce")
	}
	// Browser asset requests must not erase a valid application-only token just
	// because the portal's own ACL does not admit its roles. A root mount also
	// receives Chrome's automatic /favicon.ico request after application login.
	for _, asset := range []struct {
		path   string
		status int
	}{{"/favicon.ico", http.StatusNotFound}, {"/assets/images/favicon.svg", http.StatusOK}} {
		response := f.request(t, client, http.MethodGet, f.endpoint(asset.path), nil, nil, "")
		sqliteTicketStatus(t, response, asset.status)
		for _, c := range (&http.Response{Header: response.header}).Cookies() {
			if c.Name == sqliteTicketAccess {
				t.Fatal("portal asset request changed application access cookie")
			}
		}
		sqliteTicketStatus(t, f.request(t, client, http.MethodGet, f.base+"/resource", nil, nil, ""), http.StatusOK)
	}
	// Pending federation is independent of portal logout. Clearing an access
	// cookie does not claim upstream logout or revoke an already issued ticket.
	pending := f.issue(t, client, f.begin(t, client))
	logout := f.request(t, client, http.MethodGet, f.endpoint("/logout"), nil, nil, "")
	if logout.status != http.StatusFound && logout.status != http.StatusSeeOther {
		t.Fatalf("ticket portal logout returned HTTP %d", logout.status)
	}
	resource := f.request(t, client, http.MethodGet, f.base+"/resource", nil, nil, "")
	sqliteTicketStatus(t, resource, http.StatusUnauthorized)
	// Logout clears browser authority; previously signed JWTs retain ordinary
	// stateless expiry. Do not infer immediate token revocation from cookie removal.
	f.verifyToken(t, strings.TrimPrefix(response.header.Get("Authorization"), "Bearer "))
	f.complete(t, client, pending)
	runSQLiteTicketBrowser(t, f, destination)
}

func testSQLiteTicketConcurrency(t *testing.T, binary string) {
	f := newSQLiteTicketFixture(t, binary, "/tenant/auth")
	client := f.browser(t)
	start := f.begin(t, client)
	form := f.issuerForm(t, start, sqliteTicketPassword)
	type outcome struct {
		response oidcRPResponse
		err      error
	}
	results := make(chan outcome, 2)
	gate := make(chan struct{})
	for range 2 {
		go func() {
			<-gate
			response, err := sqliteTicketHTTP(t.Context(), f.client, http.MethodPost, f.backendConfig.IssuerURL, form, http.Header{"Origin": {f.issuer.URL}}, "")
			results <- outcome{response, err}
		}()
	}
	close(gate)
	var callback string
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.status == http.StatusSeeOther && callback == "" {
			callback = result.response.header.Get("Location")
		} else {
			sqliteTicketStatus(t, result.response, http.StatusUnauthorized)
			sqliteTicketNoCredentials(t, result.response)
			if result.response.header.Get("Location") != "" {
				t.Fatal("failed concurrent issuance published a redirect")
			}
		}
	}
	if f.issueCalls.Load() != 2 || f.issued.Load() > 1 || f.issueErrorResult.Load() {
		t.Fatal("concurrent issuance duplicated authority or returned a ticket on error")
	}
	if callback == "" {
		if f.issued.Load() != 0 || f.issueUncertain.Load() == 0 {
			t.Fatal("concurrent issuance produced no winner without concrete commit uncertainty")
		}
		t.Log("concurrent issuer commit uncertainty withheld all tickets; explicitly reopening before fresh login")
		f.reopenAfterUncertainIssue(t)
		client = f.browser(t)
		fresh := f.begin(t, client)
		oldURL, _ := url.Parse(start)
		freshURL, _ := url.Parse(fresh)
		if freshURL.Query().Get("request") == oldURL.Query().Get("request") {
			t.Fatal("uncertain issuance recovery reused the original request")
		}
		callback = f.issue(t, client, fresh)
	} else {
		if f.issued.Load() != 1 {
			t.Fatal("published concurrent issuance did not have exactly one committed result")
		}
		if f.issueUncertain.Load() != 0 {
			// Preserve the one safely published result, but retire any uncertain
			// competing handle before consuming it. Never repeat Issue for it.
			f.reopenAfterUncertainIssue(t)
		}
	}
	u, _ := url.Parse(callback)
	var cookie string
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == sqliteTicketCookie {
			cookie = c.Name + "=" + c.Value
		}
	}
	gate = make(chan struct{})
	for range 2 {
		go func() {
			<-gate
			response, err := sqliteTicketHTTP(t.Context(), f.client, http.MethodGet, callback, nil, http.Header{"Cookie": {cookie}}, "")
			results <- outcome{response, err}
		}()
	}
	close(gate)
	accepted := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.status == http.StatusSeeOther {
			accepted++
			f.verify(t, result.response)
		} else {
			sqliteTicketStatus(t, result.response, http.StatusUnauthorized)
			sqliteTicketNoCredentials(t, result.response)
		}
	}
	// Unlike independent issuer handles, both callbacks use the same Caddy-owned
	// provider. Its public backend owns a one-connection sql.DB, serializing the
	// transactions; no issuer transaction remains in flight during consumption.
	if accepted != 1 {
		t.Fatalf("concurrent ticket consumption succeeded %d times, want once", accepted)
	}
	f.deny(t, f.client, callback, http.Header{"Cookie": {cookie}}, "")
}

func (f *sqliteTicketFixture) reload(t *testing.T, source string, accepted bool) {
	t.Helper()
	f.write(t, source)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, f.binary, "reload", "--config", f.config, "--address", f.admin, "--force")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	f.mu.Lock()
	secrets := append([]string(nil), f.secrets...)
	f.mu.Unlock()
	assertAdminRedacted(t, output, secrets)
	if (err == nil) != accepted {
		t.Fatalf("ticket reload accepted=%t, want %t", err == nil, accepted)
	}
}

func testSQLiteTicketLifecycle(t *testing.T, binary string) {
	f := newSQLiteTicketFixture(t, binary, "/tenant/auth")
	client := f.browser(t)
	initial := f.complete(t, client, f.issue(t, client, f.begin(t, client)))
	pending := f.issue(t, client, f.begin(t, client))
	// Invalid native configuration reaches the real admin reload boundary and
	// leaves the existing runtime and its pending ticket alive.
	data, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	var native map[string]any
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	apps := native["apps"].(map[string]any)
	security := apps["security"].(map[string]any)
	providers := security["identity_providers"].([]any)
	providers[0].(map[string]any)["public_origin"] = "https://127.0.0.1:0"
	invalid, err := json.Marshal(native)
	if err != nil || os.WriteFile(f.config, invalid, 0600) != nil {
		t.Fatal("write invalid native ticket candidate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	cmd := exec.CommandContext(ctx, f.binary, "reload", "--config", f.config, "--address", f.admin)
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	cancel()
	assertAdminRedacted(t, output, []string{sqliteTicketPassword, sqliteTicketSigning})
	if err == nil {
		t.Fatal("invalid native ticket candidate replaced the active runtime")
	}
	// Native SQLite paths are normalized before construction. A symlink/.. path
	// must be checked against the database SQLite actually opens, before another
	// backend can attempt to acquire the same storage namespace.
	other := t.TempDir()
	child := filepath.Join(other, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(f.backendConfig.Path), "path-alias")
	if err := os.Symlink(child, link); err != nil {
		t.Fatal(err)
	}
	provider := providers[0].(map[string]any)
	provider["public_origin"] = f.base
	provider["path"] = link + "/../" + filepath.Base(f.backendConfig.Path)
	security["identity_stores"] = []any{map[string]any{"driver": "sqlite", "name": "accounts", "realm": "accounts", "path": f.backendConfig.Path}}
	invalid, err = json.Marshal(native)
	if err != nil || os.WriteFile(f.config, invalid, 0600) != nil {
		t.Fatal("write colliding native storage candidate")
	}
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
	cmd = exec.CommandContext(ctx, f.binary, "reload", "--config", f.config, "--address", f.admin)
	cmd.WaitDelay = 5 * time.Second
	output, err = cmd.CombinedOutput()
	cancel()
	assertAdminRedacted(t, output, []string{sqliteTicketPassword, sqliteTicketSigning})
	if err == nil || !bytes.Contains(output, []byte("distinct database and sidecar namespace")) {
		t.Fatal("native storage collision did not fail before backend acquisition")
	}
	f.write(t, f.source)
	unchanged := f.complete(t, client, pending)
	if unchanged["id"] != initial["id"] {
		t.Fatal("failed reload replaced the active implicit identity store")
	}
	pending = f.issue(t, client, f.begin(t, client))
	f.reload(t, f.source, true)
	reloaded := f.complete(t, client, pending)
	if reloaded["id"] == initial["id"] {
		t.Fatal("new compatible provider reused a retired implicit account ID")
	}
	// Both an issued ticket and an unissued request survive process replacement.
	issuedClient, requestClient := f.browser(t), f.browser(t)
	pending = f.issue(t, issuedClient, f.begin(t, issuedClient))
	request := f.begin(t, requestClient)
	f.stopTicket(t)
	f.startTicket(t)
	restarted := f.complete(t, issuedClient, pending)
	if restarted["id"] == reloaded["id"] {
		t.Fatal("process restart accidentally persisted a private implicit identity")
	}
	f.complete(t, requestClient, f.issue(t, requestClient, request))
	// The exact backend binding includes the independent cookie name. Restoring
	// compatible config restores pending work; mismatched config cannot consume it.
	pendingClient := f.browser(t)
	pending = f.issue(t, pendingClient, f.begin(t, pendingClient))
	f.reload(t, strings.Replace(f.source, "cookie_name "+sqliteTicketCookie, "cookie_name OTHER_TICKET_BINDING", 1), true)
	f.deny(t, pendingClient, pending, nil, "")
	f.reload(t, f.source, true)
	f.complete(t, pendingClient, pending)
	strict := strings.Replace(f.source, "action add role app/verified", "action add role app/verified\n    require totp", 1)
	f.reload(t, strict, true)
	strongClient := f.browser(t)
	strongCallback := f.issue(t, strongClient, f.begin(t, strongClient))
	u, _ := url.Parse(strongCallback)
	binding := sqliteTicketBinding(t, strongClient.Jar.Cookies(u))
	denied := f.request(t, strongClient, http.MethodGet, strongCallback, nil, nil, "")
	sqliteTicketStatus(t, denied, http.StatusForbidden)
	sqliteTicketNoCredentials(t, denied)
	f.reload(t, f.source, true)
	f.deny(t, f.client, strongCallback, http.Header{"Cookie": {sqliteTicketCookie + "=" + binding}}, "")
	// A live storage policy failure withholds redirects, tickets and credentials.
	outageClient := f.browser(t)
	outageCallback := f.issue(t, outageClient, f.begin(t, outageClient))
	outageRequest := f.begin(t, f.browser(t))
	if err := os.Chmod(f.backendConfig.Path, 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.backendConfig.Path, 0600) })
	f.deny(t, f.browser(t), f.endpoint("/provider/application"), nil, "")
	f.deny(t, outageClient, outageCallback, nil, "")
	failedIssue := f.request(t, f.client, http.MethodPost, f.backendConfig.IssuerURL, f.issuerForm(t, outageRequest, sqliteTicketPassword), http.Header{"Origin": {f.issuer.URL}}, "")
	sqliteTicketStatus(t, failedIssue, http.StatusUnauthorized)
	sqliteTicketNoCredentials(t, failedIssue)
	if failedIssue.header.Get("Location") != "" {
		t.Fatal("unavailable issuer published a ticket redirect")
	}
	if err := os.Chmod(f.backendConfig.Path, 0600); err != nil {
		t.Fatal(err)
	}
	f.complete(t, client, f.issue(t, client, f.begin(t, client)))
}

func runSQLiteTicketBrowser(t *testing.T, f *sqliteTicketFixture, destination string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "sqlite-ticket-browser-")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("remove private ticket browser profile", err)
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, f.cert)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private Chrome trust: %v\n%s", err, output)
	}
	var invalidTLSHits atomic.Int64
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		invalidTLSHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	defer untrusted.Close()
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	input, err := json.Marshal(map[string]string{"origin": f.base, "issuer": f.issuer.URL, "mount": f.mount, "password": sqliteTicketPassword, "destination": destination, "signing": sqliteTicketSigning})
	if err != nil {
		t.Fatal(err)
	}
	driver := exec.CommandContext(ctx, "node", "testdata/browser/sqlite_ticket_login.cjs", endpoint, untrusted.URL)
	driver.Stdin = bytes.NewReader(input)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	f.mu.Lock()
	secrets := append([]string(nil), f.secrets...)
	f.mu.Unlock()
	assertAdminRedacted(t, output, secrets)
	if err != nil {
		t.Fatalf("SQLite ticket browser journey: %v\n%s", err, output)
	}
	if string(output) != "SQLite ticket browser passed\n" {
		t.Fatal("browser did not confirm trusted ticket login")
	}
	if invalidTLSHits.Load() != 0 {
		t.Fatal("ticket browser accepted an untrusted TLS peer")
	}
}
