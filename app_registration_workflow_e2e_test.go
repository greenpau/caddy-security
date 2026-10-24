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
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	notifications "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	enrollment "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	xhtml "golang.org/x/net/html"
)

const (
	sqliteRegistrationPassword = "Synthetic-registration-password-2026!"
	sqliteRegistrationSigning  = "synthetic-registration-signing-secret-0123456789"
)

// All portal requests go through the production Caddy executable. Public backend
// handles provide independent inspection and management; they never create the
// enrolled accounts or complete the HTTP confirmation on Caddy's behalf.
func TestCaddySQLiteRegistrationE2E(t *testing.T) {
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
		t.Run(name, func(t *testing.T) { testSQLiteRegistrationJourney(t, binary, mount) })
	}
	for _, mode := range []string{"pending", "disabled", "deleted", "account"} {
		t.Run("uncertainty_"+mode, func(t *testing.T) { testSQLiteRegistrationUncertainty(t, binary, mode) })
	}
	t.Run("storage_and_replacement", func(t *testing.T) { testSQLiteRegistrationStorage(t, binary) })
}

type sqliteRegistrationFixture struct {
	*persistentCaddy
	smtp                                          *sqliteMessagingSMTP
	source, mount, accountPath, pendingPath, mail string
	delivered                                     bool
	secrets                                       []string
}

func newSQLiteRegistrationFixture(t *testing.T, binary, mount string, delivered bool) *sqliteRegistrationFixture {
	t.Helper()
	smtp := newSQLiteMessagingSMTP(t)
	cert, key, roots := cookieTLSCertificate(t)
	private := registrationTestDirectory(t)
	f := &sqliteRegistrationFixture{
		persistentCaddy: newPersistentCaddy(t, binary, cert, key, roots), smtp: smtp,
		mount: mount, delivered: delivered, secrets: []string{sqliteRegistrationPassword, sqliteRegistrationSigning},
		accountPath: filepath.Join(private, "accounts.db"), pendingPath: filepath.Join(private, "pending.db"), mail: filepath.Join(private, "mail.db"),
	}
	// Identity modules deliberately open existing files only. Trusted fixture
	// setup creates the empty database; all accounts still require HTTP signup.
	initial := f.openAccounts(t)
	if err := initial.Close(); err != nil {
		t.Fatal("close newly provisioned empty identity database", err)
	}
	f.client.Timeout = 12 * time.Second
	host := strings.TrimPrefix(f.base, "https://")
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		t.Fatal(err)
	}
	delivery := ""
	if delivered {
		delivery = "delivery delivery"
	}
	// A loopback-only listener without a Host matcher lets hostile Host requests
	// reach the workflow. A hostname routing rejection would not test link trust.
	f.source = fmt.Sprintf(`{
 admin %s
 persist_config off
 auto_https off
 storage file_system %q
 log {
  level WARN
 }
 security {
  identity store sqlite accounts {
   realm staff
   path %q
   timeout 5s
  }
  messaging email provider delivery {
   address %s
   protocol smtp
   passwordless
   sender registration@example.test "Synthetic Portal"
  }
  messaging sqlite provider notifications {
   path %q
   timeout 5s
   %s
  }
  user registration sqlite signup {
   path %q
   identity_store accounts
   realm staff
   email_provider notifications
   public_origin %s
   base_path %s
   timeout 1s
  }
  authentication portal myportal {
   enable identity store accounts
   enable user registration signup
   crypto key sign-verify %s
   trust login redirect uri domain exact %s path prefix /resource
   token refresh {
    realms staff
    public origin %s
    base path %s
    body transport enabled
   }
  }
  authorization policy app_policy {
   crypto key verify %s
   validate bearer header
   allow roles authp/user
   disable auth redirect
  }
 }
}
https://:%s {
 bind 127.0.0.1
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /resource* {
  authorize with app_policy
  respond "registration resource"
 }
 route %s/* {
  authenticate with myportal
 }
 respond unmatched 404
}`, f.admin, filepath.Join(private, "storage"), f.accountPath, smtp.address(), f.mail, delivery, f.pendingPath, f.base, mount,
		sqliteRegistrationSigning, host, f.base, mount, sqliteRegistrationSigning, port, cert, key, strings.TrimSuffix(mount, "/"))
	f.write(t, f.source)
	t.Cleanup(func() {
		f.kill(t)
		data, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
		if err == nil {
			assertAdminRedacted(t, data, f.secrets)
		} else if !os.IsNotExist(err) {
			t.Error("cannot read registration process diagnostics")
		}
	})
	f.startRegistration(t)
	return f
}

func (f *sqliteRegistrationFixture) endpoint(path string) string {
	return f.base + strings.TrimSuffix(f.mount, "/") + path
}

func (f *sqliteRegistrationFixture) startRegistration(t *testing.T) {
	t.Helper()
	f.start(t)
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatal("mounted registration portal did not become ready")
		case <-tick.C:
			response, err := f.client.Get(f.endpoint("/login"))
			if err != nil {
				continue
			}
			response.Body.Close()
			if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
				t.Fatal("registration fixture did not verify TLS")
			}
			if response.StatusCode == http.StatusOK {
				return
			}
		}
	}
}

func (f *sqliteRegistrationFixture) stopRegistration(t *testing.T) {
	t.Helper()
	// Reuse the production command's bounded graceful shutdown, which waits for
	// request draining, messaging workers and backend cleanup before process exit.
	shutdown := &sqliteMessagingFixture{persistentCaddy: f.persistentCaddy}
	shutdown.stopMessaging(t)
}

func (f *sqliteRegistrationFixture) restartRegistration(t *testing.T) {
	t.Helper()
	f.stopRegistration(t)
	f.startRegistration(t)
}

func (f *sqliteRegistrationFixture) request(t *testing.T, method, target string, form url.Values, hostile bool, headers http.Header) oidcRPResponse {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal("create registration HTTP request")
	}
	if headers != nil {
		request.Header = headers.Clone()
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", f.base)
	}
	if hostile {
		request.Host = "attacker.example.test"
		request.Header.Set("Forwarded", "for=192.0.2.7;host=attacker.example.test;proto=http")
		request.Header.Set("X-Forwarded-Host", "attacker.example.test")
		request.Header.Set("X-Forwarded-Proto", "http")
	}
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal("registration HTTP exchange failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal("read registration HTTP response")
	}
	return oidcRPResponse{status: response.StatusCode, header: response.Header.Clone(), body: data}
}

func (f *sqliteRegistrationFixture) submit(t *testing.T, username, password, destination string, hostile bool) oidcRPResponse {
	t.Helper()
	target := f.endpoint("/register/staff")
	if destination != "" {
		target += "?redirect_url=" + url.QueryEscape(destination)
	}
	response := f.request(t, "POST", target, url.Values{
		"registrant": {username}, "registrant_email": {username + "@example.test"}, "registrant_password": {password},
	}, hostile, nil)
	response.requireStatus(t, http.StatusOK)
	sqliteRegistrationNoCredentials(t, response)
	assertAdminRedacted(t, response.body, []string{password})
	return response
}

type sqliteRegistrationEvidence struct{ username, link, code, id string }

func (f *sqliteRegistrationFixture) enroll(t *testing.T, username, destination string, hostile bool) sqliteRegistrationEvidence {
	t.Helper()
	response := f.submit(t, username, sqliteRegistrationPassword, destination, hostile)
	if !bytes.Contains(response.body, []byte(`id="registered-section"`)) {
		t.Fatal("registration did not accept its pending enrollment")
	}
	var body string
	if f.delivered {
		body = f.smtp.receive(t, username+"@example.test").body
	} else {
		outbox := sqliteMessagingQueue(t, f.mail, "notifications")
		message, err := outbox.Claim(t.Context())
		if err != nil || !slices.Equal(message.Recipients, []string{username + "@example.test"}) {
			t.Fatal("queue-only registration lost its notification recipient")
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(message.Body)))
		if err != nil {
			t.Fatal("registration notification has invalid quoted-printable body")
		}
		body = string(decoded)
		if err := outbox.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
			t.Fatal("acknowledge test-consumed registration notification")
		}
	}
	if strings.Contains(body, "attacker.example.test") || strings.Contains(body, sqliteRegistrationPassword) {
		t.Fatal("confirmation notification used hostile metadata or exposed a password")
	}
	links := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(body)
	codes := regexp.MustCompile(`<code>([A-Za-z0-9]{6,8})</code>`).FindStringSubmatch(body)
	if len(links) != 2 || len(codes) != 2 {
		t.Fatal("registration notification lacks confirmation evidence")
	}
	link := html.UnescapeString(links[1])
	prefix := f.endpoint("/register/staff/ack/")
	if !strings.HasPrefix(link, prefix) {
		t.Fatal("confirmation link changed the canonical HTTPS origin or mount")
	}
	id := strings.TrimPrefix(link, prefix)
	if !regexp.MustCompile(`^[A-Za-z0-9]{64,96}$`).MatchString(id) {
		t.Fatal("confirmation identifier has an invalid public shape")
	}
	f.secrets = append(f.secrets, codes[1])
	return sqliteRegistrationEvidence{username: username, link: link, code: codes[1], id: id}
}

func sqliteRegistrationNoCredentials(t *testing.T, response oidcRPResponse) {
	t.Helper()
	if response.header.Get("Authorization") != "" {
		t.Fatal("registration issued an HTTP authentication credential")
	}
	parsed := &http.Response{Header: response.header}
	for _, cookie := range parsed.Cookies() {
		if slices.Contains([]string{"AUTHP_ACCESS_TOKEN", "AUTHP_REFRESH_TOKEN", "AUTHP_OIDC_SESSION_ID"}, cookie.Name) && cookie.Value != "" {
			t.Fatal("registration issued a session credential before login")
		}
	}
}

func (f *sqliteRegistrationFixture) deny(t *testing.T, target string, form url.Values) {
	t.Helper()
	response := f.request(t, "POST", target, form, false, nil)
	response.requireStatus(t, http.StatusOK)
	if response.header.Get("Location") != "" || !bytes.Contains(response.body, []byte("Registration confirmation denied")) {
		t.Fatal("invalid or uncertain confirmation did not withhold success")
	}
	sqliteRegistrationNoCredentials(t, response)
	assertAdminRedacted(t, response.body, f.secrets)
}

func (f *sqliteRegistrationFixture) confirm(t *testing.T, evidence sqliteRegistrationEvidence, destination string) string {
	t.Helper()
	// A different, still trusted destination and a shared cookie cannot override
	// navigation captured in the immutable pending registration.
	target := evidence.link + "?redirect_url=" + url.QueryEscape(f.base+"/resource/replaced")
	response := f.request(t, "POST", target, url.Values{"registration_code": {evidence.code}}, false,
		http.Header{"Cookie": {"AUTHP_REDIRECT_URL=" + url.QueryEscape(f.base+"/resource/cookie")}})
	response.requireStatus(t, http.StatusSeeOther)
	want := f.endpoint("/login") + "?redirect_url=" + url.QueryEscape(destination)
	if response.header.Get("Location") != want {
		t.Fatal("confirmation did not retain its original login destination")
	}
	sqliteRegistrationNoCredentials(t, response)
	return want
}

func (f *sqliteRegistrationFixture) openAccounts(t *testing.T) *accounts.Store {
	t.Helper()
	store, err := accounts.New(t.Context(), &accounts.Config{Name: "accounts", Realm: "staff", Path: f.accountPath, Timeout: "5s"})
	if err != nil {
		t.Fatal("open independent account inspection handle", err)
	}
	return store
}

func (f *sqliteRegistrationFixture) account(t *testing.T, username string) map[string]any {
	t.Helper()
	store := f.openAccounts(t)
	defer store.Close()
	data, err := store.FetchUserData(username, username+"@example.test")
	if errors.Is(err, accounts.ErrDenied) {
		return nil
	}
	if err != nil {
		t.Fatal("independent account inspection failed", err)
	}
	return data
}

func (f *sqliteRegistrationFixture) verifyAccount(t *testing.T, username string) string {
	t.Helper()
	data := f.account(t, username)
	if data == nil || data["username"] != username || data["email"] != username+"@example.test" || data["disabled"] != false {
		t.Fatal("confirmation did not create the expected enabled account")
	}
	roles, ok := data["roles"].([]string)
	id, validID := data["id"].(string)
	if !ok || !slices.Equal(roles, []string{"authp/user"}) || !validID || id == "" {
		t.Fatal("enrollment changed its fixed role or identity contract")
	}
	return id
}

func (f *sqliteRegistrationFixture) pendingMetadata(t *testing.T, evidence sqliteRegistrationEvidence, destination string) {
	t.Helper()
	store := f.openAccounts(t)
	defer store.Close()
	mail, err := notifications.New(t.Context(), &notifications.Config{Name: "notifications", Path: f.mail, Timeout: "5s"})
	if err != nil {
		t.Fatal("open independent notification inspection handle", err)
	}
	defer mail.Close()
	workflow, err := enrollment.New(t.Context(), &enrollment.Config{
		Name: "signup", Path: f.pendingPath, Timeout: "5s", IdentityStore: "accounts", Realm: "staff",
		EmailProvider: "notifications", PublicOrigin: f.base, BasePath: f.mount,
	}, store, mail)
	if err != nil {
		t.Fatal("open independent pending inspection handle", err)
	}
	defer workflow.Close()
	metadata, err := workflow.GetRegistrationEntry(evidence.id)
	if err != nil || len(metadata) != 4 || metadata["username"] != evidence.username || metadata["email"] != evidence.username+"@example.test" || metadata["realm_name"] != "staff" || metadata["return_url"] != destination {
		t.Fatal("pending public metadata lost identity/navigation or exposed extra fields")
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal("encode public pending metadata")
	}
	assertAdminRedacted(t, encoded, f.secrets)
}

func (f *sqliteRegistrationFixture) basic(t *testing.T, username string, allowed bool) string {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + sqliteRegistrationPassword))
	f.secrets = append(f.secrets, encoded)
	response := f.request(t, "GET", f.endpoint("/basic/login/staff"), nil, false, http.Header{"Authorization": {"Basic " + encoded}})
	if !allowed {
		response.requireStatus(t, http.StatusUnauthorized)
		sqliteRegistrationNoCredentials(t, response)
		return ""
	}
	response.requireStatus(t, http.StatusSeeOther)
	token := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
	f.verifyToken(t, token, username)
	return token
}

func (f *sqliteRegistrationFixture) verifyToken(t *testing.T, raw, username string) {
	t.Helper()
	f.secrets = append(f.secrets, raw)
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte(sqliteRegistrationSigning), nil }, jwt.WithValidMethods([]string{"HS512"}), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		t.Fatal("registration login produced an invalid signed credential")
	}
	claims := token.Claims.(jwt.MapClaims)
	roles, rolesOK := claims["roles"].([]any)
	amr, amrOK := claims["amr"].([]any)
	if claims["sub"] != username || claims["origin"] != "staff" || !rolesOK || len(roles) != 1 || roles[0] != "authp/user" || !amrOK || len(amr) != 1 || amr[0] != "pwd" {
		t.Fatal("registration login changed account identity, fixed roles or password evidence")
	}
	response := f.request(t, "GET", f.base+"/resource", nil, false, http.Header{"Authorization": {"Bearer " + raw}})
	response.requireStatus(t, http.StatusOK)
	if string(response.body) != "registration resource" {
		t.Fatal("confirmed identity did not authorize the protected resource")
	}
}

func testSQLiteRegistrationJourney(t *testing.T, binary, mount string) {
	f := newSQLiteRegistrationFixture(t, binary, mount, true)
	login := f.request(t, "GET", f.endpoint("/login"), nil, false, nil)
	login.requireStatus(t, http.StatusOK)
	signup := sqliteRegistrationSignupLink(t, login.body)
	base, _ := url.Parse(f.base)
	link, err := url.Parse(signup)
	if err != nil {
		t.Fatal("rendered signup link is malformed")
	}
	target := base.ResolveReference(link)
	want, _ := url.Parse(f.endpoint("/register/staff"))
	// The shared UI renderer deliberately carries an explicit empty destination
	// so another tab's redirect cookie cannot take over the signup navigation.
	if target.Scheme != want.Scheme || target.Host != want.Host || target.User != nil || target.Path != want.Path || target.RawPath != "" || target.Fragment != "" || target.RawQuery != "redirect_url=" {
		path := target.EscapedPath()
		if len(path) > 160 {
			path = path[:160]
		}
		t.Fatalf("rendered signup link changed its origin, mount or navigation contract: path=%q, same_origin=%t, query_keys=%d, empty_destination=%t", path,
			target.Scheme == want.Scheme && target.Host == want.Host, len(target.Query()), target.Query().Has("redirect_url") && target.Query().Get("redirect_url") == "")
	}
	f.request(t, "GET", target.String(), nil, false, nil).requireStatus(t, http.StatusOK)
	destination := f.base + "/resource?source=signup&x=one%26two"
	evidence := f.enroll(t, "alice", destination, true)
	f.pendingMetadata(t, evidence, destination)
	if f.account(t, evidence.username) != nil {
		t.Fatal("signup activated an account before confirmation")
	}
	f.basic(t, evidence.username, false)
	for _, candidate := range []struct {
		target string
		form   url.Values
	}{
		{evidence.link, url.Values{"registration_code": {"incorrect"}}},
		{evidence.link, url.Values{"registration_code": {evidence.code, evidence.code}}},
		{evidence.link + "?registration_code=" + evidence.code, url.Values{"unused": {"value"}}},
		{evidence.link + "?registration_code=" + evidence.code, url.Values{"registration_code": {evidence.code}}},
		{f.endpoint("/register/staff/ack/") + strings.Repeat("z", 64), url.Values{"registration_code": {evidence.code}}},
	} {
		f.deny(t, candidate.target, candidate.form)
	}
	if f.account(t, evidence.username) != nil {
		t.Fatal("malformed confirmation created an account")
	}
	f.restartRegistration(t)
	f.pendingMetadata(t, evidence, destination)
	f.request(t, "GET", evidence.link, nil, false, nil).requireStatus(t, http.StatusOK)
	loginURL := f.confirm(t, evidence, destination)
	f.verifyAccount(t, evidence.username)
	f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
	f.basic(t, evidence.username, true)
	native, err := authclient.NewClient(&authclient.Config{
		BaseURL: strings.TrimSuffix(f.endpoint(""), "/"), Realm: "staff", Username: "ALICE@EXAMPLE.TEST", Password: sqliteRegistrationPassword, RefreshTransport: authclient.RefreshTransportBody,
	}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal("configure confirmed-account native login")
	}
	credentials, err := native.Authenticate(t.Context())
	if err != nil {
		t.Fatal("confirmed account could not complete native login")
	}
	f.secrets = append(f.secrets, credentials.RefreshToken)
	f.verifyToken(t, credentials.AccessToken, evidence.username)
	if mount != "/" {
		runSQLiteRegistrationBrowser(t, f, evidence.username, loginURL, destination)
	}

	locked := f.enroll(t, "locked", "", false)
	for range 5 {
		f.deny(t, locked.link, url.Values{"registration_code": {"incorrect"}})
	}
	f.restartRegistration(t)
	f.deny(t, locked.link, url.Values{"registration_code": {locked.code}})
	if f.account(t, locked.username) != nil {
		t.Fatal("restart reset the durable confirmation attempt budget")
	}
	untrusted := f.enroll(t, "untrusted", "https://attacker.example.test/stolen", false)
	f.confirm(t, untrusted, "")
	for _, imported := range []string{"bcrypt:malformed", "argon2:malformed"} {
		response := f.submit(t, "imported", imported, "", false)
		if bytes.Contains(response.body, []byte(`id="registered-section"`)) {
			t.Fatal("public signup accepted an imported password hash")
		}
	}
	f.stopRegistration(t)
	f.smtp.requireQuiet(t) // No legacy admin approval message or denied-code mail.
}

func sqliteRegistrationSignupLink(t *testing.T, page []byte) string {
	t.Helper()
	document, err := xhtml.Parse(bytes.NewReader(page))
	if err != nil {
		t.Fatal("parse rendered registration navigation")
	}
	var target *xhtml.Node
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		for _, attribute := range node.Attr {
			if attribute.Key == "id" && attribute.Val == "user_register_link" {
				target = node
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(document)
	if target == nil {
		t.Fatal("portal did not expose signup navigation")
	}
	for node := target; node != nil; node = node.Parent {
		for _, attribute := range node.Attr {
			if attribute.Key == "hidden" || attribute.Key == "class" && slices.Contains(strings.Fields(attribute.Val), "hidden") {
				t.Fatal("portal hid signup despite its selected registration workflow")
			}
		}
	}
	var href string
	walk = func(node *xhtml.Node) {
		if node.Type == xhtml.ElementNode && node.Data == "a" {
			for _, attribute := range node.Attr {
				if attribute.Key == "href" {
					href = attribute.Val
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(target)
	if href == "" {
		t.Fatal("visible signup navigation omitted its destination")
	}
	return href
}

// A public SQLite read transaction holds a shared lock through the attempted
// COMMIT. No internal package, application table definition or mutation hook is
// needed; sqlite_schema is SQLite's public catalog. Cleanup always releases it.
func sqliteRegistrationReadLock(t *testing.T, path string) func() {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("open competing SQLite reader")
	}
	database.SetMaxOpenConns(1)
	transaction, err := database.BeginTx(t.Context(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		database.Close()
		t.Fatal("begin competing SQLite read")
	}
	var objects int
	if err := transaction.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema").Scan(&objects); err != nil || objects == 0 {
		transaction.Rollback()
		database.Close()
		t.Fatal("competing reader did not observe the SQLite database")
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				t.Error("release competing SQLite transaction")
			}
			if err := database.Close(); err != nil {
				t.Error("close competing SQLite reader")
			}
		})
	}
	t.Cleanup(release)
	return release
}

func testSQLiteRegistrationUncertainty(t *testing.T, binary, mode string) {
	f := newSQLiteRegistrationFixture(t, binary, "/tenant/auth", true)
	evidence := f.enroll(t, "recover", f.base+"/resource?reconciled=1", false)
	path := f.pendingPath
	if mode == "account" {
		path = f.accountPath
	}
	release := sqliteRegistrationReadLock(t, path)
	f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
	release()
	f.stopRegistration(t)
	before := f.account(t, evidence.username)
	if mode != "account" && before == nil {
		t.Fatal("pending commit failure did not occur after account creation")
	}
	if mode == "disabled" || mode == "deleted" {
		store := f.openAccounts(t)
		var err error
		if mode == "deleted" {
			err = store.DeleteUser(evidence.username, evidence.username+"@example.test")
		} else {
			err = store.DisableUser(evidence.username, evidence.username+"@example.test")
			if err == nil {
				_, err = store.OverwriteUserRoles(evidence.username, evidence.username+"@example.test", []string{"managed/limited"})
			}
		}
		store.Close()
		if err != nil {
			t.Fatal("manage committed enrollment before reconciliation", err)
		}
	}
	f.startRegistration(t)
	if mode == "deleted" {
		f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
		if f.account(t, evidence.username) != nil {
			t.Fatal("uncertain confirmation resurrected a deleted account")
		}
		f.basic(t, evidence.username, false)
	} else {
		f.confirm(t, evidence, f.base+"/resource?reconciled=1")
		after := f.account(t, evidence.username)
		if after == nil || before != nil && before["id"] != after["id"] {
			t.Fatal("reconciliation replaced the committed account identity")
		}
		if mode == "disabled" {
			roles, ok := after["roles"].([]string)
			if after["disabled"] != true || !ok || !slices.Equal(roles, []string{"managed/limited"}) {
				t.Fatal("reconciliation overwrote later account management")
			}
			f.basic(t, evidence.username, false)
		} else {
			f.verifyAccount(t, evidence.username)
			f.basic(t, evidence.username, true)
		}
		f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
	}
	f.stopRegistration(t)
	f.smtp.requireQuiet(t)
}

func testSQLiteRegistrationStorage(t *testing.T, binary string) {
	f := newSQLiteRegistrationFixture(t, binary, "/tenant/auth", false)
	// No delivery worker competes with this deterministic private-file failure.
	if err := os.Chmod(f.mail, 0644); err != nil {
		t.Fatal(err)
	}
	failed := f.submit(t, "queuefail", sqliteRegistrationPassword, "", false)
	if err := os.Chmod(f.mail, 0600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(failed.body, []byte("Internal registration messaging error")) || f.account(t, "queuefail") != nil {
		t.Fatal("queue rejection did not fail signup before account creation")
	}
	evidence := f.enroll(t, "survivor", "", false)
	if err := os.Chmod(f.accountPath, 0644); err != nil {
		t.Fatal(err)
	}
	f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
	if err := os.Chmod(f.accountPath, 0600); err != nil {
		t.Fatal(err)
	}
	if f.account(t, evidence.username) != nil {
		t.Fatal("unavailable identity storage published an account")
	}

	// A rejected replacement must preserve pending evidence and the serving app.
	f.write(t, strings.Replace(f.source, "email_provider notifications", "email_provider missing", 1))
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reload := exec.CommandContext(ctx, f.binary, "reload", "--config", f.config, "--address", f.admin)
	reload.WaitDelay = 2 * time.Second
	output, err := reload.CombinedOutput()
	assertAdminRedacted(t, output, f.secrets)
	if err == nil {
		t.Fatal("candidate with missing registration outbox was accepted")
	}
	f.write(t, f.source)
	f.confirm(t, evidence, "")
	f.verifyAccount(t, evidence.username)
	f.basic(t, evidence.username, true)
	f.restartRegistration(t)
	f.basic(t, evidence.username, true)
	f.deny(t, evidence.link, url.Values{"registration_code": {evidence.code}})
	f.stopRegistration(t)
	f.smtp.requireQuiet(t)
}

// Chrome uses the same actual Caddy listener; only its private profile receives
// the fixture CA. Credentials enter rendered forms through the driver stdin.
func runSQLiteRegistrationBrowser(t *testing.T, f *sqliteRegistrationFixture, username, loginURL, destination string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "sqlite-registration-browser-")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("remove private registration browser profile")
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, f.ca)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private Chrome trust: %v\n%s", err, output)
	}
	var untrustedHits atomic.Int64
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		untrustedHits.Add(1)
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
	input, err := json.Marshal(map[string]string{"username": username, "password": sqliteRegistrationPassword, "mount": f.mount, "loginURL": loginURL, "destination": destination})
	if err != nil {
		t.Fatal("encode private registration browser input")
	}
	driver := exec.CommandContext(ctx, "node", "testdata/browser/sqlite_registration_login.cjs", endpoint, f.base, untrusted.URL)
	driver.Stdin = bytes.NewReader(input)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	assertAdminRedacted(t, output, f.secrets)
	if err != nil {
		t.Fatalf("confirmed-registration browser login: %v\n%s", err, output)
	}
	if string(output) != "SQLite registration browser passed\n" || untrustedHits.Load() != 0 {
		t.Fatal("registration browser did not qualify login and verified TLS")
	}
}
