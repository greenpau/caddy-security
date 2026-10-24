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
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
)

// This builds the production command without cgo and uses verified Caddy TLS,
// the real registration handler, persistent SQLite and loopback SMTP sockets.
// The legacy registration provider confirms into a dropbox; activation in the
// login store remains a separate operation.
func TestCaddySQLiteMessagingE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./cmd/authcrunch")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy: %v\n%s", err, output)
	}
	t.Run("registration", func(t *testing.T) { testSQLiteMessagingRegistration(t, binary) })
	t.Run("restart_and_cleanup", func(t *testing.T) { testSQLiteMessagingLifecycle(t, binary) })
}

type sqliteMessagingFixture struct {
	*persistentCaddy
	source, path, users, dropbox string
	secrets                      []string
}

func newSQLiteMessagingFixture(t *testing.T, binary, smtpAddress string) *sqliteMessagingFixture {
	t.Helper()
	cert, key, roots := cookieTLSCertificate(t)
	private := registrationTestDirectory(t)
	f := &sqliteMessagingFixture{
		persistentCaddy: newPersistentCaddy(t, binary, cert, key, roots),
		path:            filepath.Join(private, "outbox.db"),
		users:           filepath.Join(private, "users.json"),
		dropbox:         filepath.Join(private, "registrations.json"),
		secrets:         []string{lifecyclePassword, "SyntheticRegistration42!"},
	}
	const signingKey = "synthetic-sqlite-messaging-signing-secret-0123456789"
	f.source = fmt.Sprintf(`{
 admin %s
 persist_config off
 auto_https off
 storage file_system %q
 log {
  level WARN
 }
 security {
  local identity store localdb {
   realm local
   path %q
   user alice {
    email alice@example.test
    password %q overwrite
    roles authp/user
   }
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
   delivery delivery
  }
  messaging sqlite provider isolated {
   path %q
   timeout 5s
  }
  user registration signup {
   dropbox %q
   email provider notifications
   admin email admin@example.test
   identity store localdb
  }
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify %s
  }
  authorization policy app_policy {
   crypto key verify %s
   set auth url %s/auth/login
   validate bearer header
   allow roles authp/user
  }
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /auth/* {
  authenticate with myportal
 }
 route /resource {
  authorize with app_policy
  respond "messaging resource"
 }
 respond unmatched 404
}`, f.admin, filepath.Join(private, "storage"), f.users, lifecyclePassword, smtpAddress, f.path, f.path, f.dropbox, signingKey, signingKey, f.base, f.base, cert, key)
	f.write(t, f.source)
	t.Cleanup(func() {
		f.kill(t)
		data, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
		if err == nil {
			assertAdminRedacted(t, data, f.secrets)
		} else if !os.IsNotExist(err) {
			t.Error("cannot read messaging process diagnostics")
		}
	})
	return f
}

func sqliteMessagingQueue(t *testing.T, path, name string) *messagingsqlite.Outbox {
	t.Helper()
	queue, err := messagingsqlite.New(t.Context(), &messagingsqlite.Config{Name: name, Path: path, Timeout: "5s"})
	if err != nil {
		t.Fatal("open test outbox", err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Error("close test outbox", err)
		}
	})
	return queue
}

func (f *sqliteMessagingFixture) submit(t *testing.T, username string) oidcRPResponse {
	t.Helper()
	response := persistentRequest(t, f.client, "POST", f.base+"/auth/register/local", url.Values{
		"registrant": {username}, "registrant_email": {username + "@example.test"},
		"registrant_password": {"SyntheticRegistration42!"},
	}, http.Header{"Origin": {f.base}}, http.StatusOK)
	assertAdminRedacted(t, response.body, f.secrets)
	return response
}

func (f *sqliteMessagingFixture) basic(t *testing.T, username, password string, allowed bool) {
	t.Helper()
	credential := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	f.secrets = append(f.secrets, credential)
	status := http.StatusUnauthorized
	if allowed {
		status = http.StatusSeeOther
	}
	response := persistentRequest(t, f.client, "GET", f.base+"/auth/basic/login/local", nil, http.Header{"Authorization": {"Basic " + credential}}, status)
	token := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
	if allowed {
		if token == "" {
			t.Fatal("existing account login omitted credential")
		}
		f.secrets = append(f.secrets, token)
		resource := persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}}, http.StatusOK)
		if string(resource.body) != "messaging resource" {
			t.Fatal("existing account credential did not authorize the application")
		}
	} else if token != "" {
		t.Fatal("unapproved registration issued a login credential")
	}
}

func testSQLiteMessagingRegistration(t *testing.T, binary string) {
	smtp := newSQLiteMessagingSMTP(t)
	f := newSQLiteMessagingFixture(t, binary, smtp.address())
	queue := sqliteMessagingQueue(t, f.path, "notifications")
	isolated := sqliteMessagingQueue(t, f.path, "isolated")
	if err := isolated.Send(&messaging.SendInput{Subject: "Isolated queue", Body: "private-isolated-message", Recipients: []string{"isolated@example.test"}}); err != nil {
		t.Fatal(err)
	}
	f.secrets = append(f.secrets, "private-isolated-message")
	const initialBody = "<p>caf=C3=A9 &amp; welcome</p>"
	if err := queue.Send(&messaging.SendInput{Subject: "Before Start", Body: initialBody, Recipients: []string{"prestart@example.test"}}); err != nil {
		t.Fatal(err)
	}
	validation := f.command(t, "validate", "--config", f.config)
	if output, err := validation.CombinedOutput(); err != nil {
		assertAdminRedacted(t, output, f.secrets)
		t.Fatalf("Caddy validation failed: %v", err)
	}
	// Validation provisions modules but must not claim or send queued work.
	before, err := queue.Claim(t.Context())
	if err != nil || before.Subject != "Before Start" || before.Body != initialBody {
		t.Fatal("configuration validation consumed or changed queued work")
	}
	if err := queue.Release(t.Context(), before.ID, before.Lease); err != nil {
		t.Fatal(err)
	}
	smtp.requireQuiet(t)
	f.start(t)
	initial := smtp.receive(t, "prestart@example.test")
	if initial.body != "<p>café &amp; welcome</p>" || initial.subject != "Before Start" {
		t.Fatal("worker changed quoted-printable Unicode content")
	}
	f.basic(t, "alice", lifecyclePassword, true)
	persistentRequest(t, f.client, "GET", f.base+"/auth/register/local", nil, nil, http.StatusOK)
	response := f.submit(t, "newuser")
	if !bytes.Contains(response.body, []byte(`id="registered-section"`)) {
		t.Fatal("registration did not report durable notification acceptance")
	}
	confirmation := smtp.receive(t, "newuser@example.test")
	link, code := sqliteMessagingConfirmation(t, f.base, confirmation.body)
	f.secrets = append(f.secrets, code)
	persistentRequest(t, f.client, "GET", link, nil, nil, http.StatusOK)
	wrong := persistentRequest(t, f.client, "POST", link, url.Values{"registration_code": {"WRONG123"}}, http.Header{"Origin": {f.base}}, http.StatusOK)
	if !bytes.Contains(wrong.body, []byte("Registration identifier mismatch")) {
		t.Fatal("incorrect confirmation code was not rejected")
	}
	if localIdentityRecord(t, f.dropbox, "newuser") != nil {
		t.Fatal("incorrect confirmation code persisted a registration")
	}
	persistentRequest(t, f.client, "POST", link, url.Values{"registration_code": {code}}, http.Header{"Origin": {f.base}}, http.StatusOK)
	ready := smtp.receive(t, "admin@example.test")
	if !strings.Contains(ready.body, "newuser@example.test") || !strings.Contains(ready.body, "newuser") {
		t.Fatal("administrator notification omitted registration identity")
	}
	registered := localIdentityRecord(t, f.dropbox, "newuser")
	if registered == nil || registered.GetMailClaim() != "newuser@example.test" || localIdentityRecord(t, f.users, "newuser") != nil {
		t.Fatal("confirmation did not respect the dropbox activation boundary")
	}
	f.basic(t, "newuser", "SyntheticRegistration42!", false)
	replay := persistentRequest(t, f.client, "POST", link, url.Values{"registration_code": {code}}, http.Header{"Origin": {f.base}}, http.StatusOK)
	if !bytes.Contains(replay.body, []byte("Registration identifier not found")) {
		t.Fatal("confirmation replay was not rejected")
	}

	// Exercise the public registration renderer with adversarial URL/text and
	// non-ASCII content, then deliver its queued result through the running Caddy.
	configuration := &messaging.Config{}
	if err := configuration.AddProvider("notifications", queue); err != nil {
		t.Fatal(err)
	}
	if err := configuration.Validate(); err != nil {
		t.Fatal(err)
	}
	registration := &registry.LocalUserRegistryProvider{EmailProviderName: "notifications", AdminEmails: []string{"render-admin@example.test"}}
	if err := registration.SetMessaging(configuration); err != nil {
		t.Fatal(err)
	}
	data := map[string]string{
		"template": "registration_confirmation", "session_id": "synthetic-session", "request_id": "synthetic-request", "timestamp": "now",
		"registration_id": "synthetic-registration", "registration_code": "secret-render-code", "username": "Zoë <img src=x onerror=alert(1)>",
		"email": "render@example.test", "registration_url": f.base + `/auth/register"><img src=x onerror=alert(1)>`,
		"realm_name": "local", "src_ip": "192.0.2.10", "src_conn_ip": "192.0.2.11",
	}
	f.secrets = append(f.secrets, data["registration_code"], data["username"])
	if err := registration.Notify(data); err != nil {
		t.Fatal("queue rendered confirmation", err)
	}
	rendered := smtp.receive(t, "render@example.test")
	if strings.Contains(rendered.body, "<img") || !strings.Contains(rendered.body, "Zoë &lt;img") || !strings.Contains(rendered.body, "%22") || !strings.Contains(rendered.body, "%3cimg") || !strings.Contains(rendered.body, data["registration_code"]) {
		t.Fatal("worker lost registration HTML/URL escaping or Unicode")
	}
	data["template"] = "registration_ready"
	if err := registration.Notify(data); err != nil {
		t.Fatal("queue rendered administrator notification", err)
	}
	rendered = smtp.receive(t, "render-admin@example.test")
	if strings.Contains(rendered.body, "<img") || !strings.Contains(rendered.body, "&lt;img") {
		t.Fatal("administrator notification lost HTML text escaping")
	}
	retained, err := isolated.Claim(t.Context())
	if err != nil || retained.Body != "private-isolated-message" || !slices.Equal(retained.Recipients, []string{"isolated@example.test"}) {
		t.Fatal("delivery worker consumed another named queue")
	}
	if err := isolated.Acknowledge(t.Context(), retained.ID, retained.Lease); err != nil {
		t.Fatal(err)
	}
	f.stopMessaging(t)
	smtp.requireQuiet(t)

	// Queue-only deployments still serve registration. Make rejection
	// deterministic without changing permissions underneath a delivery worker.
	f.write(t, strings.Replace(f.source, "   delivery delivery\n", "", 1))
	f.start(t)
	if err := os.Chmod(f.path, 0644); err != nil {
		t.Fatal(err)
	}
	failed := f.submit(t, "queuefailure")
	if err := os.Chmod(f.path, 0600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(failed.body, []byte("Internal registration messaging error")) || bytes.Contains(failed.body, []byte(`id="registered-section"`)) {
		t.Fatal("public registration hid durable queue rejection")
	}
	if localIdentityRecord(t, f.dropbox, "queuefailure") != nil || localIdentityRecord(t, f.users, "queuefailure") != nil {
		t.Fatal("failed notification created an account")
	}
	accepted := f.submit(t, "queueonly")
	if !bytes.Contains(accepted.body, []byte(`id="registered-section"`)) {
		t.Fatal("queue-only registration did not accept its notification")
	}
	queued, err := queue.Claim(t.Context())
	if err != nil || !slices.Equal(queued.Recipients, []string{"queueonly@example.test"}) {
		t.Fatal("queue-only notification was not available to an external worker")
	}
	if err := queue.Acknowledge(t.Context(), queued.ID, queued.Lease); err != nil {
		t.Fatal(err)
	}
	f.stopMessaging(t)
	smtp.requireQuiet(t)
}

func testSQLiteMessagingLifecycle(t *testing.T, binary string) {
	smtp := newSQLiteMessagingSMTP(t)
	f := newSQLiteMessagingFixture(t, binary, smtp.address())
	f.start(t)
	f.submit(t, "pendinguser")
	confirmation := smtp.receive(t, "pendinguser@example.test")
	link, code := sqliteMessagingConfirmation(t, f.base, confirmation.body)
	f.secrets = append(f.secrets, code)
	f.kill(t)
	queue := sqliteMessagingQueue(t, f.path, "notifications")
	const restartBody = "<p>offline caf=C3=A9 message</p>"
	if err := queue.Send(&messaging.SendInput{Subject: "Restart delivery", Body: restartBody, Recipients: []string{"restart@example.test"}}); err != nil {
		t.Fatal(err)
	}
	f.start(t)
	restored := smtp.receive(t, "restart@example.test")
	if restored.subject != "Restart delivery" || restored.body != "<p>offline café message</p>" {
		t.Fatal("restart did not preserve durable message content")
	}
	f.basic(t, "alice", lifecyclePassword, true)
	// The messaging queue is durable; legacy in-memory pending registrations
	// deliberately are not. Delivery must not be mistaken for durable signup.
	missing := persistentRequest(t, f.client, "POST", link, url.Values{"registration_code": {code}}, http.Header{"Origin": {f.base}}, http.StatusOK)
	if !bytes.Contains(missing.body, []byte("Registration identifier not found")) || localIdentityRecord(t, f.dropbox, "pendinguser") != nil {
		t.Fatal("legacy pending-registration restart contract changed")
	}

	// A rejected candidate must leave the active app and its worker usable.
	f.write(t, strings.Replace(f.source, "delivery delivery", "delivery nonexistent", 1))
	reload := f.command(t, "reload", "--config", f.config, "--address", f.admin)
	if output, err := reload.CombinedOutput(); err == nil {
		t.Fatal("replacement with missing delivery transport was accepted")
	} else {
		assertAdminRedacted(t, output, f.secrets)
	}
	f.write(t, f.source)
	if err := queue.Send(&messaging.SendInput{Subject: "After rejected reload", Body: "active-worker-survived", Recipients: []string{"active@example.test"}}); err != nil {
		t.Fatal(err)
	}
	f.secrets = append(f.secrets, "active-worker-survived")
	active := smtp.receive(t, "active@example.test")
	if active.body != "active-worker-survived" {
		t.Fatal("failed replacement disrupted active worker")
	}
	f.basic(t, "alice", lifecyclePassword, true)

	// Stop while SMTP is blocked before its greeting. A real socket must close
	// promptly; merely abandoning a delivery goroutine cannot pass this check.
	stall := smtp.stallNext(t)
	if err := queue.Send(&messaging.SendInput{Subject: "Blocked delivery", Body: "private-stalled-message", Recipients: []string{"stalled@example.test"}}); err != nil {
		t.Fatal(err)
	}
	f.secrets = append(f.secrets, "private-stalled-message")
	select {
	case <-stall.entered:
	case <-time.After(8 * time.Second):
		t.Fatal("worker did not reach stalled SMTP connection")
	}
	f.stopMessaging(t)
	select {
	case err := <-stall.closed:
		if err != nil {
			t.Fatal("SMTP connection did not close through worker cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("graceful shutdown left SMTP socket alive")
	}
	// A failed attempt retains its lease instead of immediately resending an
	// uncertain delivery. The public API deliberately does not inspect payloads
	// of leased rows; worker unit tests check acknowledgement ownership directly.
	if _, err := queue.Claim(t.Context()); !errors.Is(err, messagingsqlite.ErrEmpty) {
		t.Fatal("cancelled delivery was immediately made available for retry")
	}
	smtp.requireQuiet(t)
}

func (f *sqliteMessagingFixture) stopMessaging(t *testing.T) {
	t.Helper()
	if f.done == nil {
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stop := exec.CommandContext(ctx, f.binary, "stop", "--address", f.admin)
	stop.WaitDelay = 2 * time.Second
	if _, err := stop.CombinedOutput(); err != nil {
		f.kill(t)
		t.Fatal("Caddy graceful messaging shutdown failed", err)
	}
	select {
	case err := <-f.done:
		f.done = nil
		_ = f.log.Close()
		f.client.CloseIdleConnections()
		if err != nil {
			t.Fatal("Caddy messaging process did not exit cleanly", err)
		}
	case <-ctx.Done():
		f.kill(t)
		t.Fatal("Caddy did not drain its messaging worker within the shutdown deadline")
	}
}

func sqliteMessagingConfirmation(t *testing.T, base, body string) (string, string) {
	t.Helper()
	link := regexp.MustCompile(`href="([^"]+/ack/[^"]+)"`).FindStringSubmatch(body)
	code := regexp.MustCompile(`<code>([A-Za-z0-9]{6,8})</code>`).FindStringSubmatch(body)
	if len(link) != 2 || len(code) != 2 {
		t.Fatal("SMTP confirmation omitted usable link or code")
	}
	target := html.UnescapeString(link[1])
	if !strings.HasPrefix(target, base+"/auth/register/local/ack/") {
		t.Fatal("registration confirmation changed portal origin or realm")
	}
	return target, code[1]
}

type sqliteMessagingDelivery struct {
	sender, subject, body string
	recipients            []string
	raw                   []byte
}

type sqliteMessagingStall struct {
	entered chan struct{}
	closed  chan error
}

// The SMTP peer never uses external network services. Capture diagnostics are
// deliberately limited to protocol stages, without credentials or mail bodies.
type sqliteMessagingSMTP struct {
	listener    net.Listener
	deliveries  chan sqliteMessagingDelivery
	acceptDone  chan struct{}
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	stall       *sqliteMessagingStall
	workers     sync.WaitGroup
}

func newSQLiteMessagingSMTP(t *testing.T) *sqliteMessagingSMTP {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &sqliteMessagingSMTP{listener: listener, deliveries: make(chan sqliteMessagingDelivery, 32), acceptDone: make(chan struct{}), connections: make(map[net.Conn]struct{})}
	go func() {
		defer close(f.acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			stall := f.stall
			f.stall = nil
			f.connections[connection] = struct{}{}
			f.mu.Unlock()
			f.workers.Add(1)
			go f.serve(connection, stall)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-f.acceptDone
		f.mu.Lock()
		for connection := range f.connections {
			_ = connection.Close()
		}
		f.mu.Unlock()
		done := make(chan struct{})
		go func() { f.workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SMTP fixture did not drain")
		}
	})
	return f
}

func (f *sqliteMessagingSMTP) address() string { return f.listener.Addr().String() }

func (f *sqliteMessagingSMTP) stallNext(t *testing.T) *sqliteMessagingStall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stall != nil {
		t.Fatal("SMTP fixture already has a pending stall")
	}
	f.stall = &sqliteMessagingStall{entered: make(chan struct{}), closed: make(chan error, 1)}
	return f.stall
}

func (f *sqliteMessagingSMTP) serve(connection net.Conn, stall *sqliteMessagingStall) {
	defer f.workers.Done()
	defer func() {
		_ = connection.Close()
		f.mu.Lock()
		delete(f.connections, connection)
		f.mu.Unlock()
	}()
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	if stall != nil {
		close(stall.entered)
		_, err := io.Copy(io.Discard, connection)
		stall.closed <- err
		return
	}
	protocol := textproto.NewConn(connection)
	defer protocol.Close()
	if err := protocol.PrintfLine("220 fixture ESMTP"); err != nil {
		return
	}
	var delivery sqliteMessagingDelivery
	for {
		line, err := protocol.ReadLine()
		if err != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
			err = protocol.PrintfLine("250 fixture")
		case strings.HasPrefix(line, "MAIL FROM:"):
			delivery.sender = strings.Trim(strings.TrimPrefix(line, "MAIL FROM:"), "<>")
			err = protocol.PrintfLine("250 sender accepted")
		case strings.HasPrefix(line, "RCPT TO:"):
			delivery.recipients = append(delivery.recipients, strings.Trim(strings.TrimPrefix(line, "RCPT TO:"), "<>"))
			err = protocol.PrintfLine("250 recipient accepted")
		case line == "DATA":
			if err = protocol.PrintfLine("354 send message"); err != nil {
				return
			}
			delivery.raw, err = protocol.ReadDotBytes()
			if err == nil {
				err = protocol.PrintfLine("250 accepted")
			}
		case line == "QUIT":
			if protocol.PrintfLine("221 bye") == nil && len(delivery.raw) != 0 {
				f.deliveries <- delivery
			}
			return
		default:
			err = protocol.PrintfLine("500 unexpected command")
		}
		if err != nil {
			return
		}
	}
}

func (f *sqliteMessagingSMTP) receive(t *testing.T, recipients ...string) sqliteMessagingDelivery {
	t.Helper()
	var delivery sqliteMessagingDelivery
	select {
	case delivery = <-f.deliveries:
	case <-time.After(8 * time.Second):
		t.Fatal("SMTP delivery did not arrive before the deadline")
	}
	if delivery.sender != "registration@example.test" || !slices.Equal(delivery.recipients, recipients) {
		t.Fatal("SMTP envelope crossed sender or recipient boundaries")
	}
	message, err := mail.ReadMessage(bytes.NewReader(delivery.raw))
	if err != nil {
		t.Fatal("SMTP delivery has malformed MIME")
	}
	contentType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || contentType != "text/html" || params["charset"] != "utf-8" || message.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Fatal("SMTP delivery changed the quoted-printable HTML contract")
	}
	to, err := message.Header.AddressList("To")
	if err != nil || len(to) != len(recipients) || message.Header.Get("Bcc") != "" {
		t.Fatal("SMTP headers crossed recipient boundaries")
	}
	for i, address := range to {
		if address.Address != recipients[i] {
			t.Fatal("SMTP header and envelope recipients disagree")
		}
	}
	decoded, err := io.ReadAll(io.LimitReader(quotedprintable.NewReader(message.Body), 128<<10))
	if err != nil {
		t.Fatal("SMTP delivery has invalid quoted-printable content")
	}
	// SMTP requires a final line terminator even when SendInput.Body omitted it.
	delivery.body, delivery.subject = strings.TrimSuffix(string(decoded), "\n"), message.Header.Get("Subject")
	if delivery.subject == "" {
		t.Fatal("SMTP delivery omitted its subject")
	}
	return delivery
}

func (f *sqliteMessagingSMTP) requireQuiet(t *testing.T) {
	t.Helper()
	select {
	case <-f.deliveries:
		t.Fatal("unexpected SMTP delivery crossed a queue or notification boundary")
	default:
	}
}
