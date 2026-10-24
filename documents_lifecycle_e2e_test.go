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
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

// A real interim 100 response proves the request passed initial authority checks
// and reached the bounded body read. Mutation completes before releasing bytes.
func (f *caddyDocumentsFixture) delayed(t *testing.T, token, operation string, params map[string]string, payload any, during func(), want int) {
	t.Helper()
	op, suffix, body := caddyDocumentsRequest(t, operation, params, payload)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS12}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, ExpectContinueTimeout: 12 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(ctx, op.method, f.issuer+"/api/documents"+suffix, reader)
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		t.Fatal("cannot construct delayed Documents request")
	}
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Expect", "100-continue")
	reading := make(chan struct{})
	var once sync.Once
	request = request.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{Got100Continue: func() { once.Do(func() { close(reading) }) }}))
	var response *http.Response
	var requestErr error
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		response, requestErr = client.Do(request)
	}()
	defer func() {
		cancel()
		writer.Close()
		reader.Close()
		<-finished
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
	}()
	select {
	case <-reading:
	case <-finished:
		t.Fatal("delayed Documents request ended before body-read barrier")
	case <-ctx.Done():
		t.Fatal("delayed Documents request did not reach body-read barrier")
	}
	during()
	if _, err := writer.Write(body); err != nil {
		t.Fatal("cannot release delayed Documents body")
	}
	writer.Close()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("delayed Documents request did not finish")
	}
	if requestErr != nil || response == nil || response.ProtoMajor != 1 {
		t.Fatal("delayed Documents request failed its HTTP/1 transport")
	}
	r := caddyDocumentsRead(t, response, op.method, want)
	f.contracts.AssertResponse(t, op.method, op.path, r.status, r.header, r.body)
}

func testCaddyDocumentsSlowBody(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, mode := range []string{"credential_reset", "same_browser_account_switch"} {
		t.Run(mode, func(t *testing.T) {
			f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth"}, cert, key, roots)
			admin := f.login(t, "admin")
			token := f.login(t, "alice")
			registration := f.enroll(t, token, "alice")
			file := f.pending(t, token, registration)
			password := lifecyclePassword
			params := map[string]string{"id": file.ID, "idx": "0"}
			f.delayed(t, token, "chunk.put", params, map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))}, func() {
				if mode == "credential_reset" {
					result := f.admin(t, admin, "reset_password", nil)
					password, _ = result["password"].(string)
					if password == "" || password == lifecyclePassword {
						t.Fatal("competing reset did not return a fresh credential")
					}
					f.secrets = append(f.secrets, password)
				} else {
					current := f.loginSameBrowser(t, "bob", localIdentityBobPassword, true)
					f.bootstrap(t, current, "bob")
				}
			}, 401)
			f.doc(t, token, "bootstrap", nil, nil, 401)
			f.newBrowser(t)
			fresh := f.loginSameBrowser(t, "alice", password, false)
			ciphertext := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
			f.doc(t, fresh, "chunk.put", params, map[string]string{"ciphertext": ciphertext}, 200)
			f.doc(t, fresh, "file.commit", caddyDocumentsParams(file.ID), nil, 200)
			chunk := caddyDocumentsDecode[map[string]string](t, f.doc(t, fresh, "chunk.fetch", params, nil, 200))
			if chunk["ciphertext"] != ciphertext {
				t.Fatal("denied delayed upload stored an immutable chunk")
			}
		})
	}
	t.Run("recipient_key_reset", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth"}, cert, key, roots)
		aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
		alice, bob := f.enroll(t, aliceToken, "alice"), f.enroll(t, bobToken, "bob")
		file := f.ready(t, aliceToken, alice)
		params := map[string]string{"id": file.ID, "user_id": bob.UserID}
		var replacement documents.Key
		f.delayed(t, aliceToken, "share.put", params, map[string]any{"envelope": caddyDocumentsEnvelope(bob)}, func() {
			f.doc(t, bobToken, "key.reset", nil, map[string]string{"user_id": bob.UserID, "key_id": bob.KeyID}, 200)
			replacement = f.enroll(t, bobToken, "bob")
		}, 409)
		f.doc(t, bobToken, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
		grants := caddyDocumentsDecode[struct {
			Recipients []string `json:"recipients"`
		}](t, f.doc(t, aliceToken, "share.list", caddyDocumentsParams(file.ID), nil, 200))
		if len(grants.Recipients) != 0 {
			t.Fatal("stale delayed envelope granted access")
		}
		f.doc(t, aliceToken, "share.put", params, map[string]any{"envelope": caddyDocumentsEnvelope(replacement)}, 200)
		f.doc(t, bobToken, "chunk.fetch", map[string]string{"id": file.ID, "idx": "0"}, nil, 200)
	})
}

func testCaddyDocumentsQuotas(t *testing.T, cert, key string, roots *x509.CertPool) {
	for _, tc := range []struct {
		name   string
		limits documents.Config
		portal bool
	}{
		{"user_bytes", documents.Config{MaxFileBytes: 32, MaxUserBytes: 64, MaxTotalBytes: 1024}, false},
		{"portal_bytes", documents.Config{MaxFileBytes: 32, MaxUserBytes: 64, MaxTotalBytes: 64}, true},
		{"user_files", documents.Config{MaxFileBytes: 32, MaxUserBytes: 1024, MaxTotalBytes: 2048, MaxUserFiles: 2, MaxTotalFiles: 10}, false},
		{"portal_files", documents.Config{MaxFileBytes: 32, MaxUserBytes: 1024, MaxTotalBytes: 2048, MaxUserFiles: 2, MaxTotalFiles: 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", limits: tc.limits}, cert, key, roots)
			aliceToken, bobToken := f.login(t, "alice"), f.login(t, "bob")
			f.enroll(t, aliceToken, "alice")
			f.enroll(t, bobToken, "bob")
			first := caddyDocumentsDecode[documents.File](t, f.doc(t, aliceToken, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 200))
			f.doc(t, aliceToken, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 200)
			token := aliceToken
			if tc.portal {
				token = bobToken
			}
			f.doc(t, token, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 507)
			page := caddyDocumentsDecode[documents.Page](t, f.doc(t, aliceToken, "file.list", nil, nil, 200))
			if len(page.Files) != 2 {
				t.Fatal("quota refusal changed pending allocations")
			}
			f.doc(t, aliceToken, "file.allocate", nil, map[string]int{"size": 33, "chunks": 1}, 400)
			f.doc(t, aliceToken, "file.delete", caddyDocumentsParams(first.ID), nil, 200)
			f.doc(t, token, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 200)
		})
	}
	t.Run("recipient", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", limits: documents.Config{MaxRecipients: 1}}, cert, key, roots)
		aliceToken, bobToken, adminToken := f.login(t, "alice"), f.login(t, "bob"), f.login(t, "admin")
		alice, bob, admin := f.enroll(t, aliceToken, "alice"), f.enroll(t, bobToken, "bob"), f.enroll(t, adminToken, "admin")
		file := f.ready(t, aliceToken, alice)
		bobShare, adminShare := map[string]string{"id": file.ID, "user_id": bob.UserID}, map[string]string{"id": file.ID, "user_id": admin.UserID}
		f.doc(t, aliceToken, "share.put", bobShare, map[string]any{"envelope": caddyDocumentsEnvelope(bob)}, 200)
		f.doc(t, aliceToken, "share.put", adminShare, map[string]any{"envelope": caddyDocumentsEnvelope(admin)}, 507)
		f.doc(t, adminToken, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
		f.doc(t, aliceToken, "share.delete", bobShare, nil, 200)
		f.doc(t, aliceToken, "share.put", adminShare, map[string]any{"envelope": caddyDocumentsEnvelope(admin)}, 200)
		f.doc(t, adminToken, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	})
	t.Run("permanent_identity_reservation", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", limits: documents.Config{MaxKeys: 2}}, cert, key, roots)
		aliceToken, bobToken, adminToken := f.login(t, "alice"), f.login(t, "bob"), f.login(t, "admin")
		f.bootstrap(t, aliceToken, "alice")
		f.bootstrap(t, bobToken, "bob")
		f.doc(t, adminToken, "bootstrap", nil, nil, 507)
		alice := f.enroll(t, aliceToken, "alice")
		f.doc(t, aliceToken, "key.reset", nil, map[string]string{"user_id": alice.UserID, "key_id": alice.KeyID}, 200)
		f.doc(t, adminToken, "bootstrap", nil, nil, 507)
		f.enroll(t, aliceToken, "alice")
	})
	t.Run("concurrent_last_slot", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", limits: documents.Config{MaxFileBytes: 32, MaxUserBytes: 32, MaxTotalBytes: 32, MaxUserFiles: 1, MaxTotalFiles: 1}}, cert, key, roots)
		tokens := []string{f.login(t, "alice"), f.login(t, "bob")}
		f.enroll(t, tokens[0], "alice")
		f.enroll(t, tokens[1], "bob")
		type result struct {
			response *http.Response
			err      error
		}
		results := make(chan result, 2)
		start := make(chan struct{})
		for _, token := range tokens {
			req, err := http.NewRequestWithContext(t.Context(), "POST", f.issuer+"/api/documents/files/allocate", strings.NewReader(`{"size":32,"chunks":1}`))
			if err != nil {
				t.Fatal("cannot construct concurrent allocation")
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			go func() { <-start; response, err := f.plain.Do(req); results <- result{response, err} }()
		}
		close(start)
		var captured [2]result
		for i := range captured {
			captured[i] = <-results
		}
		defer func() {
			for _, r := range captured {
				if r.response != nil {
					r.response.Body.Close()
				}
			}
		}()
		statuses := make(map[int]int)
		for _, r := range captured {
			if r.err != nil || r.response == nil {
				t.Fatal("concurrent allocation transport failed")
			}
			statuses[r.response.StatusCode]++
			response := caddyDocumentsRead(t, r.response, "POST", r.response.StatusCode)
			f.contracts.AssertResponse(t, "POST", "/api/documents/files/allocate", response.status, response.header, response.body)
		}
		if statuses[200] != 1 || statuses[507] != 1 || len(statuses) != 2 {
			t.Fatal("ordinary concurrent quota admission was not one success and one quota refusal")
		}
		count := 0
		for _, token := range tokens {
			count += len(caddyDocumentsDecode[documents.Page](t, f.doc(t, token, "file.list", nil, nil, 200)).Files)
		}
		if count != 1 {
			t.Fatal("concurrent quota admission overallocated storage")
		}
	})
}

func testCaddyDocumentsExpiry(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", limits: documents.Config{MaxFileBytes: 32, MaxUserBytes: 32, MaxTotalBytes: 32, MaxUserFiles: 1, MaxTotalFiles: 1, UploadTTLSeconds: 60}}, cert, key, roots)
	token := f.login(t, "alice")
	registration := f.enroll(t, token, "alice")
	file := f.pending(t, token, registration)
	if lifetime := file.ExpiresAt - file.CreatedAt; lifetime < 60 || lifetime > 61 {
		t.Fatal("upload expiry did not use configured public TTL")
	}
	f.doc(t, token, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 507)
	current := caddyDocumentsDecode[documents.File](t, f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200))
	if current.ExpiresAt != file.ExpiresAt {
		t.Fatal("pending upload activity extended its deadline")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	delay := time.Until(time.Unix(file.ExpiresAt, 0).Add(20 * time.Millisecond))
	if delay < 0 || delay > 61*time.Second {
		t.Fatal("upload returned an unreasonable deadline")
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("upload expiry deadline was not reached")
	}
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
	f.doc(t, token, "chunk.put", map[string]string{"id": file.ID, "idx": "0"}, map[string]string{"ciphertext": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, 404)
	f.doc(t, token, "file.allocate", nil, map[string]int{"size": 32, "chunks": 1}, 200)
}

func testCaddyDocumentsSourceBinding(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth"}, cert, key, roots)
	token := f.login(t, "alice")
	before := f.bootstrap(t, token, "alice")
	registration := f.enroll(t, token, "alice")
	file := f.ready(t, token, registration)
	originalInput, originalAccounts := f.input, f.database
	f.stop(t)
	f.scan(t, nil)
	copied := filepath.Join(f.privateDir, "copied-users.json")
	data, err := os.ReadFile(originalAccounts)
	if err != nil || os.WriteFile(copied, data, 0600) != nil {
		t.Fatal("cannot prepare distinct authoritative identity snapshot")
	}
	f.input = strings.ReplaceAll(strings.ReplaceAll(originalInput, originalAccounts, copied), "localdb", "otherdb")
	f.database = copied
	f.start(t)
	fresh := f.login(t, "alice")
	for _, operation := range []string{"bootstrap", "key.fetch"} {
		f.doc(t, fresh, operation, nil, nil, 403)
	}
	f.doc(t, fresh, "key.reset", nil, map[string]string{"user_id": registration.UserID, "key_id": registration.KeyID}, 403)
	f.doc(t, fresh, "file.fetch", caddyDocumentsParams(file.ID), nil, 403)
	f.stop(t)
	f.input, f.database = originalInput, originalAccounts
	f.start(t)
	f.doc(t, token, "bootstrap", nil, nil, 401)
	fresh = f.login(t, "alice")
	after := f.bootstrap(t, fresh, "alice")
	if before.PortalID != after.PortalID || before.UserID != after.UserID {
		t.Fatal("root replacement changed durable Documents identity")
	}
	stored := caddyDocumentsDecode[documents.Key](t, f.doc(t, fresh, "key.fetch", nil, nil, 200))
	if stored.KeyID != registration.KeyID {
		t.Fatal("source-conflict attempt replaced the original vault")
	}
	f.doc(t, fresh, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
}

func testCaddyDocumentsRejectedReload(t *testing.T, cert, key string, roots *x509.CertPool) {
	f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth"}, cert, key, roots)
	token := f.login(t, "alice")
	registration := f.enroll(t, token, "alice")
	file := f.ready(t, token, registration)
	accounts := filepath.Join(f.privateDir, "candidate-users.json")
	data, err := os.ReadFile(f.database)
	if err != nil || os.WriteFile(accounts, data, 0600) != nil {
		t.Fatal("cannot prepare candidate identity snapshot")
	}
	originalInput, originalAccounts := f.input, f.database
	base := strings.ReplaceAll(originalInput, originalAccounts, accounts)
	var withoutDocuments []string
	for line := range strings.SplitSeq(originalInput, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "enable documents api" || strings.HasPrefix(trimmed, "documents api ") {
			continue
		}
		withoutDocuments = append(withoutDocuments, line)
	}
	reverse := strings.ReplaceAll(strings.Join(withoutDocuments, "\n"), originalAccounts, f.documentsDB)
	beforeDocuments, err := os.ReadFile(f.documentsDB)
	if err != nil {
		t.Fatal("cannot retain Documents namespace rejection evidence")
	}
	for _, tc := range []struct{ name, input, want string }{
		{"storage_namespace", strings.ReplaceAll(base, f.documentsDB, accounts), "documents API requires a distinct database and sidecar namespace"},
		{"live_local_omitted_by_candidate", strings.ReplaceAll(base, f.documentsDB, originalAccounts), "documents API requires a distinct database and sidecar namespace"},
		{"live_documents_omitted_by_candidate", reverse, "documents API requires a distinct database and sidecar namespace"},
		{"mount", strings.ReplaceAll(base, "authenticate with myportal at /tenant/auth", "authenticate with myportal at /other"), "mount"},
		{"live_portal_binding", strings.ReplaceAll(base, "myportal", "candidateportal"), "documents API requires a distinct database and sidecar namespace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(tc.input), nil)
			if err != nil {
				t.Fatal("Documents rejection fixture failed adaptation before runtime validation")
			}
			err = caddy.Load(config, true)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatal("candidate did not reach the intended Documents rejection")
			}
			currentAccounts, accountsErr := os.ReadFile(originalAccounts)
			currentDocuments, documentsErr := os.ReadFile(f.documentsDB)
			if accountsErr != nil || documentsErr != nil || !bytes.Equal(currentAccounts, data) || !bytes.Equal(currentDocuments, beforeDocuments) {
				t.Fatal("rejected candidate changed live storage bytes")
			}
			f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
		})
	}
	// A compatible Documents binding may be reopened by a candidate with a
	// distinct trusted account file. This does not preserve volatile sessions.
	config, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(base), nil)
	if err != nil || caddy.Load(config, true) != nil {
		t.Fatal("compatible Documents candidate did not activate")
	}
	f.input, f.database = base, accounts
	f.doc(t, token, "bootstrap", nil, nil, 401)
	fresh := f.login(t, "alice")
	f.doc(t, fresh, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	f.stop(t)
	// After the live graph is gone, the database itself still rejects a changed
	// immutable portal binding. Restore the original root after this failure.
	invalid := strings.ReplaceAll(originalInput, "myportal", "candidateportal")
	config, _, err = caddyconfig.GetAdapter("caddyfile").Adapt([]byte(invalid), nil)
	if err != nil {
		t.Fatal("persisted binding fixture failed adaptation")
	}
	err = caddy.Load(config, true)
	if err == nil {
		_ = caddy.Stop()
		t.Fatal("changed persisted Documents binding activated")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "documents") {
		t.Fatal("candidate did not reach persisted Documents binding validation")
	}
	f.input, f.database = originalInput, originalAccounts
	f.start(t)
	f.doc(t, token, "bootstrap", nil, nil, 401)
	fresh = f.login(t, "alice")
	f.doc(t, fresh, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	info, err := os.Stat(f.documentsDB)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("Documents storage lost private permissions")
	}
	// The public asset route must never include the private data tree.
	for _, path := range []string{"users.json", "documents.db", "runtime.jsonl", "../private/documents.db"} {
		status, _, body := registrationHTTP(t, f.plain, "GET", f.fixtureURL+path, nil, nil)
		if status != 404 || bytes.Contains(body, []byte("SQLite format")) {
			t.Fatal("Documents private storage was served as an asset")
		}
	}
}
