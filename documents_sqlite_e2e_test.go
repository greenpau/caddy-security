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
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

func TestCaddySQLiteDocumentsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddySQLiteDocumentsProcess$", "-test.v", "-test.timeout=7m")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_SQLITE_DOCUMENTS_CHILD=1", "XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("SQLite Documents Caddy journeys: %v\n%s", err, output)
	}
}

func TestCaddySQLiteDocumentsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_SQLITE_DOCUMENTS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct{ mount, realm string }{{"/", "local"}, {"/auth", "local"}, {"/tenant/auth", "staff"}} {
		t.Run(tc.mount, func(t *testing.T) {
			f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: tc.mount, realm: tc.realm, sqlite: true, transform: true, refresh: true}, cert, key, roots)
			alice, bob, admin := f.login(t, "alice"), f.login(t, "bob"), f.login(t, "admin")
			a, b := f.enroll(t, alice, "alice"), f.enroll(t, bob, "bob")
			file := f.ready(t, alice, a)
			f.doc(t, admin, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
			f.doc(t, admin, "file.delete", caddyDocumentsParams(file.ID), nil, 404)
			params := map[string]string{"id": file.ID, "user_id": b.UserID}
			f.doc(t, alice, "key.lookup", map[string]string{"user_id": b.UserID}, nil, 200)
			f.doc(t, alice, "share.put", params, map[string]any{"envelope": caddyDocumentsEnvelope(b)}, 200)
			f.doc(t, alice, "share.list", caddyDocumentsParams(file.ID), nil, 200)
			f.doc(t, bob, "file.list", nil, nil, 200)
			f.doc(t, bob, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
			f.doc(t, bob, "chunk.fetch", map[string]string{"id": file.ID, "idx": "0"}, nil, 200)
			f.doc(t, alice, "share.delete", params, nil, 200)
			f.doc(t, bob, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
			// The real Caddy app owns cleanup, new backend epochs and persistent IDs.
			f.stop(t)
			f.start(t)
			f.doc(t, alice, "bootstrap", nil, nil, 401)
			alice = f.login(t, "alice")
			if got := caddyDocumentsDecode[documents.Key](t, f.doc(t, alice, "key.fetch", nil, nil, 200)); got.UserID != a.UserID || got.KeyID != a.KeyID {
				t.Fatal("restart changed SQLite vault identity")
			}
			f.doc(t, alice, "file.delete", caddyDocumentsParams(file.ID), nil, 200)
			f.doc(t, alice, "key.reset", nil, map[string]string{"user_id": a.UserID, "key_id": a.KeyID}, 200)
			f.doc(t, alice, "key.fetch", nil, nil, 404)
			r := f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice)
			r.requireStatus(t, 200)
			var info struct {
				Entry struct{ Metadata struct{ Username string } }
			}
			if json.Unmarshal(r.body, &info) != nil || info.Entry.Metadata.Username != "alice" {
				t.Fatal("Caddy profile used transformed subject")
			}
			r = f.request(t, "GET", "/api/capabilities", nil, http.Header{"Authorization": {"Bearer " + alice}})
			r.requireStatus(t, 200)
			var capabilities struct {
				Backend   struct{ Kind, Realm string }
				Documents struct{ Allowed bool }
			}
			if json.Unmarshal(r.body, &capabilities) != nil || capabilities.Backend.Kind != "sqlite" || capabilities.Backend.Realm != tc.realm || !capabilities.Documents.Allowed {
				t.Fatal("Caddy capabilities changed backend kind or realm eligibility")
			}
			// Caddy must preserve the upstream rejection envelope and leave the
			// account readable when valid role strings exceed the stored JSON bound.
			roles := make([]string, 12)
			for i := range roles {
				roles[i] = strings.Repeat("<", 126) + fmt.Sprintf("%02d", i)
			}
			admin = f.login(t, "admin")
			r = f.json(t, f.plain, "/api/server/user", map[string]any{"realm": tc.realm, "operation": "add_roles", "user": map[string]any{"username": "alice", "email": "alice@example.test", "roles": roles}}, admin)
			r.requireStatus(t, 200)
			var failure struct{ Status, Code string }
			if json.Unmarshal(r.body, &failure) != nil || failure.Status != "failure" || failure.Code != "operation_failed" {
				t.Fatal("Caddy accepted roles that would make the account unreadable")
			}
			f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice).requireStatus(t, 200)
			// Persisted verifier corruption is an upstream storage failure. The
			// Caddy handler must retain that classification and withhold success.
			db, err := sql.Open("sqlite", f.database)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var original string
			var version uint64
			if err := db.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE realm=? AND username='alice'", tc.realm).Scan(&original, &version); err != nil {
				t.Fatal(err)
			}
			const invalid = "invalid-stored-verifier"
			if _, err := db.ExecContext(t.Context(), "UPDATE accounts SET password=? WHERE realm=? AND username='alice'", invalid, tc.realm); err != nil {
				t.Fatal(err)
			}
			r = f.json(t, f.plain, "/api/profile", map[string]string{"kind": "update_user_password", "old_password": lifecyclePassword, "new_password": "Replacement-password-2026!"}, alice)
			r.requireStatus(t, http.StatusServiceUnavailable)
			var fault struct {
				Code  string
				Entry any
			}
			if json.Unmarshal(r.body, &fault) != nil || fault.Code != "storage_unavailable" || fault.Entry != nil {
				t.Fatal("Caddy lost the stored-verifier failure classification")
			}
			var stored string
			var current uint64
			if err := db.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE realm=? AND username='alice'", tc.realm).Scan(&stored, &current); err != nil {
				t.Fatal(err)
			}
			if stored != invalid || current != version {
				t.Fatal("failed Caddy profile request changed persistent credentials")
			}
			if _, err := db.ExecContext(t.Context(), "UPDATE accounts SET password=? WHERE realm=? AND username='alice'", original, tc.realm); err != nil {
				t.Fatal(err)
			}
			f.json(t, f.plain, "/api/profile", map[string]string{"kind": "update_user_password", "old_password": "incorrect-password", "new_password": "Replacement-password-2026!"}, alice).requireStatus(t, http.StatusBadRequest)
			alice = f.login(t, "alice")
			f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice).requireStatus(t, http.StatusOK)
			// A real competing writer exhausts the backend's configured budget.
			// Both APIs must identify the outage without revoking valid evidence.
			writer, err := db.Conn(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			defer writer.ExecContext(context.Background(), "ROLLBACK")
			if _, err := writer.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			r = f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice)
			r.requireStatus(t, http.StatusServiceUnavailable)
			var timeoutFault struct {
				Code  string
				Entry any
			}
			if json.Unmarshal(r.body, &timeoutFault) != nil || timeoutFault.Code != "storage_unavailable" || timeoutFault.Entry != nil {
				t.Fatal("Caddy lost the storage deadline classification")
			}
			r = f.json(t, f.plain, "/api/server/user", map[string]any{"realm": tc.realm, "operation": "add_roles", "user": map[string]any{"username": "alice", "email": "alice@example.test", "roles": []string{"extra"}}}, admin)
			r.requireStatus(t, http.StatusOK)
			var timeoutFailure struct {
				Status, Code string
				Roles        []string
			}
			if json.Unmarshal(r.body, &timeoutFailure) != nil || timeoutFailure.Status != "failure" || timeoutFailure.Code != "storage_unavailable" || timeoutFailure.Roles != nil {
				t.Fatal("Caddy lost the admin storage deadline classification")
			}
			if _, err := writer.ExecContext(t.Context(), "ROLLBACK"); err != nil {
				t.Fatal(err)
			}
			if err := writer.QueryRowContext(t.Context(), "SELECT password,version FROM accounts WHERE realm=? AND username='alice'", tc.realm).Scan(&stored, &current); err != nil {
				t.Fatal(err)
			}
			if stored != original || current != version {
				t.Fatal("timed-out Caddy request changed persistent credentials")
			}
			f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice).requireStatus(t, http.StatusOK)
			alice = f.login(t, "alice")
			f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, alice).requireStatus(t, http.StatusOK)
		})
	}
	t.Run("admin_lifecycle", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", realm: "staff", sqlite: true, refresh: true}, cert, key, roots)
		runCaddySQLiteAdminLifecycle(t, f)
	})
	t.Run("browser_crypto", func(t *testing.T) {
		f := newCaddyDocumentsFixture(t, caddyDocumentsOptions{mount: "/tenant/auth", sqlite: true}, cert, key, roots)
		runCaddyDocumentsBrowser(t, f)
	})
}

// Exercise the advertised management operations through Caddy's real TLS
// listener, then verify both current login evidence and persisted vault identity.
func runCaddySQLiteAdminLifecycle(t *testing.T, f *caddyDocumentsFixture) {
	t.Helper()
	admin := f.login(t, "admin")
	selector := map[string]any{"username": "diana", "email": "diana@example.test", "name": "Diana Example", "roles": []string{"authp/user"}}
	manage := func(operation, want string) map[string]any {
		t.Helper()
		r := f.json(t, f.plain, "/api/server/user", map[string]any{"realm": f.realm, "operation": operation, "user": selector}, admin)
		r.requireStatus(t, http.StatusOK)
		var out map[string]any
		if json.Unmarshal(r.body, &out) != nil || want != "" && out["status"] != want {
			t.Fatalf("Caddy admin %s returned an unexpected outcome", operation)
		}
		if want == "failure" && (out["code"] != "operation_failed" || out["password"] != nil) {
			t.Fatalf("Caddy admin %s failure exposed credentials or lost its error code", operation)
		}
		return out
	}
	password := func(result map[string]any) string {
		t.Helper()
		secret, ok := result["password"].(string)
		if !ok || len(secret) < 12 {
			t.Fatal("Caddy management omitted generated credential")
		}
		f.secrets = append(f.secrets, secret)
		return secret
	}
	login := func(secret string) string {
		t.Helper()
		f.newBrowser(t)
		return f.loginSameBrowser(t, "diana", secret, false)
	}
	profile := func(token string, status int) {
		t.Helper()
		f.json(t, f.plain, "/api/profile", map[string]string{"kind": "fetch_user_info"}, token).requireStatus(t, status)
	}
	created := manage("add", "success")
	id := created["id"].(string)
	f.expectedUsers["diana"] = id
	secret := password(created)
	token := login(secret)
	key := f.enroll(t, token, "diana")
	file := f.ready(t, token, key)
	manage("add", "failure")
	selector["email"] = "wrong@example.test"
	manage("reset_password", "failure")
	selector["email"] = "diana@example.test"
	profile(token, 200)
	if info := manage("info", ""); info["id"] != id || info["credential_version"] != float64(1) {
		t.Fatal("failed Caddy management changed persisted identity")
	}
	selector["roles"] = []string{"team/reader"}
	manage("add_roles", "success")
	profile(token, 401)
	token = login(secret)
	selector["roles"] = []string{"authp/user", "team/editor"}
	manage("overwrite_roles", "success")
	profile(token, 401)
	token = login(secret)
	manage("add_roles", "success")
	profile(token, 200)
	r := f.json(t, f.plain, "/api/server/reload", map[string]string{"realm": f.realm}, admin)
	r.requireStatus(t, 200)
	var reloaded struct{ Status string }
	if json.Unmarshal(r.body, &reloaded) != nil || reloaded.Status != "success" {
		t.Fatal("Caddy realm health reload failed")
	}
	profile(token, 200)
	manage("disable", "success")
	if manage("info", "")["disabled"] != true {
		t.Fatal("Caddy lost disabled state")
	}
	profile(token, 401)
	f.doc(t, token, "bootstrap", nil, nil, 401)
	manage("enable", "success")
	profile(token, 401)
	token = login(secret)
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	replacement := password(manage("reset_password", "success"))
	profile(token, 401)
	token = login(replacement)
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	// Actual app cleanup/reopening must preserve the admin-created account,
	// password, roles and ciphertext while rejecting the previous session.
	f.stop(t)
	f.start(t)
	profile(token, 401)
	admin = f.login(t, "admin")
	token = login(replacement)
	if info := manage("info", ""); info["id"] != id || info["disabled"] != false {
		t.Fatal("Caddy restart changed managed account")
	}
	if got := caddyDocumentsDecode[documents.Key](t, f.doc(t, token, "key.fetch", nil, nil, 200)); got.UserID != key.UserID || got.KeyID != key.KeyID {
		t.Fatal("Caddy restart changed managed account's vault")
	}
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 200)
	manage("delete", "success")
	profile(token, 401)
	recreated := manage("add", "success")
	if recreated["id"] == id {
		t.Fatal("Caddy recreated account inherited its predecessor's UUID")
	}
	f.expectedUsers["diana"] = recreated["id"].(string)
	token = login(password(recreated))
	profile(token, 200)
	f.bootstrap(t, token, "diana")
	f.doc(t, token, "key.fetch", nil, nil, 404)
	f.doc(t, token, "file.fetch", caddyDocumentsParams(file.ID), nil, 404)
}
