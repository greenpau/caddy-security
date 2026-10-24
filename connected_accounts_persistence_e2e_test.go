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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Each round trip replaces an actual Caddy OS process. The executable adds only
// the private fixture CA; authentication and command dispatch use production code.
func TestCaddyConnectedAccountsPersistenceE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build connected-account Caddy fixture: %v\n%s", err, output)
	}
	for _, named := range []bool{false, true} {
		name := "implicit_memory_ignores_working_directory"
		if named {
			name = "explicit_path_with_memory_basename_persists"
		}
		t.Run(name, func(t *testing.T) { testConnectedAccountsMemoryProcess(t, binary, named) })
	}
	t.Run("ticket_explicit_local_attachment", func(t *testing.T) { testConnectedAccountsTicketProcess(t, binary) })
}

func testConnectedAccountsMemoryProcess(t *testing.T, binary string, named bool) {
	var path, diskID string
	var original []byte
	f := newPersistentProviderFixture(t, binary, named, func(f *persistentProviderFixture) {
		f.workingDirectory = registrationTestDirectory(t)
		path = filepath.Join(f.workingDirectory, ":memory:")
		// The absolute path is ordinary storage. Seed exactly the verified tuple
		// the implicit provider will later receive, before starting any Caddy.
		db, err := identity.NewDatabase(path)
		if err != nil {
			t.Fatal("create memory-basename collision fixture")
		}
		account, err := db.ResolveExternalAccount(t.Context(), identity.ExternalAccount{
			Provider: "upstream", Kind: "oauth", Issuer: f.upstream.server.URL,
			Subject: persistentProviderSubject, Email: "alice@example.test",
		}, true)
		if err != nil {
			t.Fatal("seed verified external tuple in collision file")
		}
		diskID = account.Evidence.UserID
		if err := db.AddUserRoles(&requests.Request{User: requests.User{Username: account.Identity.Username, Roles: []string{"collision/disk-only"}}}); err != nil {
			t.Fatal("seed distinctive collision role")
		}
		original, err = os.ReadFile(path)
		if err != nil || len(original) == 0 {
			t.Fatal("capture collision file bytes")
		}
		if named {
			old := fmt.Sprintf("path %q", filepath.Join(f.workspace, "external-accounts.json"))
			if !strings.Contains(f.input, old) {
				t.Fatal("fixture omitted the explicit local attachment")
			}
			f.input = strings.Replace(f.input, old, fmt.Sprintf("path %q", path), 1)
		}
	})
	check := func(tokens persistentProviderTokens) string {
		t.Helper()
		id, _ := tokens.claims["id"].(string)
		if _, err := uuid.Parse(id); err != nil || (id == diskID) != named {
			t.Fatal("provider selected the wrong memory/file identity")
		}
		roles, ok := tokens.claims["roles"].([]any)
		if !ok || slices.Contains(roles, any("collision/disk-only")) != named {
			t.Fatal("provider selected the wrong memory/file roles")
		}
		if !named {
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, current) {
				t.Fatal("implicit memory provider modified the working-directory file")
			}
		}
		return id
	}
	first := check(f.login(t))
	if check(f.login(t)) != first {
		t.Fatal("same provider instance changed its automatic identity")
	}
	f.restart(t)
	next := check(f.login(t))
	if (first == next) != named {
		t.Fatal("fresh process did not preserve the explicit/implicit storage boundary")
	}
	f.kill(t)
	if !named {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(original, current) {
			t.Fatal("process shutdown modified the private-memory collision file")
		}
	}
}

func connectedProviderRecord(t *testing.T, path, id string) *identity.User {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read attached local account snapshot")
	}
	var snapshot struct{ Users []*identity.User }
	if json.Unmarshal(data, &snapshot) != nil {
		t.Fatal("decode attached local account snapshot")
	}
	for _, user := range snapshot.Users {
		if user != nil && user.ID == id {
			return user
		}
	}
	t.Fatal("verified local ID is missing from its configured store")
	return nil
}

func connectedProviderAutomaticRecord(t *testing.T, user *identity.User, provider, kind, issuer, subject string) {
	t.Helper()
	if user == nil || !user.ExternallyProvisioned || user.Disabled || !strings.HasPrefix(user.Username, "external") ||
		len(user.EmailAddresses) != 0 || len(user.Passwords) != 0 || len(user.MfaTokens) != 0 || len(user.APIKeys) != 0 || len(user.PublicKeys) != 0 || len(user.Roles) != 0 || len(user.ExternalAccounts) != 1 {
		t.Fatal("automatic identity acquired a local alias, credential, privilege or unexpected connection")
	}
	account := user.ExternalAccounts[0]
	if account.Provider != provider || account.Kind != kind || account.Issuer != issuer || account.Subject != subject {
		t.Fatal("automatic identity did not retain its exact verified external tuple")
	}
}

func testConnectedAccountsTicketProcess(t *testing.T, binary string) {
	path := filepath.Join(registrationTestDirectory(t), "ticket-accounts.json")
	seedLocalIdentity(t, path, false)
	alice := localIdentityRecord(t, path, "alice")
	f := newSQLiteTicketFixture(t, binary, "/tenant/auth", func(f *sqliteTicketFixture) {
		f.source = strings.Replace(f.source, "security {", fmt.Sprintf("security {\nstate {\ndirectory %q\n}\nlocal identity store ticket_accounts {\nrealm local\npath %q\n}\n", f.directory, path), 1)
		f.source = strings.Replace(f.source, "identity provider sqlite tickets {", "identity provider sqlite tickets {\nattach to local identity store ticket_accounts", 1)
		// Reach the profile authentication-method check with an admitted portal
		// user role, so rejection cannot be attributed merely to its role gate.
		f.source = strings.Replace(f.source, "action add role app/verified", "action add role app/verified authp/user", 1)
		f.expectedRoles = append(f.expectedRoles, "authp/user")
		f.source = strings.Replace(f.source, "authenticate with ticketportal", "authenticate with ticketportal at /tenant/auth", 1)
	})
	login := func() string {
		t.Helper()
		browser := f.browser(t)
		claims := f.complete(t, browser, f.issue(t, browser, f.begin(t, browser)))
		id, _ := claims["id"].(string)
		if _, err := uuid.Parse(id); err != nil || id == alice.ID {
			t.Fatal("ticket attached by display email or omitted its local UUID")
		}
		connectedProviderAutomaticRecord(t, connectedProviderRecord(t, path, id), "tickets", "sqlite-ticket", f.backendConfig.IssuerURL, "alice")
		// The named local target grants identity continuity, not local profile
		// authority. The active external browser credential reaches the real API.
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.endpoint("/api/profile"), strings.NewReader(`{"kind":"fetch_user_api_keys"}`))
		if err != nil {
			t.Fatal("construct ticket profile request")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Origin", f.base)
		response, err := browser.Do(req)
		if err != nil {
			t.Fatal("request ticket profile over TLS")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNotImplemented || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatalf("ticket profile authority boundary: HTTP %d, want 501 with verified TLS", response.StatusCode)
		}
		return id
	}
	first := login()
	if login() != first {
		t.Fatal("repeat ticket login changed its explicitly attached identity")
	}
	pid := f.cmd.Process.Pid
	f.stopTicket(t)
	f.startTicket(t)
	if f.cmd.Process.Pid == pid || login() != first {
		t.Fatal("fresh ticket process did not retain the named local identity")
	}
}
