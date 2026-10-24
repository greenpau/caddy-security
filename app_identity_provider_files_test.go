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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
)

func TestSQLiteTicketStorageNamespaces(t *testing.T) {
	for _, kind := range []string{"distinct", "shared_ticket", "same", "hardlink", "ticket_hardlink", "symlink", "ancestor_symlink", "case_alias", "journal", "wal", "shm", "ticket_journal", "other_sidecar", "sidecar_hardlink", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			first := identityProviderStorageFile{path: filepath.Join(dir, "tickets.db"), ticket: true, sqlite: true}
			second := identityProviderStorageFile{path: filepath.Join(dir, "accounts.db"), sqlite: true}
			var retained string
			writeSentinel := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("existing private evidence"), 0600); err != nil {
					t.Fatal(err)
				}
				retained = path
			}
			switch kind {
			case "shared_ticket":
				second.path, second.ticket = first.path, true
			case "same":
				second.path = first.path
			case "hardlink", "ticket_hardlink":
				writeSentinel(first.path)
				if err := os.Link(first.path, second.path); err != nil {
					t.Fatal(err)
				}
				second.ticket = kind == "ticket_hardlink"
			case "symlink":
				writeSentinel(first.path)
				if err := os.Symlink(first.path, second.path); err != nil {
					t.Fatal(err)
				}
			case "ancestor_symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				second.path = filepath.Join(alias, "tickets.db")
			case "case_alias":
				second.path = filepath.Join(dir, "TICKETS.DB")
			case "journal", "wal", "shm":
				second.path = first.path + "-" + kind
			case "ticket_journal":
				second.path, second.ticket = first.path+"-journal", true
			case "other_sidecar":
				first.path = second.path + "-journal"
			case "sidecar_hardlink":
				writeSentinel(first.path + "-journal")
				if err := os.Link(retained, second.path); err != nil {
					t.Fatal(err)
				}
			case "dangling":
				if err := os.Symlink(filepath.Join(dir, "missing"), second.path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			err = validateTicketStorageFiles([]identityProviderStorageFile{first, second})
			wantError := kind != "distinct" && kind != "shared_ticket"
			if (err != nil) != wantError || err != nil && strings.Contains(err.Error(), dir) {
				t.Fatal("storage namespace admission or private-path redaction changed", err)
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(before) != len(after) {
				t.Fatal("read-only storage validation created entries", err)
			}
			if retained != "" {
				data, err := os.ReadFile(retained)
				if err != nil || string(data) != "existing private evidence" {
					t.Fatal("storage validation changed existing evidence", err)
				}
			}
		})
	}
}

func TestAppIdentityProviderStorageCategories(t *testing.T) {
	for _, kind := range []string{"account", "outbox", "pending", "api_key", "secret", "local", "dropbox", "memory", "shared_ticket"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tickets.db")
			app := &App{identityProviders: []preparedIdentityProvider{{module: &SQLiteTicketIdentityProvider{Path: path}}}}
			config := &authcrunch.Config{}
			switch kind {
			case "account":
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: path}}}
			case "outbox":
				app.messagingProviders = []preparedMessagingProvider{{module: &SQLiteMessagingProvider{Path: path}}}
			case "pending":
				app.registrationWorkflows = []preparedRegistrationWorkflow{{module: &SQLiteRegistrationWorkflow{Path: path}}}
			case "api_key":
				app.credentialAuthenticators = []preparedCredentialAuthenticator{{module: &SQLiteCredentialAuthenticator{Path: path}}}
			case "secret":
				app.secretsManagers = []SecretsManager{&SQLiteSecretsManager{Path: path}}
			case "local", "memory":
				localPath := path
				if kind == "memory" {
					localPath = ":memory:"
				}
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": localPath}}}
			case "dropbox":
				config.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Dropbox: path}}}
			case "shared_ticket":
				app.identityProviders = append(app.identityProviders, preparedIdentityProvider{module: &SQLiteTicketIdentityProvider{Path: path}})
			}
			err := app.validateIdentityProviderFiles(config)
			if (err != nil) != (kind != "memory" && kind != "shared_ticket") {
				t.Fatal("configured storage category escaped ticket namespace validation", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("namespace validation opened storage", err)
			}
		})
	}
}

func TestSQLiteTicketStorageNormalizedPaths(t *testing.T) {
	for _, kind := range []string{"ticket", "other_sqlite", "sidecar", "local_distinct", "local_alias"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			other := t.TempDir()
			child := filepath.Join(other, "child")
			if err := os.Mkdir(child, 0700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "link")
			if err := os.Symlink(child, link); err != nil {
				t.Fatal(err)
			}
			// Preserve the native spelling: filepath.Join would clean it here.
			raw := link + string(filepath.Separator) + ".." + string(filepath.Separator) + "tickets.db"
			first := identityProviderStorageFile{path: filepath.Join(dir, "tickets.db"), ticket: true, sqlite: true}
			second := identityProviderStorageFile{path: raw, sqlite: true}
			switch kind {
			case "ticket":
				first.path, second.path = raw, first.path
			case "sidecar":
				second.path += "-journal"
			case "local_distinct":
				second.sqlite = false
			case "local_alias":
				first.path = filepath.Join(other, "tickets.db")
				second.sqlite = false
			}
			err := validateTicketStorageFiles([]identityProviderStorageFile{first, second})
			if (err != nil) != (kind != "local_distinct") {
				t.Fatal("storage admission disagrees with the backend's opened path", err)
			}
			for _, path := range []string{first.path, second.path} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("namespace validation created a database or sidecar", err)
				}
			}
		})
	}
}
