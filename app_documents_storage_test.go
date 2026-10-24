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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func documentsStorageTestPortal(path string) *authn.PortalConfig {
	return &authn.PortalConfig{Name: "documents", API: &authn.APIConfig{DocumentsEnabled: true}, Documents: &documents.Config{Database: path, PublicOrigin: "https://auth.example.test", BasePath: "/auth", Realms: []string{"local"}}}
}

func documentsStorageTestFile(path string) identityProviderStorageFile {
	return identityProviderStorageFile{path: path, sqlite: true, documents: true, binding: documentsStorageBinding{documents.Protocol, "documents", "https://auth.example.test", "/auth"}}
}

func TestDocumentsStorageWithoutTickets(t *testing.T) {
	for _, category := range []string{"ticket", "identity", "messaging", "registration", "credential", "secret", "local", "dropbox", "documents", "memory", "disabled", "storage_only", "distinct"} {
		t.Run(category, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "private.db")
			portal := documentsStorageTestPortal(path)
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}}
			app := new(App)
			switch category {
			case "ticket":
				app.identityProviders = []preparedIdentityProvider{{module: &SQLiteTicketIdentityProvider{Path: path}}}
			case "identity":
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: path}}}
			case "messaging":
				app.messagingProviders = []preparedMessagingProvider{{module: &SQLiteMessagingProvider{Path: path}}}
			case "registration":
				app.registrationWorkflows = []preparedRegistrationWorkflow{{module: &SQLiteRegistrationWorkflow{Path: path}}}
			case "credential":
				app.credentialAuthenticators = []preparedCredentialAuthenticator{{module: &SQLiteCredentialAuthenticator{Path: path}}}
			case "secret":
				app.secretsManagers = []SecretsManager{&SQLiteSecretsManager{Path: path}}
			case "local":
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": path}}}
			case "dropbox":
				config.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Dropbox: path}}}
			case "documents":
				other := documentsStorageTestPortal(path)
				other.Name = "other"
				config.AuthenticationPortals = append(config.AuthenticationPortals, other)
			case "memory":
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": ":memory:"}}}
				config.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Dropbox: ":memory:"}}}
			case "disabled", "storage_only":
				portal.API.DocumentsEnabled = false
				if category == "storage_only" {
					portal.API = nil
				}
				// A dangling path proves disabled settings are not inspected.
				if err := os.Symlink(filepath.Join(dir, "absent"), path); err != nil {
					t.Fatal(err)
				}
			case "distinct":
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": filepath.Join(dir, "accounts.json")}}}
			}
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			err = app.prepareStorageInventory(config)
			wantError := category != "memory" && category != "disabled" && category != "storage_only" && category != "distinct"
			if (err != nil) != wantError || err != nil && strings.Contains(err.Error(), dir) {
				t.Fatal("Documents-only admission or private path redaction changed", err)
			}
			after, readErr := os.ReadDir(dir)
			if readErr != nil || len(before) != len(after) {
				t.Fatal("storage preflight created files", readErr)
			}
		})
	}
}

func TestDocumentsStorageAliases(t *testing.T) {
	for _, kind := range []string{"same", "hardlink", "symlink", "ancestor_symlink", "case_alias", "journal", "wal", "shm", "reverse_sidecar", "sidecar_hardlink", "dangling", "distinct"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			first := documentsStorageTestFile(filepath.Join(dir, "documents.db"))
			second := identityProviderStorageFile{path: filepath.Join(dir, "accounts.db"), sqlite: true}
			var retained string
			sentinel := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("unchanged private storage sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
				retained = path
			}
			switch kind {
			case "same":
				second.path = first.path
			case "hardlink":
				sentinel(first.path)
				if err := os.Link(first.path, second.path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				sentinel(first.path)
				if err := os.Symlink(first.path, second.path); err != nil {
					t.Fatal(err)
				}
			case "ancestor_symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				second.path = filepath.Join(alias, "documents.db")
			case "case_alias":
				second.path = filepath.Join(dir, "DOCUMENTS.DB")
			case "journal", "wal", "shm":
				second.path = first.path + "-" + kind
			case "reverse_sidecar":
				first.path = second.path + "-wal"
			case "sidecar_hardlink":
				sentinel(first.path + "-journal")
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
			for _, reverse := range []bool{false, true} {
				a, b := first, second
				if reverse {
					a, b = b, a
				}
				err := validateDocumentsStoragePair(a, b, false)
				if (err != nil) != (kind != "distinct") || err != nil && strings.Contains(err.Error(), dir) {
					t.Fatal("Documents storage alias admission changed", err)
				}
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(before) != len(after) {
				t.Fatal("namespace validation changed directory entries", err)
			}
			if retained != "" {
				raw, err := os.ReadFile(retained)
				if err != nil || string(raw) != "unchanged private storage sentinel" {
					t.Fatal("namespace validation changed storage bytes", err)
				}
			}
		})
	}
}

func TestDocumentsStorageManagedDirectories(t *testing.T) {
	for _, kind := range []string{"equal", "child", "nested", "neighbor", "ancestor_symlink", "case_alias", "sidecar"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			managed := filepath.Join(dir, "state")
			path := filepath.Join(dir, "documents.db")
			switch kind {
			case "equal":
				path = managed
			case "child":
				path = filepath.Join(managed, "documents.db")
			case "nested":
				path = filepath.Join(managed, "nested", "documents.db")
			case "neighbor":
				path = filepath.Join(dir, "state-other", "documents.db")
			case "ancestor_symlink":
				if err := os.Mkdir(managed, 0700); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(managed, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "documents.db")
			case "case_alias":
				path = filepath.Join(dir, "STATE", "documents.db")
			case "sidecar":
				managed = path + "-wal"
			}
			files := []identityProviderStorageFile{documentsStorageTestFile(path)}
			err := validateDocumentsStorageDirectories(files, []string{managed})
			if (err != nil) != (kind != "neighbor") || err != nil && strings.Contains(err.Error(), dir) {
				t.Fatal("managed namespace admission changed", err)
			}
			candidate, active := appStorageInventory{files: files}, appStorageInventory{directories: []string{managed}}
			for range 2 {
				err = validateDocumentsStorageTransition(candidate, active)
				if (err != nil) != (kind != "neighbor") {
					t.Fatal("reload lost managed directory isolation", err)
				}
				candidate, active = active, candidate
			}
		})
	}
}

func TestDocumentsStorageTransition(t *testing.T) {
	for _, kind := range []string{"same_binding", "portal", "origin", "mount", "protocol", "hardlink", "sidecar", "old_local", "old_documents", "unrelated", "distinct"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			old := documentsStorageTestFile(filepath.Join(dir, "documents.db"))
			next := old
			switch kind {
			case "portal":
				next.binding.portal = "other"
			case "origin":
				next.binding.origin = "https://other.example.test"
			case "mount":
				next.binding.mount = "/other"
			case "protocol":
				next.binding.protocol = "other"
			case "hardlink":
				if err := os.WriteFile(old.path, []byte("private sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
				next.path = filepath.Join(dir, "alias.db")
				if err := os.Link(old.path, next.path); err != nil {
					t.Fatal(err)
				}
			case "sidecar":
				next.path += "-journal"
			case "old_local":
				old.documents = false
				old.sqlite = false
			case "old_documents":
				next.documents = false
				next.sqlite = false
			case "unrelated":
				old.documents = false
				next.documents = false
			case "distinct":
				next.path = filepath.Join(dir, "other.db")
			}
			err := validateDocumentsStorageTransition(appStorageInventory{files: []identityProviderStorageFile{next}}, appStorageInventory{files: []identityProviderStorageFile{old}})
			allowed := kind == "same_binding" || kind == "unrelated" || kind == "distinct"
			if (err == nil) != allowed {
				t.Fatal("active storage transition admission changed", err)
			}
			if kind == "same_binding" && validateDocumentsStorageInventory(appStorageInventory{files: []identityProviderStorageFile{old, next}}) == nil {
				t.Fatal("same-binding reload exception escaped into one candidate")
			}
		})
	}
}

func TestDocumentsStorageInventorySnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.db")
	module := &SQLiteIdentityStore{Path: path}
	app := &App{identityStores: []preparedIdentityStore{{module: module}}, OAuthRegistrationStore: &OAuthRegistrationStoreConfig{Path: filepath.Join(dir, "registrations")}}
	config := &authcrunch.Config{State: &state.Config{Directory: filepath.Join(dir, "state")}}
	if err := app.prepareStorageInventory(config); err != nil {
		t.Fatal(err)
	}
	module.Path = filepath.Join(dir, "changed.db")
	app.OAuthRegistrationStore.Path = filepath.Join(dir, "changed-registrations")
	config.State.Directory = filepath.Join(dir, "changed-state")
	// An old app without Documents still protects its detached storage values.
	candidate := appStorageInventory{files: []identityProviderStorageFile{documentsStorageTestFile(path)}}
	if validateDocumentsStorageTransition(candidate, *app.storageInventory) == nil {
		t.Fatal("module mutation changed active storage ownership")
	}
	for _, name := range []string{"state", "registrations"} {
		candidate.files[0].path = filepath.Join(dir, name, "documents.db")
		if validateDocumentsStorageTransition(candidate, *app.storageInventory) == nil {
			t.Fatal("managed directory mutation changed active storage ownership")
		}
	}
	portal := documentsStorageTestPortal(filepath.Join(dir, "documents.db"))
	active := new(App)
	if err := active.prepareStorageInventory(&authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{portal}}); err != nil {
		t.Fatal(err)
	}
	original := active.storageInventory.files[0]
	portal.Documents.Database = path
	portal.Documents.PublicOrigin = "https://changed.example.test"
	portal.Documents.BasePath = "/changed"
	portal.Name = "changed"
	if active.storageInventory.files[0] != original {
		t.Fatal("native declaration mutation changed prepared Documents binding")
	}
}
