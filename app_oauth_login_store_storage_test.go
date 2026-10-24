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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func oauthStorageTestBinding(t *testing.T, name, path string, capacity int) preparedOAuthLoginStore {
	t.Helper()
	module := &SQLiteOAuthLoginStore{Name: name, Path: path, Capacity: capacity}
	factory, err := module.PrepareOAuthLoginStore()
	if err != nil {
		t.Fatal("cannot prepare OAuth storage fixture", err)
	}
	descriptor, err := factory.OAuthLoginStoreConfig()
	if err != nil {
		t.Fatal("cannot describe OAuth storage fixture", err)
	}
	return preparedOAuthLoginStore{config: descriptor, factory: factory}
}

func oauthStorageTestFile(path string) identityProviderStorageFile {
	return identityProviderStorageFile{path: path, sqlite: true, oauth: true, capacity: 10000}
}

func TestOAuthLoginStoreStorageCategories(t *testing.T) {
	for _, category := range []string{"ticket", "identity", "messaging", "registration", "credential", "secret", "local", "dropbox", "documents", "same_oauth", "different_capacity", "distinct", "memory"} {
		t.Run(category, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "logins.db")
			app := &App{oauthLoginStores: []preparedOAuthLoginStore{oauthStorageTestBinding(t, "shared", path, 0)}}
			config := &authcrunch.Config{}
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
				config.AuthenticationPortals = []*authn.PortalConfig{documentsStorageTestPortal(path)}
			case "same_oauth", "different_capacity":
				capacity := 10000
				if category == "different_capacity" {
					capacity = 1
				}
				app.oauthLoginStores = append(app.oauthLoginStores, oauthStorageTestBinding(t, "peer", path, capacity))
			case "distinct":
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: filepath.Join(dir, "accounts.db")}}}
			case "memory":
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": ":memory:"}}}
				config.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Dropbox: ":memory:"}}}
			}
			err := app.prepareStorageInventory(config)
			allowed := category == "same_oauth" || category == "distinct" || category == "memory"
			if (err == nil) != allowed || err != nil && strings.Contains(err.Error(), dir) {
				t.Fatal("OAuth storage category admission or path redaction changed", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("storage preflight created a file", err)
			}
		})
	}
}

func TestOAuthLoginStoreStorageAliases(t *testing.T) {
	for _, kind := range []string{"same", "hardlink", "oauth_hardlink", "symlink", "ancestor_symlink", "case_alias", "journal", "wal", "shm", "reverse_sidecar", "sidecar_hardlink", "oauth_sidecar", "shared", "shared_symlink", "capacity", "dangling", "distinct", "unrelated"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			first := oauthStorageTestFile(filepath.Join(dir, "logins.db"))
			second := identityProviderStorageFile{path: filepath.Join(dir, "accounts.db"), sqlite: true}
			var retained string
			writeSentinel := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("unchanged private storage sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
				retained = path
			}
			switch kind {
			case "same":
				second.path = first.path
			case "hardlink", "oauth_hardlink":
				writeSentinel(first.path)
				if err := os.Link(first.path, second.path); err != nil {
					t.Fatal(err)
				}
				second.oauth, second.capacity = kind == "oauth_hardlink", first.capacity
			case "symlink", "shared_symlink":
				writeSentinel(first.path)
				if err := os.Symlink(first.path, second.path); err != nil {
					t.Fatal(err)
				}
				second.oauth, second.capacity = kind == "shared_symlink", first.capacity
			case "ancestor_symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				second.path = filepath.Join(alias, "logins.db")
			case "case_alias":
				second.path = filepath.Join(dir, "LOGINS.DB")
			case "journal", "wal", "shm":
				second.path = first.path + "-" + kind
			case "reverse_sidecar":
				first.path = second.path + "-wal"
			case "sidecar_hardlink":
				writeSentinel(first.path + "-journal")
				if err := os.Link(retained, second.path); err != nil {
					t.Fatal(err)
				}
			case "oauth_sidecar":
				second = oauthStorageTestFile(first.path + "-journal")
			case "shared", "capacity":
				second = first
				if kind == "capacity" {
					second.capacity = 1
				}
			case "dangling":
				if err := os.Symlink(filepath.Join(dir, "absent"), second.path); err != nil {
					t.Fatal(err)
				}
			case "unrelated":
				first.oauth = false
				second.path = first.path
			}
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			allowed := kind == "shared" || kind == "shared_symlink" || kind == "distinct" || kind == "unrelated"
			for range 2 {
				inventory := appStorageInventory{files: []identityProviderStorageFile{first, second}}
				transition := validateDocumentsStorageTransition(appStorageInventory{files: inventory.files[:1]}, appStorageInventory{files: inventory.files[1:]})
				for _, err := range []error{validateDocumentsStorageInventory(inventory), transition} {
					if (err == nil) != allowed || err != nil && strings.Contains(err.Error(), dir) {
						t.Fatal("OAuth alias or candidate/active transition changed", err)
					}
				}
				first, second = second, first
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(before) != len(after) {
				t.Fatal("metadata admission changed filesystem entries", err)
			}
			if retained != "" {
				data, err := os.ReadFile(retained)
				if err != nil || string(data) != "unchanged private storage sentinel" {
					t.Fatal("metadata admission modified private storage", err)
				}
			}
		})
	}
}

func TestOAuthLoginStoreStorageDirectories(t *testing.T) {
	for _, kind := range []string{"state", "registration", "equal", "ancestor_symlink", "directory_hardlink", "neighbor"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			managed := filepath.Join(dir, "managed")
			if err := os.Mkdir(managed, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(managed, "logins.db")
			switch kind {
			case "equal":
				path = managed
			case "ancestor_symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(managed, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "logins.db")
			case "directory_hardlink":
				// A file already owned within the directory also cannot be opened
				// through an outside hardlink name as a new database namespace.
				inside := filepath.Join(managed, "private.db")
				if err := os.WriteFile(inside, []byte("private sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(dir, "alias.db")
				if err := os.Link(inside, path); err != nil {
					t.Fatal(err)
				}
				// Directory containment does not enumerate its contents. An
				// explicit known-file inventory is needed for this inode alias.
				inventory := appStorageInventory{files: []identityProviderStorageFile{oauthStorageTestFile(path), {path: inside}}}
				if validateDocumentsStorageInventory(inventory) == nil {
					t.Fatal("known managed file hardlink escaped isolation")
				}
				return
			case "neighbor":
				path = filepath.Join(managed+"-neighbor", "logins.db")
			}
			app := &App{oauthLoginStores: []preparedOAuthLoginStore{oauthStorageTestBinding(t, "shared", path, 0)}}
			config := &authcrunch.Config{}
			if kind == "registration" {
				app.OAuthRegistrationStore = &OAuthRegistrationStoreConfig{Path: managed}
			} else {
				config.State = &state.Config{Directory: managed}
			}
			if err := app.prepareStorageInventory(config); (err == nil) != (kind == "neighbor") {
				t.Fatal("managed directory admission changed", err)
			}
			candidate, active := appStorageInventory{files: []identityProviderStorageFile{oauthStorageTestFile(path)}}, appStorageInventory{directories: []string{managed}}
			for range 2 {
				if err := validateDocumentsStorageTransition(candidate, active); (err == nil) != (kind == "neighbor") {
					t.Fatal("candidate/active managed directory admission changed", err)
				}
				candidate, active = active, candidate
			}
		})
	}
}

func TestOAuthLoginStoreStorageDeferredPathChange(t *testing.T) {
	for _, kind := range []string{"file", "sidecar", "managed_directory", "distinct"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			original, target := filepath.Join(dir, "original"), filepath.Join(dir, "target")
			for _, path := range []string{original, target} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(dir, "alias")
			if err := os.Symlink(original, alias); err != nil {
				t.Fatal(err)
			}
			name := "private.db"
			if kind == "sidecar" {
				name += "-wal"
			}
			opening := filepath.Join(alias, name)
			app := &App{oauthLoginStores: []preparedOAuthLoginStore{oauthStorageTestBinding(t, "shared", opening, 0)}}
			config := &authcrunch.Config{}
			if kind == "managed_directory" {
				config.State = &state.Config{Directory: target}
			} else if kind != "distinct" {
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: filepath.Join(target, "private.db")}}}
			}
			if err := app.prepareStorageInventory(config); err != nil {
				t.Fatal("initial distinct graph was rejected", err)
			}
			physical := app.storageInventory.files[0].path
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			if kind == "distinct" {
				if err := app.validateStorageInventory(config); err != nil || app.storageInventory.files[0].path == physical {
					t.Fatal("accepted opening path did not refresh physical ownership", err)
				}
				return
			}
			app.runtimeConfig = config
			if err := app.Start(); err == nil || strings.Contains(err.Error(), dir) {
				t.Fatal("deferred Start admitted a retargeted unsafe opening path", err)
			}
			if app.server != nil || app.storageInventory.files[0].path != physical {
				t.Fatal("failed admission published a runtime or changed retained ownership")
			}
			for _, path := range []string{original, target} {
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != 0 {
					t.Fatal("rejected deferred Start opened backend storage", err)
				}
			}
		})
	}
}

func TestOAuthLoginStoreStorageRetainsActivePhysicalPath(t *testing.T) {
	dir := t.TempDir()
	owned, replacement, alias := filepath.Join(dir, "owned"), filepath.Join(dir, "replacement"), filepath.Join(dir, "alias")
	for _, path := range []string{owned, replacement} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(owned, alias); err != nil {
		t.Fatal(err)
	}
	old := &App{oauthLoginStores: []preparedOAuthLoginStore{oauthStorageTestBinding(t, "shared", filepath.Join(alias, "private.db"), 0)}}
	if err := old.prepareStorageInventory(&authcrunch.Config{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, alias); err != nil {
		t.Fatal(err)
	}
	candidate := appStorageInventory{files: []identityProviderStorageFile{{path: filepath.Join(owned, "private.db"), sqlite: true}}}
	if validateDocumentsStorageTransition(candidate, *old.storageInventory) == nil {
		t.Fatal("retargeting a logical path discarded the active physical owner")
	}
}
