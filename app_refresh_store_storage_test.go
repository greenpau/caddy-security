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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func refreshStorageTestBinding(t *testing.T, name, path string, capacity int, rotations ...int) preparedRefreshStore {
	t.Helper()
	module := &SQLiteRefreshStore{Name: name, Path: path, MaxSessions: capacity}
	if len(rotations) > 0 {
		module.MaxRotations = rotations[0]
	}
	factory, err := module.PrepareRefreshStore()
	if err != nil {
		t.Fatal("cannot prepare refresh storage fixture", err)
	}
	descriptor, err := factory.RefreshStoreConfig()
	if err != nil {
		t.Fatal("cannot describe refresh storage fixture", err)
	}
	return preparedRefreshStore{config: descriptor, factory: factory}
}

func refreshStorageTestFile(path string) identityProviderStorageFile {
	return identityProviderStorageFile{path: path, sqlite: true, refresh: true, maxSessions: 10000, maxRotations: 1024}
}

func TestRefreshStoreStorageCategories(t *testing.T) {
	for _, category := range []string{"ticket", "identity", "messaging", "registration", "credential", "secret", "local", "dropbox", "documents", "same_refresh", "different_capacity", "different_rotations", "oauth", "key", "distinct", "memory"} {
		t.Run(category, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "logins.db")
			app := &App{refreshStores: []preparedRefreshStore{refreshStorageTestBinding(t, "shared", path, 0)}}
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
			case "oauth":
				app.oauthLoginStores = []preparedOAuthLoginStore{oauthStorageTestBinding(t, "other", path, 0)}
			case "key":
				config.AuthenticationPortals = []*authn.PortalConfig{{Name: "portal", RawCryptoKeyStoreConfig: []string{"crypto key current verify from file " + path}}}
			case "same_refresh", "different_capacity", "different_rotations":
				capacity := 10000
				if category == "different_capacity" {
					capacity = 1
				}
				rotations := 1024
				if category == "different_rotations" {
					rotations = 3
				}
				app.refreshStores = append(app.refreshStores, refreshStorageTestBinding(t, "peer", path, capacity, rotations))
			case "distinct":
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: filepath.Join(dir, "accounts.db")}}}
			case "memory":
				config.IdentityStores = []*ids.IdentityStoreConfig{{Kind: "local", Params: map[string]any{"path": ":memory:"}}}
				config.UserRegistration = &registry.Config{LocalProviders: []*registry.LocalUserRegistryProvider{{Dropbox: ":memory:"}}}
			}
			err := app.prepareStorageInventory(config)
			allowed := category == "same_refresh" || category == "distinct" || category == "memory"
			if (err == nil) != allowed || err != nil && strings.Contains(err.Error(), dir) {
				t.Fatal("refresh storage category admission or path redaction changed", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("storage preflight created a file", err)
			}
		})
	}
}

func TestRefreshStoreStorageAliases(t *testing.T) {
	for _, kind := range []string{"same", "hardlink", "refresh_hardlink", "symlink", "ancestor_symlink", "case_alias", "journal", "wal", "shm", "reverse_sidecar", "sidecar_hardlink", "refresh_sidecar", "shared", "shared_symlink", "capacity", "rotations", "dangling", "distinct", "unrelated"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			first := refreshStorageTestFile(filepath.Join(dir, "logins.db"))
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
			case "hardlink", "refresh_hardlink":
				writeSentinel(first.path)
				if err := os.Link(first.path, second.path); err != nil {
					t.Fatal(err)
				}
				second.refresh, second.maxSessions, second.maxRotations = kind == "refresh_hardlink", first.maxSessions, first.maxRotations
			case "symlink", "shared_symlink":
				writeSentinel(first.path)
				if err := os.Symlink(first.path, second.path); err != nil {
					t.Fatal(err)
				}
				second.refresh, second.maxSessions, second.maxRotations = kind == "shared_symlink", first.maxSessions, first.maxRotations
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
			case "refresh_sidecar":
				second = refreshStorageTestFile(first.path + "-journal")
			case "shared", "capacity", "rotations":
				second = first
				if kind == "capacity" {
					second.maxSessions = 1
				}
				if kind == "rotations" {
					second.maxRotations = 1
				}
			case "dangling":
				if err := os.Symlink(filepath.Join(dir, "absent"), second.path); err != nil {
					t.Fatal(err)
				}
			case "unrelated":
				first.refresh = false
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
						t.Fatal("refresh alias or candidate/active transition changed", err)
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

func TestRefreshStoreStorageDirectories(t *testing.T) {
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
				inventory := appStorageInventory{files: []identityProviderStorageFile{refreshStorageTestFile(path), {path: inside}}}
				if validateDocumentsStorageInventory(inventory) == nil {
					t.Fatal("known managed file hardlink escaped isolation")
				}
				return
			case "neighbor":
				path = filepath.Join(managed+"-neighbor", "logins.db")
			}
			app := &App{refreshStores: []preparedRefreshStore{refreshStorageTestBinding(t, "shared", path, 0)}}
			config := &authcrunch.Config{}
			if kind == "registration" {
				app.OAuthRegistrationStore = &OAuthRegistrationStoreConfig{Path: managed}
			} else {
				config.State = &state.Config{Directory: managed}
			}
			if err := app.prepareStorageInventory(config); (err == nil) != (kind == "neighbor") {
				t.Fatal("managed directory admission changed", err)
			}
			candidate, active := appStorageInventory{files: []identityProviderStorageFile{refreshStorageTestFile(path)}}, appStorageInventory{directories: []string{managed}}
			for range 2 {
				if err := validateDocumentsStorageTransition(candidate, active); (err == nil) != (kind == "neighbor") {
					t.Fatal("candidate/active managed directory admission changed", err)
				}
				candidate, active = active, candidate
			}
		})
	}
}

func TestRefreshStoreStorageDeferredPathChange(t *testing.T) {
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
			app := &App{refreshStores: []preparedRefreshStore{refreshStorageTestBinding(t, "shared", opening, 0)}}
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

func TestRefreshStoreStorageRetainsActivePhysicalPath(t *testing.T) {
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
	old := &App{refreshStores: []preparedRefreshStore{refreshStorageTestBinding(t, "shared", filepath.Join(alias, "private.db"), 0)}}
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

// A replacement may remove all refresh declarations while its ordinary KMS
// reader would still open the active application's database during construction.
// Preserve both graphs, including consumers without a strict token profile.
func TestRefreshStoreStorageOrdinaryKeyTransition(t *testing.T) {
	for _, role := range []string{"portal", "policy"} {
		for _, native := range []bool{false, true} {
			for _, distinct := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/native=%v/distinct=%v", role, native, distinct), func(t *testing.T) {
					dir := t.TempDir()
					database := filepath.Join(dir, "refresh.db")
					active := &App{refreshStores: []preparedRefreshStore{refreshStorageTestBinding(t, "shared", database, 0)}}
					if err := active.prepareStorageInventory(&authcrunch.Config{}); err != nil {
						t.Fatal("cannot prepare active refresh inventory", err)
					}
					keyPath := database
					if distinct {
						keyPath = filepath.Join(dir, "public.pem")
					}
					raw := []string{fmt.Sprintf("crypto key current verify from file %q", keyPath)}
					config := &authcrunch.Config{}
					if role == "portal" {
						portal := &authn.PortalConfig{Name: "ordinary", RawCryptoKeyStoreConfig: raw}
						if native {
							var err error
							portal.CryptoKeyStoreConfig, err = kms.NewCryptoKeyStoreConfig(raw)
							if err != nil {
								t.Fatal("cannot prepare native KMS declaration", err)
							}
							portal.RawCryptoKeyStoreConfig = nil
						}
						config.AuthenticationPortals = []*authn.PortalConfig{portal}
					} else {
						policy := &authz.PolicyConfig{Name: "ordinary", RawCryptoKeyStoreConfig: raw}
						if native {
							var err error
							policy.CryptoKeyStoreConfig, err = kms.NewCryptoKeyStoreConfig(raw)
							if err != nil {
								t.Fatal("cannot prepare native KMS declaration", err)
							}
							policy.RawCryptoKeyStoreConfig = nil
						}
						config.AuthorizationPolicies = []*authz.PolicyConfig{policy}
					}
					candidate := &App{} // removal: no managed refresh declaration
					if err := candidate.prepareStorageInventory(config); err != nil {
						t.Fatal("ordinary metadata declaration rejected", err)
					}
					if len(candidate.storageInventory.files) != 1 || !candidate.storageInventory.files[0].keyRead {
						t.Fatal("ordinary key reader was omitted from replacement inventory")
					}
					first, second := *candidate.storageInventory, *active.storageInventory
					for range 2 {
						if err := validateDocumentsStorageTransition(first, second); (err == nil) != distinct || err != nil && strings.Contains(err.Error(), dir) {
							t.Fatal("key reader versus active refresh transition changed", err)
						}
						first, second = second, first
					}
					if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
						t.Fatal("key transition metadata check opened storage", err)
					}
				})
			}
		}
	}
}
