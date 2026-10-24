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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func accessKeyStorageBinding(t *testing.T, path string) preparedAccessSigner {
	t.Helper()
	module := &RSAPSSAccessSigner{Name: "primary", KeyFile: path, KeyID: "current", Issuer: "https://auth.example.test/auth", Audience: "resource"}
	factory, err := module.PrepareAccessSigner()
	if err != nil {
		t.Fatal("cannot prepare access signer fixture", err)
	}
	config, err := factory.AccessSignerConfig()
	if err != nil {
		t.Fatal("cannot describe access signer fixture", err)
	}
	return preparedAccessSigner{config: config, factory: factory}
}

func accessKeyStoragePortal(lines ...string) *authn.PortalConfig {
	return &authn.PortalConfig{Name: "portal", AccessTokenProfile: &kms.AccessTokenProfileConfig{
		Issuer: "https://auth.example.test/auth", Audience: "resource", KeyIDs: []string{"current"}, MaxLifetimeSeconds: 900,
	}, RawCryptoKeyStoreConfig: lines}
}

func accessKeyStorageLine(source, path string) string {
	return cfgutil.EncodeArgs([]string{"crypto", "key", "verify", "from", source, path})
}

func TestAccessKeyStorageInventorySources(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(filepath.Join(keys, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.pem", "nested/two.key", "ignored.txt"} {
		if err := os.WriteFile(filepath.Join(keys, name), []byte("not a cryptographic key"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// KMS does not walk through a symlinked directory. Matching that behavior
	// avoids inventing additional key reads or following an unbounded tree.
	if err := os.Symlink(keys, filepath.Join(keys, "loop")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "nonexistent.pem")
	t.Setenv("AUTHCRUNCH_TEST_KEY_READ_FILE", file)
	t.Setenv("AUTHCRUNCH_TEST_KEY_READ_DIRECTORY", keys)
	for _, source := range []string{"file", "directory", "env_file", "env_directory", "literal", "env_literal"} {
		t.Run(source, func(t *testing.T) {
			var line string
			var expected []string
			switch source {
			case "file":
				line, expected = accessKeyStorageLine("file", file), []string{file}
			case "directory":
				line, expected = accessKeyStorageLine("directory", keys), []string{filepath.Join(keys, "one.pem"), filepath.Join(keys, "nested", "two.key")}
			case "env_file":
				line, expected = "crypto key verify from env AUTHCRUNCH_TEST_KEY_READ_FILE as file", []string{file}
			case "env_directory":
				line, expected = "crypto key verify from env AUTHCRUNCH_TEST_KEY_READ_DIRECTORY as directory", []string{filepath.Join(keys, "one.pem"), filepath.Join(keys, "nested", "two.key")}
			case "literal":
				line = "crypto key verify test-only-literal"
			case "env_literal":
				line = "crypto key verify from env AUTHCRUNCH_TEST_KEY_READ_FILE"
			}
			app := &App{}
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{accessKeyStoragePortal(line)}}
			for _, consumer := range []string{"portal", "policy", "native_kms"} {
				switch consumer {
				case "policy":
					p := config.AuthenticationPortals[0]
					config = &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", AccessTokenProfile: p.AccessTokenProfile, RawCryptoKeyStoreConfig: p.RawCryptoKeyStoreConfig}}}
				case "native_kms":
					p := config.AuthorizationPolicies[0]
					keyStore, err := kms.NewCryptoKeyStoreConfig(p.RawCryptoKeyStoreConfig)
					if err != nil {
						t.Fatal(err)
					}
					keyStore.AccessTokenProfile, p.AccessTokenProfile = p.AccessTokenProfile, nil
					p.CryptoKeyStoreConfig = keyStore
				}
				files, err := app.configuredAccessKeyFiles(config)
				if err != nil {
					t.Fatal("metadata inventory read malformed or absent key contents", err)
				}
				var paths []string
				for _, entry := range files {
					if !entry.keyRead || entry.sqlite || entry.path != entry.openingPath {
						t.Fatal("key-read inventory lost source semantics")
					}
					paths = append(paths, entry.path)
				}
				slices.Sort(paths)
				slices.Sort(expected)
				if !slices.Equal(paths, expected) {
					t.Fatal("inventory differs from actual configured key reads", source, consumer)
				}
			}
		})
	}
	app := &App{accessSigners: []preparedAccessSigner{accessKeyStorageBinding(t, file)}}
	files, err := app.configuredAccessKeyFiles(nil)
	if err != nil || len(files) != 1 || files[0].path != file {
		t.Fatal("unused declared signer was omitted from preflight")
	}
	config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{RawCryptoKeyStoreConfig: []string{accessKeyStorageLine("directory", filepath.Join(dir, "absent"))}}}}
	if _, err := app.configuredAccessKeyFiles(config); err == nil || strings.Contains(err.Error(), dir) {
		t.Fatal("ordinary key directory failure escaped metadata preflight or exposed its path")
	}
}

func TestAccessKeyStorageAliases(t *testing.T) {
	for _, kind := range []string{"same", "hardlink", "symlink", "ancestor", "case", "journal", "wal", "shm", "sidecar_hardlink", "distinct", "keys_only", "non_sqlite"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			db := filepath.Join(dir, "database.pem")
			key := filepath.Join(dir, "private.pem")
			write := func(path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("private database sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			link := func(target, path string, symbolic bool) {
				t.Helper()
				var err error
				if symbolic {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "same", "keys_only", "non_sqlite":
				key = db
			case "hardlink", "symlink":
				write(db)
				link(db, key, kind == "symlink")
			case "ancestor":
				alias := filepath.Join(dir, "alias")
				link(dir, alias, true)
				key = filepath.Join(alias, "database.pem")
			case "case":
				key = filepath.Join(dir, "DATABASE.PEM")
			case "journal", "wal", "shm":
				key = db + "-" + kind
			case "sidecar_hardlink":
				write(db + "-wal")
				link(db+"-wal", key, false)
			}
			first := identityProviderStorageFile{path: key, keyRead: true}
			second := identityProviderStorageFile{path: db, sqlite: true}
			switch kind {
			case "keys_only":
				second.keyRead, second.sqlite = true, false
			case "non_sqlite":
				second.sqlite = false
			}
			allowed := kind == "distinct" || kind == "keys_only" || kind == "non_sqlite"
			for range 2 {
				candidate, active := appStorageInventory{files: []identityProviderStorageFile{first}}, appStorageInventory{files: []identityProviderStorageFile{second}}
				for _, err := range []error{validateDocumentsStorageInventory(appStorageInventory{files: []identityProviderStorageFile{first, second}}), validateDocumentsStorageTransition(candidate, active)} {
					if (err == nil) != allowed || err != nil && strings.Contains(err.Error(), dir) {
						t.Fatal("key reader/storage alias admission changed", err)
					}
				}
				first, second = second, first
			}
		})
	}
}

func TestAccessKeyStorageBundledCategories(t *testing.T) {
	for _, category := range []string{"identity", "ticket", "messaging", "registration", "credential", "secret", "oauth", "documents"} {
		t.Run(category, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "shared.pem")
			app := &App{accessSigners: []preparedAccessSigner{accessKeyStorageBinding(t, path)}}
			config := &authcrunch.Config{}
			switch category {
			case "identity":
				app.identityStores = []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: path}}}
			case "ticket":
				app.identityProviders = []preparedIdentityProvider{{module: &SQLiteTicketIdentityProvider{Path: path}}}
			case "messaging":
				app.messagingProviders = []preparedMessagingProvider{{module: &SQLiteMessagingProvider{Path: path}}}
			case "registration":
				app.registrationWorkflows = []preparedRegistrationWorkflow{{module: &SQLiteRegistrationWorkflow{Path: path}}}
			case "credential":
				app.credentialAuthenticators = []preparedCredentialAuthenticator{{module: &SQLiteCredentialAuthenticator{Path: path}}}
			case "secret":
				app.secretsManagers = []SecretsManager{&SQLiteSecretsManager{Path: path}}
			case "oauth":
				app.oauthLoginStores = []preparedOAuthLoginStore{oauthStorageTestBinding(t, "shared", path, 0)}
			case "documents":
				config.AuthenticationPortals = []*authn.PortalConfig{documentsStorageTestPortal(path)}
			}
			if err := app.prepareStorageInventory(config); err == nil || !strings.Contains(err.Error(), "distinct SQLite") || strings.Contains(err.Error(), dir) {
				t.Fatal("bundled SQLite/key alias escaped preflight", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("preflight opened storage or a key", err)
			}
		})
	}
}

type accessKeyReadCounterFactory struct {
	config kms.ExternalAccessSignerConfig
	calls  *atomic.Int32
}

func (f *accessKeyReadCounterFactory) AccessSignerConfig() (kms.ExternalAccessSignerConfig, error) {
	return f.config, nil
}

func (f *accessKeyReadCounterFactory) NewAccessSigner(context.Context) (kms.AccessSigner, error) {
	f.calls.Add(1)
	return nil, fmt.Errorf("test constructor must not run")
}

func TestAccessKeyStorageDeferredAdmission(t *testing.T) {
	for _, change := range []string{"private_ancestor", "public_ancestor", "env_file", "env_directory", "new_directory_entry"} {
		t.Run(change, func(t *testing.T) {
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
			database := filepath.Join(target, "database.pem")
			if err := os.WriteFile(database, []byte("private database sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			private := filepath.Join(original, "private.pem")
			if change == "private_ancestor" {
				private = filepath.Join(alias, "database.pem")
			}
			binding := accessKeyStorageBinding(t, private)
			var calls atomic.Int32
			counter := binding.config
			counter.Name = "counter"
			app := &App{accessSigners: []preparedAccessSigner{{config: counter, factory: &accessKeyReadCounterFactory{config: counter, calls: &calls}}, binding},
				identityStores: []preparedIdentityStore{{module: &SQLiteIdentityStore{Path: database}}}}
			config := &authcrunch.Config{}
			switch change {
			case "public_ancestor":
				config.AuthenticationPortals = []*authn.PortalConfig{accessKeyStoragePortal(accessKeyStorageLine("file", filepath.Join(alias, "database.pem")))}
			case "env_file":
				t.Setenv("AUTHCRUNCH_TEST_DEFERRED_KEY", filepath.Join(original, "public.pem"))
				config.AuthenticationPortals = []*authn.PortalConfig{accessKeyStoragePortal("crypto key verify from env AUTHCRUNCH_TEST_DEFERRED_KEY as file")}
			case "env_directory":
				t.Setenv("AUTHCRUNCH_TEST_DEFERRED_KEY", original)
				config.AuthenticationPortals = []*authn.PortalConfig{accessKeyStoragePortal("crypto key verify from env AUTHCRUNCH_TEST_DEFERRED_KEY as directory")}
			case "new_directory_entry":
				config.AuthenticationPortals = []*authn.PortalConfig{accessKeyStoragePortal(accessKeyStorageLine("directory", original))}
			}
			if err := app.prepareStorageInventory(config); err != nil {
				t.Fatal("initial distinct graph rejected", err)
			}
			before := slices.Clone(app.storageInventory.files)
			switch change {
			case "private_ancestor", "public_ancestor":
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
			case "env_file":
				t.Setenv("AUTHCRUNCH_TEST_DEFERRED_KEY", database)
			case "env_directory":
				t.Setenv("AUTHCRUNCH_TEST_DEFERRED_KEY", target)
			case "new_directory_entry":
				if err := os.Link(database, filepath.Join(original, "added.key")); err != nil {
					t.Fatal(err)
				}
			}
			app.runtimeConfig = config
			err := app.Start()
			if err == nil || !strings.Contains(err.Error(), "distinct SQLite") || strings.Contains(err.Error(), dir) {
				t.Fatal("deferred key reader was not rejected by metadata preflight", err)
			}
			if calls.Load() != 0 || app.server != nil || !slices.Equal(before, app.storageInventory.files) {
				t.Fatal("rejected preflight invoked a constructor or published ownership")
			}
		})
	}
}

func TestAccessKeyStorageRetainsActivePhysicalPath(t *testing.T) {
	dir := t.TempDir()
	owned, replacement := filepath.Join(dir, "owned"), filepath.Join(dir, "replacement")
	for _, path := range []string{owned, replacement} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(owned, alias); err != nil {
		t.Fatal(err)
	}
	app := &App{accessSigners: []preparedAccessSigner{accessKeyStorageBinding(t, filepath.Join(alias, "private.pem"))}}
	if err := app.prepareStorageInventory(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, alias); err != nil {
		t.Fatal(err)
	}
	candidate := appStorageInventory{files: []identityProviderStorageFile{{path: filepath.Join(owned, "private.pem"), sqlite: true}}}
	if validateDocumentsStorageTransition(candidate, *app.storageInventory) == nil {
		t.Fatal("active key reader lost its physical ownership before drain")
	}
}
