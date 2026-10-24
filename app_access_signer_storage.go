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
	"io/fs"
	"path/filepath"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

// configuredAccessKeyFiles reads metadata only. Opening and then closing even a
// rejected PEM can release process-wide SQLite locks if it aliases a database.
// Inspect every actual KMS read in a selected consumer, including unrelated
// explicit verifier/system keys, because construction loads those entries too.
func (app *App) configuredAccessKeyFiles(config *authcrunch.Config) ([]identityProviderStorageFile, error) {
	var files []identityProviderStorageFile
	addFile := func(path string) {
		files = append(files, identityProviderStorageFile{path: path, openingPath: path, keyRead: true})
	}
	for _, binding := range app.accessSigners {
		if factory, ok := binding.factory.(*rsapssAccessSignerFactory); ok && factory != nil {
			addFile(factory.signingConfig().KeyFile)
		}
	}
	addKeys := func(keyStore *kms.CryptoKeyStoreConfig, raw []string) error {
		if keyStore == nil {
			var err error
			keyStore, err = kms.NewCryptoKeyStoreConfig(raw)
			if err != nil {
				return fmt.Errorf("access key configuration is unavailable")
			}
		}
		keys, err := kms.ParseCryptoKeyConfigs(keyStore.RawKeyConfigs)
		if err != nil {
			return fmt.Errorf("access key configuration is unavailable")
		}
		for _, key := range keys {
			var path string
			var directory bool
			switch key.Source {
			case "config":
				if key.Algorithm == "hmac" || key.Algorithm == "XChaCha20-Poly1305" {
					continue
				}
				if key.FilePath != "" {
					path = key.FilePath
				} else {
					path, directory = key.DirPath, true
				}
			case "env":
				switch key.EnvVarType {
				case "file":
					path = key.EnvVarValue
				case "directory":
					path, directory = key.EnvVarValue, true
				}
			}
			if path == "" {
				continue
			}
			if !directory {
				addFile(path)
				continue
			}
			// Match KMS's metadata walk: recurse real directories, not directory
			// symlinks, and select its supported extensions before reading files.
			if err := filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && (filepath.Ext(path) == ".pem" || filepath.Ext(path) == ".key") {
					addFile(path)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("access key directory is unavailable")
			}
		}
		return nil
	}
	if config != nil {
		for _, portal := range config.AuthenticationPortals {
			if portal != nil && (portal.AccessSigner != "" || portal.AccessTokenProfile != nil || portal.CryptoKeyStoreConfig != nil && portal.CryptoKeyStoreConfig.AccessTokenProfile != nil) {
				if err := addKeys(portal.CryptoKeyStoreConfig, portal.RawCryptoKeyStoreConfig); err != nil {
					return nil, err
				}
			}
		}
		for _, policy := range config.AuthorizationPolicies {
			if policy != nil && (policy.AccessTokenProfile != nil || policy.CryptoKeyStoreConfig != nil && policy.CryptoKeyStoreConfig.AccessTokenProfile != nil) {
				if err := addKeys(policy.CryptoKeyStoreConfig, policy.RawCryptoKeyStoreConfig); err != nil {
					return nil, err
				}
			}
		}
	}
	return files, nil
}

func validateAccessKeyStorageInventory(inventory appStorageInventory) error {
	for i, file := range inventory.files {
		if file.keyRead {
			if _, err := storageFileNamespace(file); err != nil {
				return fmt.Errorf("access key storage namespace is unavailable")
			}
		}
		for j := range i {
			if err := validateAccessKeyStoragePair(file, inventory.files[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAccessKeyStorageTransition(candidate, active appStorageInventory) error {
	for _, file := range candidate.files {
		for _, old := range active.files {
			if err := validateAccessKeyStoragePair(file, old); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAccessKeyStoragePair(first, second identityProviderStorageFile) error {
	if !(first.keyRead && second.sqlite || second.keyRead && first.sqlite) {
		return nil
	}
	paths, err := storageFileNamespace(first)
	if err != nil {
		return fmt.Errorf("access key storage namespace is unavailable")
	}
	other, err := storageFileNamespace(second)
	if err != nil {
		return fmt.Errorf("access key storage namespace is unavailable")
	}
	for _, path := range paths {
		for _, existing := range other {
			if sameIdentityFile(path, existing) {
				return fmt.Errorf("access key readers require a distinct SQLite database and sidecar namespace")
			}
		}
	}
	return nil
}
