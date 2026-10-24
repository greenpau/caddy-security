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
	"fmt"
	"path/filepath"
	"slices"

	"github.com/greenpau/go-authcrunch"
)

type identityProviderStorageFile struct {
	path        string
	openingPath string
	keyRead     bool
	oauth       bool
	capacity    int
	ticket      bool
	sqlite      bool
	documents   bool
	binding     documentsStorageBinding
}

// validateIdentityProviderFiles checks known storage namespaces before live
// backend construction. Secret modules have already read and closed their
// provisioning snapshots. Custom modules own their storage separation contract.
// These checks neither open files nor reserve SQLite as a local snapshot owner.
func (app *App) validateIdentityProviderFiles(config *authcrunch.Config) error {
	return validateTicketStorageFiles(app.configuredStorageFiles(config))
}

// configuredStorageFiles copies scalar paths without opening any backend. Keep
// every bundled category even when no ticket is configured: a Documents portal
// in a later candidate must also protect the currently serving storage graph.
func (app *App) configuredStorageFiles(config *authcrunch.Config) []identityProviderStorageFile {
	var files []identityProviderStorageFile
	for _, binding := range app.oauthLoginStores {
		if factory, ok := binding.factory.(*sqliteOAuthLoginStoreFactory); ok && factory != nil {
			config := factory.sqliteConfig()
			files = append(files, identityProviderStorageFile{path: config.Path, sqlite: true, oauth: true, capacity: config.Capacity})
		}
	}
	for _, binding := range app.identityProviders {
		if module, ok := binding.module.(*SQLiteTicketIdentityProvider); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, ticket: true, sqlite: true})
		}
	}
	for _, binding := range app.identityStores {
		if module, ok := binding.module.(*SQLiteIdentityStore); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, sqlite: true})
		}
	}
	for _, binding := range app.messagingProviders {
		if module, ok := binding.module.(*SQLiteMessagingProvider); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, sqlite: true})
		}
	}
	for _, binding := range app.registrationWorkflows {
		if module, ok := binding.module.(*SQLiteRegistrationWorkflow); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, sqlite: true})
		}
	}
	for _, binding := range app.credentialAuthenticators {
		if module, ok := binding.module.(*SQLiteCredentialAuthenticator); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, sqlite: true})
		}
	}
	for _, manager := range app.secretsManagers {
		if module, ok := manager.(*SQLiteSecretsManager); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, sqlite: true})
		}
	}
	if config != nil {
		for _, store := range config.IdentityStores {
			if store != nil && store.Kind == "local" {
				path, _ := store.Params["path"].(string)
				if path != ":memory:" {
					files = append(files, identityProviderStorageFile{path: path})
				}
			}
		}
		if config.UserRegistration != nil {
			for _, provider := range config.UserRegistration.LocalProviders {
				if provider != nil && provider.Dropbox != ":memory:" {
					files = append(files, identityProviderStorageFile{path: provider.Dropbox})
				}
			}
		}
	}
	return files
}

func validateTicketStorageFiles(files []identityProviderStorageFile) error {
	if !slices.ContainsFunc(files, func(file identityProviderStorageFile) bool { return file.ticket }) {
		return nil
	}
	paths := make([][]string, len(files))
	for i, file := range files {
		var err error
		paths[i], err = storageFileNamespace(file)
		if err != nil {
			return fmt.Errorf("ticket identity provider storage namespace is unavailable")
		}
	}
	for i, file := range files {
		for j := range i {
			if !file.ticket && !files[j].ticket {
				continue
			}
			// Compatible ticket configurations can share one canonical file.
			// Different hardlink names cannot safely share rollback journals.
			if file.ticket && files[j].ticket && paths[i][0] == paths[j][0] {
				continue
			}
			for _, path := range paths[i] {
				for _, other := range paths[j] {
					if sameIdentityFile(path, other) {
						return fmt.Errorf("ticket identity provider requires a distinct database and sidecar namespace")
					}
				}
			}
		}
	}
	return nil
}

// storageFileNamespace matches constructor path semantics, including SQLite's
// lexical normalization before opening. Local snapshot stores open raw paths.
func storageFileNamespace(file identityProviderStorageFile) ([]string, error) {
	path := file.path
	if file.sqlite {
		path = filepath.Clean(path)
	}
	base, err := identityFilePath(path)
	if err != nil {
		return nil, err
	}
	paths := []string{base}
	if file.sqlite {
		for _, suffix := range []string{"-journal", "-wal", "-shm"} {
			sidecar, err := identityFilePath(base + suffix)
			if err != nil {
				return nil, err
			}
			paths = append(paths, sidecar)
		}
	}
	return paths, nil
}
