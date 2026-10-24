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

	"github.com/greenpau/go-authcrunch"
)

type identityProviderStorageFile struct {
	path   string
	ticket bool
	sqlite bool
}

// validateIdentityProviderFiles checks known storage namespaces before live
// backend construction. Secret modules have already read and closed their
// provisioning snapshots. Custom modules own their storage separation contract.
// These checks neither open files nor reserve SQLite as a local snapshot owner.
func (app *App) validateIdentityProviderFiles(config *authcrunch.Config) error {
	var files []identityProviderStorageFile
	for _, binding := range app.identityProviders {
		if module, ok := binding.module.(*SQLiteTicketIdentityProvider); ok && module != nil {
			files = append(files, identityProviderStorageFile{path: module.Path, ticket: true, sqlite: true})
		}
	}
	if len(files) == 0 {
		return nil
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
	return validateTicketStorageFiles(files)
}

func validateTicketStorageFiles(files []identityProviderStorageFile) error {
	paths := make([][]string, len(files))
	for i, file := range files {
		path := file.path
		if file.sqlite {
			// SQLite constructors clean native JSON paths before opening them.
			// Local snapshot/dropbox stores instead open the original path.
			path = filepath.Clean(path)
		}
		base, err := identityFilePath(path)
		if err != nil {
			return fmt.Errorf("ticket identity provider storage path is unavailable")
		}
		paths[i] = []string{base}
		if file.sqlite {
			for _, suffix := range []string{"-journal", "-wal", "-shm"} {
				path, err := identityFilePath(base + suffix)
				if err != nil {
					return fmt.Errorf("ticket identity provider storage sidecar is unavailable")
				}
				paths[i] = append(paths[i], path)
			}
		}
	}
	for i, file := range files {
		for j := 0; j < i; j++ {
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
