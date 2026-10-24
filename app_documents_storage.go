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

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

type documentsStorageBinding struct {
	protocol, portal, origin, mount string
}

// Detached scalar paths remain available through request drain. No reference to
// mutable module configuration, realm slices or declarative JSON is retained.
type appStorageInventory struct {
	files       []identityProviderStorageFile
	directories []string
}

func (app *App) prepareStorageInventory(config *authcrunch.Config) error {
	inventory := appStorageInventory{files: app.configuredStorageFiles(config)}
	if config != nil {
		for _, portal := range config.AuthenticationPortals {
			if portal == nil || portal.API == nil || !portal.API.DocumentsEnabled {
				continue
			}
			if portal.Documents == nil {
				return fmt.Errorf("documents API storage configuration is unavailable")
			}
			c := portal.Documents
			inventory.files = append(inventory.files, identityProviderStorageFile{
				path: c.Database, sqlite: true, documents: true,
				binding: documentsStorageBinding{documents.Protocol, portal.Name, c.PublicOrigin, c.BasePath},
			})
		}
		if config.State != nil {
			inventory.directories = append(inventory.directories, config.State.Directory)
		}
	}
	if app.OAuthRegistrationStore != nil {
		inventory.directories = append(inventory.directories, app.OAuthRegistrationStore.Path)
	}
	// Remember physical paths where available, including existing ancestors of
	// future files. Failure here does not introduce new policy for unrelated
	// modules; comparisons involving Documents enforce availability below.
	for i, file := range inventory.files {
		if paths, err := storageFileNamespace(file); err == nil {
			inventory.files[i].path = paths[0]
		}
	}
	for i, directory := range inventory.directories {
		if path, err := identityFilePath(directory); err == nil {
			inventory.directories[i] = path
		}
	}
	if err := app.validateDocumentsStorage(inventory); err != nil {
		return err
	}
	app.storageInventory = &inventory
	return nil
}

// validateStorageInventory repeats filesystem identity checks immediately before
// constructors, including deferred Start. Earlier secret/registration snapshots
// have their own provisioning I/O; this checker only reads filesystem metadata.
func (app *App) validateStorageInventory(config *authcrunch.Config) error {
	if app.storageInventory == nil {
		return app.prepareStorageInventory(config)
	}
	return app.validateDocumentsStorage(*app.storageInventory)
}

func (app *App) validateDocumentsStorage(inventory appStorageInventory) error {
	if err := validateDocumentsStorageInventory(inventory); err != nil {
		return err
	}
	current, err := caddy.ActiveContext().AppIfConfigured(appName)
	if err != nil {
		return nil
	}
	old, ok := current.(*App)
	if !ok || old == app {
		return nil
	}
	old.mu.Lock()
	var active appStorageInventory
	if old.storageInventory != nil {
		active.files = slices.Clone(old.storageInventory.files)
		active.directories = slices.Clone(old.storageInventory.directories)
	}
	old.mu.Unlock()
	// Normal Caddy loads are serialized and publish the candidate only after
	// Start succeeds. Do not skip a disposing old app: it may still be draining.
	return validateDocumentsStorageTransition(inventory, active)
}

func validateDocumentsStorageInventory(inventory appStorageInventory) error {
	for i, file := range inventory.files {
		for j := range i {
			if err := validateDocumentsStoragePair(file, inventory.files[j], false); err != nil {
				return err
			}
		}
	}
	return validateDocumentsStorageDirectories(inventory.files, inventory.directories)
}

func validateDocumentsStorageTransition(candidate, active appStorageInventory) error {
	for _, file := range candidate.files {
		for _, old := range active.files {
			if err := validateDocumentsStoragePair(file, old, true); err != nil {
				return err
			}
		}
	}
	if err := validateDocumentsStorageDirectories(candidate.files, active.directories); err != nil {
		return err
	}
	return validateDocumentsStorageDirectories(active.files, candidate.directories)
}

func validateDocumentsStoragePair(first, second identityProviderStorageFile, transition bool) error {
	if !first.documents && !second.documents {
		return nil
	}
	paths, err := storageFileNamespace(first)
	if err != nil {
		return fmt.Errorf("documents API storage namespace is unavailable")
	}
	other, err := storageFileNamespace(second)
	if err != nil {
		return fmt.Errorf("documents API storage namespace is unavailable")
	}
	// Across roots, the same bound SQLite file may be reopened. Hardlink aliases
	// cannot use this exception because their rollback-journal names differ.
	if transition && first.documents && second.documents && paths[0] == other[0] && first.binding == second.binding {
		return nil
	}
	for _, path := range paths {
		for _, existing := range other {
			if sameIdentityFile(path, existing) {
				return fmt.Errorf("documents API requires a distinct database and sidecar namespace")
			}
		}
	}
	return nil
}

func validateDocumentsStorageDirectories(files []identityProviderStorageFile, directories []string) error {
	for _, file := range files {
		if !file.documents {
			continue
		}
		paths, err := storageFileNamespace(file)
		if err != nil {
			return fmt.Errorf("documents API storage namespace is unavailable")
		}
		for _, directory := range directories {
			root, err := identityFilePath(directory)
			if err != nil {
				return fmt.Errorf("documents API managed storage namespace is unavailable")
			}
			for _, path := range paths {
				// Compare components with the same existing-inode/missing-alias
				// rules as files, rather than treating a sibling prefix as inside.
				for at := path; ; {
					if sameIdentityFile(at, root) {
						return fmt.Errorf("documents API storage must be outside managed state and OAuth registration directories")
					}
					parent := filepath.Dir(at)
					if parent == at {
						break
					}
					at = parent
				}
			}
		}
	}
	return nil
}
