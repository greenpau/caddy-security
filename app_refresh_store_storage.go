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
	"path/filepath"
)

func validateRefreshStoreStorageInventory(inventory appStorageInventory) error {
	for i, file := range inventory.files {
		if file.refresh {
			if _, err := storageFileNamespace(file); err != nil {
				return fmt.Errorf("refresh storage namespace is unavailable")
			}
		}
		for j := range i {
			if err := validateRefreshStoreStoragePair(file, inventory.files[j]); err != nil {
				return err
			}
		}
	}
	return validateRefreshStoreStorageDirectories(inventory.files, inventory.directories)
}

func validateRefreshStoreStorageTransition(candidate, active appStorageInventory) error {
	for _, file := range candidate.files {
		for _, old := range active.files {
			if err := validateRefreshStoreStoragePair(file, old); err != nil {
				return err
			}
		}
	}
	if err := validateRefreshStoreStorageDirectories(candidate.files, active.directories); err != nil {
		return err
	}
	return validateRefreshStoreStorageDirectories(active.files, candidate.directories)
}

func validateRefreshStoreStoragePair(first, second identityProviderStorageFile) error {
	if !first.refresh && !second.refresh {
		return nil
	}
	paths, err := storageFileNamespace(first)
	if err != nil {
		return fmt.Errorf("refresh storage namespace is unavailable")
	}
	other, err := storageFileNamespace(second)
	if err != nil {
		return fmt.Errorf("refresh storage namespace is unavailable")
	}
	if first.refresh && second.refresh && paths[0] == other[0] {
		if first.maxSessions != second.maxSessions || first.maxRotations != second.maxRotations {
			return fmt.Errorf("shared refresh storage requires matching session and rotation limits")
		}
		return nil
	}
	// Distinct hardlink names cannot share SQLite journal namespaces safely.
	for _, path := range paths {
		for _, existing := range other {
			if sameIdentityFile(path, existing) {
				return fmt.Errorf("refresh storage requires a distinct database and sidecar namespace")
			}
		}
	}
	return nil
}

func validateRefreshStoreStorageDirectories(files []identityProviderStorageFile, directories []string) error {
	for _, file := range files {
		if !file.refresh {
			continue
		}
		paths, err := storageFileNamespace(file)
		if err != nil {
			return fmt.Errorf("refresh storage namespace is unavailable")
		}
		for _, directory := range directories {
			root, err := identityFilePath(directory)
			if err != nil {
				return fmt.Errorf("refresh managed storage namespace is unavailable")
			}
			for _, path := range paths {
				for at := path; ; {
					if sameIdentityFile(at, root) {
						return fmt.Errorf("refresh storage must be outside managed state and OAuth registration directories")
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
