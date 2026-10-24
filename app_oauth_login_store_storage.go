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
	"slices"
)

// Retain both the immutable constructor path and its resolved ownership path.
// Rechecking only the latter misses a retargeted ancestor symlink before Start.
// This is metadata admission, not a promise against filesystem replacement
// after admission. Operators must keep serving storage paths stable.
func refreshStorageInventory(original appStorageInventory) appStorageInventory {
	inventory := appStorageInventory{
		files:              slices.Clone(original.files),
		directories:        slices.Clone(original.directories),
		openingDirectories: slices.Clone(original.openingDirectories),
	}
	for i, file := range inventory.files {
		if file.openingPath != "" {
			file.path = file.openingPath
		}
		inventory.files[i] = file
		if paths, err := storageFileNamespace(file); err == nil {
			inventory.files[i].path = paths[0]
		}
	}
	for i, opening := range inventory.openingDirectories {
		inventory.directories[i] = opening
		if path, err := identityFilePath(opening); err == nil {
			inventory.directories[i] = path
		}
	}
	return inventory
}

func validateOAuthLoginStoreStorageInventory(inventory appStorageInventory) error {
	for i, file := range inventory.files {
		if file.oauth {
			if _, err := storageFileNamespace(file); err != nil {
				return fmt.Errorf("OAuth login storage namespace is unavailable")
			}
		}
		for j := range i {
			if err := validateOAuthLoginStoreStoragePair(file, inventory.files[j]); err != nil {
				return err
			}
		}
	}
	return validateOAuthLoginStoreStorageDirectories(inventory.files, inventory.directories)
}

func validateOAuthLoginStoreStorageTransition(candidate, active appStorageInventory) error {
	for _, file := range candidate.files {
		for _, old := range active.files {
			if err := validateOAuthLoginStoreStoragePair(file, old); err != nil {
				return err
			}
		}
	}
	if err := validateOAuthLoginStoreStorageDirectories(candidate.files, active.directories); err != nil {
		return err
	}
	return validateOAuthLoginStoreStorageDirectories(active.files, candidate.directories)
}

func validateOAuthLoginStoreStoragePair(first, second identityProviderStorageFile) error {
	if !first.oauth && !second.oauth {
		return nil
	}
	paths, err := storageFileNamespace(first)
	if err != nil {
		return fmt.Errorf("OAuth login storage namespace is unavailable")
	}
	other, err := storageFileNamespace(second)
	if err != nil {
		return fmt.Errorf("OAuth login storage namespace is unavailable")
	}
	if first.oauth && second.oauth && paths[0] == other[0] {
		if first.capacity != second.capacity {
			return fmt.Errorf("shared OAuth login storage requires matching capacity")
		}
		return nil
	}
	// Distinct hardlink names cannot share SQLite journal namespaces safely.
	for _, path := range paths {
		for _, existing := range other {
			if sameIdentityFile(path, existing) {
				return fmt.Errorf("OAuth login storage requires a distinct database and sidecar namespace")
			}
		}
	}
	return nil
}

func validateOAuthLoginStoreStorageDirectories(files []identityProviderStorageFile, directories []string) error {
	for _, file := range files {
		if !file.oauth {
			continue
		}
		paths, err := storageFileNamespace(file)
		if err != nil {
			return fmt.Errorf("OAuth login storage namespace is unavailable")
		}
		for _, directory := range directories {
			root, err := identityFilePath(directory)
			if err != nil {
				return fmt.Errorf("OAuth login managed storage namespace is unavailable")
			}
			for _, path := range paths {
				for at := path; ; {
					if sameIdentityFile(at, root) {
						return fmt.Errorf("OAuth login storage must be outside managed state and OAuth registration directories")
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
