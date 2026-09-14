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
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/greenpau/go-authcrunch"
	"golang.org/x/text/unicode/norm"
)

// identityFileOwners coordinates this process only. A local AuthCrunch store
// holds a database snapshot, so even serialized writes from separate stores can
// lose updates. Reserve the entire lifetime, including construction and drain.
var identityFileOwners = struct {
	sync.Mutex
	paths map[string]bool
}{paths: make(map[string]bool)}

func reserveIdentityFiles(config *authcrunch.Config) ([]string, error) {
	identityFileOwners.Lock()
	defer identityFileOwners.Unlock()
	var paths []string
	addPath := func(path, owner string) error {
		if path == ":memory:" {
			return nil
		}
		path, err := identityFilePath(path)
		if err != nil {
			return fmt.Errorf("%s path: %w", owner, err)
		}
		for reserved := range identityFileOwners.paths {
			if sameIdentityFile(path, reserved) {
				return fmt.Errorf("identity file %q already belongs to a security runtime; overlapping local file reload requires AuthCrunch database coordination; stop the previous runtime before reusing this file", path)
			}
		}
		for _, other := range paths {
			if sameIdentityFile(path, other) {
				return fmt.Errorf("identity file %q is used by multiple stores or registration providers; use distinct files and share named providers across portals", path)
			}
		}
		paths = append(paths, path)
		return nil
	}
	for _, store := range config.IdentityStores {
		if store.Kind != "local" {
			continue
		}
		path, _ := store.Params["path"].(string)
		if err := addPath(path, fmt.Sprintf("identity store %q", store.Name)); err != nil {
			return nil, err
		}
	}
	if config.UserRegistration != nil {
		for _, provider := range config.UserRegistration.LocalProviders {
			if err := addPath(provider.Dropbox, fmt.Sprintf("registration provider %q", provider.Name)); err != nil {
				return nil, err
			}
		}
	}
	for _, path := range paths {
		identityFileOwners.paths[path] = true
	}
	return paths, nil
}

func releaseIdentityFiles(paths []string) {
	identityFileOwners.Lock()
	defer identityFileOwners.Unlock()
	for _, path := range paths {
		delete(identityFileOwners.paths, path)
	}
}

// Resolve existing ancestors too: a not-yet-created database can be addressed
// through a symlink to its parent. External path replacement remains outside
// this in-process reservation contract.
func identityFilePath(path string) (string, error) {
	// EvalSymlinks must precede Abs/Clean: link/../file follows the link
	// before traversing its parent when AuthCrunch opens the original path.
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return filepath.Abs(resolved)
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	// An existing symlink with a missing target cannot be treated as a new
	// ordinary file. Reject it before construction can write through the link.
	if _, statErr := os.Lstat(path); statErr == nil {
		return "", fmt.Errorf("cannot resolve identity path %q: %w", path, err)
	} else if !os.IsNotExist(statErr) {
		return "", statErr
	}
	parent, base := filepath.Split(path)
	if base == "" || base == "." || base == ".." {
		return "", err
	}
	if parent == "" {
		parent = "."
	} else {
		// Split keeps every trailing separator. Remove them before recursing
		// into a missing directory, but retain the separator of a volume root.
		for len(parent) > len(filepath.VolumeName(parent))+1 && os.IsPathSeparator(parent[len(parent)-1]) {
			parent = parent[:len(parent)-1]
		}
	}
	parent, err = identityFilePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, base), nil
}

func sameIdentityFile(a, b string) bool {
	if a == b {
		return true
	}
	first, firstErr := os.Stat(a)
	second, secondErr := os.Stat(b)
	if firstErr == nil && secondErr == nil {
		return os.SameFile(first, second)
	}
	// Before construction, inode comparison cannot identify case or Unicode
	// normalization aliases. Be conservative for missing files on every
	// filesystem; known distinct existing files are handled by SameFile above.
	return (os.IsNotExist(firstErr) || os.IsNotExist(secondErr)) && strings.EqualFold(norm.NFC.String(a), norm.NFC.String(b))
}
