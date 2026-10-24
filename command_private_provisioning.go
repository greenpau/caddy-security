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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unicode/utf8"
)

// Reuse the private registration store's no-symlink, ownership and file checks.
// The returned root bounds reads/publication; callers close it after use.
func privateProvisioningRoot(ctx context.Context, filename string) (*os.Root, string, error) {
	if runtime.GOOS == "windows" {
		return nil, "", fmt.Errorf("private provisioning requires a local POSIX filesystem")
	}
	if filename == "" || filepath.Clean(filename) != filename {
		return nil, "", fmt.Errorf("a clean private provisioning file path is required")
	}
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, "", fmt.Errorf("invalid private provisioning path")
	}
	if err := checkRegistrationDirectory(ctx, filepath.Dir(absolute), true); err != nil {
		return nil, "", fmt.Errorf("provisioning files require a private directory and trusted ancestors")
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, "", fmt.Errorf("cannot open private provisioning directory")
	}
	return root, filepath.Base(absolute), nil
}

func readPrivateProvisioningFile(ctx context.Context, filename string) ([]byte, error) {
	root, name, err := privateProvisioningRoot(ctx, filename)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := (&oauthRegistrationStore{root: root}).read(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("cannot read private provisioning input")
	}
	return data, nil
}

// Decode trusted command input separately from Caddy's generic JSON tree.
// Preserve exact numbers and reject duplicate keys, invalid UTF-8/surrogates,
// extra documents and oversized/deep graphs before any storage mutation.
func parsePrivateProvisioningJSON(data []byte) (map[string]any, error) {
	invalid := func() (map[string]any, error) { return nil, fmt.Errorf("invalid private provisioning JSON") }
	if len(data) > 128<<10 || !utf8.Valid(data) || !registrationJSONUnicodeValid(data) {
		return invalid()
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	budget := 4200
	value, err := decodePrivateProvisioningJSON(dec, 0, &budget)
	if err != nil {
		return invalid()
	}
	if _, err := dec.Token(); err != io.EOF {
		return invalid()
	}
	doc, ok := value.(map[string]any)
	if !ok {
		return invalid()
	}
	return doc, nil
}

func decodePrivateProvisioningJSON(dec *json.Decoder, depth int, budget *int) (any, error) {
	*budget--
	if depth > 18 || *budget < 0 {
		return nil, fmt.Errorf("invalid private provisioning JSON")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid private provisioning JSON")
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				token, err := dec.Token()
				key, ok := token.(string)
				if err != nil || !ok {
					return nil, fmt.Errorf("invalid private provisioning JSON")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("invalid private provisioning JSON")
				}
				v, err := decodePrivateProvisioningJSON(dec, depth+1, budget)
				if err != nil {
					return nil, err
				}
				object[key] = v
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, fmt.Errorf("invalid private provisioning JSON")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				v, err := decodePrivateProvisioningJSON(dec, depth+1, budget)
				if err != nil {
					return nil, err
				}
				array = append(array, v)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, fmt.Errorf("invalid private provisioning JSON")
			}
			return array, nil
		default:
			return nil, fmt.Errorf("invalid private provisioning JSON")
		}
	case json.Number:
		if len(t) > 128 {
			return nil, fmt.Errorf("invalid private provisioning JSON")
		}
		return t, nil
	default:
		return token, nil
	}
}
