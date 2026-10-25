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

package sqlite

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	backend "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
)

func TestOAuthLoginFactoryEncodingFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "private-canary.db")
	module := &SQLiteOAuthLoginStore{Name: "shared", Path: path, Timeout: "1000ms"}
	factory, err := module.prepareOAuthLoginStore(func(value any) ([]byte, error) {
		config, ok := value.(*backend.Config)
		if !ok || config.Path != path || config.Timeout != "1s" || config.Capacity != 10000 {
			t.Fatal("encoder did not receive the normalized configuration")
		}
		return nil, errors.New("private-canary encoding diagnostic")
	})
	if factory != nil || err == nil || strings.Contains(err.Error(), "private-canary") {
		t.Fatal("failed encoding published a factory or disclosed diagnostics", err)
	}
	if module.Timeout != "1000ms" || module.Capacity != 0 {
		t.Fatal("failed preparation changed native fields")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("failed preparation touched storage")
	}
	// The injected error is local to one invocation and cannot poison normal preparation.
	if next, err := module.PrepareOAuthLoginStore(); err != nil || next == nil {
		t.Fatal("encoding failure changed the next preparation", err)
	}
}
