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

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	backend "github.com/greenpau/go-authcrunch/plugins/session-and-refresh-storage/sqlite"
)

func TestRefreshFactoryDescriptorFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "private-canary.db")
	module := &SQLiteRefreshStore{Name: "sessions", Path: path, Timeout: "1000ms"}
	factory, err := module.prepareRefreshStore(func(name, kind string, sessions, rotations int, value any) (*tokenrefresh.ExternalStoreConfig, error) {
		config, ok := value.(*backend.Config)
		if !ok || config.Path != path || config.Timeout != "1s" || name != "sessions" || kind != "sqlite" || sessions != 10000 || rotations != 1024 {
			t.Fatal("descriptor did not receive normalized binding and storage limits")
		}
		return nil, errors.New("private-canary descriptor diagnostic")
	})
	if factory != nil || err == nil || strings.Contains(err.Error(), "private-canary") {
		t.Fatal("descriptor failure published a factory or disclosed diagnostics", err)
	}
	if module.Timeout != "1000ms" || module.MaxSessions != 0 || module.MaxRotations != 0 {
		t.Fatal("failed preparation changed native fields")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("failed preparation touched storage")
	}
	if next, err := module.PrepareRefreshStore(); err != nil || next == nil {
		t.Fatal("descriptor failure affected the next preparation", err)
	}
}
