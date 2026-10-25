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
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"
)

func sqliteCredentialsConfig(t *testing.T) *credentials.Config {
	t.Helper()
	return &credentials.Config{Name: "keys", Path: filepath.Join(registrationTestDirectory(t), "credentials.db"), Realm: "staff", Timeout: "500ms"}
}
func sqliteCredentialsRaw(t *testing.T, cfg *credentials.Config) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(map[string]any{"driver": "sqlite", "name": cfg.Name, "path": cfg.Path, "realm": cfg.Realm, "timeout": cfg.Timeout})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func sqliteCredentialsIssue(t *testing.T, cfg *credentials.Config) string {
	t.Helper()
	b, err := credentials.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	key, err := b.Issue(t.Context(), "alice", "alice@example.test", []string{"authp/user"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
