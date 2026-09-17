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
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// The app must pass static-user overwrite intent to the database API. Reusing a
// hash is distinct from a security mutation: credential versions still advance.
func TestLocalIdentityProvisioning(t *testing.T) {
	for _, mode := range []string{"preserve", "same-password", "same-import", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			seedLocalIdentity(t, path, false)
			before := localIdentityRecord(t, path, "alice")
			original := localIdentityActivePassword(t, before)
			if before.CredentialVersion != 0 {
				t.Fatal("fixture did not preserve legacy version zero")
			}
			password := lifecyclePassword
			if mode == "same-import" {
				password = "bcrypt:8:" + original.Hash
			}
			if mode == "replacement" || mode == "preserve" {
				password = "ReplacementPassword42!"
			}
			cfg := lifecycleConfig()
			cfg.IdentityStores[0].Params["path"] = path
			cfg.IdentityStores[0].Params["users"] = []any{map[string]any{
				"username": "alice", "email_address": "alice@example.test", "password": password,
				"password_overwrite_enabled": mode != "preserve", "roles": []string{"authp/admin"},
			}}
			app := provisionLifecycleApp(t, cfg)
			if err := app.Cleanup(); err != nil {
				t.Fatal(err)
			}
			after := localIdentityRecord(t, path, "alice")
			active := localIdentityActivePassword(t, after)
			wantVersion := uint64(1)
			if mode == "preserve" {
				wantVersion = 0
			}
			if after.CredentialVersion != wantVersion || after.ID != before.ID {
				t.Fatal("app provisioning lost database security-mutation semantics")
			}
			if mode == "replacement" {
				if active.Hash == original.Hash {
					t.Fatal("overwrite did not replace active password")
				}
			} else if active.Hash != original.Hash || !active.CreatedAt.Equal(original.CreatedAt) {
				t.Fatal("preserved or duplicate password was rehashed")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var file struct{ Users []map[string]json.RawMessage }
			if json.Unmarshal(data, &file) != nil {
				t.Fatal("invalid persisted database")
			}
			foundLegacy := false
			for _, user := range file.Users {
				if string(user["username"]) == `"bob"` {
					foundLegacy = true
					if user["credential_version"] != nil {
						t.Fatal("provisioning migrated an unrelated legacy record")
					}
				}
			}
			if !foundLegacy {
				t.Fatal("provisioning removed the unrelated legacy record")
			}
		})
	}
}

// The management HTTP reset endpoint generates a new password. Exercise the
// underlying public database contract separately for caller-specified identical
// plaintext and imports; do not invent an HTTP reset-password input field.
func TestLocalIdentitySamePasswordReset(t *testing.T) {
	for _, imported := range []bool{false, true} {
		t.Run(map[bool]string{false: "plaintext", true: "import"}[imported], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			seedLocalIdentity(t, path, false)
			before := localIdentityRecord(t, path, "alice")
			old := localIdentityActivePassword(t, before)
			password := lifecyclePassword
			if imported {
				password = "bcrypt:8:" + old.Hash
			}
			db, err := identity.NewDatabase(path)
			if err != nil {
				t.Fatal(err)
			}
			request := &requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: password}}
			if err := db.ResetUserPassword(request); err != nil {
				t.Fatal("same-password reset failed")
			}
			after := localIdentityRecord(t, path, "alice")
			active := localIdentityActivePassword(t, after)
			if after.CredentialVersion != before.CredentialVersion+1 || active.CreatedAt.Equal(old.CreatedAt) || len(after.Passwords) != len(before.Passwords)+1 {
				t.Fatal("reset reused a password record or lost credential invalidation")
			}
			if imported && active.Hash != old.Hash || !imported && active.Hash == old.Hash {
				t.Fatal("reset confused imported hash identity with plaintext equality")
			}
		})
	}
}
