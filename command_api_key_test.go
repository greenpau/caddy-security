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
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"
)

func sqliteAPIKeyDocument(t *testing.T, cfg *credentials.Config, fields map[string]any) []byte {
	t.Helper()
	doc := map[string]any{"config": cfg}
	for key, value := range fields {
		doc[key] = value
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func sqliteAPIKeyIssueFields() map[string]any {
	return map[string]any{"subject": "alice", "email": "alice@example.test", "roles": []string{"authp/user"}, "expires": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}
func TestSecurityAPIKeyInput(t *testing.T) {
	good := `{"config":{"name":"keys","path":"/private/keys.db","realm":"staff"},"subject":"private-sentinel","email":"alice@example.test","roles":["viewer"],"expires":"2030-01-01T00:00:00Z"}`
	if input, err := parseSQLiteAPIKeyInput([]byte(good), "issue"); err != nil || input.config.Timeout != "1s" || input.subject != "private-sentinel" {
		t.Fatal("valid shape rejected", err)
	}
	for name, input := range map[string]string{
		"duplicate":        strings.Replace(good, `"subject":"private-sentinel"`, `"subject":"a","subject":"b"`, 1),
		"config_duplicate": strings.Replace(good, `"realm":"staff"`, `"realm":"staff","realm":"other"`, 1),
		"case":             strings.Replace(good, `"name"`, `"Name"`, 1),
		"unknown":          strings.Replace(good, `"subject"`, `"secret"`, 1),
		"surrogate":        strings.Replace(good, "private-sentinel", `\uD800`, 1),
		"utf8":             strings.Replace(good, "private-sentinel", string([]byte{255}), 1),
		"roles_type":       strings.Replace(good, `["viewer"]`, `"viewer"`, 1),
		"null_role":        strings.Replace(good, `["viewer"]`, `[null]`, 1),
		"empty_roles":      strings.Replace(good, `["viewer"]`, `[]`, 1),
		"expiry":           strings.Replace(good, "2030-01-01T00:00:00Z", "not-a-date", 1),
		"extra":            good + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseSQLiteAPIKeyInput([]byte(input), "issue")
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("unsafe input accepted or disclosed")
			}
		})
	}
	if _, err := parseSQLiteAPIKeyInput([]byte(good), "revoke"); err == nil {
		t.Fatal("revocation accepted issuance fields")
	}
}
func TestSecurityAPIKeyProvisioning(t *testing.T) {
	cfg := sqliteCredentialsConfig(t)
	dir := filepath.Dir(cfg.Path)
	input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "client.key")
	write := func(fields map[string]any) {
		t.Helper()
		if err := os.WriteFile(input, sqliteAPIKeyDocument(t, cfg, fields), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(action string, wantErr bool) string {
		t.Helper()
		cmd, out := securityTestCommand(t)
		args := []string{"api-key", action, "--config", input}
		if action == "issue" {
			args = append(args, "--output", output)
		}
		cmd.SetArgs(args)
		err := cmd.Execute()
		if (err != nil) != wantErr {
			t.Fatal("unexpected command outcome", err)
		}
		return out.String()
	}
	write(sqliteAPIKeyIssueFields())
	if err := os.WriteFile(output, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	run("issue", true)
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("occupied destination mutated database")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	var issuedOutput string
	for _, mode := range []os.FileMode{0644, 0600} {
		if err := os.Chmod(input, mode); err != nil {
			t.Fatal(err)
		}
		text := run("issue", mode != 0600)
		if mode == 0600 {
			issuedOutput = text
		}
		if strings.Contains(text, cfg.Path) {
			t.Fatal("path disclosed")
		}
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSuffix(string(data), "\n")
	if strings.Contains(issuedOutput, key) {
		t.Fatal("issuance printed raw key")
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 || len(data) != 44 || len(key) != 43 {
		t.Fatal("unsafe key file")
	}
	if text := run("issue", true); strings.Contains(text, key) {
		t.Fatal("key disclosed")
	}
	// Read the raw database only while all handles are closed; this avoids
	// disrupting POSIX SQLite locks on an active database in this process.
	database, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(database), key) {
		t.Fatal("database retained plaintext")
	}
	backend, err := credentials.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	req := &authproxy.Request{Realm: "staff", Secret: key}
	if err := backend.APIKeyAuthContext(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	cfg.Realm = "guests"
	write(map[string]any{"key_file": output})
	run("revoke", false)
	if err := backend.APIKeyAuthContext(t.Context(), req); err != nil {
		t.Fatal("cross-realm revoke removed key")
	}
	cfg.Realm = "staff"
	write(map[string]any{"key_file": output})
	run("revoke", false)
	run("revoke", false)
	if err := backend.APIKeyAuthContext(t.Context(), req); err == nil {
		t.Fatal("revoked key accepted")
	}
	if err := os.WriteFile(output, []byte(key+" \n"), 0600); err != nil {
		t.Fatal(err)
	}
	if text := run("revoke", true); strings.Contains(text, key) {
		t.Fatal("malformed key disclosed")
	}
	for _, args := range [][]string{{"api-key", "issue", "private-sentinel"}, {"api-key", "issue", "--secret=private-sentinel"}, {"api-key", "unknown-private-sentinel"}, {"api-key", "issue"}, {"api-key", "revoke"}} {
		cmd, out := securityTestCommand(t)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || strings.Contains(err.Error()+out.String(), "private-sentinel") {
			t.Fatal("unsafe command failure")
		}
	}
	for _, action := range []string{"issue", "revoke"} {
		cmd, out := securityTestCommand(t)
		cmd.SetArgs([]string{"api-key", action, "--help"})
		if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "private") {
			t.Fatal("missing help")
		}
	}
}
func TestSecurityAPIKeyRejectedIssue(t *testing.T) {
	for _, kind := range []string{"expired", "too_far", "email", "roles", "symlink", "public_output_directory", "missing_revoke_database"} {
		t.Run(kind, func(t *testing.T) {
			cfg := sqliteCredentialsConfig(t)
			dir := filepath.Dir(cfg.Path)
			input, output := filepath.Join(dir, "input.json"), filepath.Join(dir, "out.key")
			fields := sqliteAPIKeyIssueFields()
			action := "issue"
			switch kind {
			case "expired":
				fields["expires"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			case "too_far":
				fields["expires"] = time.Now().Add(31 * 24 * time.Hour).UTC().Format(time.RFC3339)
			case "email":
				fields["email"] = "private-sentinel"
			case "roles":
				fields["roles"] = []string{""}
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "absent"), output); err != nil {
					t.Fatal(err)
				}
			case "public_output_directory":
				public := filepath.Join(dir, "public")
				if err := os.Mkdir(public, 0755); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(public, "out.key")
			case "missing_revoke_database":
				action = "revoke"
				if err := os.WriteFile(output, []byte(strings.Repeat("A", 43)), 0600); err != nil {
					t.Fatal(err)
				}
				fields = map[string]any{"key_file": output}
			}
			if err := os.WriteFile(input, sqliteAPIKeyDocument(t, cfg, fields), 0600); err != nil {
				t.Fatal(err)
			}
			if err := provisionSQLiteAPIKey(t.Context(), input, output, action); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid issuance accepted/disclosed")
			}
			if kind == "missing_revoke_database" {
				if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
					t.Fatal("revoke created storage")
				}
			}
		})
	}
}
