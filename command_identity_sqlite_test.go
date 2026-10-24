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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	identities "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

func sqliteIdentityCLIConfig(t *testing.T) *identities.Config {
	t.Helper()
	return &identities.Config{Name: "accounts", Path: filepath.Join(registrationTestDirectory(t), "accounts.db"), Realm: "staff", Timeout: "5s"}
}

func sqliteIdentityCLIDocument(t *testing.T, cfg *identities.Config, fields map[string]any) []byte {
	t.Helper()
	doc := map[string]any{"config": cfg, "username": "Alice", "email": "Alice@example.test"}
	for key, value := range fields {
		doc[key] = value
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSecuritySQLiteIdentityInput(t *testing.T) {
	good := `{"config":{"name":"accounts","path":"/private/accounts.db","realm":"staff"},"username":"Alice","email":"Alice@example.test","name":"Alice Example","roles":["viewer"]}`
	if input, err := parseSQLiteIdentityInput([]byte(good), "create"); err != nil || input.config.Timeout != "1s" || input.account.Username != "Alice" || input.account.Name != "Alice Example" {
		t.Fatal("valid account rejected", err)
	}
	for name, input := range map[string]string{
		"duplicate":          strings.Replace(good, `"username":"Alice"`, `"username":"Alice","username":"private-sentinel"`, 1),
		"config_duplicate":   strings.Replace(good, `"realm":"staff"`, `"realm":"staff","realm":"private-sentinel"`, 1),
		"config_unknown":     strings.Replace(good, `"realm":"staff"`, `"password":"private-sentinel"`, 1),
		"case":               strings.Replace(good, `"username"`, `"Username"`, 1),
		"secret":             strings.Replace(good, `"name":"Alice Example"`, `"password":"private-sentinel"`, 1),
		"username_email":     strings.Replace(good, `"username":"Alice"`, `"username":"alice@example.test"`, 1),
		"username_reserved":  strings.Replace(good, `"username":"Alice"`, `"username":"Nobody"`, 1),
		"username_short":     strings.Replace(good, `"username":"Alice"`, `"username":"ab"`, 1),
		"username_long":      strings.Replace(good, `"username":"Alice"`, `"username":"`+strings.Repeat("a", 65)+`"`, 1),
		"email_display_name": strings.Replace(good, `"email":"Alice@example.test"`, `"email":"Alice <alice@example.test>"`, 1),
		"email_missing":      strings.Replace(good, `"email":"Alice@example.test",`, ``, 1),
		"name_type":          strings.Replace(good, `"name":"Alice Example"`, `"name":null`, 1),
		"roles_type":         strings.Replace(good, `["viewer"]`, `"viewer"`, 1),
		"roles_null":         strings.Replace(good, `["viewer"]`, `[null]`, 1),
		"roles_empty":        strings.Replace(good, `["viewer"]`, `[]`, 1),
		"roles_blank":        strings.Replace(good, `["viewer"]`, `[" "]`, 1),
		"roles_control":      strings.Replace(good, `["viewer"]`, `["view\ner"]`, 1),
		"roles_limit":        strings.Replace(good, `["viewer"]`, `[`+strings.Repeat(`"viewer",`, 32)+`"viewer"]`, 1),
		"timeout_type":       strings.Replace(good, `"realm":"staff"`, `"realm":"staff","timeout":1`, 1),
		"relative_path":      strings.Replace(good, `/private/accounts.db`, `relative.db`, 1),
		"surrogate":          strings.Replace(good, `Alice Example`, `\uD800`, 1),
		"invalid_utf8":       strings.Replace(good, `Alice Example`, string([]byte{255}), 1),
		"extra":              good + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSQLiteIdentityInput([]byte(input), "create"); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("unsafe input accepted or disclosed")
			}
		})
	}
	for _, action := range []string{"set-password", "roles", "disable", "enable", "delete", "unknown"} {
		if _, err := parseSQLiteIdentityInput([]byte(good), action); err == nil {
			t.Fatalf("%s accepted unexpected create fields", action)
		}
	}
	cfg := sqliteIdentityCLIConfig(t)
	for _, action := range []string{"set-password", "roles", "disable", "enable", "delete"} {
		fields := map[string]any{}
		if action == "roles" {
			fields["roles"] = []string{"viewer"}
		}
		if _, err := parseSQLiteIdentityInput(sqliteIdentityCLIDocument(t, cfg, fields), action); err != nil {
			t.Fatalf("%s rejected valid input: %v", action, err)
		}
	}
}

func TestSecuritySQLiteIdentityPrivateInput(t *testing.T) {
	for _, kind := range []string{"config_permissions", "config_symlink", "password_permissions", "password_symlink", "public_directory", "oversized_input", "password_short", "password_long", "password_blank", "password_invalid_utf8", "no_terminal", "empty_password_flag", "stdin_password_flag", "missing_database", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			cfg := sqliteIdentityCLIConfig(t)
			dir := filepath.Dir(cfg.Path)
			inputPath, passwordPath := filepath.Join(dir, "input.json"), filepath.Join(dir, "password")
			fields := map[string]any{"roles": []string{"viewer"}}
			password := []byte("private-sentinel-password")
			if kind == "missing_database" {
				fields = nil
			}
			if err := os.WriteFile(inputPath, sqliteIdentityCLIDocument(t, cfg, fields), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "password_short":
				password = []byte("too-short")
			case "password_long":
				password = []byte(strings.Repeat("a", 73))
			case "password_blank":
				password = []byte(strings.Repeat(" ", 20))
			case "password_invalid_utf8":
				password = append(password, 255)
			}
			if err := os.WriteFile(passwordPath, password, 0600); err != nil {
				t.Fatal(err)
			}
			cmd, out := securityTestCommand(t)
			args := []string{"identity", "create", "--config", inputPath, "--password-file", passwordPath}
			switch kind {
			case "config_permissions", "password_permissions":
				path := inputPath
				if kind == "password_permissions" {
					path = passwordPath
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "config_symlink", "password_symlink":
				path, index := inputPath, 3
				if kind == "password_symlink" {
					path, index = passwordPath, 5
				}
				if err := os.Symlink(path, path+".link"); err != nil {
					t.Fatal(err)
				}
				args[index] = path + ".link"
			case "public_directory":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "oversized_input":
				if err := os.WriteFile(inputPath, []byte(strings.Repeat(" ", 129<<10)), 0600); err != nil {
					t.Fatal(err)
				}
			case "no_terminal":
				args = args[:4]
				cmd.SetIn(strings.NewReader("private-sentinel-password"))
			case "empty_password_flag":
				args[5] = ""
			case "stdin_password_flag":
				args[5] = "-"
			case "missing_database":
				args = []string{"identity", "disable", "--config", inputPath}
			case "canceled":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				cmd.SetContext(ctx)
			}
			cmd.SetArgs(args)
			if err := cmd.Execute(); err == nil || strings.Contains(err.Error()+out.String(), "private-sentinel") {
				t.Fatal("unsafe provisioning accepted or disclosed")
			}
			if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
				t.Fatal("rejected operation created storage")
			}
		})
	}
}

func TestSecuritySQLiteIdentityCommands(t *testing.T) {
	for _, action := range []string{"create", "set-password", "roles", "disable", "enable", "delete"} {
		cmd, out := securityTestCommand(t)
		cmd.SetArgs([]string{"identity", action, "--help"})
		if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "private") {
			t.Fatal("missing private input help")
		}
		for _, tail := range [][]string{{}, {"private-sentinel"}, {"--password=private-sentinel"}} {
			cmd, out := securityTestCommand(t)
			cmd.SetArgs(append([]string{"identity", action}, tail...))
			if err := cmd.Execute(); err == nil || strings.Contains(err.Error()+out.String(), "private-sentinel") {
				t.Fatal("unsafe command failure")
			}
		}
	}
	cmd, out := securityTestCommand(t)
	cmd.SetArgs([]string{"identity", "private-sentinel"})
	if err := cmd.Execute(); err == nil || strings.Contains(err.Error()+out.String(), "private-sentinel") {
		t.Fatal("unknown command disclosed")
	}
}
