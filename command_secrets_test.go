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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
)

func sqliteSecretsInput(t *testing.T, cfg *sqlite.Config, values map[string]any) []byte {
	t.Helper()
	doc := map[string]any{"config": cfg}
	if values != nil {
		doc["values"] = values
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestSecuritySecretsInput(t *testing.T) {
	good := `{"config":{"name":"signing","path":"/private/secrets.db","record":"access"},"values":{"key":"private-sentinel","number":9007199254740993,"null":null,"object":{"a":true},"array":["x",1.00]}}`
	cfg, values, err := parseSQLiteSecretsInput([]byte(good), "put")
	if err != nil || cfg.Timeout != "1s" || values["number"] != json.Number("9007199254740993") || values["array"].([]any)[1] != json.Number("1.00") {
		t.Fatal("types/defaults changed", err)
	}
	for name, input := range map[string]string{
		"duplicate":        strings.Replace(good, `"key":"private-sentinel"`, `"key":"a","key":"b"`, 1),
		"nested_duplicate": strings.Replace(good, `"a":true`, `"a":true,"a":false`, 1),
		"case_alias":       strings.Replace(good, `"name"`, `"Name"`, 1),
		"unknown":          strings.Replace(good, `"record":"access"`, `"private-sentinel":"access"`, 1),
		"extra":            good + ` {}`,
		"surrogate":        strings.Replace(good, "private-sentinel", `\uD800`, 1),
		"utf8":             strings.Replace(good, "private-sentinel", string([]byte{255}), 1),
		"nonstring_config": strings.Replace(good, `"record":"access"`, `"record":123`, 1),
		"null_values":      strings.Replace(good, good[strings.Index(good, `"values":`):], `"values":null}`, 1),
		"depth":            strings.Replace(good, `"private-sentinel"`, strings.Repeat("[", 20)+"0"+strings.Repeat("]", 20), 1),
		"number_limit":     strings.Replace(good, "9007199254740993", strings.Repeat("1", 129), 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseSQLiteSecretsInput([]byte(input), "put")
			if err == nil {
				t.Fatal("invalid input accepted")
			}
			if strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("payload in error")
			}
		})
	}
	if _, _, err := parseSQLiteSecretsInput([]byte(good), "delete"); err == nil {
		t.Fatal("delete accepted values")
	}
}

func TestSecuritySecretsProvisioning(t *testing.T) {
	cfg := sqliteSecretsTestConfig(t)
	path := filepath.Join(filepath.Dir(cfg.Path), "input.json")
	write := func(values map[string]any) {
		t.Helper()
		if err := os.WriteFile(path, sqliteSecretsInput(t, cfg, values), 0600); err != nil {
			t.Fatal(err)
		}
	}
	execute := func(action string, wantErr bool) {
		t.Helper()
		cmd, out := securityTestCommand(t)
		cmd.SetArgs([]string{"secrets", action, "--config", path})
		err := cmd.Execute()
		if (err != nil) != wantErr {
			t.Fatal("command outcome", err)
		}
		if strings.Contains(out.String(), "private-sentinel") || strings.Contains(out.String(), cfg.Path) {
			t.Fatal("private data in output")
		}
	}
	write(map[string]any{"key": "private-sentinel", "number": json.Number("9007199254740993")})
	execute("put", false)
	c, err := sqlite.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data, err := c.GetSecrets(t.Context())
	if err != nil || data["number"] != json.Number("9007199254740993") {
		t.Fatal("record not stored exactly")
	}
	write(map[string]any{"key": strings.Repeat("x", 65537)})
	execute("put", true)
	// Public library rejects malformed native strings/shape before any mutation.
	for _, values := range []map[string]any{{"key": string([]byte{255})}, {"key": []byte("not-json")}} {
		if err := c.Put(t.Context(), values); err == nil {
			t.Fatal("invalid replacement accepted")
		}
	}
	if value, err := c.GetString(t.Context(), "key"); err != nil || value != "private-sentinel" {
		t.Fatal("invalid update destroyed old record")
	}
	fresh, _ := sqliteSecretsTestModule(t, cfg)
	if value, err := fresh.GetSecretByKey(t.Context(), "key"); err != nil || value != "private-sentinel" {
		t.Fatal("fresh consumer lost last valid record")
	}
	write(map[string]any{"key": "second-private-sentinel"})
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	execute("put", true)
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	execute("put", false)
	write(nil)
	execute("delete", false)
	execute("delete", false)
	if _, err := c.GetSecrets(t.Context()); !errors.Is(err, sqlite.ErrNotFound) {
		t.Fatal("record remains after delete")
	}
	for _, args := range [][]string{{"secrets", "--help"}, {"secrets", "put", "--help"}, {"secrets", "delete", "--help"}} {
		cmd, out := securityTestCommand(t)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), "secrets") {
			t.Fatal("help", err)
		}
	}
	for _, args := range [][]string{{"secrets", "put", "private-sentinel"}, {"secrets", "put", "--values=private-sentinel"}, {"secrets", "unsupported-private-sentinel"}} {
		cmd, out := securityTestCommand(t)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || strings.Contains(err.Error()+out.String(), "private-sentinel") {
			t.Fatal("unsafe command error")
		}
	}
}
