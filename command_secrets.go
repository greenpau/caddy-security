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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
	sqliteparser "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite/parser"
	"github.com/spf13/cobra"
)

// Secret mutation is an explicit offline command. Values are accepted only from
// an owner-only JSON file, never from flags, a Caddyfile, or an HTTP endpoint.
func addSecuritySecretsCommands(parent *cobra.Command) {
	group := &cobra.Command{Use: "secrets", Short: "Provision private SQLite secret records", Args: cobra.ArbitraryArgs, RunE: cmdSecurityGroup}
	parent.AddCommand(group)
	for _, action := range []string{"put", "delete"} {
		cmd := &cobra.Command{
			Use: action, Short: action + " a bound SQLite secret record",
			Long: "Use a private JSON file with config (name, path, record, optional timeout). Put also requires values, a JSON object; delete rejects values. The file must be 0600 in a private 0700 directory with trusted ancestors. Values are never printed. Changes require an explicit consumer reload. Reconcile an uncertain commit before retrying.",
			Args: securityNoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				filename, _ := cmd.Flags().GetString("config")
				ctx, cancel := context.WithTimeout(cmd.Context(), 35*time.Second)
				defer cancel()
				if err := provisionSQLiteSecrets(ctx, filename, action); err != nil {
					return err
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "secret record "+action+" completed"); err != nil {
					return fmt.Errorf("secret operation completed; result output failed")
				}
				return nil
			},
		}
		cmd.Flags().String("config", "", "Private JSON provisioning input (required)")
		group.AddCommand(cmd)
	}
}

func provisionSQLiteSecrets(ctx context.Context, filename, action string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("SQLite secrets require a local POSIX filesystem")
	}
	if filename == "" || filepath.Clean(filename) != filename {
		return fmt.Errorf("a clean private provisioning input path is required")
	}
	filename, err := filepath.Abs(filename)
	if err != nil {
		return fmt.Errorf("invalid provisioning input path")
	}
	if err := checkRegistrationDirectory(ctx, filepath.Dir(filename), true); err != nil {
		return fmt.Errorf("provisioning input requires a private directory and trusted ancestors")
	}
	root, err := os.OpenRoot(filepath.Dir(filename))
	if err != nil {
		return fmt.Errorf("cannot open provisioning input directory")
	}
	defer root.Close()
	data, err := (&oauthRegistrationStore{root: root}).read(ctx, filepath.Base(filename))
	if err != nil {
		return fmt.Errorf("cannot read private provisioning input")
	}
	config, values, err := parseSQLiteSecretsInput(data, action)
	if err != nil {
		return err
	}
	client, err := sqlite.New(ctx, config)
	if err != nil {
		return fmt.Errorf("cannot open SQLite secrets database")
	}
	if action == "put" {
		err = client.Put(ctx, values)
	} else {
		err = client.Delete(ctx)
	}
	closeErr := client.Close()
	if errors.Is(err, sqlite.ErrCommitUncertain) {
		return fmt.Errorf("secret commit outcome uncertain; reconcile before retry: %w", sqlite.ErrCommitUncertain)
	}
	if err != nil {
		return fmt.Errorf("SQLite secret operation failed")
	}
	if closeErr != nil {
		return fmt.Errorf("secret operation completed; database close failed; reconcile before retry")
	}
	return nil
}

// Decode outside Caddy's generic JSON tree so numbers cannot become float64.
// Reject duplicate keys at every level, invalid Unicode (including escaped lone
// surrogates), unknown/case-folded schema keys and extra documents before writing.
func parseSQLiteSecretsInput(data []byte, action string) (*sqlite.Config, map[string]any, error) {
	invalid := func() (*sqlite.Config, map[string]any, error) {
		return nil, nil, fmt.Errorf("invalid SQLite secrets provisioning JSON")
	}
	if len(data) > 128<<10 || !utf8.Valid(data) || !registrationJSONUnicodeValid(data) || (action != "put" && action != "delete") {
		return invalid()
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	budget := 4200
	value, err := decodeSQLiteSecretsJSON(dec, 0, &budget)
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
	for key := range doc {
		if key != "config" && key != "values" {
			return invalid()
		}
	}
	cfg, ok := doc["config"].(map[string]any)
	if !ok {
		return invalid()
	}
	var statements []string
	for key, value := range cfg {
		if key != "name" && key != "path" && key != "record" && key != "timeout" {
			return invalid()
		}
		s, ok := value.(string)
		if !ok || s == "" {
			return invalid()
		}
		statements = append(statements, encodeOAuthDirective([]string{key, s}))
	}
	config, err := sqliteparser.NewSQLiteSecretsConfigFromDirectives(statements)
	if err != nil {
		return invalid()
	}
	if _, err := (&SQLiteSecretsManager{Name: config.Name, Path: config.Path, Record: config.Record, Timeout: config.Timeout}).config(); err != nil {
		return invalid()
	}
	values, has := doc["values"]
	if action == "delete" {
		if has {
			return invalid()
		}
		return config, nil, nil
	}
	object, ok := values.(map[string]any)
	if !ok || len(object) == 0 {
		return invalid()
	}
	return config, object, nil
}

func decodeSQLiteSecretsJSON(dec *json.Decoder, depth int, budget *int) (any, error) {
	*budget--
	if depth > 18 || *budget < 0 {
		return nil, sqlite.ErrInvalid
	}
	token, err := dec.Token()
	if err != nil {
		return nil, sqlite.ErrInvalid
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
					return nil, sqlite.ErrInvalid
				}
				if _, exists := object[key]; exists {
					return nil, sqlite.ErrInvalid
				}
				v, err := decodeSQLiteSecretsJSON(dec, depth+1, budget)
				if err != nil {
					return nil, err
				}
				object[key] = v
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, sqlite.ErrInvalid
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				v, err := decodeSQLiteSecretsJSON(dec, depth+1, budget)
				if err != nil {
					return nil, err
				}
				array = append(array, v)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, sqlite.ErrInvalid
			}
			return array, nil
		default:
			return nil, sqlite.ErrInvalid
		}
	case json.Number:
		if len(t) > 128 {
			return nil, sqlite.ErrInvalid
		}
		return t, nil
	default:
		return token, nil
	}
}
