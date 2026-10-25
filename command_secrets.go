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
	"errors"
	"fmt"
	"time"

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
	data, err := readPrivateProvisioningFile(ctx, filename)
	if err != nil {
		return err
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
	if action != "put" && action != "delete" {
		return invalid()
	}
	doc, err := parsePrivateProvisioningJSON(data)
	if err != nil {
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
	if _, err := (&SQLiteSecretsManager{Name: config.Name, Path: config.Path, Record: config.Record, Timeout: config.Timeout}).BackendConfig(); err != nil {
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
