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
	"io/fs"
	"os"
	"strings"
	"time"

	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"
	credentialparser "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite/parser"
	"github.com/spf13/cobra"
)

// API-key provisioning is offline and trusted. Secret bytes enter/leave only
// private files, never flags, regular command output or Caddy configuration.
func addSecurityAPIKeyCommands(parent *cobra.Command) {
	group := &cobra.Command{Use: "api-key", Short: "Issue and revoke SQLite API keys", Args: cobra.ArbitraryArgs, RunE: cmdSecurityGroup}
	parent.AddCommand(group)
	for _, action := range []string{"issue", "revoke"} {
		cmd := &cobra.Command{Use: action, Short: action + " a realm-bound SQLite API key", Args: securityNoArgs,
			Long: "Use a private JSON input with config (name, path, realm, optional timeout). Issue requires subject, email, roles and expires (RFC3339 within 30 days), and --output names a new private key file. Revoke requires key_file instead. Files must be 0600 in private 0700 directories with trusted ancestors. Raw credentials are never printed. Reconcile uncertain issuance before retrying.",
			RunE: func(cmd *cobra.Command, _ []string) error {
				filename, _ := cmd.Flags().GetString("config")
				output := ""
				if action == "issue" {
					output, _ = cmd.Flags().GetString("output")
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), 35*time.Second)
				defer cancel()
				if err := provisionSQLiteAPIKey(ctx, filename, output, action); err != nil {
					return err
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), "API key "+action+" completed"); err != nil {
					return fmt.Errorf("API-key operation completed; result output failed")
				}
				return nil
			},
		}
		cmd.Flags().String("config", "", "Private JSON provisioning input (required)")
		if action == "issue" {
			cmd.Flags().String("output", "", "New private file for the issued key (required; never overwritten)")
		}
		group.AddCommand(cmd)
	}
}

type sqliteAPIKeyInput struct {
	config         *credentials.Config
	subject, email string
	roles          []string
	expires        time.Time
	keyFile        string
}

func parseSQLiteAPIKeyInput(data []byte, action string) (*sqliteAPIKeyInput, error) {
	invalid := func() (*sqliteAPIKeyInput, error) { return nil, fmt.Errorf("invalid SQLite API-key provisioning JSON") }
	doc, err := parsePrivateProvisioningJSON(data)
	if err != nil || (action != "issue" && action != "revoke") {
		return invalid()
	}
	for key := range doc {
		if key == "config" || (action == "issue" && (key == "subject" || key == "email" || key == "roles" || key == "expires")) || (action == "revoke" && key == "key_file") {
			continue
		}
		return invalid()
	}
	fields, ok := doc["config"].(map[string]any)
	if !ok {
		return invalid()
	}
	var statements []string
	for key, value := range fields {
		if key != "name" && key != "path" && key != "realm" && key != "timeout" {
			return invalid()
		}
		value, ok := value.(string)
		if !ok || value == "" {
			return invalid()
		}
		statements = append(statements, encodeOAuthDirective([]string{key, value}))
	}
	cfg, err := credentialparser.NewSQLiteCredentialsConfigFromDirectives(statements)
	if err != nil {
		return invalid()
	}
	if _, err := (&SQLiteCredentialAuthenticator{Name: cfg.Name, Path: cfg.Path, Realm: cfg.Realm, Timeout: cfg.Timeout}).BackendConfig(); err != nil {
		return invalid()
	}
	input := &sqliteAPIKeyInput{config: cfg}
	if action == "revoke" {
		input.keyFile, ok = doc["key_file"].(string)
		if !ok || input.keyFile == "" {
			return invalid()
		}
		return input, nil
	}
	input.subject, ok = doc["subject"].(string)
	if !ok {
		return invalid()
	}
	input.email, ok = doc["email"].(string)
	if !ok {
		return invalid()
	}
	roles, ok := doc["roles"].([]any)
	if !ok || len(roles) == 0 || len(roles) > 32 {
		return invalid()
	}
	for _, role := range roles {
		role, ok := role.(string)
		if !ok {
			return invalid()
		}
		input.roles = append(input.roles, role)
	}
	expiry, ok := doc["expires"].(string)
	if !ok {
		return invalid()
	}
	input.expires, err = time.Parse(time.RFC3339, expiry)
	if err != nil {
		return invalid()
	}
	return input, nil
}

func provisionSQLiteAPIKey(ctx context.Context, filename, output, action string) error {
	data, err := readPrivateProvisioningFile(ctx, filename)
	if err != nil {
		return err
	}
	input, err := parseSQLiteAPIKeyInput(data, action)
	if err != nil {
		return err
	}
	if action == "revoke" {
		data, err := readPrivateProvisioningFile(ctx, input.keyFile)
		if err != nil {
			return err
		}
		key := strings.TrimSuffix(string(data), "\n")
		// The library owns strict base64url validation; only remove the newline our
		// issue command writes. Whitespace is never normalized into a credential.
		if len(key) != 43 {
			return fmt.Errorf("invalid API-key file")
		}
		if info, err := os.Lstat(input.config.Path); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("API-key database unavailable")
		}
		backend, err := credentials.New(ctx, input.config)
		if err != nil {
			return fmt.Errorf("API-key database unavailable")
		}
		mutationErr := backend.Revoke(ctx, key)
		closeErr := backend.Close()
		if errors.Is(mutationErr, credentials.ErrCommitUncertain) {
			return fmt.Errorf("API-key revocation outcome uncertain; reconcile before retry: %w", credentials.ErrCommitUncertain)
		}
		if mutationErr != nil {
			return fmt.Errorf("API-key revocation failed")
		}
		if closeErr != nil {
			return fmt.Errorf("API-key revocation completed; database close failed; reconcile before retry")
		}
		return nil
	}
	root, name, err := privateProvisioningRoot(ctx, output)
	if err != nil {
		return err
	}
	defer root.Close()
	// Reject occupied destinations before opening/creating credential storage.
	if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("API-key output must be a new private file")
	}
	backend, err := credentials.New(ctx, input.config)
	if err != nil {
		return fmt.Errorf("API-key database unavailable")
	}
	var key string
	err = (&oauthRegistrationStore{root: root}).publish(ctx, name, func(file *os.File) error {
		var issueErr error
		key, issueErr = backend.Issue(ctx, input.subject, input.email, input.roles, input.expires)
		if issueErr != nil {
			return issueErr
		}
		_, err := file.WriteString(key + "\n")
		return err
	})
	var revokeErr error
	if err != nil && key != "" {
		// A known committed key whose output could not be published must not stay
		// live silently. Revoke once with an independent, bounded cleanup context.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		revokeErr = backend.Revoke(cleanupCtx, key)
		cancel()
	}
	closeErr := backend.Close()
	if errors.Is(err, credentials.ErrCommitUncertain) {
		return fmt.Errorf("API-key issuance outcome uncertain; reconcile before retry: %w", credentials.ErrCommitUncertain)
	}
	if err != nil {
		if key != "" {
			if revokeErr != nil {
				return fmt.Errorf("API-key issuance committed; private output failed and revocation is unconfirmed; reconcile before retry")
			}
			return fmt.Errorf("API-key issuance committed; private output failed; issued key revoked")
		}
		return fmt.Errorf("API-key issuance failed")
	}
	if closeErr != nil {
		return fmt.Errorf("API key issued to private output; database close failed; reconcile before retry")
	}
	return nil
}
