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
	"net/mail"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	identities "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	identityparser "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite/parser"
	"github.com/spf13/cobra"
)

// Identity management is a trusted offline operation. Neither Caddy config nor
// command arguments carry password bytes, and no default account is created.
func addSecurityIdentityCommands(parent *cobra.Command) {
	group := &cobra.Command{Use: "identity", Short: "Manage SQLite password identities offline", Args: cobra.ArbitraryArgs, RunE: cmdSecurityGroup}
	parent.AddCommand(group)
	for _, action := range []string{"create", "set-password", "roles", "disable", "enable", "delete"} {
		cmd := &cobra.Command{
			Use: action, Short: action + " a SQLite password identity", Args: securityNoArgs,
			Long: "Use a private JSON input with config (name, path, realm, optional timeout), username and email. Create additionally requires roles and accepts name; roles requires a complete replacement role list. Other actions reject these extra fields. Files must be 0600 in private 0700 directories with trusted ancestors. Password actions use a private --password-file or a non-echo terminal prompt with confirmation. One final LF or CRLF is removed from password files; other bytes are preserved. Passwords require 12-72 UTF-8 bytes. No account attributes or passwords are printed. Non-create actions require an existing database. Reconcile an uncertain commit before retrying.",
			RunE: func(cmd *cobra.Command, _ []string) error { return runSecuritySQLiteIdentity(cmd, action) },
		}
		cmd.Flags().String("config", "", "Private JSON provisioning input (required)")
		if action == "create" || action == "set-password" {
			cmd.Flags().String("password-file", "", "Private password file; omit for terminal input with confirmation")
		}
		group.AddCommand(cmd)
	}
}

type sqliteIdentityInput struct {
	config  *identities.Config
	account identities.Account
}

func parseSQLiteIdentityInput(data []byte, action string) (*sqliteIdentityInput, error) {
	invalid := func() (*sqliteIdentityInput, error) {
		return nil, fmt.Errorf("invalid SQLite identity provisioning JSON")
	}
	switch action {
	case "create", "set-password", "roles", "disable", "enable", "delete":
	default:
		return invalid()
	}
	doc, err := parsePrivateProvisioningJSON(data)
	if err != nil {
		return invalid()
	}
	for key := range doc {
		if key == "config" || key == "username" || key == "email" || (key == "name" && action == "create") || (key == "roles" && (action == "create" || action == "roles")) {
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
	cfg, err := identityparser.NewSQLiteIdentityStoreConfigFromDirectives(statements)
	if err != nil {
		return invalid()
	}
	input := &sqliteIdentityInput{config: cfg}
	input.account.Username, ok = doc["username"].(string)
	if !ok {
		return invalid()
	}
	// Mutations require both exact selectors. Keep malformed selectors away from
	// storage; the library remains authoritative for account validation and lookup.
	username := strings.ToLower(input.account.Username)
	valid, _ := regexp.MatchString(`^[a-z0-9][a-z0-9_.-]{2,63}$`, username)
	if !valid || username == "nobody" {
		return invalid()
	}
	input.account.Email, ok = doc["email"].(string)
	if !ok || !sqliteIdentityInputText(input.account.Email, 320) {
		return invalid()
	}
	address, err := mail.ParseAddress(input.account.Email)
	if err != nil || address.Address != input.account.Email {
		return invalid()
	}
	if value, exists := doc["name"]; exists {
		input.account.Name, ok = value.(string)
		if !ok || (input.account.Name != "" && !sqliteIdentityInputText(input.account.Name, 256)) {
			return invalid()
		}
	}
	if action == "create" || action == "roles" {
		roles, ok := doc["roles"].([]any)
		if !ok || len(roles) == 0 || len(roles) > 32 {
			return invalid()
		}
		for _, value := range roles {
			role, ok := value.(string)
			if !ok || !sqliteIdentityInputText(role, 128) {
				return invalid()
			}
			input.account.Roles = append(input.account.Roles, role)
		}
	}
	return input, nil
}

func sqliteIdentityInputText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, unicode.IsControl)
}

func runSecuritySQLiteIdentity(cmd *cobra.Command, action string) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 35*time.Second)
	defer cancel()
	filename, _ := cmd.Flags().GetString("config")
	data, err := readPrivateProvisioningFile(ctx, filename)
	if err != nil {
		return err
	}
	input, err := parseSQLiteIdentityInput(data, action)
	if err != nil {
		return err
	}
	password := ""
	if action == "create" || action == "set-password" {
		password, err = readSQLiteIdentityPassword(ctx, cmd)
		if err != nil {
			return err
		}
	}
	if err := provisionSQLiteIdentity(ctx, input, password, action); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Identity "+action+" completed"); err != nil {
		return fmt.Errorf("identity operation completed; result output failed")
	}
	return nil
}

func readSQLiteIdentityPassword(ctx context.Context, cmd *cobra.Command) (string, error) {
	filename, _ := cmd.Flags().GetString("password-file")
	var password string
	if cmd.Flags().Changed("password-file") {
		// Stdin is intentionally excluded from this private-file interface.
		if filename == "" || filename == "-" {
			return "", fmt.Errorf("password file must name a private file")
		}
		data, err := readPrivateProvisioningFile(ctx, filename)
		if err != nil {
			return "", fmt.Errorf("cannot read private password input")
		}
		password = strings.TrimSuffix(string(data), "\n")
		if len(password) < len(data) {
			password = strings.TrimSuffix(password, "\r")
		}
	} else {
		// Restore terminal echo on cancellation and release signal handling before
		// bcrypt, which cannot be interrupted by context cancellation.
		var err error
		password, err = func() (string, error) {
			ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			password, err := readSecuritySecret(ctx, cmd.InOrStdin(), cmd.ErrOrStderr(), "Password: ")
			if err != nil {
				return "", fmt.Errorf("cannot read password; use a terminal or --password-file")
			}
			confirmation, err := readSecuritySecret(ctx, cmd.InOrStdin(), cmd.ErrOrStderr(), "Confirm password: ")
			if err != nil || password != confirmation {
				return "", fmt.Errorf("password confirmation failed")
			}
			return password, nil
		}()
		if err != nil {
			return "", err
		}
	}
	if len(password) < 12 || len(password) > 72 || !utf8.ValidString(password) || strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password requires 12-72 UTF-8 bytes and must not be blank")
	}
	return password, nil
}

func provisionSQLiteIdentity(ctx context.Context, input *sqliteIdentityInput, password, action string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if action != "create" {
		if info, err := os.Lstat(input.config.Path); err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("identity database unavailable")
		}
	}
	backend, err := identities.New(ctx, input.config)
	if err != nil {
		return fmt.Errorf("identity database unavailable")
	}
	account := input.account
	switch action {
	case "create":
		_, err = backend.Create(ctx, &account, password)
	case "set-password":
		err = backend.SetPassword(ctx, account.Username, account.Email, password)
	case "roles":
		_, err = backend.OverwriteUserRoles(account.Username, account.Email, account.Roles)
	case "disable":
		err = backend.DisableUser(account.Username, account.Email)
	case "enable":
		err = backend.EnableUser(account.Username, account.Email)
	case "delete":
		err = backend.DeleteUser(account.Username, account.Email)
	default:
		err = fmt.Errorf("unsupported identity operation")
	}
	closeErr := backend.Close()
	if errors.Is(err, identities.ErrCommitUncertain) {
		return fmt.Errorf("identity mutation outcome uncertain; reconcile before retry: %w", identities.ErrCommitUncertain)
	}
	if err != nil {
		return fmt.Errorf("identity operation failed")
	}
	if closeErr != nil {
		return fmt.Errorf("identity operation completed; database close failed; reconcile before retry")
	}
	return nil
}
