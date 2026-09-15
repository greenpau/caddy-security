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
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

func securityCommandGroup(parent *cobra.Command, name, short string) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: short, Args: cobra.ArbitraryArgs, RunE: cmdSecurityGroup}
	parent.AddCommand(cmd)
	return cmd
}

func securityNoArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%s accepts named flags only; use --help", cmd.CommandPath())
	}
	return nil
}

func addSecurityLocalCommands(parent *cobra.Command) {
	local := securityCommandGroup(parent, "local", "Manage local user stores and generate credentials")
	local.Long = "Manage local identity stores through a running portal's admin API, using an authdbctl-compatible client YAML file. Remote commands require enable admin api and an administrator account. Generate commands work offline. Database files are never edited directly."
	list := securityCommandGroup(local, "list", "List local realms and users")
	info := securityCommandGroup(local, "info", "Inspect a local realm or user")
	add := securityCommandGroup(local, "add", "Add local users")
	update := securityCommandGroup(local, "update", "Update local users")
	del := securityCommandGroup(local, "delete", "Delete local users")
	for _, action := range []struct {
		parent                 *cobra.Command
		name, operation, short string
	}{
		{local, "connect", "connect", "Authenticate and save private portal credentials"},
		{local, "metadata", "metadata", "Read portal server metadata"},
		{local, "reload", "reload", "Reload a realm's database from disk"},
		{list, "realms", "realms", "List local identity realms"},
		{list, "users", "users", "List users in a local realm"},
		{info, "realm", "realm", "Read local database metadata and policy"},
		{info, "user", "info", "Read a user record (may include credential hashes)"},
		{add, "user", "add", "Create a user and return a generated password"},
		{update, "user", "update", "Change account status, reset a password, or update roles and challenges"},
		{del, "user", "delete", "Delete the user matching both username and email"},
	} {
		cmd := &cobra.Command{Use: action.name, Short: action.short, Args: securityNoArgs}
		cmd.Long = action.short + ".\n\nUse --config for client YAML, separate from the server Caddyfile. The config realm identifies the administrator; --realm selects the database to manage. Success prints JSON. User creation and password reset print a new password: protect stdout. Requests are never automatically retried. Use connect to replace expired credentials."
		cmd.RunE = func(cmd *cobra.Command, _ []string) error { return runSecurityLocal(cmd, action.operation) }
		flags := cmd.Flags()
		flags.String("config", "", "Private authentication client YAML file (required)")
		flags.String("token-path", "", "Private token file override; use a distinct path per portal and identity")
		flags.String("ca-file", "", "Additional trusted PEM CA certificates")
		flags.Duration("timeout", 30*time.Second, "Overall login and request timeout")
		if action.operation != "connect" && action.operation != "metadata" && action.operation != "realms" {
			flags.String("realm", "", "Target local identity realm (required)")
		}
		if action.name == "user" {
			flags.String("username", "", "Target username (required)")
			flags.String("email", "", "Target email address (required)")
		}
		if action.operation == "add" {
			flags.String("name", "", "Full display name (required)")
			flags.StringSlice("roles", nil, "Roles, comma-separated or repeated (required)")
		}
		if action.operation == "update" {
			flags.Bool("enable", false, "Enable the account")
			flags.Bool("disable", false, "Disable the account")
			flags.Bool("reset-password", false, "Generate and return a replacement password")
			flags.StringSlice("overwrite-roles", nil, "Replace roles, comma-separated or repeated")
			flags.StringSlice("add-roles", nil, "Append roles, comma-separated or repeated")
			flags.StringSlice("overwrite-auth-challenges", nil, "Replace challenge rules, comma-separated or repeated")
		}
		if action.operation == "users" || action.operation == "realms" {
			flags.String("format", "json", "Output format: json, table, or csv")
		}
		action.parent.AddCommand(cmd)
	}
	addSecurityCredentialCommands(local)
}

type securityLocalUser struct {
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	Name       string   `json:"name,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Challenges []string `json:"challenges,omitempty"`
}

type securityLocalRequest struct {
	Realm     string             `json:"realm,omitempty"`
	Query     string             `json:"query,omitempty"`
	Operation string             `json:"operation,omitempty"`
	User      *securityLocalUser `json:"user,omitempty"`
}

// Validate the entire action before reading credentials or contacting a portal.
func securityLocalPayload(cmd *cobra.Command, operation string) (string, []byte, bool, error) {
	flags := cmd.Flags()
	for _, name := range []string{"config", "realm", "username", "email", "name"} {
		if flags.Lookup(name) == nil {
			continue
		}
		value, _ := flags.GetString(name)
		if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return "", nil, false, fmt.Errorf("a valid --%s is required", name)
		}
	}
	if flags.Lookup("format") != nil {
		format, _ := flags.GetString("format")
		if format != "json" && format != "table" && format != "csv" {
			return "", nil, false, fmt.Errorf("format must be json, table, or csv")
		}
	}
	if operation == "connect" || operation == "metadata" {
		return operation, nil, false, nil
	}
	payload := securityLocalRequest{}
	if flags.Lookup("realm") != nil {
		payload.Realm, _ = flags.GetString("realm")
	}
	endpoint, mutation := operation, false
	switch operation {
	case "realms", "users":
		payload.Query = "all"
	case "realm":
		endpoint = "info"
	case "reload":
		mutation = true
	case "add", "delete", "info", "update":
		endpoint, mutation = "user", operation != "info"
		payload.Operation = operation
		payload.User = &securityLocalUser{}
		payload.User.Username, _ = flags.GetString("username")
		payload.User.Email, _ = flags.GetString("email")
		if operation == "add" {
			payload.User.Name, _ = flags.GetString("name")
			roles, err := securityLocalValues(cmd, "roles")
			if err != nil {
				return "", nil, false, err
			}
			payload.User.Roles = roles
		}
		if operation == "update" {
			selected := 0
			for _, name := range []string{"enable", "disable", "reset-password", "overwrite-roles", "add-roles", "overwrite-auth-challenges"} {
				if !flags.Changed(name) {
					continue
				}
				// Even an explicitly false switch counts: conflicting operation flags
				// must not silently select a different mutation.
				selected++
				if flags.Lookup(name).Value.Type() == "bool" {
					enabled, _ := flags.GetBool(name)
					if !enabled {
						return "", nil, false, fmt.Errorf("user update switches must be true")
					}
				} else {
					values, err := securityLocalValues(cmd, name)
					if err != nil {
						return "", nil, false, err
					}
					if name == "overwrite-auth-challenges" {
						payload.User.Challenges = values
					} else {
						payload.User.Roles = values
					}
				}
				payload.Operation = strings.ReplaceAll(name, "-", "_")
			}
			if selected != 1 {
				return "", nil, false, fmt.Errorf("select exactly one user update operation")
			}
		}
	default:
		return "", nil, false, fmt.Errorf("unsupported local operation")
	}
	data, err := json.Marshal(payload)
	return endpoint, data, mutation, err
}

func securityLocalValues(cmd *cobra.Command, name string) ([]string, error) {
	values, err := cmd.Flags().GetStringSlice(name)
	if err != nil || len(values) == 0 {
		return nil, fmt.Errorf("--%s requires at least one value", name)
	}
	for _, value := range values {
		if strings.TrimSpace(value) != value || value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("invalid --%s value", name)
		}
	}
	return values, nil
}

func runSecurityLocal(cmd *cobra.Command, operation string) error {
	endpoint, body, mutation, err := securityLocalPayload(cmd, operation)
	if err != nil {
		return err
	}
	timeout, _ := cmd.Flags().GetDuration("timeout")
	if timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := newSecurityLocalClient(ctx, cmd)
	if err != nil {
		return err
	}
	defer client.http.CloseIdleConnections()
	if operation == "connect" {
		if err := client.authenticate(ctx); err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"status": "success", "token_path": client.tokenPath})
	}
	data, err := client.request(ctx, endpoint, body, mutation)
	if err != nil {
		return err
	}
	reset, _ := cmd.Flags().GetBool("reset-password")
	if operation == "add" || reset {
		var result struct {
			Password string `json:"password"`
		}
		if json.Unmarshal(data, &result) != nil || result.Password == "" {
			return fmt.Errorf("operation completed but the response omitted the generated password; inspect the account before resetting it")
		}
	}
	format := "json"
	if cmd.Flags().Lookup("format") != nil {
		format, _ = cmd.Flags().GetString("format")
	}
	if err := writeSecurityLocalResponse(cmd.OutOrStdout(), operation, format, data); err != nil {
		if mutation {
			return fmt.Errorf("operation completed; cannot write result (inspect the user before repeating): %w", err)
		}
		return err
	}
	return nil
}
