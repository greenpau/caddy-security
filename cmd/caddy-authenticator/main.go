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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/greenpau/versioned"
	"github.com/spf13/cobra"
)

var (
	app        *versioned.PackageManager
	appVersion string
	gitBranch  string
	gitCommit  string
	buildUser  string
	buildDate  string
)

func init() {
	app = versioned.NewPackageManager("caddy-authenticator")
	app.Description = "Authenticate to a Caddy security portal using named profiles"
	app.Documentation = "https://github.com/greenpau/caddy-security/tree/main/cmd/caddy-authenticator"
	// Keep the go install fallback synchronized with VERSION via make version-sync.
	app.SetVersion(appVersion, "1.2.2")
	app.SetGitBranch(gitBranch, "")
	app.SetGitCommit(gitCommit, "")
	app.SetBuildUser(buildUser, "")
	app.SetBuildDate(buildDate, "")
}

type options struct {
	home, profile string
	timeout       time.Duration
	interactive   bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newCommand(os.Getenv).ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "caddy-authenticator:", err)
		os.Exit(1)
	}
}

func newCommand(getenv func(string) string) *cobra.Command {
	o := &options{home: getenv("CADDY_AUTHENTICATOR_HOME"), profile: getenv("CADDY_AUTHENTICATOR_PROFILE")}
	if o.profile == "" {
		o.profile = "default"
	}
	root := &cobra.Command{
		Use: app.Name, Short: app.Description,
		SilenceUsage: true, SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.SetFlagErrorFunc(func(*cobra.Command, error) error { return errors.New("invalid command flag; use --help") })
	root.PersistentFlags().StringVar(&o.home, "home", o.home, "State directory (default: ~/.caddy-authenticator; CADDY_AUTHENTICATOR_HOME)")
	root.PersistentFlags().StringVar(&o.profile, "profile", o.profile, "Profile name (CADDY_AUTHENTICATOR_PROFILE)")
	root.PersistentFlags().DurationVar(&o.timeout, "timeout", 45*time.Second, "Total command deadline, including input")
	root.PersistentFlags().BoolVar(&o.interactive, "interactive", false, "Enable terminal prompts for missing settings, passwords and MFA codes")

	configure := &cobra.Command{Use: "configure", Short: "Create or update a profile in the credentials file"}
	configure.Flags().Bool("clear-secrets", false, "Remove stored password, API key and TOTP secret before applying new settings")
	for _, f := range []struct{ name, help string }{
		{"url", "Portal base URL, including its mount path (not /login)"},
		{"realm", "Identity store realm"}, {"username", "Login username (empty clears it for API-key login)"},
		{"ca-file", "Additional PEM trust certificates; empty uses system trust"},
		{"refresh-transport", "cookie (default) or body for explicitly enabled native login"},
		{"access-token-name", "Fallback access token name"},
	} {
		configure.Flags().String(f.name, "", f.help)
	}
	for _, name := range []string{"password", "api-key", "totp-secret"} {
		configure.Flags().String(name+"-file", "", "Store "+name+" from a private file, or - for stdin")
	}
	configure.RunE = o.withState(true, configureProfile)
	login := &cobra.Command{Use: "login", Short: "Reuse, refresh or obtain the profile's saved credentials"}
	login.Flags().Bool("force", false, "Authenticate again even when a cached token is present")
	login.Flags().String("password-file", "", "Use a private password file, or - for stdin, without storing the password")
	login.Flags().String("ca-file", "", "Override the profile's PEM trust certificates for this login")
	login.RunE = o.withState(false, loginProfile)
	profiles := &cobra.Command{Use: "profiles", Short: "List configured profile names"}
	profiles.RunE = o.withState(false, func(cmd *cobra.Command, s *state, _ *options) error {
		all, err := s.readProfiles(false)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(all))
		for name := range all {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), name); err != nil {
				return err
			}
		}
		return nil
	})
	token := &cobra.Command{Use: "token", Short: "Print the saved access token (sensitive output; no network request)"}
	token.Flags().Bool("header", false, "Print the full Authorization header using the portal's token name")
	token.Flags().Bool("path", false, "Print only the token file path")
	token.MarkFlagsMutuallyExclusive("header", "path")
	token.RunE = o.withState(false, showToken)
	clear := &cobra.Command{Use: "clear", Short: "Remove the selected profile's local token; does not revoke server sessions"}
	clear.RunE = o.withState(false, func(cmd *cobra.Command, s *state, _ *options) error {
		if err := s.openProfile(false); err != nil {
			return err
		}
		if err := s.runLogged("clear", s.clearToken); err != nil {
			return err
		}
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "Local token cleared.")
		return err
	})
	version := &cobra.Command{
		Use: "version", Short: "Print the application version and available build metadata",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeOutput(cmd.OutOrStdout(), app.Banner())
		},
	}
	for _, cmd := range []*cobra.Command{configure, login, profiles, token, clear, version} {
		cmd.Args = func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return errors.New("unexpected positional argument; use --help")
			}
			return nil
		}
		root.AddCommand(cmd)
	}
	return root
}

func (o *options) withState(create bool, run func(*cobra.Command, *state, *options) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("home") && o.home == "" {
			return errors.New("home directory must not be empty")
		}
		if o.timeout <= 0 {
			return errors.New("timeout must be positive")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
		defer cancel()
		cmd.SetContext(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validProfileName(o.profile); err != nil {
			return err
		}
		dir := o.home
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return errors.New("cannot determine user home directory; set --home")
			}
			dir = filepath.Join(home, ".caddy-authenticator")
		}
		s, err := openState(dir, o.profile, create)
		if err != nil {
			return err
		}
		defer s.close()
		return run(cmd, s, o)
	}
}

func writeOutput(w io.Writer, value string) error { _, err := fmt.Fprintln(w, value); return err }
