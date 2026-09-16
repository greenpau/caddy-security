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
	"fmt"
	"runtime/debug"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
)

func init() {
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "security",
		Short: "Inspect the security version and manage users, credentials, and provider signing keys",
		Long:  "Security administration commands. Use version to print the linked go-authcrunch version. Use local to manage local user stores through a portal or generate password hashes and API keys offline. Use oauth to initialize private provisioning storage, create applications, or rotate client secrets. Use oidc to create provider signing keys. Run security <group> --help to explore its commands.",
		CobraFunc: func(cmd *cobra.Command) {
			// Cobra parses flags before running our handlers. Its default errors
			// include raw values and unknown flag names, which may contain secrets.
			// Descendants inherit this handler; CommandPath contains only known names.
			cmd.SetFlagErrorFunc(func(cmd *cobra.Command, _ error) error {
				return fmt.Errorf("invalid flags for %s; use --help", cmd.CommandPath())
			})
			addSecurityProvisioningCommands(cmd)
			addSecurityLocalCommands(cmd)
			cmd.AddCommand(&cobra.Command{
				Use: "version", Short: "Print the linked go-authcrunch version",
				Long: "Print the go-authcrunch module version embedded in this binary, including any module replacement. No configuration or running server is required.",
				Args: securityNoArgs,
				RunE: func(cmd *cobra.Command, _ []string) error {
					info, _ := debug.ReadBuildInfo()
					_, err := fmt.Fprintln(cmd.OutOrStdout(), securityAuthcrunchVersion(info))
					return err
				},
			})
		},
	})
}

// Read the linked dependency rather than the working directory's go.mod or an
// authdb version string. Those can differ from the actual module or replacement.
func securityAuthcrunchVersion(info *debug.BuildInfo) string {
	if info != nil {
		for _, dep := range info.Deps {
			if dep.Path != "github.com/greenpau/go-authcrunch" {
				continue
			}
			version := dep.Version
			if version == "" {
				version = "(devel)"
			}
			result := "go-authcrunch " + version
			if replacement := dep.Replace; replacement != nil {
				version = replacement.Version
				if version == "" {
					version = "(devel)"
				}
				result += " => " + replacement.Path + " " + version
			}
			return result
		}
	}
	return "go-authcrunch unknown"
}

// Cobra otherwise shows help successfully for unknown arguments on groups that
// have no handler. Reject those arguments without echoing possible credentials.
func cmdSecurityGroup(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%s requires a supported subcommand; use --help", cmd.CommandPath())
	}
	return cmd.Help()
}
