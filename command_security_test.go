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
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/cobra"
)

func securityTestCommand(t *testing.T) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	definition, ok := caddycmd.Commands()["security"]
	if !ok || definition.CobraFunc == nil {
		t.Fatal("security command group is not registered with Caddy")
	}
	cmd := &cobra.Command{Use: definition.Name, Short: definition.Short, Long: definition.Long, SilenceErrors: true, SilenceUsage: true}
	definition.CobraFunc(cmd)
	output := new(bytes.Buffer)
	cmd.SetOut(output)
	cmd.SetErr(output)
	return cmd, output
}

func TestSecurityCommandHelp(t *testing.T) {
	for _, tc := range []struct {
		path, children string
	}{
		{"", "local oauth oidc version"},
		{"oauth init", "provisioning"},
		{"oauth init provisioning", "store"},
		{"oauth", "create init rotate"},
		{"oauth create", "application"},
		{"oauth rotate", "secret"},
		{"oidc", "create"},
		{"oidc create", "signing"},
		{"oidc create signing", "key"},
		{"oauth init provisioning store", ""},
		{"oauth create application", ""},
		{"oauth rotate secret", ""},
		{"oidc create signing key", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			cmd, output := securityTestCommand(t)
			cmd.SetArgs(append(strings.Fields(tc.path), "--help"))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), strings.TrimSpace("security "+tc.path)) {
				t.Fatal("command help omits the full command path")
			}
			for _, child := range strings.Fields(tc.children) {
				if !strings.Contains(output.String(), "  "+child+" ") {
					t.Fatal("group help omits a subcommand")
				}
			}
			leaf := tc.children == ""
			if strings.Contains(output.String(), "--config") != leaf ||
				strings.Contains(output.String(), "--operation") ||
				strings.Contains(output.String(), "--from") != (tc.path == "oauth rotate secret") ||
				strings.Contains(output.String(), "--name") != (leaf && tc.path != "oauth init provisioning store") {
				t.Fatal("command help exposes missing or unrelated operation flags")
			}
		})
	}
}

func TestSecurityCommandDispatch(t *testing.T) {
	dir := registrationTestDirectory(t)
	store := filepath.Join(dir, "registrations")
	input := filepath.Join(dir, "input.Caddyfile")
	if err := os.WriteFile(input, []byte("oauth registration store {\npath "+store+"\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{"--help"},
		{"oauth"},
		{"oauth", "create"},
		{"oauth", "rotate"},
		{"oidc"},
		{"oidc", "create"},
		{"oidc", "create", "signing"},
		{"oauth", "init", "provisioning", "store", "--config", input, "--help"},
		{"oauth", "create", "application", "--config", input, "--help"},
		{"oauth", "rotate", "secret", "--config", input, "--help"},
		{"oidc", "create", "signing", "key", "--config", input, "--help"},
	} {
		cmd, _ := securityTestCommand(t)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(store); !os.IsNotExist(err) {
			t.Fatal("help initialized registration storage")
		}
	}
	for _, args := range [][]string{
		{registrationTestSecret},
		{"oauth", registrationTestSecret},
		{"oauth", "create", registrationTestSecret},
		{"oauth", "application", "create"},
		{"oauth", "create", "unknown"},
		{"oauth", "init", "provisioning", "store", "--config", input, registrationTestSecret},
		{"oauth", "init", "provisioning", "store", "--config", input, "--name", "website"},
		{"oauth", "create", "application", "--config", input, "--from", "v1"},
		{"oidc", "create", "signing", "key", "--config", input, "--operation", "create"},
		{"oauth", "init", "provisioning", "store"},
	} {
		cmd, _ := securityTestCommand(t)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || strings.Contains(err.Error(), registrationTestSecret) {
			t.Fatalf("invalid command with %d arguments accepted or secret exposed", len(args))
		}
		if _, err := os.Lstat(store); !os.IsNotExist(err) {
			t.Fatal("invalid command initialized registration storage")
		}
	}
	cmd, _ := securityTestCommand(t)
	cmd.SetArgs([]string{"oauth", "init", "provisioning", "store", "--config", input})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(store); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("security command did not initialize private storage")
	}
}

func TestCaddySecurityCommandE2E(t *testing.T) {
	for _, path := range []string{"", "oauth init", "oauth init provisioning", "oauth", "oauth create", "oauth rotate", "oidc", "oidc create", "oidc create signing", "oauth init provisioning store", "oauth create application", "oauth rotate secret", "oidc create signing key"} {
		t.Run(path, func(t *testing.T) {
			args := append([]string{"security"}, strings.Fields(path)...)
			if path == "oauth init provisioning store" || path == "oauth create application" || path == "oauth rotate secret" || path == "oidc create signing key" {
				args = append(args, "--help")
			}
			output, err := securityCommand(t, args...)
			if err != nil || !bytes.Contains(output, []byte("Usage:")) {
				t.Fatal("Caddy command help failed", err)
			}
			if !bytes.Contains(output, []byte(strings.TrimSpace("security "+path))) {
				t.Fatal("Caddy did not dispatch nested command help")
			}
		})
	}
	for _, path := range []string{"", "oauth", "oauth create", "oauth init provisioning", "oauth init provisioning store"} {
		args := append([]string{"security"}, strings.Fields(path)...)
		output, err := securityCommand(t, append(args, registrationTestSecret)...)
		if err == nil || bytes.Contains(output, []byte(registrationTestSecret)) {
			t.Fatalf("Caddy accepted a positional secret under security %s or exposed it in diagnostics", path)
		}
	}
}

func TestSecurityCommandFlagErrors(t *testing.T) {
	dir := registrationTestDirectory(t)
	store := filepath.Join(dir, "registrations")
	input := filepath.Join(dir, "oauth_store.Caddyfile")
	if err := os.WriteFile(input, []byte("oauth registration store {\npath "+store+"\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "version", "oauth", "oauth init provisioning store", "oauth rotate secret", "oidc create signing key"} {
		t.Run(path, func(t *testing.T) {
			for _, flag := range []string{"--help=" + registrationTestSecret, "-h" + registrationTestSecret, "--" + registrationTestSecret, "-" + registrationTestSecret} {
				cmd, output := securityTestCommand(t)
				args := strings.Fields(path)
				if path == "oauth init provisioning store" {
					args = append(args, "--config", input)
				}
				cmd.SetArgs(append(args, flag))
				err := cmd.Execute()
				if err == nil || strings.Contains(err.Error(), registrationTestSecret) || bytes.Contains(output.Bytes(), []byte(registrationTestSecret)) {
					t.Error("flag parsing accepted or exposed a misplaced credential")
				}
				if _, err := os.Lstat(store); !os.IsNotExist(err) {
					t.Fatal("invalid flags initialized registration storage")
				}
			}
		})
	}
}

func TestCaddySecurityCommandFlagErrorsE2E(t *testing.T) {
	for _, path := range []string{"", "version", "oauth init provisioning store", "oauth rotate secret"} {
		t.Run(path, func(t *testing.T) {
			for _, flag := range []string{"--help=" + registrationTestSecret, "-h" + registrationTestSecret, "--" + registrationTestSecret} {
				args := append([]string{"security"}, strings.Fields(path)...)
				output, err := securityCommand(t, append(args, flag)...)
				if err == nil || bytes.Contains(output, []byte(registrationTestSecret)) {
					t.Error("Caddy flag parsing accepted or exposed a misplaced credential")
				}
			}
		})
	}
}

func TestSecurityAuthcrunchVersion(t *testing.T) {
	const path = "github.com/greenpau/go-authcrunch"
	for _, tc := range []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{"unavailable", nil, "go-authcrunch unknown"},
		{"missing dependency", &debug.BuildInfo{Main: debug.Module{Path: "github.com/greenpau/caddy-security", Version: "v1.0.0"}}, "go-authcrunch unknown"},
		{"release", &debug.BuildInfo{Deps: []*debug.Module{{Path: "unrelated", Version: "v2.0.0"}, {Path: path, Version: "v1.2.3"}}}, "go-authcrunch v1.2.3"},
		{"pseudo-version", &debug.BuildInfo{Deps: []*debug.Module{{Path: path, Version: "v1.2.4-0.20260916000000-abcdef123456"}}}, "go-authcrunch v1.2.4-0.20260916000000-abcdef123456"},
		{"unversioned", &debug.BuildInfo{Deps: []*debug.Module{{Path: path}}}, "go-authcrunch (devel)"},
		{"local replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: path, Version: "v1.2.3", Replace: &debug.Module{Path: "../go-authcrunch"}}}}, "go-authcrunch v1.2.3 => ../go-authcrunch (devel)"},
		{"versioned replacement", &debug.BuildInfo{Deps: []*debug.Module{{Path: path, Version: "v1.2.3", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.3.0"}}}}, "go-authcrunch v1.2.3 => example.com/fork v1.3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityAuthcrunchVersion(tc.info); got != tc.want {
				t.Fatalf("version = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestSecurityVersionCommand(t *testing.T) {
	cmd, output := securityTestCommand(t)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil || !strings.HasPrefix(output.String(), "go-authcrunch ") {
		t.Fatalf("version command failed: %q, %v", output.String(), err)
	}
	cmd, output = securityTestCommand(t)
	cmd.SetArgs([]string{"version", "--help"})
	if err := cmd.Execute(); err != nil || !strings.Contains(output.String(), "security version") || strings.Contains(output.String(), "--config") {
		t.Fatalf("version help failed: %q, %v", output.String(), err)
	}
	cmd, output = securityTestCommand(t)
	cmd.SetArgs([]string{"version", registrationTestSecret})
	if err := cmd.Execute(); err == nil || strings.Contains(err.Error(), registrationTestSecret) || output.Len() != 0 {
		t.Fatal("version accepted or exposed a positional argument")
	}
	cmd, _ = securityTestCommand(t)
	cmd.SetArgs([]string{"version"})
	cmd.SetOut(securityFailedWriter{})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("version lost stdout failure: %v", err)
	}
}
