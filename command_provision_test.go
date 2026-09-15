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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/pflag"
)

func TestRegistrationCommandConfigIdentity(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input func(string) string
		valid bool
	}{
		{"absolute", func(dir string) string { return dir + "/input.Caddyfile" }, true},
		{"relative", func(string) string { return "input.Caddyfile" }, true},
		{"dot", func(dir string) string { return dir + "/./input.Caddyfile" }, false},
		{"missing parent", func(dir string) string { return dir + "/missing/../input.Caddyfile" }, false},
		{"double separator", func(dir string) string { return dir + "//input.Caddyfile" }, false},
		{"trailing separator", func(dir string) string { return dir + "/input.Caddyfile/" }, false},
		{"missing config", func(string) string { return "" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := registrationTestDirectory(t)
			t.Chdir(dir)
			store := filepath.Join(dir, "store")
			if err := os.WriteFile(filepath.Join(dir, "input.Caddyfile"), []byte("oauth registration store {\npath "+store+"\n}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			flags := pflag.NewFlagSet("oauth init provisioning store", pflag.ContinueOnError)
			flags.String("config", tc.input(dir), "")
			status, err := cmdSecurityProvision(caddycmd.Flags{FlagSet: flags}, "init")
			if tc.valid {
				if err != nil || status != 0 {
					t.Fatal("clean input path rejected", err)
				}
				if info, err := os.Stat(store); err != nil || !info.IsDir() {
					t.Fatal("command did not initialize the selected store")
				}
			} else {
				if err == nil || status == 0 {
					t.Fatal("unclean or absent input path accepted")
				}
				if _, err := os.Lstat(store); !os.IsNotExist(err) {
					t.Fatal("rejected input path created storage")
				}
			}
		})
	}
}

func TestRegistrationCommandOutputFailure(t *testing.T) {
	cfg, store := registrationTestStore(t)
	input := filepath.Join(filepath.Dir(cfg.Path), "oauth_client.Caddyfile")
	data := "oauth registration store {\npath " + cfg.Path + "\n}\noauth application website {\nredirect_uri https://rp.example.test/callback\nclient_secret " + registrationTestSecret + "\n}\n"
	if err := os.WriteFile(input, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Open(input) // A readable descriptor rejects writes with EBADF.
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	flags := pflag.NewFlagSet("oauth create application", pflag.ContinueOnError)
	flags.String("config", input, "")
	flags.String("name", "website", "")
	flags.String("revision", "v1", "")
	status, err := func() (int, error) {
		previous := os.Stdout
		os.Stdout = output
		defer func() { os.Stdout = previous }()
		return cmdSecurityProvision(caddycmd.Flags{FlagSet: flags}, "create")
	}()
	if err == nil || status == 0 {
		t.Fatal("command reported success without delivering the result path")
	}
	if !strings.Contains(err.Error(), "provisioning completed") || strings.Contains(err.Error(), registrationTestSecret) {
		t.Fatal("output failure did not report the completed operation safely")
	}
	application, err := store.application(t.Context(), "website", "v1")
	if err != nil || application.Client.ClientSecret != registrationTestSecret {
		t.Fatal("output failure lost the persisted registration")
	}
	if _, err := provisionRegistration(t.Context(), registrationTestInput(cfg), "create", "website", "v1", ""); !errors.Is(err, fs.ErrExist) {
		t.Fatal("retry overwrote credentials after output failure")
	}
}
