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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestCaddySecurityVersionE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "authcrunch")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", binary, "./cmd/authcrunch")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build authcrunch: %v\n%s", err, output)
	}
	// Compare the executable's embedded dependency with Go's selected module,
	// including replacements, without hard-coding a release in this test.
	module := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", "github.com/greenpau/go-authcrunch")
	module.WaitDelay = 5 * time.Second
	data, err := module.Output()
	if err != nil {
		t.Fatal(err)
	}
	var selected debug.Module
	if err := json.Unmarshal(data, &selected); err != nil {
		t.Fatal(err)
	}
	want := securityAuthcrunchVersion(&debug.BuildInfo{Deps: []*debug.Module{&selected}}) + "\n"

	// Version reporting must work away from the checkout, with no config, Go
	// executable, credentials or server. Keep all default storage paths isolated.
	work := t.TempDir()
	cmd := exec.CommandContext(ctx, binary, "security", "version")
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "PATH=", "HOME="+work, "USERPROFILE="+work,
		"XDG_CONFIG_HOME="+work, "XDG_DATA_HOME="+work, "APPDATA="+work)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil || string(output) != want {
		t.Fatalf("security version = %q, %v; want %q", output, err, want)
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatal("security version modified user state")
	}
}
