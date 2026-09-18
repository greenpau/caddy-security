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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if err := configureSubprocessCoverage(testing.CoverMode(), flag.CommandLine); err != nil {
		fmt.Fprintln(os.Stderr, "subprocess coverage:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// Go supplies both -test.gocoverdir and GOCOVERDIR to the parent executable.
// Our E2E helpers inherit only the environment. Without the flag, m.Run writes
// their counters into a new temporary directory and deletes it before the
// parent can collect them. Honor the private directory supplied by the parent;
// collectSubprocessCoverage later publishes these files for Go's native merge.
// GOCOVERDIR also serves CLI helpers that call os.Exit without returning to m.Run.
func configureSubprocessCoverage(mode string, flags *flag.FlagSet) error {
	if mode == "" {
		return nil
	}
	destination := flags.Lookup("test.gocoverdir")
	if destination == nil {
		return fmt.Errorf("instrumented test executable has no test.gocoverdir flag")
	}
	dir := destination.Value.String()
	if dir == "" {
		dir = os.Getenv("GOCOVERDIR")
	}
	if dir == "" {
		return nil
	}
	if err := flags.Set("test.gocoverdir", dir); err != nil {
		return err
	}
	// Keep descendants aligned when an explicitly supplied flag overrides the
	// inherited environment. Never create a shared or persistent fallback directory.
	return os.Setenv("GOCOVERDIR", dir)
}

// collectSubprocessCoverage configures a copy of this test executable, or a PTY
// broker that launches it, after cmd.Env is set and before it starts. The caller
// must wait for the process before its test returns. Each child gets its own
// directory because Go's metadata writers can race even with an existing file.
// Cleanup publishes finished data before m.Run writes the parent's profile.
func collectSubprocessCoverage(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if testing.CoverMode() == "" {
		return
	}
	parent := flag.Lookup("test.gocoverdir").Value.String()
	if parent == "" {
		t.Fatal("subprocess coverage requires Go's test.gocoverdir")
	}
	dir := t.TempDir()
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.Env = append(cmd.Env, "GOCOVERDIR="+dir)
	t.Cleanup(func() {
		if err := collectCoverageFiles(dir, parent); err != nil {
			t.Errorf("collect subprocess coverage: %v", err)
		}
	})
}

func collectCoverageFiles(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "covmeta.") && !strings.HasPrefix(name, "covcounters.") {
			continue
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("coverage data %q is not a regular file", name)
		}
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			return err
		}
		if err := publishCoverageFile(destination, name, data); err != nil {
			return err
		}
	}
	return nil
}

func publishCoverageFile(dir, name string, data []byte) error {
	// Stage on the destination filesystem. Go ignores these temporary filenames;
	// parallel cleanups can publish identical metadata without partial reads or
	// colliding temporary names. Counter filenames already contain PID/timestamp.
	f, err := os.CreateTemp(dir, ".subprocess-coverage-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}
