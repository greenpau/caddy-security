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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureSubprocessCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, mode, explicit, inherited, wantFlag, wantEnv string
	}{
		{"no instrumentation", "", "", "/unused coverage", "", "/unused coverage"},
		{"no destination", "atomic", "", "", "", ""},
		{"inherited atomic", "atomic", "", "/run coverage", "/run coverage", "/run coverage"},
		{"inherited set", "set", "", "/set coverage", "/set coverage", "/set coverage"},
		{"inherited count", "count", "", "/count coverage", "/count coverage", "/count coverage"},
		{"explicit destination", "atomic", "/chosen", "/other", "/chosen", "/chosen"},
		{"explicit without environment", "atomic", "/chosen", "", "/chosen", "/chosen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOCOVERDIR", tc.inherited)
			flags := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
			dir := flags.String("test.gocoverdir", tc.explicit, "")
			if err := configureSubprocessCoverage(tc.mode, flags); err != nil {
				t.Fatal(err)
			}
			if *dir != tc.wantFlag || os.Getenv("GOCOVERDIR") != tc.wantEnv {
				t.Fatalf("coverage flag=%q env=%q; want flag=%q env=%q", *dir, os.Getenv("GOCOVERDIR"), tc.wantFlag, tc.wantEnv)
			}
		})
	}
	t.Run("missing coverage flag", func(t *testing.T) {
		flags := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
		if err := configureSubprocessCoverage("atomic", flags); err == nil {
			t.Fatal("instrumented executable silently lost coverage setup")
		}
		if err := configureSubprocessCoverage("", flags); err != nil {
			t.Fatal("uninstrumented executable needs no coverage flag", err)
		}
	})
}

func TestCollectCoverageFiles(t *testing.T) {
	t.Run("parallel children", func(t *testing.T) {
		destination := t.TempDir()
		metadata := []byte("shared metadata")
		t.Run("collect", func(t *testing.T) {
			for i := range 24 {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					t.Parallel()
					source := t.TempDir()
					for name, data := range map[string][]byte{
						"covmeta.hash":                          metadata,
						fmt.Sprintf("covcounters.hash.%d.1", i): []byte(fmt.Sprint(i)),
						"tmp.covcounters.unfinished":            []byte("unflushed"),
					} {
						if err := os.WriteFile(filepath.Join(source, name), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
					if err := collectCoverageFiles(source, destination); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
		data, err := os.ReadFile(filepath.Join(destination, "covmeta.hash"))
		if err != nil || !bytes.Equal(data, metadata) {
			t.Fatal("parallel metadata publication corrupted data", err)
		}
		entries, err := os.ReadDir(destination)
		if err != nil || len(entries) != 25 {
			t.Fatal("lost counters or retained temporary files", err, len(entries))
		}
		for i := range 24 {
			data, err := os.ReadFile(filepath.Join(destination, fmt.Sprintf("covcounters.hash.%d.1", i)))
			if err != nil || string(data) != fmt.Sprint(i) {
				t.Fatal("parallel counter publication corrupted data", i, err)
			}
		}
	})
	t.Run("empty killed child", func(t *testing.T) {
		if err := collectCoverageFiles(t.TempDir(), t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unreadable source", func(t *testing.T) {
		if err := collectCoverageFiles(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
			t.Fatal("missing coverage evidence was ignored")
		}
	})
	t.Run("nonregular data", func(t *testing.T) {
		source := t.TempDir()
		if err := os.Mkdir(filepath.Join(source, "covmeta.hash"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := collectCoverageFiles(source, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatal("invalid coverage data was ignored", err)
		}
	})
	t.Run("unwritable destination", func(t *testing.T) {
		source := t.TempDir()
		if err := os.WriteFile(filepath.Join(source, "covmeta.hash"), []byte("metadata"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := collectCoverageFiles(source, filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("coverage collection failure was ignored")
		}
	})
}
