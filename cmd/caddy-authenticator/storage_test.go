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
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPrivateStorageAndLock(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	s, err := openState(home, "default", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := openState(home, "default", false); err == nil {
		t.Fatal("concurrent command acquired lock")
	}
	if err := s.openProfile(true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "credentials")
	if err := atomicWrite(path, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err := readFile(path, true)
	if err != nil || string(data) != "new" {
		t.Fatal("atomic credentials update failed")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readFile(path, true); err == nil {
			t.Fatal("accepted exposed credentials")
		}
		if err := atomicWrite(path, []byte("replacement")); err == nil {
			t.Fatal("rewrote exposed credentials")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(s.dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := s.openProfile(false); err == nil {
			t.Fatal("accepted shared profile directory")
		}
	}
}

func TestStorageRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}
	for _, target := range []string{"home", "profiles", "profile", "credentials", "token.jwt", "auth.log", "refresh.pending"} {
		t.Run(target, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "state")
			s, err := openState(home, "default", true)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.openProfile(true); err != nil {
				t.Fatal(err)
			}
			s.close()
			outside := t.TempDir()
			link := home
			switch target {
			case "profiles":
				link = filepath.Join(home, "profiles")
			case "profile":
				link = s.dir
			case "credentials":
				link = filepath.Join(home, target)
			case "token.jwt", "auth.log", "refresh.pending":
				link = filepath.Join(s.dir, target)
			}
			if target == "home" || target == "profiles" || target == "profile" {
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
			} else {
				outside = filepath.Join(outside, "untouched")
				if err := os.WriteFile(outside, []byte("sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			_, _, err = cli(t, home, "", "configure", "--url", "https://example.test", "--realm", "local", "--username", "alice")
			if err == nil {
				t.Fatal("accepted symlink storage")
			}
			if target == "credentials" || target == "token.jwt" || target == "auth.log" || target == "refresh.pending" {
				data, err := os.ReadFile(outside)
				if err != nil || string(data) != "sentinel" {
					t.Fatal("modified symlink target")
				}
			}
		})
	}
}

func TestProfileLogRotation(t *testing.T) {
	s, err := openState(filepath.Join(t.TempDir(), "state"), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.openProfile(true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, "auth.log")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxFileSize), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.logEvent("login", "success"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path + ".1")
	if err != nil || info.Size() != maxFileSize {
		t.Fatal("previous log was not retained")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte(`"event":"login"`)) || len(data) > 256 {
		t.Fatal("new log entry missing")
	}
}

func TestStatePathResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}
	top, target := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(top, "link")
	if err := os.Symlink(filepath.Join(target, "child"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openState(link+"/", "default", false); err == nil {
		t.Fatal("trailing separator bypassed symlink rejection")
	}
	// The original path resolves into target, while filepath.Clean would pick top.
	path := link + "/../state"
	if err := os.Mkdir(filepath.Join(target, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	s, err := openState(path, "default", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	want, err := filepath.EvalSymlinks(filepath.Join(target, "state"))
	if err != nil || s.home != want {
		t.Fatal("path cleaning changed the selected private directory")
	}
}

func TestAbsoluteInputPath(t *testing.T) {
	base := t.TempDir()
	for _, path := range []string{"ca.pem", "link/../ca.pem", filepath.Join(base, "link") + "/../ca.pem"} {
		got, err := absoluteInputPath(path, base)
		want := path
		if !filepath.IsAbs(path) {
			want = base + string(filepath.Separator) + path
		}
		if err != nil || got != want {
			t.Fatal("input path traversal changed")
		}
	}
	if _, err := absoluteInputPath("", base); err == nil {
		t.Fatal("accepted empty input path")
	}
	if runtime.GOOS == "windows" {
		for _, path := range []string{`C:ca.pem`, `\ca.pem`, `/ca.pem`} {
			if _, err := absoluteInputPath(path, base); err == nil {
				t.Fatal("accepted ambiguous Windows input path")
			}
		}
	}
}

func TestCompletionLogFailureReportsCommittedOperation(t *testing.T) {
	s, err := openState(filepath.Join(t.TempDir(), "state"), "default", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err := s.openProfile(true); err != nil {
		t.Fatal(err)
	}
	called := 0
	err = s.runLogged("configure", func() error {
		called++
		logPath := filepath.Join(s.dir, "auth.log")
		if err := os.Remove(logPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(logPath, 0700); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if called != 1 || err == nil || !strings.Contains(err.Error(), "configure completed") {
		t.Fatal("completion logging failure hid the completed operation")
	}
}
