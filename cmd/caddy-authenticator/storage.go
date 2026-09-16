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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

const maxFileSize = 1 << 20

// Anchor relative inputs without lexical cleaning: link/.. must traverse the
// filesystem before .. is interpreted. An empty base selects the current directory.
func absoluteInputPath(path, base string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}
	if path == "" || filepath.VolumeName(path) != "" || os.IsPathSeparator(path[0]) {
		return "", errors.New("input path must be absolute or relative without a drive qualifier")
	}
	if base == "" {
		var err error
		base, err = os.Getwd()
		if err != nil {
			return "", errors.New("cannot resolve input directory")
		}
	}
	return base + string(filepath.Separator) + path, nil
}

type state struct{ home, profile, dir string }

func openState(dir, profileName string, create bool) (*state, error) {
	if dir == "" {
		return nil, errors.New("state directory is empty")
	}
	if err := privateDir(dir, create); err != nil {
		return nil, err
	}
	// Resolve trusted, user-selected ancestors once. Below this private root,
	// all path components are fixed names or validated profile identifiers.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, errors.New("cannot resolve state directory")
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		return nil, errors.New("cannot resolve state directory")
	}
	if err := os.Mkdir(filepath.Join(abs, ".lock"), 0700); err != nil {
		return nil, errors.New("cannot lock state directory; another command may be running (see README for stale .lock recovery)")
	}
	return &state{home: abs, profile: profileName, dir: filepath.Join(abs, "profiles", profileName)}, nil
}

func (s *state) close()              { _ = os.Remove(filepath.Join(s.home, ".lock")) }
func (s *state) tokenPath() string   { return filepath.Join(s.dir, "token.jwt") }
func (s *state) pendingPath() string { return filepath.Join(s.dir, "refresh.pending") }

func (s *state) clearToken() error {
	for _, path := range []string{s.tokenPath(), s.pendingPath()} {
		if _, err := checkFile(path, true, true); err != nil {
			return err
		}
	}
	if err := removePrivate(s.tokenPath()); err != nil {
		return err
	}
	return removePrivate(s.pendingPath())
}

func privateDir(path string, create bool) error {
	// Lstat follows the last link when the path has a trailing separator.
	// Trim separators without cleaning link/.. before filesystem resolution.
	for len(path) > len(filepath.VolumeName(path))+1 && os.IsPathSeparator(path[len(path)-1]) {
		path = path[:len(path)-1]
	}
	if create {
		if err := os.MkdirAll(path, 0700); err != nil {
			return errors.New("cannot create private directory")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory must be an existing directory, not a symlink; run configure first")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("state directories must have owner-only permissions (0700)")
	}
	return nil
}

func (s *state) openProfile(create bool) error {
	if err := privateDir(filepath.Join(s.home, "profiles"), create); err != nil {
		return err
	}
	return privateDir(s.dir, create)
}

func checkFile(path string, private, missingOK bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot read required file; run configure or login first")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input and output files must be regular files, not symlinks")
	}
	if private && runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("credential and log files must have owner-only permissions (0600)")
	}
	return info, nil
}

func readFile(path string, private bool) ([]byte, error) {
	info, err := checkFile(path, private, false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open input file")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil || len(data) > maxFileSize {
		return nil, errors.New("cannot read input file or size limit exceeded")
	}
	return data, nil
}

func removePrivate(path string) error {
	info, err := checkFile(path, true, true)
	if err != nil || info == nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return errors.New("cannot remove private file")
	}
	return nil
}

func atomicWrite(path string, data []byte) error {
	if _, err := checkFile(path, true, true); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return errors.New("cannot create private temporary file")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return errors.New("cannot write private file")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot sync private file")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot close private file")
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return errors.New("cannot replace private file")
	}
	return nil
}

func (s *state) readProfiles(missingOK bool) (profiles, error) {
	path := filepath.Join(s.home, "credentials")
	info, err := checkFile(path, true, missingOK)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return profiles{}, nil
	}
	data, err := readFile(path, true)
	if err != nil {
		return nil, err
	}
	return parseProfiles(data)
}

func (s *state) selectedProfile() (profile, error) {
	all, err := s.readProfiles(false)
	if err != nil {
		return nil, err
	}
	p := all[s.profile]
	if p == nil {
		return nil, errors.New("profile is not configured; run configure --profile <name>")
	}
	return p, nil
}

func (s *state) tokenStore() (*authclient.FileTokenStore, error) {
	if _, err := checkFile(s.tokenPath(), true, true); err != nil {
		return nil, err
	}
	return authclient.NewFileTokenStore(s.tokenPath())
}

// Establish usable logging before changing credentials or contacting a portal.
// A completion-log failure cannot roll back an already completed operation.
func (s *state) runLogged(event string, run func() error) error {
	if err := s.logEvent(event, "started"); err != nil {
		return err
	}
	err := run()
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	if logErr := s.logEvent(event, outcome); logErr != nil {
		if err == nil {
			return fmt.Errorf("%s completed, but its completion could not be logged: %w", event, logErr)
		}
		return errors.Join(err, logErr)
	}
	return err
}

// Only fixed event names/outcomes are accepted by callers. Never record errors,
// URLs, identity data, HTTP bodies, challenge responses or credentials here.
func (s *state) logEvent(event, outcome string) error {
	path := filepath.Join(s.dir, "auth.log")
	info, err := checkFile(path, true, true)
	if err != nil {
		return err
	}
	if info != nil && info.Size() >= maxFileSize {
		if err := removePrivate(path + ".1"); err != nil {
			return err
		}
		if err := os.Rename(path, path+".1"); err != nil {
			return errors.New("cannot rotate profile log")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot open profile log")
	}
	record := struct {
		Time    string `json:"time"`
		Event   string `json:"event"`
		Outcome string `json:"outcome"`
	}{time.Now().UTC().Format(time.RFC3339Nano), event, outcome}
	err = json.NewEncoder(f).Encode(record)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot write profile log")
	}
	return nil
}
