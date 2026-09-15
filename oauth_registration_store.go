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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// OAuthRegistrationStoreConfig identifies host-owned, private, immutable credential
// revisions. It is independent of Caddy storage and AuthCrunch session storage.
// Path must be an explicit absolute path; normal configuration never creates it.
type OAuthRegistrationStoreConfig struct {
	Path string `json:"path"`
}

type oauthRegistrationStore struct{ root *os.Root }

const registrationMaxFileSize = 1 << 20

func (cfg *OAuthRegistrationStoreConfig) validate() error {
	if cfg == nil || !filepath.IsAbs(cfg.Path) || filepath.Clean(cfg.Path) != cfg.Path || cfg.Path == string(filepath.Separator) || strings.ContainsAny(cfg.Path, "\x00\r\n{}") {
		return fmt.Errorf("oauth registration store requires a clean absolute path without placeholders")
	}
	return nil
}

// Check every ancestor before opening a bounded root. Private directories are
// trusted against same-owner replacement; symlinks and writable ancestors are
// not accepted as an alternate storage identity.
func checkRegistrationDirectory(ctx context.Context, path string, private bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect registration directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("registration directory must not be a symlink")
	}
	if private {
		if info.Mode().Perm() != 0700 || !registrationFileOwner(info, false) {
			return fmt.Errorf("registration directory requires owner-only 0700 permissions and current ownership")
		}
	} else if !registrationFileOwner(info, true) || info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("registration directory has an untrusted ancestor")
	}
	parent := filepath.Dir(path)
	if parent != path {
		return checkRegistrationDirectory(ctx, parent, false)
	}
	return nil
}

func (cfg *OAuthRegistrationStoreConfig) open(ctx context.Context) (*oauthRegistrationStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := checkRegistrationDirectory(ctx, cfg.Path, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("open oauth registration store: %w", err)
	}
	return &oauthRegistrationStore{root: root}, nil
}

func (cfg *OAuthRegistrationStoreConfig) initialize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := checkRegistrationDirectory(ctx, filepath.Dir(cfg.Path), false); err != nil {
		return err
	}
	// Mkdir refuses any existing entry, including a dangling symlink.
	if err := os.Mkdir(cfg.Path, 0700); err != nil {
		return fmt.Errorf("create registration directory: %w", err)
	}
	if err := os.Chmod(cfg.Path, 0700); err != nil {
		return fmt.Errorf("set registration directory permissions: %w", err)
	}
	parent, err := os.Open(filepath.Dir(cfg.Path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func registrationFilename(kind, name, revision string) (string, error) {
	if name == "" || len(name) > 256 || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\r\n\t") {
		return "", fmt.Errorf("invalid registration nickname")
	}
	if len(revision) == 0 || len(revision) > 64 {
		return "", fmt.Errorf("invalid registration revision")
	}
	for i, c := range revision {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_')) {
			return "", fmt.Errorf("invalid registration revision")
		}
	}
	ext := ".json"
	if kind == "key" {
		ext = ".pem"
	} else if kind != "application" {
		return "", fmt.Errorf("invalid registration kind")
	}
	return fmt.Sprintf("%s-%x.%s%s", kind, sha256.Sum256([]byte(name)), revision, ext), nil
}

func (s *oauthRegistrationStore) read(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := s.root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("read registration record: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !registrationFileOwner(info, false) {
		return nil, fmt.Errorf("registration record requires a regular owner-only 0600 file")
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open registration record: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("registration record changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, registrationMaxFileSize+1))
	if err != nil || len(data) > registrationMaxFileSize {
		return nil, fmt.Errorf("cannot read bounded registration record")
	}
	return data, nil
}

func (s *oauthRegistrationStore) application(ctx context.Context, name, revision string) (*oidc.OAuthApplicationConfig, error) {
	filename, err := registrationFilename("application", name, revision)
	if err != nil {
		return nil, err
	}
	data, err := s.read(ctx, filename)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid stored registration UTF-8")
	}
	if !registrationJSONUnicodeValid(data) {
		return nil, fmt.Errorf("invalid stored registration Unicode escape")
	}
	fields, err := registrationJSONFields(data)
	if err != nil {
		return nil, err
	}
	if _, err := registrationJSONFields(fields["client"]); err != nil {
		return nil, err
	}
	var saved oidc.OAuthApplicationConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&saved); err != nil {
		return nil, fmt.Errorf("invalid stored registration JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid stored registration JSON suffix")
	}
	validated, err := oidc.NewOAuthApplicationConfig(saved.Name, saved.Client)
	if err != nil || saved.Name != name {
		return nil, fmt.Errorf("invalid stored registration")
	}
	return validated, nil
}

// encoding/json repairs unpaired UTF-16 surrogate escapes with U+FFFD. Reject
// those corrupt records before decoding can silently change a credential. Valid
// surrogate pairs, literal U+FFFD, and escaped backslashes retain their meaning.
// JSON syntax is checked separately; in valid JSON, backslashes occur in strings.
func registrationJSONUnicodeValid(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		unit, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil || unit >= 0xDC00 && unit <= 0xDFFF {
			return false
		}
		i += 4
		if unit < 0xD800 || unit > 0xDBFF {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return true
}

// encoding/json accepts duplicate object members and case-insensitive aliases,
// silently keeping the last credential. Reject ambiguous records before typed
// validation. Only the registration and client objects have member names; the
// client lists contain strings, so no recursive JSON traversal is needed.
func registrationJSONFields(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("invalid stored registration JSON object")
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, fmt.Errorf("invalid stored registration JSON member")
		}
		// All schema member names are ASCII. Exclude non-ASCII case-fold aliases.
		for _, r := range key {
			if r > 127 {
				return nil, fmt.Errorf("invalid stored registration JSON member")
			}
		}
		key = strings.ToLower(key)
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("duplicate stored registration JSON member")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("invalid stored registration JSON value")
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, fmt.Errorf("invalid stored registration JSON object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid stored registration JSON suffix")
	}
	return fields, nil
}

// Writers serialize across processes, without touching files during reads.
// A crashed writer leaves a visible lock requiring deliberate local recovery.
func (s *oauthRegistrationStore) lock(ctx context.Context) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("registration writer lock: %w", err)
		}
		err := s.root.Mkdir(".writer-lock", 0700)
		if err == nil {
			return func() { _ = s.root.Remove(".writer-lock") }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("registration writer lock: %w", err)
		}
		info, err := s.root.Lstat(".writer-lock")
		if err == nil && (!info.IsDir() || info.Mode().Perm() != 0700 || !registrationFileOwner(info, false)) {
			return nil, fmt.Errorf("invalid registration writer lock")
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// publish writes and syncs a complete private file before a no-replace hard-link
// publication. Caller holds the writer lock. No revision is ever overwritten.
// A directory-sync error after linking leaves an explicit recoverable revision;
// callers must inspect it, never activate it merely because the file exists.
func (s *oauthRegistrationStore) publish(ctx context.Context, name string, write func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := s.root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("registration revision exists: %w", fs.ErrExist)
		}
		return err
	}
	tmp := ".pending-" + rand.Text()
	f, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create private registration file: %w", err)
	}
	defer s.root.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("set registration file permissions: %w", err)
	}
	if err := write(f); err != nil {
		return fmt.Errorf("write private registration file: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync private registration file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect private registration file: %w", err)
	}
	if info.Size() == 0 || info.Size() > registrationMaxFileSize {
		return fmt.Errorf("private registration file must contain 1 to %d bytes", registrationMaxFileSize)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.root.Link(tmp, name); err != nil {
		return fmt.Errorf("publish registration revision: %w", err)
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("registration published; directory sync unavailable: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("registration published; durability uncertain: %w", err)
	}
	return nil
}
