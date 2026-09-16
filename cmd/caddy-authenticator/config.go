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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	authclientparser "github.com/greenpau/go-authcrunch/pkg/authclient/parser"
	"github.com/spf13/cobra"
)

type profile map[string]string
type profiles map[string]profile

func validProfileName(name string) error {
	valid := len(name) > 0 && len(name) <= 64
	for i, c := range name {
		valid = valid && (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '-' || c == '_'))
	}
	switch name {
	case "con", "prn", "aux", "nul":
		valid = false
	}
	if len(name) == 4 && (strings.HasPrefix(name, "com") || strings.HasPrefix(name, "lpt")) && name[3] >= '1' && name[3] <= '9' {
		valid = false
	}
	if !valid {
		return errors.New("profile names must be 1-64 lowercase letters, digits, hyphens or underscores, start with a letter or digit, and not be a reserved Windows name")
	}
	return nil
}

func knownSetting(key string) bool {
	switch key {
	case "base_url", "realm", "username", "password", "api_key", "totp_secret", "totp_code_length", "totp_code_lifetime", "access_token_name", "refresh_transport", "ca_file":
		return true
	}
	return false
}

// This deliberately small INI dialect has no interpolation, multiline values,
// inheritance or inline comments. Quoted values use Go string escaping so a
// credential's surrounding whitespace and punctuation survive a rewrite.
func parseProfiles(data []byte) (profiles, error) {
	if len(data) > maxFileSize || !utf8.Valid(data) {
		return nil, errors.New("invalid credentials file encoding or size")
	}
	all := profiles{}
	var current profile
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxFileSize+1)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, ";") {
			continue
		}
		invalid := func() (profiles, error) {
			return nil, fmt.Errorf("invalid credentials syntax at line %d (values redacted)", line)
		}
		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				return invalid()
			}
			name := text[1 : len(text)-1]
			if validProfileName(name) != nil || all[name] != nil {
				return invalid()
			}
			current = profile{}
			all[name] = current
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || current == nil || !knownSetting(key) {
			return invalid()
		}
		if _, exists := current[key]; exists {
			return invalid()
		}
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return invalid()
			}
			value = decoded
		}
		if !validValue(value) {
			return invalid()
		}
		current[key] = value
	}
	if scanner.Err() != nil {
		return nil, errors.New("cannot parse credentials file")
	}
	return all, nil
}

func validValue(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func encodeProfiles(all profiles) []byte {
	var out strings.Builder
	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&out, "[%s]\n", name)
		keys := make([]string, 0, len(all[name]))
		for key := range all[name] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&out, "%s = %s\n", key, strconv.Quote(all[name][key]))
		}
		out.WriteByte('\n')
	}
	return []byte(out.String())
}

func (p profile) config() (*authclient.Config, error) {
	keys := make([]string, 0, len(p))
	for key := range p {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var directives []string
	for _, key := range keys {
		value := p[key]
		if !knownSetting(key) || !validValue(value) {
			return nil, errors.New("invalid profile setting")
		}
		if key == "ca_file" || value == "" {
			continue
		}
		// Always CSV-quote values: the shared directive encoder otherwise trims
		// trailing whitespace from raw password, API-key and TOTP secret bytes.
		directives = append(directives, strings.ReplaceAll(key, "_", " ")+` "`+strings.ReplaceAll(value, `"`, `""`)+`"`)
	}
	return authclientparser.NewAuthenticationClientConfigFromDirectives(directives)
}

func configureProfile(cmd *cobra.Command, s *state, o *options) error {
	stdinCount := 0
	for _, flag := range []string{"password-file", "api-key-file", "totp-secret-file"} {
		path, _ := cmd.Flags().GetString(flag)
		if path == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return errors.New("only one secret may be read from stdin")
	}
	all, err := s.readProfiles(true)
	if err != nil {
		return err
	}
	p := all[s.profile]
	if p == nil {
		p = profile{}
	}
	clearSecrets, _ := cmd.Flags().GetBool("clear-secrets")
	if clearSecrets {
		delete(p, "password")
		delete(p, "api_key")
		delete(p, "totp_secret")
	}
	for _, f := range []struct{ flag, key string }{
		{"url", "base_url"}, {"realm", "realm"}, {"username", "username"}, {"ca-file", "ca_file"},
		{"refresh-transport", "refresh_transport"}, {"access-token-name", "access_token_name"},
	} {
		if cmd.Flags().Changed(f.flag) {
			p[f.key], _ = cmd.Flags().GetString(f.flag)
		}
	}
	for _, key := range []string{"password", "api_key", "totp_secret"} {
		flag := strings.ReplaceAll(key, "_", "-") + "-file"
		if !cmd.Flags().Changed(flag) {
			continue
		}
		path, _ := cmd.Flags().GetString(flag)
		value, err := readSecretFile(cmd.Context(), cmd.InOrStdin(), path)
		if err != nil {
			return err
		}
		p[key] = value
	}
	if p["api_key"] != "" {
		// Switching authentication methods is explicit; do not silently ignore
		// an existing password or TOTP enrollment configuration.
		if cmd.Flags().Changed("api-key-file") && !cmd.Flags().Changed("password-file") && !cmd.Flags().Changed("totp-secret-file") {
			if !cmd.Flags().Changed("username") {
				delete(p, "username")
			}
			delete(p, "password")
			delete(p, "totp_secret")
			if !cmd.Flags().Changed("refresh-transport") {
				delete(p, "refresh_transport")
			}
		}
	}
	terminal := newTerminalInput(cmd.InOrStdin(), cmd.ErrOrStderr())
	for _, field := range []struct{ key, label string }{{"base_url", "Portal URL: "}, {"realm", "Realm: "}, {"username", "Username: "}} {
		if field.key == "username" && p["api_key"] != "" {
			continue
		}
		if p[field.key] != "" {
			continue
		}
		if !o.interactive {
			return errors.New("missing profile settings; provide --url, --realm and --username or --api-key-file, or use --interactive")
		}
		value, err := terminal.read(cmd.Context(), field.label, false)
		if err != nil {
			return err
		}
		p[field.key] = value
	}
	if cmd.Flags().Changed("ca-file") && p["ca_file"] != "" {
		p["ca_file"], err = absoluteInputPath(p["ca_file"], "")
		if err != nil {
			return errors.New("cannot resolve CA file")
		}
	}
	if _, err := p.config(); err != nil {
		return err
	}
	all[s.profile] = p
	data := encodeProfiles(all)
	if len(data) > maxFileSize {
		return errors.New("credentials file exceeds size limit")
	}
	if err := cmd.Context().Err(); err != nil {
		return err
	}
	if err := s.openProfile(true); err != nil {
		return err
	}
	if err := s.runLogged("configure", func() error {
		// Clear before committing a reconfiguration: a failed write may require a
		// fresh login but cannot leave a token associated with a new identity.
		if err := s.clearToken(); err != nil {
			return err
		}
		return atomicWrite(filepath.Join(s.home, "credentials"), data)
	}); err != nil {
		return err
	}
	return writeOutput(cmd.OutOrStdout(), "Profile configured. Run login to authenticate.")
}
