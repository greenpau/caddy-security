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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/transform"
)

func TestSecurityTerminalEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		invalid     bool
	}{
		{"ASCII", "Terminal-secret-123\n", false},
		{"Unicode", "Terminal-秘密-é-🔑-123\n", false},
		{"large Unicode", strings.Repeat("秘密🔑", 1000), false},
		{"invalid byte", "Terminal-\xff-secret\n", true},
		{"overlong encoding", "Terminal-\xc0\xaf-secret\n", true},
		{"truncated encoding", "Terminal-\xe2\x82", true},
		{"replacement character", "Terminal-\ufffd-secret\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunked := range []bool{false, true} {
				var input io.Reader = strings.NewReader(tc.value)
				if chunked {
					input = iotest.OneByteReader(input)
				}
				data, err := io.ReadAll(transform.NewReader(input, securityTerminalUTF8{}))
				if tc.invalid {
					if !errors.Is(err, errSecurityTerminalEncoding) {
						t.Error("corruptible terminal input was accepted")
					}
				} else if err != nil || string(data) != tc.value {
					t.Error("valid input changed when split across reads")
				}
			}
		})
	}
}

func FuzzSecurityTerminalEncoding(f *testing.F) {
	for _, seed := range []string{"Secret-123\n", "秘密-é-🔑\n", "\xff\n", "\ufffd\n", "\xe2\x82", "\x1b[200~pasted\x1b[201~\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}
		reader := transform.NewReader(iotest.OneByteReader(strings.NewReader(input)), securityTerminalUTF8{})
		output, err := io.ReadAll(reader)
		if err == nil {
			if !utf8.Valid(output) || string(output) != input {
				t.Fatal("terminal encoding changed accepted input")
			}
		} else if !errors.Is(err, errSecurityTerminalEncoding) {
			t.Fatal("unexpected terminal encoding error")
		}
	})
}

func executeCredentialCommand(t *testing.T, input string, args ...string) ([]byte, error) {
	t.Helper()
	cmd, output := securityTestCommand(t)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(append([]string{"local", "generate"}, args...))
	err := cmd.Execute()
	return output.Bytes(), err
}

func passwordDirective(t *testing.T, output []byte, password string) {
	t.Helper()
	parts := regexp.MustCompile(`^password "bcrypt:8:(\$2[aby]\$08\$[^"\n]+)"\n$`).FindSubmatch(output)
	if len(parts) != 2 {
		t.Fatal("invalid password directive")
	}
	if err := bcrypt.CompareHashAndPassword(parts[1], []byte(password)); err != nil {
		t.Fatal("generated password hash does not match input")
	}
	if bytes.Contains(output, []byte(password)) {
		t.Fatal("password appeared in output")
	}
}

func apiKeyDirective(t *testing.T, output []byte) (string, string) {
	t.Helper()
	parts := regexp.MustCompile(`^secret: ([A-Za-z0-9]{72})\napi key ([A-Za-z0-9]{24}) "(bcrypt:8:\$2[aby]\$08\$[^"\n]+)"\n$`).FindSubmatch(output)
	if len(parts) != 4 || !bytes.Equal(parts[1][:24], parts[2]) {
		t.Fatal("invalid API key output or prefix")
	}
	password, err := identity.ParseHashedPassword(string(parts[3]))
	if err != nil || !password.Match(string(parts[1])) {
		t.Fatal("API key hash does not match generated secret")
	}
	return string(parts[1]), string(parts[3])
}

func TestSecurityCredentialGeneration(t *testing.T) {
	for _, input := range []string{"Test-secret-123", "Test-secret-123\n", "Test-secret-123\r\n", "bcrypt:8:literal-password\n", "Test-\ufffd-secret-123\n"} {
		output, err := executeCredentialCommand(t, input, "password", "hash", "--cost", "8", "--password-file", "-")
		if err != nil {
			t.Fatal(err)
		}
		passwordDirective(t, output, strings.TrimSuffix(strings.TrimSuffix(input, "\n"), "\r"))
	}
	seen := map[string]bool{}
	for range 2 {
		output, err := executeCredentialCommand(t, "", "api", "key", "--cost", "8")
		if err != nil {
			t.Fatal(err)
		}
		secret, _ := apiKeyDirective(t, output)
		if seen[secret] {
			t.Error("API key repeated")
		}
		seen[secret] = true
	}
}

func TestSecurityCredentialFailures(t *testing.T) {
	for _, input := range []string{"", "short", strings.Repeat("a", 73), strings.Repeat("a", 1000), " secret123", "secret123 ", "secret123\nextra", "secret123\x00", "secret123\xff", "secret123\n\n"} {
		output, err := executeCredentialCommand(t, input, "password", "hash", "--cost", "8", "--password-file", "-")
		if err == nil || len(output) != 0 {
			t.Error("invalid password accepted or disclosed")
		}
	}
	for _, args := range [][]string{
		{"password", "hash", "--cost", "7", "--password-file", "-"},
		{"api", "key", "--cost", "32"},
		{"api", "key", "--cost", "0"},
		{"password", "hash", "--password", registrationTestSecret},
		{"password", "hash", registrationTestSecret},
		{"password", "hash", "--cost", registrationTestSecret},
		{"password", "hash", "--password-file", ""},
		{"password", "hash"},
	} {
		output, err := executeCredentialCommand(t, registrationTestSecret, args...)
		if err == nil || bytes.Contains(output, []byte(registrationTestSecret)) || strings.Contains(err.Error(), registrationTestSecret) {
			t.Error("invalid generator accepted or disclosed secret")
		}
	}
	cmd, _ := securityTestCommand(t)
	cmd.SetOut(securityFailedWriter{})
	cmd.SetArgs([]string{"local", "generate", "api", "key", "--cost", "8"})
	if err := cmd.Execute(); err == nil {
		t.Error("generator ignored output failure")
	}
}

func TestSecurityCredentialPolicyReadOnly(t *testing.T) {
	dir := t.TempDir()
	database, passwordFile := filepath.Join(dir, "users.json"), filepath.Join(dir, "password.txt")
	// Missing fields would cause NewDatabase(path) to apply defaults and save.
	data := []byte(`{"policy":{"password":{"min_length":12,"max_length":30,"require_uppercase":true,"require_lowercase":true,"require_number":true,"require_non_alpha_numeric":true}},"users":[]}`)
	if err := os.WriteFile(database, data, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordFile, []byte("Policy-secret-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	output, err := executeCredentialCommand(t, "", "password", "hash", "--cost", "8", "--db-path", database, "--password-file", passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	passwordDirective(t, output, "Policy-secret-123")
	for _, password := range []string{"too-short", "all-lowercase-123", "ALL-UPPERCASE-123", "Missing-numbers", "MissingSymbols123"} {
		if _, err := executeCredentialCommand(t, password, "password", "hash", "--cost", "8", "--db-path", database, "--password-file", "-"); err == nil {
			t.Error("ignored password policy")
		}
	}
	after, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(database)
	if err != nil || !bytes.Equal(actual, data) || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		t.Error("hashing modified database")
	}
	missing := filepath.Join(dir, "missing", "users.json")
	if _, err := executeCredentialCommand(t, "Policy-secret-123", "password", "hash", "--cost", "8", "--db-path", missing, "--password-file", "-"); err == nil {
		t.Error("missing database accepted")
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Error("policy read created database directory")
	}
	for _, content := range []string{"null", "[]", "{", `{"policy":{"password":{"min_length":20,"max_length":10}}}`} {
		path := filepath.Join(dir, "invalid.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := securityPasswordPolicy(t.Context(), path); err == nil {
			t.Error("invalid policy accepted")
		}
	}
}

func securityCommandInput(t *testing.T, input string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestRegistrationCommandProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "SECURITY_REGISTRATION_COMMAND=1")
	cmd.Stdin = strings.NewReader(input)
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

func TestSecurityCredentialCommandE2E(t *testing.T) {
	output, err := securityCommandInput(t, "Process-\ufffd-secret-123\n", "security", "local", "generate", "password", "hash", "--password-file", "-", "--cost", "8")
	if err != nil {
		t.Fatal("Caddy password generator failed", err)
	}
	passwordDirective(t, output, "Process-\ufffd-secret-123")
	output, err = securityCommand(t, "security", "local", "generate", "api", "key", "--cost", "8")
	if err != nil {
		t.Fatal("Caddy API key generator failed", err)
	}
	apiKeyDirective(t, output)
	for _, path := range []string{"local", "local list", "local list users", "local info user", "local add user", "local delete user", "local update user", "local reload", "local connect", "local metadata", "local generate", "local generate password", "local generate password hash", "local generate api", "local generate api key"} {
		args := append([]string{"security"}, strings.Fields(path)...)
		output, err := securityCommand(t, append(args, "--help")...)
		if err != nil || !bytes.Contains(output, []byte("security "+path)) {
			t.Error("Caddy local help failed", path)
		}
		output, err = securityCommand(t, append(args, registrationTestSecret)...)
		if err == nil || bytes.Contains(output, []byte(registrationTestSecret)) {
			t.Error("Caddy local command accepted or exposed positional secret", path)
		}
	}
	// Password-file support also works without any portal configuration.
	path := filepath.Join(t.TempDir(), "password.txt")
	if err := os.WriteFile(path, []byte("File-secret-123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, err = securityCommand(t, "security", "local", "generate", "password", "hash", "--password-file", path, "--cost", "8")
	if err != nil {
		t.Fatal("password file generator failed", err)
	}
	passwordDirective(t, output, "File-secret-123")
}

func TestSecurityLocalMutationOutputFailure(t *testing.T) {
	// The output layer propagates errors for JSON that may contain a newly
	// generated password; a closed pipe must not report successful delivery.
	data, err := json.Marshal(map[string]string{"status": "success", "password": registrationTestSecret})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSecurityLocalResponse(securityFailedWriter{}, "add", "json", data); err == nil || strings.Contains(fmt.Sprint(err), registrationTestSecret) {
		t.Error("password output error ignored or disclosed secret")
	}
}
