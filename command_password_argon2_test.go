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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/identity"
)

func generatedArgon2Password(t *testing.T, output []byte, plaintext string) *identity.Password {
	t.Helper()
	prefix, suffix := "password \"", "\"\n"
	if !bytes.HasPrefix(output, []byte(prefix)) || !bytes.HasSuffix(output, []byte(suffix)) {
		t.Fatal("generator did not emit a quoted password directive")
	}
	encoded := string(output[len(prefix) : len(output)-len(suffix)])
	password, err := identity.ParseHashedPassword(encoded)
	if err != nil || password.Algorithm != "argon2" || !password.Match(plaintext) || password.Match(encoded) {
		t.Fatal("generated Argon2 import did not verify the original plaintext exclusively")
	}
	if bytes.Contains(output, []byte(plaintext)) {
		t.Fatal("generator disclosed plaintext")
	}
	return password
}

func TestSecurityCredentialArgon2Options(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want identity.PasswordHashConfig
	}{
		{"default", nil, identity.PasswordHashConfig{Algorithm: "bcrypt", Cost: 10}},
		{"bcrypt", []string{"--algorithm", "bcrypt", "--cost", "8"}, identity.PasswordHashConfig{Algorithm: "bcrypt", Cost: 8}},
		{"argon2 defaults", []string{"--algorithm", "argon2"}, identity.PasswordHashConfig{Algorithm: "argon2", Memory: 65536, Iterations: 3, Parallelism: 4}},
		{"argon2 custom", []string{"--algorithm", "argon2", "--memory", "1024", "--iterations", "2", "--parallelism", "2"}, identity.PasswordHashConfig{Algorithm: "argon2", Memory: 1024, Iterations: 2, Parallelism: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, _ := securityTestCommand(t)
			cmd, _, err := root.Find([]string{"local", "generate", "password", "hash"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatal(err)
			}
			got, err := securityPasswordHashConfig(cmd)
			if err != nil || *got != tc.want {
				t.Fatalf("unexpected hashing options: %v", err)
			}
		})
	}
}

func TestSecurityCredentialArgon2Generation(t *testing.T) {
	args := []string{"password", "hash", "--algorithm", "argon2", "--memory", "1024", "--iterations", "2", "--parallelism", "2", "--password-file", "-"}
	for _, plaintext := range []string{argon2FixturePlaintext, strings.Repeat("LongPassword!", 8), "秘密-Test-🔑-123"} {
		var previous string
		for range 2 {
			output, err := executeCredentialCommand(t, plaintext+"\r\n", args...)
			if err != nil {
				t.Fatal(err)
			}
			p := generatedArgon2Password(t, output, plaintext)
			if !strings.HasPrefix(p.Hash, "$argon2id$v=19$m=1024,t=2,p=2$") || p.Cost != 0 || p.Hash == previous {
				t.Fatal("Argon2 parameters or random salt lost")
			}
			previous = p.Hash
		}
	}
}

func TestSecurityCredentialArgon2AlgorithmExact(t *testing.T) {
	for _, algorithm := range []string{"argon2", "bcrypt"} {
		for _, suffix := range []struct{ name, value string }{
			{"space", " "}, {"tab", "\t"}, {"unicode space", "\u2003"}, {"carriage return", "\r"},
		} {
			t.Run(algorithm+"/"+suffix.name, func(t *testing.T) {
				cmd, output := securityTestCommand(t)
				input := strings.NewReader(argon2FixturePlaintext)
				cmd.SetIn(input)
				cmd.SetArgs([]string{"local", "generate", "password", "hash", "--algorithm", algorithm + suffix.value, "--password-file", "-"})
				err := cmd.Execute()
				if err == nil || output.Len() != 0 || input.Len() != len(argon2FixturePlaintext) {
					t.Fatal("invalid algorithm was normalized, emitted output, or read the password")
				}
			})
		}
	}
}

func TestSecurityCredentialArgon2Failures(t *testing.T) {
	for _, flags := range [][]string{
		{"--algorithm", "argon2", "--cost", "10"},
		{"--algorithm", "argon2", "--cost", "0"},
		{"--algorithm", "bcrypt", "--memory", "1024"},
		{"--iterations", "2"}, {"--parallelism", "0"},
		{"--algorithm", "argon2id"}, {"--algorithm", ""},
		{"--algorithm", registrationTestSecret},
		{"--algorithm", "argon2", "--memory", "0"},
		{"--algorithm", "argon2", "--memory", "-1"},
		{"--algorithm", "argon2", "--memory", "262145"},
		{"--algorithm", "argon2", "--memory", "262144", "--iterations", "5"},
		{"--algorithm", "argon2", "--memory", "8", "--parallelism", "2"},
		{"--algorithm", "argon2", "--iterations", "11"},
		{"--algorithm", "argon2", "--parallelism", "17"},
		{"--algorithm", "argon2", "--memory", registrationTestSecret},
	} {
		// No input source: option rejection must precede the terminal prompt/KDF.
		output, err := executeCredentialCommand(t, registrationTestSecret, append([]string{"password", "hash"}, flags...)...)
		if err == nil || len(output) != 0 || strings.Contains(err.Error(), registrationTestSecret) || strings.Contains(err.Error(), "terminal") {
			t.Error("invalid options accepted, disclosed, or read input")
		}
	}
	for _, candidate := range []string{"", "short", " padded-secret", "padded-secret ", "embedded\nnewline", "invalid-\xff-UTF8", "embedded\x00NUL", strings.Repeat("a", 129), argon2FixtureHash, bcryptFixtureHash, "argon2:malformed", "bcrypt:malformed"} {
		output, err := executeCredentialCommand(t, candidate, "password", "hash", "--algorithm", "argon2", "--memory", "1024", "--password-file", "-")
		if err == nil || len(output) != 0 || (candidate != "" && strings.Contains(err.Error(), candidate)) {
			t.Error("invalid Argon2 plaintext accepted or disclosed")
		}
	}
	output, err := executeCredentialCommand(t, "", "api", "key", "--algorithm", "argon2")
	if err == nil || len(output) != 0 {
		t.Fatal("API key generator accepted Argon2")
	}
	cmd, _ := securityTestCommand(t)
	cmd.SetOut(securityFailedWriter{})
	cmd.SetIn(strings.NewReader(argon2FixturePlaintext))
	cmd.SetArgs([]string{"local", "generate", "password", "hash", "--algorithm", "argon2", "--memory", "1024", "--password-file", "-"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("Argon2 generator ignored output failure")
	}
}

func TestSecurityCredentialArgon2PolicyReadOnly(t *testing.T) {
	dir := t.TempDir()
	database, input := filepath.Join(dir, "users.json"), filepath.Join(dir, "password.txt")
	// Impossible username policy must not affect offline password generation.
	data := []byte(`{"policy":{"user":{"min_length":200,"max_length":201},"password":{"min_length":16,"max_length":100,"require_uppercase":true,"require_number":true}},"users":[]}`)
	if err := os.WriteFile(database, data, 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte(argon2FixturePlaintext+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"password", "hash", "--algorithm", "argon2", "--memory", "1024", "--db-path", database, "--password-file", input}
	output, err := executeCredentialCommand(t, "", args...)
	if err != nil {
		t.Fatal(err)
	}
	generatedArgon2Password(t, output, argon2FixturePlaintext)
	for _, password := range []string{"Short-secret1", "missinguppercase12345", "MissingNumbersPassword", strings.Repeat("A1", 51)} {
		args[len(args)-1] = "-"
		output, err := executeCredentialCommand(t, password, args...)
		if err == nil || len(output) != 0 {
			t.Fatal("ignored independent password policy")
		}
	}
	after, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(database)
	if err != nil || !bytes.Equal(actual, data) || !after.ModTime().Equal(before.ModTime()) || after.Mode() != before.Mode() {
		t.Fatal("generation changed database")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("generation created database sidecars")
	}
}
