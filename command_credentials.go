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
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"golang.org/x/text/transform"
)

var errSecurityTerminalEncoding = errors.New("terminal input contains invalid UTF-8 or a replacement character; use a private config or password file")

// x/term's line editor treats utf8.RuneError as an incomplete key and can
// discard it. Validate the stream first, including sequences split across
// reads. Literal U+FFFD is rejected here too; file input preserves it exactly.
type securityTerminalUTF8 struct{ transform.NopResetter }

// Transform preserves complete UTF-8 sequences and rejects input the editor would discard.
func (securityTerminalUTF8) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		if !atEOF && !utf8.FullRune(src[nSrc:]) {
			return nDst, nSrc, transform.ErrShortSrc
		}
		value, size := utf8.DecodeRune(src[nSrc:])
		if value == utf8.RuneError {
			return nDst, nSrc, errSecurityTerminalEncoding
		}
		if len(dst)-nDst < size {
			return nDst, nSrc, transform.ErrShortDst
		}
		copy(dst[nDst:], src[nSrc:nSrc+size])
		nDst += size
		nSrc += size
	}
	return nDst, nSrc, nil
}

func addSecurityCredentialCommands(parent *cobra.Command) {
	generate := securityCommandGroup(parent, "generate", "Generate credentials offline")
	password := securityCommandGroup(generate, "password", "Generate password hashes")
	api := securityCommandGroup(generate, "api", "Generate API credentials")
	for _, action := range []struct {
		parent *cobra.Command
		name   string
		api    bool
	}{
		{password, "hash", false}, {api, "key", true},
	} {
		cmd := &cobra.Command{Use: action.name, Args: securityNoArgs}
		cmd.Flags().Int("cost", 10, "Bcrypt cost (8-31)")
		if action.api {
			cmd.Short = "Generate an API key and its Caddyfile hash"
			cmd.Long = "Generate a random 72-character API key and a bcrypt hash. Output includes the plaintext secret and an api key Caddyfile directive with its 24-character prefix. Protect stdout. No server or database is accessed."
		} else {
			cmd.Short = "Generate a Caddyfile password hash"
			cmd.Long = "Read a password without terminal echo and print a password Caddyfile directive. For automation use --password-file, or --password-file - for stdin. One final LF or CRLF is removed; other whitespace is never silently trimmed. An optional --db-path reads password policy without modifying the database."
			cmd.Flags().String("password-file", "", "Owner-only password file, or - to read stdin")
			cmd.Flags().String("db-path", "", "Existing local database to read password policy from")
		}
		cmd.RunE = func(cmd *cobra.Command, _ []string) error { return runSecurityCredential(cmd, action.api) }
		action.parent.AddCommand(cmd)
	}
}

// The caller owns terminal state so cancellation restores echo immediately.
// A pending terminal read may remain until this CLI process exits; it never owns
// terminal restoration and therefore cannot put the terminal back in raw mode.
func readSecuritySecret(ctx context.Context, input io.Reader, output io.Writer, prompt string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", fmt.Errorf("terminal input required; configure credentials or use --password-file for hashing")
	}
	fd := int(f.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("cannot read terminal input")
	}
	defer term.Restore(fd, state)
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return "", err
	}
	type result struct {
		text string
		err  error
	}
	results := make(chan result, 1)
	terminal := term.NewTerminal(struct {
		io.Reader
		io.Writer
	}{transform.NewReader(input, securityTerminalUTF8{}), io.Discard}, "")
	go func() { value, err := terminal.ReadPassword(""); results <- result{value, err} }()
	select {
	case value := <-results:
		if _, err := fmt.Fprint(output, "\r\n"); err != nil {
			return "", err
		}
		if value.err != nil {
			if errors.Is(value.err, errSecurityTerminalEncoding) {
				return "", errSecurityTerminalEncoding
			}
			return "", fmt.Errorf("cannot read terminal input")
		}
		return value.text, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func runSecurityCredential(cmd *cobra.Command, api bool) error {
	cost, _ := cmd.Flags().GetInt("cost")
	if cost < 8 || cost > bcrypt.MaxCost {
		return fmt.Errorf("bcrypt cost must be between 8 and 31")
	}
	var secret string
	if api {
		// Authcrunch requires 64-72 alphanumeric bytes and indexes the first 24.
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		var value [72]byte
		for i := range value {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return fmt.Errorf("cannot generate API key")
			}
			value[i] = alphabet[n.Int64()]
		}
		secret = string(value[:])
	} else {
		path, _ := cmd.Flags().GetString("db-path")
		policy, err := securityPasswordPolicy(cmd.Context(), path)
		if err != nil {
			return err
		}
		passwordFile, _ := cmd.Flags().GetString("password-file")
		if cmd.Flags().Changed("password-file") && passwordFile == "" {
			return fmt.Errorf("password file must not be empty")
		}
		if passwordFile == "" {
			secret, err = func() (string, error) {
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				return readSecuritySecret(ctx, cmd.InOrStdin(), cmd.ErrOrStderr(), "Password: ")
			}()
			// Release the interrupt handler before bcrypt, which cannot observe
			// context cancellation. Ctrl-C must still stop an expensive hash.
		} else {
			var data []byte
			if passwordFile == "-" {
				data, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 75))
			} else {
				data, err = readSecurityLocalFile(cmd.Context(), passwordFile, 74, true)
			}
			if err != nil {
				return fmt.Errorf("cannot read password input")
			}
			secret = strings.TrimSuffix(string(data), "\n")
			if len(secret) < len(data) {
				secret = strings.TrimSuffix(secret, "\r")
			}
		}
		if err != nil {
			return err
		}
		if err := validateSecurityPassword(secret, policy); err != nil {
			return err
		}
	}
	// Hash plaintext directly: the upstream constructor interprets bcrypt:
	// prefixes as already-hashed input and silently trims password whitespace.
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return fmt.Errorf("cannot generate bcrypt hash")
	}
	if api {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "secret: %s\napi key %s \"bcrypt:%d:%s\"\n", secret, secret[:24], cost, hash)
	} else {
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "password \"bcrypt:%d:%s\"\n", cost, hash)
	}
	return err
}

func securityPasswordPolicy(ctx context.Context, path string) (identity.PasswordPolicy, error) {
	if err := ctx.Err(); err != nil {
		return identity.PasswordPolicy{}, err
	}
	// Obtain upstream defaults in memory. NewDatabase(path) can create or rewrite
	// files while applying defaults, even for a supposedly read-only hash command.
	db, err := identity.NewDatabase(":memory:")
	if err != nil {
		return identity.PasswordPolicy{}, fmt.Errorf("cannot initialize password policy")
	}
	policy := db.Policy.Password
	if path == "" || path == ":memory:" {
		return policy, nil
	}
	data, err := readSecurityLocalFile(ctx, path, 64<<20, false)
	if err != nil {
		return policy, fmt.Errorf("read database policy: %w", err)
	}
	var record *struct {
		Policy struct {
			Password identity.PasswordPolicy `json:"password"`
		} `json:"policy"`
	}
	if json.Unmarshal(data, &record) != nil || record == nil {
		return policy, fmt.Errorf("invalid database policy JSON")
	}
	loaded := record.Policy.Password
	if loaded.MinLength == 0 {
		loaded.MinLength = policy.MinLength
	}
	if loaded.MaxLength == 0 {
		loaded.MaxLength = policy.MaxLength
	}
	if loaded.MinLength < 0 || loaded.MaxLength < loaded.MinLength {
		return policy, fmt.Errorf("invalid database password length policy")
	}
	return loaded, nil
}

func validateSecurityPassword(secret string, policy identity.PasswordPolicy) error {
	if !utf8.ValidString(secret) || strings.ContainsAny(secret, "\r\n\x00") || strings.TrimSpace(secret) != secret {
		return fmt.Errorf("password must be valid UTF-8 without line breaks, NUL, or surrounding whitespace")
	}
	if len(secret) == 0 || len(secret) > 72 {
		return fmt.Errorf("bcrypt password must contain 1-72 bytes")
	}
	if len(secret) < policy.MinLength || len(secret) > policy.MaxLength {
		return fmt.Errorf("password does not satisfy database length policy")
	}
	var upper, lower, number, special bool
	for _, c := range secret {
		upper = upper || unicode.IsUpper(c)
		lower = lower || unicode.IsLower(c)
		number = number || unicode.IsDigit(c)
		special = special || (!unicode.IsLetter(c) && !unicode.IsDigit(c))
	}
	if (policy.RequireUppercase && !upper) || (policy.RequireLowercase && !lower) || (policy.RequireNumber && !number) || (policy.RequireNonAlphaNumeric && !special) {
		return fmt.Errorf("password does not satisfy database character requirements")
	}
	return nil
}
