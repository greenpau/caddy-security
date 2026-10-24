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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func TestCaddySQLiteRefreshUncertaintyE2E(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private SQLite refresh backend requires POSIX file ownership")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "caddy-authenticator")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-o", binary, "./cmd/caddy-authenticator")
	// The real production CLI is CGO-free. Its enclosing actual Caddy test process
	// retains the caller's race/coverage instrumentation.
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath -p=1")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual native authenticator: %v\n%s", err, output)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddySQLiteRefreshUncertaintyProcess$", "-test.v", "-test.timeout=200s")
	child.Env = append(os.Environ(), "CADDY_SQLITE_REFRESH_UNCERTAINTY_CHILD=1", "CADDY_SQLITE_REFRESH_AUTHENTICATOR="+binary,
		"XDG_DATA_HOME="+t.TempDir(), "XDG_CONFIG_HOME="+t.TempDir())
	collectSubprocessCoverage(t, child)
	child.WaitDelay = 5 * time.Second
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("actual SQLite COMMIT client recovery: %v\n%s", err, output)
	}
}
func TestCaddySQLiteRefreshUncertaintyProcess(t *testing.T) {
	if os.Getenv("CADDY_SQLITE_REFRESH_UNCERTAINTY_CHILD") != "1" {
		t.Skip("isolated Caddy helper")
	}
	cert, key, roots := cookieTLSCertificate(t)
	t.Run("browser", func(t *testing.T) {
		f := newSQLiteCommitFixture(t, cert, key, roots)
		runSQLiteCommitBrowser(t, f)
	})
	t.Run("native", func(t *testing.T) {
		f := newSQLiteCommitFixture(t, cert, key, roots)
		runSQLiteCommitCLI(t, f, os.Getenv("CADDY_SQLITE_REFRESH_AUTHENTICATOR"))
	})
}

func sqliteCommitPrivateFile(t *testing.T, path string) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 128<<10 {
		t.Fatal("native credential evidence is missing, oversized or not private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read private native evidence")
	}
	return data
}
func runSQLiteCommitCLI(t *testing.T, f *sqliteCommitFixture, binary string) {
	t.Helper()
	if binary == "" {
		t.Fatal("actual authenticator binary is unavailable")
	}
	home := filepath.Join(t.TempDir(), "authenticator")
	profile := filepath.Join(home, "profiles", "sqlite")
	tokenPath, pendingPath := filepath.Join(profile, "token.jwt"), filepath.Join(profile, "refresh.pending")
	var outputs [][]byte
	call := func(input string, args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, append([]string{"--home", home, "--timeout", "10s"}, args...)...)
		command.Env = append(os.Environ(), "CADDY_AUTHENTICATOR_HOME=", "CADDY_AUTHENTICATOR_PROFILE=")
		command.Stdin = strings.NewReader(input)
		command.WaitDelay = 2 * time.Second
		output, err := command.CombinedOutput()
		outputs = append(outputs, bytes.Clone(output))
		return output, err
	}
	load := func() (*authclient.Credentials, []byte) {
		t.Helper()
		data := sqliteCommitPrivateFile(t, tokenPath)
		store, err := authclient.NewFileTokenStore(tokenPath)
		if err != nil {
			t.Fatal("cannot select native token file")
		}
		credentials, err := store.Load()
		if credentials != nil {
			f.secrets = append(f.secrets, credentials.AccessToken, credentials.RefreshToken)
		}
		if err != nil || credentials == nil {
			t.Fatal("cannot load actual native credentials")
		}
		return credentials, data
	}
	t.Cleanup(func() {
		f.capture()
		for _, output := range outputs {
			assertAdminRedacted(t, output, f.secrets)
		}
		if data, err := os.ReadFile(filepath.Join(profile, "auth.log")); err == nil {
			assertAdminRedacted(t, data, f.secrets)
		} else {
			t.Error("native diagnostic evidence is missing")
		}
	})
	if _, err := call("", "configure", "--profile", "sqlite", "--url", f.issuer, "--realm", "local", "--username", "alice", "--ca-file", f.cert, "--refresh-transport", "body"); err != nil {
		t.Fatal("native private-CA body profile configuration failed")
	}
	if _, err := call(lifecyclePassword+"\n", "login", "--profile", "sqlite", "--password-file", "-"); err != nil {
		t.Fatal("native initial real password login failed")
	}
	first, firstBytes := load()
	firstClaims := f.verify(t, first.AccessToken)
	if first.RefreshToken == "" || first.SessionID == "" || firstClaims["sid"] != first.SessionID || first.AccessExpiresAt <= time.Now().Unix() || first.AccessExpiresAt-time.Now().Unix() >= 180 {
		t.Fatal("native login did not receive a genuine short-lived renewable grant")
	}
	f.resource(t, first.AccessToken, 200)
	before := f.ArmCommitFailure(t)
	output, err := call("", "login", "--profile", "sqlite")
	f.capture()
	if err == nil || !bytes.Contains(output, []byte("HTTP 503")) || !bytes.Contains(output, []byte("login --force")) {
		t.Fatal("native uncertain exchange did not require fresh login")
	}
	f.AssertUncertain(t, before)
	unchanged, afterBytes := load()
	if !bytes.Equal(firstBytes, afterBytes) || unchanged.AccessToken != first.AccessToken || unchanged.RefreshToken != first.RefreshToken {
		t.Fatal("native uncertain exchange overwrote retained credentials")
	}
	marker := sqliteCommitPrivateFile(t, pendingPath)
	if string(marker) != "Refresh may have consumed its credential. Use login --force to authenticate again.\n" {
		t.Fatal("native uncertainty marker changed its fixed non-secret contract")
	}
	snapshot := f.witness.snapshot()
	for _, reopen := range []bool{false, true} {
		if reopen {
			f.RestartSameConfig(t)
		}
		output, err = call("", "login", "--profile", "sqlite")
		if err == nil || !bytes.Contains(output, []byte("previous refresh may have consumed")) {
			t.Fatal("native client did not preserve its local uncertainty refusal")
		}
		f.assertNoExchange(t, snapshot)
		if !bytes.Equal(sqliteCommitPrivateFile(t, tokenPath), firstBytes) || !bytes.Equal(sqliteCommitPrivateFile(t, pendingPath), marker) {
			t.Fatal("native uncertainty refusal changed private state")
		}
	}
	// Capacity is four: the deterministic failed COMMIT may have rolled back and
	// kept the old family. Fresh native proof does not submit it for replacement.
	if _, err := call(lifecyclePassword+"\n", "login", "--profile", "sqlite", "--force", "--password-file", "-"); err != nil {
		t.Fatal("native fresh login after reopen failed")
	}
	fresh, _ := load()
	freshClaims := f.verify(t, fresh.AccessToken)
	if fresh.SessionID == first.SessionID || fresh.SessionID == "" || freshClaims["sid"] != fresh.SessionID || fresh.AccessToken == first.AccessToken || fresh.RefreshToken == first.RefreshToken {
		t.Fatal("native fresh login did not publish a new independent family")
	}
	if _, err := os.Lstat(pendingPath); !os.IsNotExist(err) {
		t.Fatal("native fresh login retained uncertainty marker")
	}
	f.resource(t, fresh.AccessToken, http.StatusOK)
	beforeRotation := f.witness.snapshot()
	if _, err := call("", "login", "--profile", "sqlite"); err != nil {
		t.Fatal("native new-family refresh failed")
	}
	rotated, _ := load()
	f.verify(t, rotated.AccessToken)
	now := f.witness.snapshot()
	if rotated.SessionID != fresh.SessionID || rotated.RefreshToken == fresh.RefreshToken || now.RefreshRequests != beforeRotation.RefreshRequests+1 || now.RotateCalls != beforeRotation.RotateCalls+1 || now.Uncertain != beforeRotation.Uncertain {
		t.Fatal("native recovery did not rotate exactly the new family")
	}
	f.resource(t, rotated.AccessToken, http.StatusOK)
	f.assertOriginalExchangedOnce(t, first.RefreshToken)
	// The staged access token must remain private even though it has a valid
	// signature. Never present it to an authentication or refresh endpoint.
	staged := f.witness.snapshot().Staged
	for _, data := range [][]byte{firstBytes, afterBytes, sqliteCommitPrivateFile(t, tokenPath), marker} {
		if staged != "" && bytes.Contains(data, []byte(staged)) {
			t.Fatal("native client published the uncommitted staged token")
		}
	}
}
