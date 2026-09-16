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
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func cli(t *testing.T, home, input string, args ...string) (string, string, error) {
	t.Helper()
	cmd := newCommand(func(string) string { return "" })
	var out, diagnostics bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&diagnostics)
	cmd.SetIn(strings.NewReader(input))
	cmd.SetArgs(append([]string{"--home", home}, args...))
	err := cmd.ExecuteContext(t.Context())
	return out.String(), diagnostics.String(), err
}

func mustCLI(t *testing.T, home, input string, args ...string) string {
	t.Helper()
	out, _, err := cli(t, home, input, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func configureTest(t *testing.T, home, profileName, url string, args ...string) {
	t.Helper()
	base := []string{"configure", "--profile", profileName, "--url", url, "--realm", "local", "--username", "alice"}
	mustCLI(t, home, "", append(base, args...)...)
}

func TestCLIProfileLifecycle(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/auth/login" || r.Header.Get("Accept") != "application/json" {
			t.Error("incorrect login request")
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request["refresh_transport"] != "" {
			t.Error("legacy login unexpectedly requested refresh")
		}
		if request["challenge_kind"] == "" {
			io.WriteString(w, `{"sandbox_id":"sandbox","sandbox_secret":"secret","next_challenge":"password"}`)
			return
		}
		if request["challenge_response"] != "correct-password\t" {
			http.Error(w, "never disclose response", 401)
			return
		}
		io.WriteString(w, `{"authenticated":true,"access_token":"synthetic.jwt.value","access_token_name":"CUSTOM_TOKEN"}`)
	}))
	defer server.Close()
	home := filepath.Join(t.TempDir(), "authenticator")
	configureTest(t, home, "work", server.URL+"/auth")
	configureTest(t, home, "personal", server.URL+"/auth")
	if got := mustCLI(t, home, "", "profiles"); got != "personal\nwork\n" {
		t.Fatal("incorrect profile list")
	}
	output := mustCLI(t, home, "correct-password\t\r\n", "login", "--profile", "work", "--password-file", "-")
	if strings.Contains(output, "synthetic.jwt.value") {
		t.Fatal("login printed bearer credentials")
	}
	if requests.Load() != 2 {
		t.Fatal("unexpected challenge count")
	}
	path := filepath.Join(home, "profiles", "work", "token.jwt")
	store, _ := authclient.NewFileTokenStore(path)
	saved, err := store.Load()
	if err != nil || saved.AccessTokenName != "custom_token" {
		t.Fatal("shared store could not reopen named credentials")
	}
	if got := mustCLI(t, home, "", "token", "--profile", "work", "--header"); got != "Authorization: custom_token=synthetic.jwt.value\n" {
		t.Fatal("incorrect authorization header")
	}
	if got := mustCLI(t, home, "", "token", "--profile", "work"); got != "synthetic.jwt.value\n" {
		t.Fatal("incorrect raw token")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustCLI(t, home, "", "token", "--profile", "work", "--path"); got != canonical+"\n" {
		t.Fatal("incorrect token path")
	}
	if _, _, err := cli(t, home, "", "token", "--profile", "personal"); err == nil {
		t.Fatal("token leaked across profiles")
	}
	before, _ := os.ReadFile(path)
	_, diagnostics, err := cli(t, home, "wrong-password", "login", "--force", "--profile", "work", "--password-file", "-")
	if err == nil || strings.Contains(err.Error()+diagnostics, "never disclose") {
		t.Fatal("login failure was lost or leaked response")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed login replaced token")
	}
	config, _ := os.ReadFile(filepath.Join(home, "credentials"))
	logs, _ := os.ReadFile(filepath.Join(home, "profiles", "work", "auth.log"))
	for _, secret := range []string{"correct-password", "wrong-password", "synthetic.jwt.value", "sandbox", "never disclose"} {
		if bytes.Contains(config, []byte(secret)) || bytes.Contains(logs, []byte(secret)) {
			t.Fatal("secret appeared in configuration or logs")
		}
	}
	if !bytes.Contains(logs, []byte(`"outcome":"failed"`)) {
		t.Fatal("login failure was not logged")
	}
	mustCLI(t, home, "", "clear", "--profile", "work")
	mustCLI(t, home, "", "clear", "--profile", "work")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("clear retained token")
	}
	if _, err := os.Stat(filepath.Join(home, "profiles", "work", "auth.log")); err != nil {
		t.Fatal("clear deleted logs")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{home, filepath.Join(home, "profiles"), filepath.Join(home, "profiles", "work"), filepath.Join(home, "credentials"), filepath.Join(home, "profiles", "work", "auth.log")} {
			info, err := os.Stat(p)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatal("storage is not private")
			}
		}
	}
}

func TestCLIReconfigureAndPrecedence(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	configureTest(t, home, "default", "https://example.test")
	configureTest(t, home, "work", "https://work.example.test", "--refresh-transport", "body")
	store, _ := authclient.NewFileTokenStore(filepath.Join(home, "profiles", "work", "token.jwt"))
	if err := store.Save(&authclient.Credentials{AccessToken: "old-token"}); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, home, "api-key-bytes\n", "configure", "--profile", "work", "--api-key-file", "-")
	if _, err := store.Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("reconfigured profile retained token")
	}
	data, _ := os.ReadFile(filepath.Join(home, "credentials"))
	all, _ := parseProfiles(data)
	if all["default"]["username"] != "alice" || all["work"]["username"] != "" || all["work"]["api_key"] != "api-key-bytes" || all["work"]["refresh_transport"] != "" {
		t.Fatal("reconfiguration changed the wrong identity")
	}
	mustCLI(t, home, "", "configure", "--profile", "work", "--clear-secrets", "--username", "bob")
	data, _ = os.ReadFile(filepath.Join(home, "credentials"))
	all, _ = parseProfiles(data)
	if all["work"]["api_key"] != "" || all["work"]["username"] != "bob" {
		t.Fatal("could not switch back to password login")
	}
	cmd := newCommand(func(key string) string {
		if key == "CADDY_AUTHENTICATOR_HOME" {
			return filepath.Join(home, "missing")
		}
		return "unknown"
	})
	cmd.SetArgs([]string{"--home", home, "--profile", "work", "configure"})
	cmd.SetOut(io.Discard)
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal("flags did not override environment:", err)
	}
	cmd = newCommand(func(key string) string {
		if key == "CADDY_AUTHENTICATOR_HOME" {
			return home
		}
		return "default"
	})
	cmd.SetArgs([]string{"configure"})
	cmd.SetOut(io.Discard)
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal("environment selection failed:", err)
	}
	for _, args := range [][]string{{"login", "--profile", "../escape"}, {"login", "--timeout", "0"}, {"token", "--header", "--path"}, {"login", "extra"}} {
		if _, _, err := cli(t, home, "", args...); err == nil {
			t.Fatal("accepted invalid command")
		}
	}
}

func TestCLIDefaultHomeAndHelp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cmd := newCommand(func(string) string { return "" })
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"configure", "--url", "https://example.test", "--realm", "local", "--username", "alice"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".caddy-authenticator", "credentials"))
	if err != nil {
		t.Fatal("default state path not created:", err)
	}
	all, err := parseProfiles(data)
	if err != nil || all["default"]["username"] != "alice" {
		t.Fatal("default profile was not configured")
	}
	unused := filepath.Join(home, "unused")
	mustCLI(t, unused, "", "--help")
	if _, err := os.Stat(unused); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("help touched profile storage")
	}
}

func TestCLIDefaultsAndTimeoutOverride(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   []string
		timeout time.Duration
	}{
		{"defaults", nil, 45 * time.Second},
		{"explicit non-interactive", []string{"--interactive=false"}, 45 * time.Second},
		{"override", []string{"--timeout", "5s"}, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newCommand(func(string) string { return "" })
			cmd.SetArgs(append([]string{"--home", filepath.Join(t.TempDir(), "state"), "configure"}, tc.flags...))
			cmd.SetIn(strings.NewReader(""))
			var diagnostics bytes.Buffer
			cmd.SetErr(&diagnostics)
			cmd.SetOut(io.Discard)
			before := time.Now()
			executed, err := cmd.ExecuteContextC(context.Background())
			after := time.Now()
			if err == nil || !strings.Contains(err.Error(), "missing profile settings") || !strings.Contains(err.Error(), "--interactive") {
				t.Fatal("missing settings did not fail non-interactively with opt-in guidance")
			}
			if diagnostics.Len() != 0 {
				t.Fatal("default configure emitted a prompt")
			}
			deadline, ok := executed.Context().Deadline()
			if !ok || deadline.Before(before.Add(tc.timeout)) || deadline.After(after.Add(tc.timeout)) {
				t.Fatal("command did not apply the expected total deadline")
			}
		})
	}
}

func TestCLIVersion(t *testing.T) {
	version, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(t.TempDir(), "unused")
	output, diagnostics, err := cli(t, home, "", "version", "--profile", "../invalid")
	if err != nil || diagnostics != "" || output != "caddy-authenticator "+strings.TrimSpace(string(version))+"\n" {
		t.Fatalf("unexpected version output: %q, %q, %v", output, diagnostics, err)
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("version accessed profile storage")
	}
	if _, _, err := cli(t, home, "", "version", "extra"); err == nil {
		t.Fatal("version accepted positional arguments")
	}
	cmd := newCommand(func(string) string { return "" })
	cmd.SetArgs([]string{"version"})
	cmd.SetOut(failingVersionWriter{})
	if err := cmd.ExecuteContext(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("version lost stdout failure: %v", err)
	}
}

type failingVersionWriter struct{}

func (failingVersionWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCLILoginDoesNotPromptByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"sandbox_id":"sandbox","sandbox_secret":"secret","next_challenge":"password"}`)
	}))
	defer server.Close()
	home := filepath.Join(t.TempDir(), "state")
	configureTest(t, home, "default", server.URL)
	_, diagnostics, err := cli(t, home, "", "login")
	if err == nil || !strings.Contains(err.Error(), "authentication input required") || !strings.Contains(err.Error(), "--interactive") || diagnostics != "" {
		t.Fatal("default login did not reject missing input without prompting")
	}
}

func TestConfigurePreservesRelativeCA(t *testing.T) {
	home := filepath.Join(t.TempDir(), "state")
	configureTest(t, home, "default", "https://example.test")
	path := filepath.Join(home, "credentials")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	all, err := parseProfiles(data)
	if err != nil {
		t.Fatal(err)
	}
	all["default"]["ca_file"] = "relative-ca.pem"
	if err := os.WriteFile(path, encodeProfiles(all), 0600); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, home, "", "configure", "--username", "bob")
	data, _ = os.ReadFile(path)
	all, _ = parseProfiles(data)
	if all["default"]["ca_file"] != "relative-ca.pem" {
		t.Fatal("unrelated configure changed relative CA resolution")
	}
}

func TestConfigureCAPathTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}
	home, top, target := filepath.Join(t.TempDir(), "state"), t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "child"), filepath.Join(top, "link")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{top, target} {
		if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("synthetic certificate"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configureTest(t, home, "default", "https://example.test", "--ca-file", filepath.Join(top, "link")+"/../ca.pem")
	data, err := os.ReadFile(filepath.Join(home, "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := parseProfiles(data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(all["default"]["ca_file"])
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(filepath.Join(target, "ca.pem"))
	if err != nil || !os.SameFile(got, want) {
		t.Fatal("configure changed the selected CA file by cleaning link/..")
	}
}

func TestRejectedCommandPreservesState(t *testing.T) {
	for _, command := range []string{"configure", "clear"} {
		t.Run(command, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "state")
			configureTest(t, home, "default", "https://example.test")
			configPath := filepath.Join(home, "credentials")
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			tokenPath := filepath.Join(home, "profiles", "default", "token.jwt")
			store, _ := authclient.NewFileTokenStore(tokenPath)
			if err := store.Save(&authclient.Credentials{AccessToken: "preserved-token"}); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(home, "profiles", "default", "auth.log")
			if err := os.Remove(logPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(logPath, 0700); err != nil {
				t.Fatal(err)
			}
			args := []string{command}
			if command == "configure" {
				args = append(args, "--username", "bob")
			}
			if _, _, err := cli(t, home, "", args...); err == nil {
				t.Fatal("accepted unusable profile log")
			}
			after, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Error("rejected command changed credentials")
			}
			if token, err := store.Load(); err != nil || token.AccessToken != "preserved-token" {
				t.Error("rejected command removed token")
			}
		})
	}
}

func TestExplicitEmptyHomeDoesNotUseDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if _, _, err := cli(t, "", "", "configure", "--url", "https://example.test", "--realm", "local", "--username", "alice"); err == nil {
		t.Error("explicit empty home used the default directory")
	}
	if _, err := os.Stat(filepath.Join(home, ".caddy-authenticator")); !errors.Is(err, os.ErrNotExist) {
		t.Error("explicit empty home modified default state")
	}
}

func TestConfigureRejectsMultipleStdinBeforeReading(t *testing.T) {
	input := bytes.NewBufferString("synthetic-secret\n")
	cmd := newCommand(func(string) string { return "" })
	cmd.SetArgs([]string{"--home", filepath.Join(t.TempDir(), "state"), "configure", "--url", "https://example.test", "--realm", "local", "--username", "alice", "--password-file", "-", "--totp-secret-file", "-"})
	cmd.SetIn(input)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "only one secret") {
		t.Fatal("ambiguous stdin flags were accepted")
	}
	if input.String() != "synthetic-secret\n" {
		t.Fatal("invalid command consumed secret input")
	}
}

func TestCLITLSAndRedirect(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		io.WriteString(w, `{"authenticated":true,"access_token":"tls-token"}`)
	}))
	defer server.Close()
	home := filepath.Join(t.TempDir(), "state")
	configureTest(t, home, "default", server.URL)
	if _, _, err := cli(t, home, "", "login"); err == nil {
		t.Fatal("accepted untrusted TLS")
	}
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, home, "", "login", "--ca-file", cert)
	if count.Load() != 1 {
		t.Fatal("TLS trust checks contacted portal unexpectedly")
	}
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer redirect.Close()
	configureTest(t, home, "default", redirect.URL)
	if _, _, err := cli(t, home, "", "login"); err == nil || leaked.Load() != 0 {
		t.Fatal("redirect followed or reported successful")
	}
	configureTest(t, home, "default", "http://example.test")
	if _, _, err := cli(t, home, "", "login"); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatal("allowed remote cleartext login")
	}
}

func TestLoginRelativeCAPathTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"authenticated":true,"access_token":"synthetic-token"}`)
	}))
	defer server.Close()
	home, target := filepath.Join(t.TempDir(), "state"), t.TempDir()
	configureTest(t, home, "default", server.URL)
	if err := os.Mkdir(filepath.Join(target, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "child"), filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "ca.pem"), []byte("incorrect CA selection"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(home, "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	all, err := parseProfiles(data)
	if err != nil {
		t.Fatal(err)
	}
	all["default"]["ca_file"] = "link/../ca.pem"
	if err := os.WriteFile(filepath.Join(home, "credentials"), encodeProfiles(all), 0600); err != nil {
		t.Fatal(err)
	}
	mustCLI(t, home, "", "login")
}

func TestCLIDeadlineAndInput(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))
	defer server.Close()
	defer close(done)
	home := filepath.Join(t.TempDir(), "state")
	configureTest(t, home, "default", server.URL)
	start := time.Now()
	if _, _, err := cli(t, home, "", "login", "--timeout", "40ms"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("HTTP request did not observe deadline")
	}
	if time.Since(start) > time.Second {
		t.Fatal("deadline was not bounded")
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := readSecretFile(ctx, r, "-"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stdin did not observe deadline")
	}
	if _, err := newTerminalInput(strings.NewReader("password"), io.Discard).read(t.Context(), "Password: ", true); err == nil {
		t.Fatal("silently accepted nonterminal prompt")
	}
	for _, data := range []string{"", "a\nb", "a\x00b", "\xff", strings.Repeat("a", maxFileSize+1)} {
		if _, err := readSecretFile(t.Context(), strings.NewReader(data), "-"); err == nil {
			t.Fatal("accepted malformed secret")
		}
	}
	value, err := readSecretFile(t.Context(), strings.NewReader(" secret\t\r\n"), "-")
	if err != nil || value != " secret\t" {
		t.Fatal("secret file whitespace changed")
	}
}
