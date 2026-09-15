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
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

// Exercise Caddy's registered local command using its actual flag/dispatch path.
func TestRegistrationCommandProcess(t *testing.T) {
	if os.Getenv("SECURITY_REGISTRATION_COMMAND") != "1" {
		t.Skip("command process helper")
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			caddycmd.Main()
			// Match the real executable: keep Go's test PASS trailer out of
			// machine-readable command output.
			os.Exit(0)
		}
	}
	t.Fatal("missing command arguments")
}

func securityCommand(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestRegistrationCommandProcess$", "--"}, args...)...)
	command.Env = append(os.Environ(), "SECURITY_REGISTRATION_COMMAND=1")
	command.WaitDelay = 5 * time.Second
	return command.CombinedOutput()
}

func registrationCommand(t *testing.T, config, operation, name, revision, from string) ([]byte, error) {
	t.Helper()
	var subcommand string
	switch operation {
	case "init":
		subcommand = "oauth init provisioning store"
	case "create":
		subcommand = "oauth create application"
	case "rotate":
		subcommand = "oauth rotate secret"
	case "key":
		subcommand = "oidc create signing key"
	default:
		t.Fatal("unsupported test provisioning operation")
	}
	args := append([]string{"security"}, strings.Fields(subcommand)...)
	args = append(args, "--config", config)
	for _, flag := range []struct{ name, value string }{{"name", name}, {"revision", revision}, {"from", from}} {
		if flag.value != "" {
			args = append(args, "--"+flag.name, flag.value)
		}
	}
	return securityCommand(t, args...)
}

func TestCaddyRegistrationE2E(t *testing.T) {
	dir := registrationTestDirectory(t)
	cfg := &OAuthRegistrationStoreConfig{Path: filepath.Join(dir, "store")}
	storeInput := "oauth registration store {\n path " + cfg.Path + "\n}\n"
	storeFile := filepath.Join(dir, "oauth_store.Caddyfile")
	clientFile := filepath.Join(dir, "oauth_client.Caddyfile")
	if err := os.WriteFile(storeFile, []byte(storeInput), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientFile, []byte(storeInput+"oauth application website {\n redirect_uri https://rp.example.test/callback\n skip_consent on\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	legacyFile := filepath.Join(dir, "legacy.Caddyfile")
	if err := os.WriteFile(legacyFile, []byte(strings.TrimPrefix(storeInput, "oauth ")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := registrationCommand(t, legacyFile, "init", "", "", ""); err == nil {
		t.Fatal("CLI accepted the obsolete unscoped registration store declaration")
	}
	if _, err := os.Lstat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("rejected store declaration initialized storage")
	}
	// Cleaning a nonexistent component followed by .. would open a different
	// input file and previously initialized a store from that unintended input.
	if _, err := registrationCommand(t, dir+"/missing/../oauth_store.Caddyfile", "init", "", "", ""); err == nil {
		t.Fatal("CLI silently cleaned the requested provisioning config path")
	}
	if _, err := os.Lstat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("rejected CLI path created storage")
	}
	if output, err := registrationCommand(t, storeFile, "init", "", "", ""); err != nil {
		t.Fatalf("CLI init: %v\n%s", err, output)
	}
	oversizedFile := filepath.Join(dir, "oversized.Caddyfile")
	if err := os.WriteFile(oversizedFile, []byte(storeInput+"oauth application website {\n"+strings.Join(oversizedRegistrationDirectives(), "\n")+"\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := registrationCommand(t, oversizedFile, "create", "website", "v1", ""); err == nil {
		t.Fatal("CLI published an unreadable oversized registration")
	}
	if entries := registrationSnapshot(t, cfg.Path); len(entries) != 0 {
		t.Fatal("rejected CLI record left storage artifacts")
	}
	invalidInput := storeInput + "oauth application website {\nclient_secret " + registrationTestSecret + "\xff\nredirect_uri https://rp.example.test/callback\n}\n"
	invalidFile := filepath.Join(dir, "invalid.Caddyfile")
	if err := os.WriteFile(invalidFile, []byte(invalidInput), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := registrationCommand(t, invalidFile, "create", "website", "v1", ""); err == nil || bytes.Contains(output, []byte(registrationTestSecret)) {
		t.Fatal("CLI normalized malformed credential bytes or exposed the secret")
	}
	if entries := registrationSnapshot(t, cfg.Path); len(entries) != 0 {
		t.Fatal("rejected malformed input left storage artifacts")
	}
	// Independent processes share a directory lock and no-replace publication.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	outputs := make([][]byte, 4)
	for i := range 4 {
		wg.Go(func() { outputs[i], errs[i] = registrationCommand(t, clientFile, "create", "website", "v1", "") })
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("CLI concurrent creation had %d winners", wins)
	}
	if output, err := registrationCommand(t, storeFile, "key", "login", "k1", ""); err != nil {
		t.Fatalf("CLI key: %v\n%s", err, output)
	}
	store, err := cfg.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer store.root.Close()
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range outputs {
		if bytes.Contains(output, []byte(first.Client.ClientSecret)) {
			t.Fatal("CLI exposed generated secret")
		}
	}
	keyName, _ := registrationFilename("key", "login", "k1")
	keyBefore, err := store.read(t.Context(), keyName)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := registrationCommand(t, storeFile, "key", "login", "k1", ""); err == nil || bytes.Contains(output, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("key creation overwrote or exposed private material")
	}
	// Keep the RP's original credentials in the same private store across actual
	// process restarts. The first process stages/activates v2; the second loads it.
	for _, stage := range []string{"initial", "restart"} {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyRegistrationProcess$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "SECURITY_REGISTRATION_STAGE="+stage, "SECURITY_REGISTRATION_STORE="+cfg.Path,
			"XDG_DATA_HOME="+dir, "XDG_CONFIG_HOME="+dir)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		cancel()
		if bytes.Contains(output, []byte(first.Client.ClientSecret)) || bytes.Contains(output, []byte(registrationTestSecret)) || bytes.Contains(output, []byte("BEGIN PRIVATE KEY")) {
			t.Fatal("Caddy diagnostic output exposed credentials")
		}
		if err != nil {
			t.Fatalf("Caddy %s: %v\n%s", stage, err, output)
		}
		if !bytes.Contains(output, []byte("provisioning app instance")) {
			t.Fatal("Caddy runtime did not execute")
		}
	}
	keyAfter, err := store.read(t.Context(), keyName)
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("reload/restart changed provider key")
	}
	firstAfter, err := store.application(t.Context(), "website", "v1")
	if err != nil || firstAfter.Client.ClientSecret != first.Client.ClientSecret || firstAfter.Client.ClientID != first.Client.ClientID {
		t.Fatal("rotation replaced previous registration")
	}
}

func TestCaddyRegistrationOutputFailureE2E(t *testing.T) {
	cfg, store := registrationTestStore(t)
	firstPath := registrationTestCreate(t, cfg)
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(filepath.Dir(cfg.Path), "oauth_rotate.Caddyfile")
	body := fmt.Sprintf("oauth registration store {\npath %s\n}\noauth application website {\nredirect_uri https://rp.example.test/callback\nclient_secret %s\n}\n", cfg.Path, registrationTestSecret)
	if err := os.WriteFile(input, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistrationCommandProcess$", "--", "security", "oauth", "rotate", "secret", "--config", input, "--name", "website", "--revision", "v2", "--from", "v1")
	cmd.Env = append(os.Environ(), "SECURITY_REGISTRATION_COMMAND=1")
	cmd.WaitDelay = 5 * time.Second
	var diagnostics bytes.Buffer
	cmd.Stdout, cmd.Stderr = output, &diagnostics
	if err := cmd.Run(); err == nil {
		t.Fatal("Caddy reported success without delivering the rotation result path")
	}
	if !bytes.Contains(diagnostics.Bytes(), []byte("provisioning completed")) || bytes.Contains(diagnostics.Bytes(), []byte(registrationTestSecret)) || bytes.Contains(diagnostics.Bytes(), []byte(first.Client.ClientSecret)) {
		t.Fatal("Caddy did not report the completed rotation safely")
	}
	rotated, err := store.application(t.Context(), "website", "v2")
	if err != nil || rotated.Client.ClientID != first.Client.ClientID || rotated.Client.ClientSecret != registrationTestSecret {
		t.Fatal("output failure lost the deliberate rotation candidate")
	}
	if before, err := os.ReadFile(firstPath); err != nil || !bytes.Equal(before, firstBytes) {
		t.Fatal("output failure replaced the recovery registration")
	}
	retryOutput, retryErr := registrationCommand(t, input, "rotate", "website", "v2", "v1")
	if retryErr == nil || !bytes.Contains(retryOutput, []byte("registration revision exists")) || bytes.Contains(retryOutput, []byte(registrationTestSecret)) {
		t.Fatal("retry did not preserve the completed rotation safely")
	}
}

func TestCaddyRegistrationFirstRevisionConcurrencyE2E(t *testing.T) {
	cfg, store := registrationTestStore(t)
	input := filepath.Join(filepath.Dir(cfg.Path), "oauth_client.Caddyfile")
	body := fmt.Sprintf("oauth registration store {\npath %s\n}\noauth application website {\nredirect_uri https://rp.example.test/callback\nclient_secret %s\n}\n", cfg.Path, registrationTestSecret)
	if err := os.WriteFile(input, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	// Different revision filenames must still have one winner for this nickname.
	// The existing concurrency flow separately tests identical target filenames.
	var wg sync.WaitGroup
	errs := make([]error, 4)
	outputs := make([][]byte, 4)
	for i := range 4 {
		wg.Go(func() {
			outputs[i], errs[i] = registrationCommand(t, input, "create", "website", fmt.Sprintf("v%d", i), "")
		})
	}
	wg.Wait()
	wins := 0
	for i, err := range errs {
		if bytes.Contains(outputs[i], []byte(registrationTestSecret)) {
			t.Fatal("concurrent CLI creation exposed the secret")
		}
		if err != nil {
			if !bytes.Contains(outputs[i], []byte("application already exists")) {
				t.Fatal("competing CLI creation failed outside nickname reservation")
			}
			continue
		}
		wins++
		application, err := store.application(t.Context(), "website", fmt.Sprintf("v%d", i))
		if err != nil || application.Client.ClientSecret != registrationTestSecret {
			t.Fatal("winning CLI registration is not readable with the original secret")
		}
	}
	if wins != 1 || len(registrationSnapshot(t, cfg.Path)) != 1 {
		t.Fatal("concurrent CLI creation published multiple first revisions or left artifacts")
	}
}

// Stop inside the real publisher after a partial private write. The parent
// kills this process, so neither the publisher's nor the lock's defers run.
func TestRegistrationInterruptedWriterProcess(t *testing.T) {
	path := os.Getenv("SECURITY_INTERRUPTED_REGISTRATION_STORE")
	if path == "" {
		t.Skip("interrupted writer process helper")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	store, err := (&OAuthRegistrationStoreConfig{Path: path}).open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.root.Close()
	unlock, err := store.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	filename, err := registrationFilename("application", "website", "v2")
	if err != nil {
		t.Fatal(err)
	}
	err = store.publish(ctx, filename, func(f *os.File) error {
		if _, err := f.WriteString(`{"name":"website","client":`); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(os.Stdout, "writer ready"); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	})
	t.Fatal("interrupted writer was not killed", err)
}

func TestCaddyRegistrationInterruptedWriterE2E(t *testing.T) {
	cfg, store := registrationTestStore(t)
	firstPath := registrationTestCreate(t, cfg)
	before := registrationSnapshot(t, cfg.Path)
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	writer := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegistrationInterruptedWriterProcess$", "-test.timeout=40s")
	writer.Env = append(os.Environ(), "SECURITY_INTERRUPTED_REGISTRATION_STORE="+cfg.Path)
	writer.WaitDelay = 5 * time.Second
	var diagnostics bytes.Buffer
	writer.Stderr = &diagnostics
	stdout, err := writer.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if writer.ProcessState == nil {
			_ = writer.Process.Kill()
			_ = writer.Wait()
		}
	}()
	// CommandContext bounds this read even if the child fails before signaling.
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || ready != "writer ready\n" {
		t.Fatal("writer did not reach the partial-write boundary")
	}
	if err := writer.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exitError *exec.ExitError
	if err := writer.Wait(); !errors.As(err, &exitError) || exitError.ProcessState.Success() || ctx.Err() != nil {
		t.Fatal("writer did not terminate from the deliberate interruption")
	}
	if bytes.Contains(diagnostics.Bytes(), []byte(first.Client.ClientSecret)) {
		t.Fatal("interrupted writer diagnostics exposed credentials")
	}
	lockPath := filepath.Join(cfg.Path, ".writer-lock")
	lock, err := os.Lstat(lockPath)
	if err != nil || !lock.IsDir() || lock.Mode().Perm() != 0700 {
		t.Fatal("interruption did not retain the private recovery lock")
	}
	entries, err := os.ReadDir(cfg.Path)
	if err != nil || len(entries) != 3 {
		t.Fatal("interrupted publication changed the usable revision set")
	}
	var pending string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			pending = entry.Name()
		}
	}
	partial, err := store.read(t.Context(), pending)
	if err != nil || string(partial) != `{"name":"website","client":` {
		t.Fatal("interruption did not preserve the private partial file")
	}
	input := filepath.Join(filepath.Dir(cfg.Path), "oauth_rotate.Caddyfile")
	storeInput := fmt.Sprintf("oauth registration store {\npath %s\n}\n", cfg.Path)
	if err := os.WriteFile(input, []byte(storeInput+"oauth application website {\nclient_secret "+registrationTestSecret+"\nredirect_uri https://rp.example.test/callback\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The actual Caddy command must time out on the abandoned lock instead of
	// guessing that it is stale and publishing new credentials behind it.
	output, err := registrationCommand(t, input, "rotate", "website", "v2", "v1")
	if err == nil || !bytes.Contains(output, []byte("context deadline exceeded")) || bytes.Contains(output, []byte(registrationTestSecret)) {
		t.Fatal("CLI bypassed the abandoned writer lock or did not report its timeout safely")
	}
	currentLock, err := os.Lstat(lockPath)
	if err != nil || !os.SameFile(lock, currentLock) {
		t.Fatal("timed-out CLI removed or replaced the abandoned lock")
	}
	remaining, err := store.read(t.Context(), pending)
	if err != nil || !bytes.Equal(partial, remaining) {
		t.Fatal("timed-out CLI modified the interrupted file")
	}
	adaptInput := filepath.Join(filepath.Dir(cfg.Path), "adapt.Caddyfile")
	if err := os.WriteFile(adaptInput, []byte("{\nsecurity {\n"+storeInput+"oauth application website {\nregistration v1\nredirect_uri https://rp.example.test/callback\n}\n}\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, err = securityCommand(t, "adapt", "--config", adaptInput, "--adapter", "caddyfile")
	if err != nil || !bytes.Contains(output, []byte("oauth_application_sources")) || bytes.Contains(output, []byte(first.Client.ClientSecret)) {
		t.Fatal("abandoned writer blocked read-only adaptation or exposed the active secret")
	}
	// Recovery is deliberate and happens only after Wait confirmed termination.
	if err := os.Remove(filepath.Join(cfg.Path, pending)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	after := registrationSnapshot(t, cfg.Path)
	if len(after) != 1 || after[filepath.Base(firstPath)] != before[filepath.Base(firstPath)] {
		t.Fatal("interruption or rejected command changed the previous registration")
	}
	if _, err := registrationCommand(t, input, "rotate", "website", "v2", "v1"); err != nil {
		t.Fatal("explicit recovery did not unblock the CLI rotation", err)
	}
	rotated, err := store.application(t.Context(), "website", "v2")
	if err != nil || rotated.Client.ClientID != first.Client.ClientID || rotated.Client.ClientSecret != registrationTestSecret {
		t.Fatal("recovered rotation did not preserve identity and use the explicit secret")
	}
	after = registrationSnapshot(t, cfg.Path)
	if len(after) != 2 || after[filepath.Base(firstPath)] != before[filepath.Base(firstPath)] {
		t.Fatal("recovered rotation replaced the old revision or left temporary files")
	}
}

func TestCaddyRegistrationProcess(t *testing.T) {
	stage := os.Getenv("SECURITY_REGISTRATION_STAGE")
	if stage == "" {
		t.Skip("Caddy process helper")
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg := &OAuthRegistrationStoreConfig{Path: os.Getenv("SECURITY_REGISTRATION_STORE")}
	store, err := cfg.open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer store.root.Close()
	first, err := store.application(t.Context(), "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	keyName, _ := registrationFilename("key", "login", "k1")
	certFile, tlsKeyFile, roots := cookieTLSCertificate(t)
	address, admin := lifecycleAddress(t), lifecycleAddress(t)
	base := "https://" + address
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	currentRevision := "v1"
	if stage == "restart" {
		currentRevision = "v2"
	}
	config := func(revision, keyFiles string) []byte {
		input := fmt.Sprintf(`{
 debug
 admin %s
 auto_https off
 security {
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify synthetic-application-portal-signing-key
   oidc provider {
    issuer %s/auth
    realms local
    signing key files %s
    applications website
   }
  }
  oauth application website {
   registration %s
   redirect_uri https://rp.example.test/callback
   skip_consent on
  }
  local identity store localdb {
   realm local
   path :memory:
   user alice {
    email alice@example.com
    password SyntheticPassword42!
    roles authp/user
   }
  }
  oauth registration store {
   path %s
  }
 }
}
https://%s {
 tls %q %q
 route /auth/* {
  authenticate with myportal
 }
}
`, admin, base, keyFiles, revision, cfg.Path, address, certFile, tlsKeyFile)
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(first.Client.ClientSecret)) || bytes.Contains(data, []byte(registrationTestSecret)) {
			t.Fatal("adapted configuration contains stored secret")
		}
		return data
	}
	keyFiles := fmt.Sprintf("%q", filepath.Join(cfg.Path, keyName))
	data := config(currentRevision, keyFiles)
	checkExchange := func(revision, rejectedSecret string) string {
		client.Jar, _ = cookiejar.New(nil)
		if lifecycleLogin(t, client, base) == "" {
			t.Fatal("real portal login failed")
		}
		registration, err := store.application(t.Context(), "website", revision)
		if err != nil {
			t.Fatal(err)
		}
		return registrationRPExchange(t, client, base+"/auth", registration.Client, rejectedSecret)
	}
	before, _ := json.Marshal(registrationSnapshot(t, cfg.Path))
	var kid string
	for range 3 {
		// Caddy Validate provisions and disposes a candidate without activation.
		var dry caddy.Config
		if err := json.Unmarshal(data, &dry); err != nil {
			t.Fatal(err)
		}
		if err := caddy.Validate(&dry); err != nil {
			t.Fatal(err)
		}
		if err := caddy.Load(data, true); err != nil {
			t.Fatal(err)
		}
		reject := "incorrect-secret"
		if stage == "restart" {
			reject = first.Client.ClientSecret
		}
		got := checkExchange(currentRevision, reject)
		if kid != "" && got != kid {
			t.Fatal("reload changed ID-token signing key")
		}
		kid = got
		// Verify the actual admin configuration view and autosave, not just the
		// adapter output, because both must retain references rather than secrets.
		adminClient := &http.Client{Timeout: 5 * time.Second}
		status, _, view := registrationHTTP(t, adminClient, "GET", "http://"+admin+"/config/", nil, nil)
		if status != http.StatusOK {
			t.Fatalf("admin configuration view status %d", status)
		}
		autosave, err := os.ReadFile(caddy.ConfigAutosavePath)
		if err != nil {
			t.Fatal(err)
		}
		for _, surface := range [][]byte{view, autosave} {
			if !bytes.Contains(surface, []byte("oauth_application_sources")) || !bytes.Contains(surface, []byte("oidc_provider_directives")) {
				t.Fatal("admin view or autosave lost durable references")
			}
			if bytes.Contains(surface, []byte(first.Client.ClientSecret)) || bytes.Contains(surface, []byte(registrationTestSecret)) || bytes.Contains(surface, []byte("BEGIN PRIVATE KEY")) {
				t.Fatal("admin view or autosave exposed private credentials")
			}
		}
	}
	after, _ := json.Marshal(registrationSnapshot(t, cfg.Path))
	if !bytes.Equal(before, after) {
		t.Fatal("adapt/validate/reload wrote private storage")
	}
	if stage == "restart" {
		return
	}
	// Duplicate members could decode to the same normalized digest as the
	// original registration. The raw persisted record must still fail closed.
	filename, err := registrationFilename("application", "website", "v1")
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(cfg.Path, filename)
	validRecord, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	adaptInput := filepath.Join(filepath.Dir(cfg.Path), "adapt.Caddyfile")
	if err := os.WriteFile(adaptInput, []byte(fmt.Sprintf("{\nsecurity {\noauth registration store {\npath %s\n}\noauth application website {\nregistration v1\nredirect_uri https://rp.example.test/callback\n}\n}\n}\n", cfg.Path)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range [][]byte{
		bytes.Replace(validRecord, []byte(`"name":`), []byte(`"name":"wrong","name":`), 1),
		bytes.Replace(validRecord, []byte(first.Client.ClientSecret), append([]byte(first.Client.ClientSecret), 0xff), 1),
		bytes.Replace(validRecord, []byte(first.Client.ClientSecret), []byte(first.Client.ClientSecret+`\ud800`), 1),
	} {
		if err := os.WriteFile(recordPath, malformed, 0600); err != nil {
			t.Fatal(err)
		}
		adaptOutput, adaptErr := securityCommand(t, "adapt", "--config", adaptInput, "--adapter", "caddyfile")
		loadErr := caddy.Load(data, true)
		if err := os.WriteFile(recordPath, validRecord, 0600); err != nil {
			t.Fatal(err)
		}
		if adaptErr == nil || bytes.Contains(adaptOutput, []byte(first.Client.ClientSecret)) {
			t.Fatal("Caddy adapted a malformed stored record or exposed its credential")
		}
		if loadErr == nil {
			t.Fatal("malformed stored JSON replaced the active deployment")
		}
		checkExchange("v1", registrationTestSecret)
	}
	// The host must check exactly the key path AuthCrunch will open. A lexical
	// Dir/Base split used to check the private key while AuthCrunch followed the
	// symlink and .. to this different, world-readable key file.
	outside := registrationTestDirectory(t)
	if err := os.Mkdir(filepath.Join(outside, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	keyContents, err := os.ReadFile(filepath.Join(cfg.Path, keyName))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, keyName), keyContents, 0644); err != nil {
		t.Fatal(err)
	}
	// Native JSON providers must enforce the same private-key boundary as the
	// provider directive path. Build an explicit config from this valid snapshot.
	nativeKeyConfig := func(keyPath string) []byte {
		var native caddy.Config
		if err := json.Unmarshal(data, &native); err != nil {
			t.Fatal(err)
		}
		var app App
		if err := json.Unmarshal(native.AppsRaw["security"], &app); err != nil {
			t.Fatal(err)
		}
		if err := app.resolveOAuthRegistrationConfig(t.Context(), app.Config); err != nil {
			t.Fatal(err)
		}
		app.OAuthRegistrationStore = nil
		app.OAuthApplicationSources = nil
		app.OIDCProviderDirectives = nil
		app.Config.AuthenticationPortals[0].OIDCProvider.SigningKeyFiles = []string{keyPath}
		appJSON, err := json.Marshal(&app)
		if err != nil {
			t.Fatal(err)
		}
		native.AppsRaw["security"] = appJSON
		encoded, err := json.Marshal(&native)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	activeBefore, err := os.ReadFile(caddy.ConfigAutosavePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(nativeKeyConfig(filepath.Join(outside, keyName)), true); err == nil {
		t.Fatal("native JSON bypassed provider key permissions")
	}
	activeAfter, err := os.ReadFile(caddy.ConfigAutosavePath)
	if err != nil || !bytes.Equal(activeBefore, activeAfter) {
		t.Fatal("rejected native provider changed active autosave")
	}
	checkExchange("v1", registrationTestSecret)
	// Explicit native configurations remain supported when key storage is safe.
	if err := caddy.Load(nativeKeyConfig(filepath.Join(cfg.Path, keyName)), true); err != nil {
		t.Fatal(err)
	}
	if got := checkExchange("v1", registrationTestSecret); got != kid {
		t.Fatal("native provider changed the selected signing key")
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "child"), filepath.Join(cfg.Path, "key-link")); err != nil {
		t.Fatal(err)
	}
	uncleanKey := cfg.Path + "/key-link/../" + keyName
	if err := caddy.Load(config("v1", fmt.Sprintf("%q", uncleanKey)), true); err == nil {
		t.Fatal("Caddy accepted a key path whose meaning changes when cleaned")
	}
	if err := os.Remove(filepath.Join(cfg.Path, "key-link")); err != nil {
		t.Fatal(err)
	}
	checkExchange("v1", registrationTestSecret)
	// Stage an intentional rotation with the real CLI; the active provider must
	// still accept the old secret until Caddy successfully loads the new revision.
	rotationFile := filepath.Join(filepath.Dir(cfg.Path), "oauth_rotate.Caddyfile")
	rotationInput := fmt.Sprintf("oauth registration store {\npath %s\n}\noauth application website {\nredirect_uri https://rp.example.test/callback\nskip_consent on\nclient_secret %s\n}\n", cfg.Path, registrationTestSecret)
	if err := os.WriteFile(rotationFile, []byte(rotationInput), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := registrationCommand(t, rotationFile, "rotate", "website", "v2", "v1"); err != nil {
		t.Fatalf("CLI rotate failed: %v\n%s", err, output)
	}
	checkExchange("v1", registrationTestSecret)
	candidate := config("v2", keyFiles)
	activeAutosave, err := os.ReadFile(caddy.ConfigAutosavePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("recoverable publication failure", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("directory read-permission fault requires an unprivileged owner")
		}
		v2, err := store.application(t.Context(), "website", "v2")
		if err != nil {
			t.Fatal(err)
		}
		record, err := json.Marshal(v2)
		if err != nil {
			t.Fatal(err)
		}
		name, err := registrationFilename("application", "website", "uncertain")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cfg.Path, 0700) })
		publicationErr := func() error {
			unlock, err := store.lock(t.Context())
			if err != nil {
				return err
			}
			defer unlock()
			return store.publish(t.Context(), name, func(f *os.File) error {
				if _, err := f.Write(record); err != nil {
					return err
				}
				return os.Chmod(cfg.Path, 0300)
			})
		}()
		// The already-running provider owns its in-memory credentials. A new
		// candidate must fail while the backing store is no longer private 0700.
		loadErr := caddy.Load(candidate, true)
		if err := os.Chmod(cfg.Path, 0700); err != nil {
			t.Fatal(err)
		}
		if publicationErr == nil || !strings.Contains(publicationErr.Error(), "registration published; directory sync unavailable") || strings.Contains(publicationErr.Error(), registrationTestSecret) {
			t.Fatal("publication failure did not report the complete recoverable revision safely")
		}
		if loadErr == nil {
			t.Fatal("Caddy activated a candidate through unavailable private storage")
		}
		current, err := os.ReadFile(caddy.ConfigAutosavePath)
		if err != nil || !bytes.Equal(current, activeAutosave) {
			t.Fatal("storage failure replaced the active configuration or autosave")
		}
		recovered, err := store.application(t.Context(), "website", "uncertain")
		if err != nil || recovered.Client.ClientID != first.Client.ClientID || recovered.Client.ClientSecret != registrationTestSecret {
			t.Fatal("storage failure lost the complete recovery candidate")
		}
	})
	checkExchange("v1", registrationTestSecret)
	var failed map[string]any
	if err := json.Unmarshal(candidate, &failed); err != nil {
		t.Fatal(err)
	}
	failed["apps"].(map[string]any)["security_lifecycle_fail_start"] = map[string]any{}
	invalid, _ := json.Marshal(failed)
	if err := caddy.Load(invalid, true); err == nil {
		t.Fatal("injected activation failure succeeded")
	}
	failedAutosave, err := os.ReadFile(caddy.ConfigAutosavePath)
	if err != nil || !bytes.Equal(activeAutosave, failedAutosave) {
		t.Fatal("failed activation replaced the recoverable active configuration")
	}
	checkExchange("v1", registrationTestSecret)
	// Failed adaptation also cannot change the running provider or either record.
	bad := &OAuthApplicationSource{Name: "website", Revision: "missing", Directives: []string{"redirect_uri https://rp.example.test/callback"}}
	if _, err := bad.load(t.Context(), store); err == nil {
		t.Fatal("missing candidate silently bootstrapped")
	}
	checkExchange("v1", registrationTestSecret)
	if err := caddy.Load(candidate, true); err != nil {
		t.Fatal(err)
	}
	if got := checkExchange("v2", first.Client.ClientSecret); got != kid {
		t.Fatal("secret rotation changed provider key")
	}
	// Explicit key rollover creates a new provider-owned key. First signs; both
	// keys remain in JWKS until the operator deliberately retires the previous key.
	if _, err := provisionRegistration(t.Context(), &provisioningInput{store: cfg}, "key", "login", "k2", ""); err != nil {
		t.Fatal(err)
	}
	key2, _ := registrationFilename("key", "login", "k2")
	rollover := config("v2", fmt.Sprintf("%q %s", filepath.Join(cfg.Path, key2), keyFiles))
	if err := caddy.Load(rollover, true); err != nil {
		t.Fatal(err)
	}
	if got := checkExchange("v2", first.Client.ClientSecret); got == kid {
		t.Fatal("deliberate key rollover did not change signer")
	}
	_, _, keys := registrationHTTP(t, client, "GET", base+"/auth/oidc/jwks", nil, nil)
	if !bytes.Contains(keys, []byte(kid)) {
		t.Fatal("rollover removed old public verification key")
	}
	// Return to k1 for the second process, proving selection is configuration-owned.
	if err := caddy.Load(candidate, true); err != nil {
		t.Fatal(err)
	}
	if got := checkExchange("v2", first.Client.ClientSecret); got != kid {
		t.Fatal("key rollback did not restore selected signer")
	}
}

func registrationHTTP(t *testing.T, client *http.Client, method, target string, form url.Values, headers http.Header) (int, http.Header, []byte) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		r.Header = headers.Clone()
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, data
}

func registrationRPExchange(t *testing.T, client *http.Client, issuer string, registration *oidc.ClientConfig, rejectedSecret string) string {
	t.Helper()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := sha256.Sum256([]byte(verifier))
	query := url.Values{"client_id": {registration.ClientID}, "response_type": {"code"}, "redirect_uri": {registration.RedirectURIs[0]}, "scope": {"openid profile email"}, "state": {"rp-state"}, "nonce": {"rp-nonce"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	status, headers, _ := registrationHTTP(t, client, "GET", issuer+"/oidc/authorize?"+query.Encode(), nil, nil)
	if status != 302 && status != 303 {
		t.Fatalf("RP authorization status %d", status)
	}
	callback, err := url.Parse(headers.Get("Location"))
	if err != nil || callback.Host != "rp.example.test" || callback.Query().Get("state") != "rp-state" || callback.Query().Get("code") == "" {
		t.Fatal("RP did not receive the authorization code/state")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {registration.RedirectURIs[0]}, "code_verifier": {verifier}}
	auth := func(secret string) http.Header {
		return http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(registration.ClientID)+":"+url.QueryEscape(secret)))}}
	}
	status, _, _ = registrationHTTP(t, client, "POST", issuer+"/oidc/token", form, auth(rejectedSecret))
	if status != 401 {
		t.Fatalf("old/incorrect secret was not rejected: %d", status)
	}
	status, _, body := registrationHTTP(t, client, "POST", issuer+"/oidc/token", form, auth(registration.ClientSecret))
	if status != 200 {
		t.Fatalf("RP code exchange status %d", status)
	}
	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil || tokens.IDToken == "" || tokens.AccessToken == "" {
		t.Fatal("RP tokens missing")
	}
	status, _, body = registrationHTTP(t, client, "GET", issuer+"/oidc/jwks", nil, nil)
	if status != 200 {
		t.Fatalf("JWKS status %d", status)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatal(err)
	}
	var kid string
	parsed, err := jwt.Parse(tokens.IDToken, func(token *jwt.Token) (any, error) {
		kid, _ = token.Header["kid"].(string)
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				n, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return nil, err
				}
				e, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					return nil, err
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
			}
		}
		return nil, fmt.Errorf("missing RP signing key")
	}, jwt.WithIssuer(issuer), jwt.WithAudience(registration.ClientID), jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid {
		t.Fatal("RP rejected ID-token signature or claims")
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["nonce"] != "rp-nonce" || claims["sub"] == "" {
		t.Fatal("RP ID-token nonce/subject missing")
	}
	status, _, body = registrationHTTP(t, client, "GET", issuer+"/oidc/userinfo", nil, http.Header{"Authorization": {"Bearer " + tokens.AccessToken}})
	var userinfo map[string]any
	if status != 200 || json.Unmarshal(body, &userinfo) != nil || userinfo["sub"] != claims["sub"] {
		t.Fatal("RP userinfo failed or subject differs")
	}
	return kid
}
