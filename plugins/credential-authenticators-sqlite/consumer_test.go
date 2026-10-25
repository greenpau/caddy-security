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

package sqlite_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/credential-authenticators-sqlite"
)

func sqliteCredentialsConfig(t *testing.T) *credentials.Config {
	t.Helper()
	return &credentials.Config{Name: "keys", Path: filepath.Join(privateDirectory(t), "credentials.db"), Realm: "staff", Timeout: "500ms"}
}

func sqliteCredentialsIssue(t *testing.T, cfg *credentials.Config) string {
	t.Helper()
	b, err := credentials.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	key, err := b.Issue(t.Context(), "alice", "alice@example.test", []string{"authp/user"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSQLiteCredentialParser(t *testing.T) {
	good := "keys {\npath \"/private keys/credentials.db\"\nrealm staff\ntimeout 750ms\n}"
	m := new(companion.SQLiteCredentialAuthenticator)
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if m.Name != "keys" || m.Path != "/private keys/credentials.db" || m.Realm != "staff" || m.Timeout != "750ms" {
		t.Fatal("lost configuration")
	}
	for name, input := range map[string]string{
		"empty":             "",
		"extra_name":        strings.Replace(good, "keys {", "keys other {", 1),
		"duplicate_name":    strings.Replace(good, "realm staff", "name keys\nrealm staff", 1),
		"duplicate_path":    strings.Replace(good, "realm staff", "path /private/other.db\nrealm staff", 1),
		"duplicate_realm":   strings.Replace(good, "realm staff", "realm staff\nrealm other", 1),
		"duplicate_timeout": strings.Replace(good, "timeout 750ms", "timeout 1s\ntimeout 2s", 1),
		"missing_realm":     strings.Replace(good, "realm staff\n", "", 1),
		"relative":          strings.Replace(good, "/private keys/credentials.db", "relative.db", 1),
		"nested":            strings.Replace(good, "realm staff", "realm {\nstaff\n}", 1),
		"unknown":           strings.Replace(good, "realm staff", "private-sentinel data", 1),
		"unclosed":          strings.TrimSuffix(good, "}"),
		"quoted_open":       strings.Replace(good, " {", " \"{\"", 1),
		"zero":              strings.Replace(good, "750ms", "0s", 1),
		"too_long":          strings.Replace(good, "750ms", "31s", 1),
		"remote_name":       strings.Replace(good, "keys {", "https://host {", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := new(companion.SQLiteCredentialAuthenticator).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	if err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(strings.Replace(strings.Replace(good, "realm staff", "realm \"}\"", 1), "timeout 750ms\n", "", 1))); err != nil || m.Realm != "}" || m.Timeout != "1s" {
		t.Fatal("quoted data/default lost", err)
	}
}

func TestSQLiteCredentialBackend(t *testing.T) {
	cfg := sqliteCredentialsConfig(t)
	m := &companion.SQLiteCredentialAuthenticator{Name: cfg.Name, Path: cfg.Path, Realm: cfg.Realm, Timeout: cfg.Timeout}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if b, err := m.NewCredentialAuthenticator(t.Context()); err == nil || b != nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(cfg.Path); !os.IsNotExist(err) {
		t.Fatal("consumer created database")
	}
	key := sqliteCredentialsIssue(t, cfg)
	backend, err := m.NewCredentialAuthenticator(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	req := &authproxy.Request{Realm: "staff", Secret: key}
	if err := backend.APIKeyAuthContext(t.Context(), req); err != nil || !req.Response.IsPlainPayload {
		t.Fatal("key rejected", err)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(req.Response.Payload), &claims); err != nil || claims["sub"] != "alice" || claims["origin"] != "staff" {
		t.Fatal("identity not preserved", err)
	}
	if err := backend.BasicAuthContext(t.Context(), req); err == nil || req.Response.Payload != "" {
		t.Fatal("Basic allowed or stale identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := backend.APIKeyAuthContext(ctx, req); err == nil || req.Response.Payload != "" {
		t.Fatal("cancellation accepted")
	}
	writer, err := credentials.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Revoke(t.Context(), key); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.APIKeyAuthContext(t.Context(), req); !errors.Is(err, credentials.ErrDenied) {
		t.Fatal("revoked key accepted", err)
	}
	meta, _ := json.Marshal(backend.GetConfig())
	if strings.Contains(string(meta), key) || strings.Contains(string(meta), cfg.Path) {
		t.Fatal("private metadata")
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.APIKeyAuthContext(t.Context(), req); !errors.Is(err, credentials.ErrUnavailable) {
		t.Fatal("closed backend accepted", err)
	}
}

func privateDirectory(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
