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
	"slices"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/messaging-sqlite"
)

func sqliteMessagingTestConfig(t *testing.T) *companion.SQLiteMessagingProvider {
	t.Helper()
	return &companion.SQLiteMessagingProvider{Name: "notifications", Path: filepath.Join(privateDirectory(t), "outbox.db"), Timeout: "5s"}
}

func sqliteMessagingTestLoad(t *testing.T, raw json.RawMessage) (any, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	loader := &moduleLoader{MessagingProviderConfigs: []json.RawMessage{raw}}
	loaded, err := ctx.LoadModule(loader, "MessagingProviderConfigs")
	if err != nil {
		return nil, cancel, err
	}
	modules, ok := loaded.([]any)
	if !ok || len(modules) != 1 {
		t.Fatal("Caddy did not load exactly one messaging module")
	}
	return modules[0], cancel, nil
}

func TestSQLiteMessagingParser(t *testing.T) {
	good := "notifications {\npath \"/private mail/outbox.db\"\ntimeout 1000ms\ndelivery smtp-local\n}"
	module := new(companion.SQLiteMessagingProvider)
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if module.Name != "notifications" || module.Path != "/private mail/outbox.db" || module.Timeout != "1s" || module.Delivery != "smtp-local" {
		t.Fatal("parser lost settings or failed to normalize the timeout")
	}
	for name, input := range map[string]string{
		"empty":              "",
		"extra_name":         strings.Replace(good, "notifications {", "notifications other {", 1),
		"duplicate_name":     strings.Replace(good, "path ", "name notifications\npath ", 1),
		"duplicate_path":     strings.Replace(good, "path ", "path /private/other.db\npath ", 1),
		"duplicate_timeout":  strings.Replace(good, "timeout 1000ms", "timeout 1s\ntimeout 2s", 1),
		"duplicate_delivery": strings.Replace(good, "delivery smtp-local", "delivery smtp-local\ndelivery smtp-other", 1),
		"missing_path":       "notifications {\ndelivery smtp-local\n}",
		"missing_delivery":   strings.Replace(good, "delivery smtp-local", "delivery", 1),
		"empty_delivery":     strings.Replace(good, "delivery smtp-local", "delivery \"\"", 1),
		"extra_delivery":     strings.Replace(good, "delivery smtp-local", "delivery smtp-local smtp-other", 1),
		"space_delivery":     strings.Replace(good, "delivery smtp-local", "delivery \" smtp-local\"", 1),
		"long_delivery":      strings.Replace(good, "smtp-local", strings.Repeat("x", 129), 1),
		"relative_path":      strings.Replace(good, "/private mail/outbox.db", "relative.db", 1),
		"root_path":          strings.Replace(good, "/private mail/outbox.db", "/", 1),
		"nested":             strings.Replace(good, "delivery smtp-local", "delivery {\nsmtp-local\n}", 1),
		"unknown":            strings.Replace(good, "delivery smtp-local", "credentials private-sentinel", 1),
		"unclosed":           strings.TrimSuffix(good, "}"),
		"quoted_open":        strings.Replace(good, " {", " \"{\"", 1),
		"timeout_zero":       strings.Replace(good, "1000ms", "0s", 1),
		"timeout_too_short":  strings.Replace(good, "1000ms", "999us", 1),
		"timeout_too_long":   strings.Replace(good, "1000ms", "31s", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := new(companion.SQLiteMessagingProvider).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	defaults := "notifications {\npath \"/private/{env.OUTBOX}/outbox.db\"\n}"
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(defaults)); err != nil || module.Timeout != "1s" || module.Delivery != "" || module.Path != "/private/{env.OUTBOX}/outbox.db" {
		t.Fatal("default, queue-only mode or literal path did not survive parsing", err)
	}
	quoted := "notifications {\npath /private/outbox.db\ndelivery \"}\"\n}"
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(quoted)); err != nil || module.Delivery != "}" {
		t.Fatal("quoted brace was not retained as a literal provider name", err)
	}
}

func TestSQLiteMessagingValidationIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "outbox.db")
	module := &companion.SQLiteMessagingProvider{Name: "notifications", Path: path, Delivery: "smtp-local"}
	before, err := json.Marshal(module)
	if err != nil {
		t.Fatal(err)
	}
	if err := module.Validate(); err != nil {
		t.Fatal(err)
	}
	if name, err := module.MessagingProviderName(); err != nil || name != "notifications" {
		t.Fatal("module name failed validation", err)
	}
	for _, timeout := range []string{"", "1s", "1000ms", "1000000us"} {
		copy := *module
		copy.Timeout = timeout
		cfg, err := copy.BackendConfig()
		if err != nil || cfg.Name != module.Name || cfg.Path != path || cfg.Timeout != "1s" || copy.Timeout != timeout {
			t.Fatalf("timeout %q was not normalized on a private configuration: %v", timeout, err)
		}
	}
	after, _ := json.Marshal(module)
	if string(before) != string(after) {
		t.Fatal("validation mutated native configuration")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("validation opened or created storage")
	}
	for name, delivery := range map[string]string{
		"leading_space": " smtp", "trailing_space": "smtp ", "tab": "smtp\tlocal", "newline": "smtp\nlocal", "nul": "smtp\x00local", "unicode_control": "smtp\u0085local", "invalid_utf8": "smtp\xff", "too_long": strings.Repeat("x", 129),
	} {
		t.Run(name, func(t *testing.T) {
			copy := *module
			copy.Delivery = delivery
			if err := copy.Validate(); err == nil {
				t.Fatal("invalid native delivery reference accepted")
			}
			if name, err := copy.MessagingProviderName(); err == nil || name != "" {
				t.Fatal("invalid declaration published a provider name")
			}
			if provider, err := copy.NewMessagingProvider(t.Context()); err == nil || provider != nil {
				t.Fatal("invalid declaration constructed a provider")
			}
		})
	}
	for _, delivery := range []string{"", "smtp-local", "通知", strings.Repeat("x", 128), "{env.SMTP_PROVIDER}"} {
		copy := *module
		copy.Delivery = delivery
		if err := copy.Validate(); err != nil {
			t.Fatalf("valid literal delivery reference rejected: %v", err)
		}
	}
}

func TestSQLiteMessagingConsumer(t *testing.T) {
	declaration := sqliteMessagingTestConfig(t)
	raw := caddyconfig.JSONModuleObject(declaration, "driver", "sqlite", nil)
	entry, cancel, err := sqliteMessagingTestLoad(t, raw)
	if err != nil {
		t.Fatal(err)
	}
	module := entry.(*companion.SQLiteMessagingProvider)
	setupCtx, cancelSetup := context.WithCancel(t.Context())
	t.Cleanup(cancelSetup)
	provider, err := module.NewMessagingProvider(setupCtx)
	if err != nil {
		t.Fatal(err)
	}
	producer := provider.(*messagingsqlite.Outbox)
	t.Cleanup(func() { _ = producer.Close() })
	info, err := os.Stat(module.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("factory did not create private queue storage", err)
	}
	// Neither the setup deadline nor configuration retirement owns the runtime.
	cancelSetup()
	cancel()
	bindings := &messaging.Config{}
	if err := bindings.AddProvider(module.Name, provider); err != nil {
		t.Fatal(err)
	}
	if err := bindings.Validate(); err != nil || bindings.ExtractProvider(module.Name) != provider || bindings.GetProviderType(module.Name) != "sqlite" {
		t.Fatal("public runtime binding lost the factory-created queue", err)
	}
	input := &messaging.SendInput{Subject: "Registration confirmation", Body: "<p>Alice =26 Bob</p>\r\n", Recipients: []string{"alice@example.test"}}
	if err := bindings.ExtractProvider(module.Name).Send(input); err != nil {
		t.Fatal("queue did not accept a message after module context cancellation", err)
	}
	input.Body, input.Recipients[0] = "changed", "other@example.test"
	metadata := provider.AsMap()
	if len(metadata) != 2 || metadata["kind"] != "sqlite" || metadata["name"] != "notifications" {
		t.Fatal("runtime metadata included private storage or delivery settings")
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Send(input); !errors.Is(err, messagingsqlite.ErrUnavailable) {
		t.Fatal("closed queue remained writable", err)
	}
	restored, err := module.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	worker := restored.(*messagingsqlite.Outbox)
	t.Cleanup(func() { _ = worker.Close() })
	if worker == producer {
		t.Fatal("factory reused a disposed runtime handle")
	}
	message, err := worker.Claim(t.Context())
	if err != nil || message.Subject != "Registration confirmation" || message.Body != "<p>Alice =26 Bob</p>\r\n" || !slices.Equal(message.Recipients, []string{"alice@example.test"}) {
		t.Fatal("reopened queue lost the exact accepted message snapshot", err)
	}
	if err := worker.Release(t.Context(), message.ID, message.Lease); err != nil {
		t.Fatal(err)
	}
	claimed, err := worker.Claim(t.Context())
	if err != nil || claimed.ID != message.ID || claimed.Lease == message.Lease {
		t.Fatal("released message did not receive a fresh lease", err)
	}
	if err := worker.Acknowledge(t.Context(), message.ID, message.Lease); !errors.Is(err, messagingsqlite.ErrLease) {
		t.Fatal("stale worker acknowledged a replacement lease", err)
	}
	if err := worker.Acknowledge(t.Context(), claimed.ID, claimed.Lease); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.Claim(t.Context()); !errors.Is(err, messagingsqlite.ErrEmpty) {
		t.Fatal("acknowledged message was retained", err)
	}
	input.Credentials = &credentials.GenericCredential{}
	if err := worker.Send(input); !errors.Is(err, messagingsqlite.ErrInvalid) {
		t.Fatal("queue accepted transport credentials", err)
	}
}

func TestSQLiteMessagingFactoryFailures(t *testing.T) {
	for _, name := range []string{"missing_parent", "public_parent", "directory", "symlink", "canceled"} {
		t.Run(name, func(t *testing.T) {
			module := sqliteMessagingTestConfig(t)
			ctx := t.Context()
			switch name {
			case "missing_parent":
				module.Path = filepath.Join(filepath.Dir(module.Path), "missing", "outbox.db")
			case "public_parent":
				if err := os.Chmod(filepath.Dir(module.Path), 0755); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(module.Path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(filepath.Dir(module.Path), "target.db"), module.Path); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			provider, err := module.NewMessagingProvider(ctx)
			if provider != nil || !errors.Is(err, messagingsqlite.ErrUnavailable) || strings.Contains(err.Error(), module.Path) {
				t.Fatal("factory did not return a safe error and real nil handle", err)
			}
			if name == "missing_parent" || name == "public_parent" || name == "canceled" {
				if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
					t.Fatal("rejected factory created queue storage")
				}
			}
		})
	}
}

type moduleLoader struct {
	MessagingProviderConfigs []json.RawMessage `caddy:"namespace=security.messaging inline_key=driver"`
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
