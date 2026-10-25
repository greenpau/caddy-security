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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func sqliteMessagingTestConfig(t *testing.T) *SQLiteMessagingProvider {
	t.Helper()
	return &SQLiteMessagingProvider{Name: "notifications", Path: filepath.Join(registrationTestDirectory(t), "outbox.db"), Timeout: "5s"}
}

func sqliteMessagingTestLoad(t *testing.T, raw json.RawMessage) (any, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	loader := &App{MessagingProviderConfigs: []json.RawMessage{raw}}
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

func TestSQLiteMessagingBackendDispatch(t *testing.T) {
	good := "messaging sqlite provider notifications {\npath /private/outbox.db\ndelivery smtp-local\n}"
	for name, input := range map[string]string{
		"valid":          good,
		"short_header":   "messaging sqlite provider",
		"extra_header":   strings.Replace(good, "notifications {", "notifications other {", 1),
		"wrong_selector": strings.Replace(good, "sqlite provider", "sqlite store", 1),
		"unknown_driver": strings.Replace(good, "sqlite provider", "not_registered provider", 1),
	} {
		t.Run(name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(input)
			if !d.Next() {
				t.Fatal("missing input")
			}
			app := new(App)
			err := parseCaddyfileMessagingBackend(d, app)
			if name != "valid" {
				if err == nil || len(app.MessagingProviderConfigs) != 0 {
					t.Fatal("invalid declaration published a module")
				}
				return
			}
			if err != nil || len(app.MessagingProviderConfigs) != 1 {
				t.Fatal("valid module dispatch failed", err)
			}
			var native struct {
				SQLiteMessagingProvider
				Driver string `json:"driver"`
			}
			if err := json.Unmarshal(app.MessagingProviderConfigs[0], &native); err != nil || native.Driver != "sqlite" || native.Name != "notifications" || native.Timeout != "1s" || native.Delivery != "smtp-local" {
				t.Fatal("dispatch did not preserve the registered module", err)
			}
		})
	}
}

func TestSQLiteMessagingNativeConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "outbox.db")
	valid := fmt.Sprintf(`{"driver":"sqlite","name":"notifications","path":%q,"timeout":"1000ms","delivery":"smtp-local"}`, path)
	entry, _, err := sqliteMessagingTestLoad(t, json.RawMessage(valid))
	if err != nil {
		t.Fatal(err)
	}
	module, ok := entry.(*SQLiteMessagingProvider)
	if !ok || module.Name != "notifications" || module.Path != path || module.Timeout != "1000ms" || module.Delivery != "smtp-local" {
		t.Fatal("native Caddy loading changed literal fields")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("native Caddy loading touched storage")
	}
	for name, raw := range map[string]string{
		"missing_name":   strings.Replace(valid, `"name":"notifications",`, "", 1),
		"relative_path":  strings.Replace(valid, fmt.Sprintf("%q", path), `"relative.db"`, 1),
		"timeout":        strings.Replace(valid, "1000ms", "31s", 1),
		"delivery":       strings.Replace(valid, "smtp-local", " smtp-local", 1),
		"delivery_type":  strings.Replace(valid, `"delivery":"smtp-local"`, `"delivery":true`, 1),
		"unknown_field":  strings.Replace(valid, `"timeout":`, `"credentials":"private-sentinel","timeout":`, 1),
		"unknown_driver": strings.Replace(valid, `"driver":"sqlite"`, `"driver":"not_registered"`, 1),
		"null":           "null",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := sqliteMessagingTestLoad(t, json.RawMessage(raw)); err == nil {
				t.Fatal("invalid native module accepted")
			}
		})
	}
}

func TestSQLiteMessagingAdaptationIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-parent", "{env.OUTBOX}", "outbox.db")
	input := fmt.Sprintf("{\nsecurity {\nmessaging sqlite provider notifications {\npath %q\ndelivery smtp-local\n}\nmessaging email provider smtp-local {\naddress 127.0.0.1:1025\nprotocol smtp\npasswordless\nsender portal@example.test\n}\n}\n}\n", path)
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps struct {
			Security App `json:"security"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	app := &document.Apps.Security
	if len(app.MessagingProviderConfigs) != 1 || app.Config == nil || app.Config.Messaging == nil || len(app.Config.Messaging.RawConfigs) != 1 {
		t.Fatal("adaptation did not separate the queue module and built-in email provider")
	}
	var module SQLiteMessagingProvider
	if err := json.Unmarshal(app.MessagingProviderConfigs[0], &module); err != nil || module.Path != path || module.Name != "notifications" || module.Timeout != "1s" || module.Delivery != "smtp-local" {
		t.Fatal("adaptation changed literal module configuration", err)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(path))); !os.IsNotExist(err) {
		t.Fatal("adaptation created storage")
	}
}
