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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"go.uber.org/zap"
)

func TestParseCaddyfileState(t *testing.T) {
	for _, tc := range []struct{ name, body, directory string }{
		{"omitted", "", ""},
		{"canonical", "state {\n directory /var/lib/authcrunch/../runtime\n }", "/var/lib/runtime"},
		{"quoted", "state {\n directory \"/var/lib/private runtime\"\n }", "/var/lib/private runtime"},
		{"encoded punctuation", "state {\n directory \"/var/lib/private,runtime\"\n }", "/var/lib/private,runtime"},
		{"partial runtime placeholder", "state {\n directory /var/lib/{env.RUNTIME_STATE_NAME}\n }", "/var/lib/{env.RUNTIME_STATE_NAME}"},
		{"runtime placeholder", "state {\n directory {env.RUNTIME_STATE_PATH}\n }", "{env.RUNTIME_STATE_PATH}"},
		{"secret reference", "state {\n directory secrets:manager:path\n }", "secrets:manager:path"},
		{"duplicates", "state {\n directory /tmp/one\n }\n state {\n directory /tmp/two\n }", "ERROR"},
		{"empty", "state {\n }", "ERROR"},
		{"missing", "state", "ERROR"},
		{"relative", "state {\n directory sentinel-secret\n }", "ERROR"},
		{"root", "state {\n directory /\n }", "ERROR"},
		{"unknown", "state {\n sentinel-secret /tmp/private\n }", "ERROR"},
		{"extra argument", "state {\n directory /tmp/private sentinel-secret\n }", "ERROR"},
		{"header argument", "state sentinel-secret {\n directory /tmp/private\n }", "ERROR"},
		{"empty value", "state {\n directory \"\"\n }", "ERROR"},
		{"multiline value", "state {\n directory \"/var/lib/sentinel-secret\nother\"\n }", "ERROR"},
		{"duplicate setting", "state {\n directory /tmp/private\n directory /tmp/private\n }", "ERROR"},
		{"nested", "state {\n directory /tmp/private {\n sentinel-secret yes\n }\n }", "ERROR"},
		{"nested empty", "state {\n directory /tmp/private {\n }\n }", "ERROR"},
		{"closing suffix", "state {\n directory /tmp/private\n } sentinel-secret", "ERROR"},
		{"quoted closing brace", "state {\n directory /tmp/private\n \"}\"", "ERROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseCaddyfile(caddyfile.NewTestDispenser("security {\n"+tc.body+"\n}"), nil)
			if tc.directory == "ERROR" {
				if err == nil || strings.Contains(err.Error(), "sentinel-secret") {
					t.Fatalf("expected redacted error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var app App
			if err := json.Unmarshal(result.(httpcaddyfile.App).Value, &app); err != nil {
				t.Fatal(err)
			}
			if tc.directory == "" {
				if app.Config.State != nil {
					t.Fatal("omission enabled persistence")
				}
			} else if app.Config.State == nil || app.Config.State.Directory != tc.directory {
				t.Fatal("state did not preserve canonical directory")
			}
		})
	}
}

func TestStateAdaptValidateNoRuntimeIO(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent state")
	t.Setenv("CADDY_STATE_DIRECTORY", dir)
	input := `{
 admin off
 security {
  state {
   directory "{$CADDY_STATE_DIRECTORY}"
  }
  authorization policy test {
   crypto key verify synthetic-test-key
   allow roles authp/user
  }
 }
}`
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	// Caddy consumes AppsRaw while provisioning.
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("validation touched runtime directory: %v", err)
	}
	var app App
	if err := json.Unmarshal(cfg.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	if app.Config.State == nil || app.Config.State.Directory != dir {
		t.Fatal("JSON lost state")
	}
}

func TestStateRuntimeReplacement(t *testing.T) {
	t.Setenv("CADDY_STATE_DIRECTORY", filepath.Join(t.TempDir(), "private runtime"))
	cfg := &authcrunch.Config{State: &state.Config{Directory: "{env.CADDY_STATE_DIRECTORY}"}}
	if err := ResolveRuntimeAppConfig(context.Background(), caddy.NewReplacer(), nil, cfg, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if cfg.State.Directory != os.Getenv("CADDY_STATE_DIRECTORY") {
		t.Fatal("state directory not resolved")
	}
	for _, value := range []string{"", "/", "relative", "{env.ABSENT_STATE_DIRECTORY}"} {
		cfg.State.Directory = value
		if err := ResolveRuntimeAppConfig(context.Background(), caddy.NewReplacer(), nil, cfg, zap.NewNop()); err == nil {
			t.Fatal("invalid runtime directory accepted")
		}
	}
}

func TestStateRuntimeSecretReplacement(t *testing.T) {
	const secretKey = "sentinel-secret-state-path"
	directory := filepath.Join(t.TempDir(), "private runtime")
	for _, tc := range []struct {
		name    string
		values  map[string]string
		invalid bool
	}{
		{"resolved", map[string]string{secretKey: directory}, false},
		{"missing", nil, true},
		{"empty", map[string]string{secretKey: ""}, true},
		{"invalid", map[string]string{secretKey: "sentinel-secret-relative-path"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &authcrunch.Config{State: &state.Config{Directory: "secrets:oauth:" + secretKey}}
			managers := []SecretsManager{&oauthRuntimeSecrets{Values: tc.values}}
			err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), managers, cfg, zap.NewNop())
			if tc.invalid {
				if err == nil || strings.Contains(err.Error(), "sentinel-secret") {
					t.Fatalf("expected redacted state replacement failure, got %v", err)
				}
			} else if err != nil || cfg.State.Directory != directory {
				t.Fatalf("state secret resolution failed: %v", err)
			}
		})
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("secret resolution initialized runtime storage")
	}
}
