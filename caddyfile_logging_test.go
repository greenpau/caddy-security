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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/logging"
	"go.uber.org/zap"
)

func TestParseCaddyfileLogging(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       *logging.Config
	}{
		{"omitted", "", nil},
		{"empty", "logging {\n}", &logging.Config{}},
		{"issue example", `logging {
 skip partial text "auth provider returned error"
 skip partial text "reason: no token found"
}`, &logging.Config{Skip: []logging.SkipRule{{Match: "partial", Text: "auth provider returned error"}, {Match: "partial", Text: "reason: no token found"}}}},
		{"all matchers and encoding", `logging {
 skip exact text "  quoted \"value\", with spaces  "
 skip partial text 世界
 skip prefix text "start here"
 skip suffix text "end here"
 skip regex text "^error:\s+\d{2}\\path$"
 skip exact text "  quoted \"value\", with spaces  "
 skip exact text "{env.LOGGING_LITERAL}"
 skip exact text secrets:literal:text
}`, &logging.Config{Skip: []logging.SkipRule{
			{Match: "exact", Text: `  quoted "value", with spaces  `},
			{Match: "partial", Text: "世界"},
			{Match: "prefix", Text: "start here"},
			{Match: "suffix", Text: "end here"},
			{Match: "regex", Text: `^error:\s+\d{2}\\path$`},
			{Match: "exact", Text: `  quoted "value", with spaces  `},
			{Match: "exact", Text: "{env.LOGGING_LITERAL}"},
			{Match: "exact", Text: "secrets:literal:text"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LOGGING_LITERAL", "must not expand")
			raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+tc.body+"\n}\n}"), nil)
			if err != nil {
				t.Fatal(err)
			}
			var config caddy.Config
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			var app App
			if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
				t.Fatal(err)
			}
			assertLoggingConfig(t, tc.want, app.Config.Logging)
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, app.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			assertLoggingConfig(t, tc.want, app.Config.Logging)
			// Exercise the public library's file serialization, then the Caddy
			// app's private provisioning copy with an actual policy runtime.
			path := filepath.Join(t.TempDir(), "security.json")
			if err := app.Config.DumpToJSONFile(path); err != nil {
				t.Fatal(err)
			}
			var restored authcrunch.Config
			if err := restored.LoadFromJSONFile(path); err != nil {
				t.Fatal(err)
			}
			assertLoggingConfig(t, tc.want, restored.Logging)
			cfg := lifecycleConfig()
			cfg.Logging = restored.Logging
			provisioned := provisionLifecycleApp(t, cfg)
			assertLoggingConfig(t, tc.want, provisioned.Config.Logging)
		})
	}
}

func assertLoggingConfig(t *testing.T, want, got *logging.Config) {
	t.Helper()
	// Compiled matcher state is private to AuthCrunch. Compare the public JSON.
	x, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	y, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(string(x), string(y)); diff != "" {
		t.Fatalf("logging config (-want +got):\n%s", diff)
	}
}

func TestParseCaddyfileLoggingRejects(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"inline empty rejected by Caddy", "logging { }", "Unexpected next token"},
		{"header argument", "logging sentinel-pattern {\n}", "takes no arguments"},
		{"missing block", "logging", "requires a block"},
		{"duplicate empty", "logging {\n}\nlogging {\n}", "duplicate security logging block"},
		{"duplicate populated", "logging {\nskip exact text first\n}\nlogging {\nskip exact text second\n}", "duplicate security logging block"},
		{"missing matcher", "logging {\nskip text sentinel-pattern\n}", "invalid logging directive"},
		{"extra token", "logging {\nskip exact text sentinel-pattern extra\n}", "invalid logging directive"},
		{"wrong action", "logging {\nkeep exact text sentinel-pattern\n}", "unsupported logging directive"},
		{"wrong selector", "logging {\nskip exact field sentinel-pattern\n}", "unsupported logging directive"},
		{"wrong matcher", "logging {\nskip glob text sentinel-pattern\n}", "unsupported matcher"},
		{"case sensitive matcher", "logging {\nskip EXACT text sentinel-pattern\n}", "unsupported matcher"},
		{"regex", "logging {\nskip regex text [sentinel-pattern\n}", "invalid regex"},
		{"empty text", "logging {\nskip exact text \"\"\n}", "arguments must not be empty"},
		{"empty token before valid rule", "logging {\nskip \"\" exact text sentinel-pattern\n}", "arguments must not be empty"},
		{"blank text", "logging {\nskip exact text \"  \"\n}", "invalid text"},
		{"multiline text", "logging {\nskip exact text \"sentinel-pattern\nmore\"\n}", "invalid logging directive"},
		{"nested", "logging {\nskip exact text sentinel-pattern {\nunknown value\n}\n}", "nested security logging"},
		{"nested empty", "logging {\nskip exact text sentinel-pattern {\n}\n}", "nested security logging"},
		{"closing suffix", "logging {\nskip exact text sentinel-pattern\n} extra", "closing brace must end its line"},
		{"quoted close", "logging {\nskip exact text sentinel-pattern\n\"}\"", "closing brace must be unquoted"},
		{"last invalid", "logging {\nskip exact text valid\nskip regex text [sentinel-pattern\n}", "invalid regex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\nsecurity {\n"+tc.body+"\n}\n}"), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "Caddyfile:") || strings.Contains(err.Error(), "sentinel-pattern") {
				t.Fatalf("expected location-aware %q error without pattern, got %v", tc.want, err)
			}
		})
	}
}

func TestLoggingParserDoesNotPublishPartialConfig(t *testing.T) {
	cfg := authcrunch.NewConfig()
	d := caddyfile.NewTestDispenser("logging {\nskip exact text valid\nskip regex text [\n}")
	d.Next()
	if err := parseCaddyfileLogging(d, cfg); err == nil || cfg.Logging != nil {
		t.Fatalf("failed parse published config: %v", err)
	}
}

func TestLoggingDuplicateSecurityBlocks(t *testing.T) {
	for _, second := range []string{"", "logging {\n}", "logging {\nskip exact text second\n}"} {
		input := "{\nsecurity {\nlogging {\nskip exact text first\n}\n}\nsecurity {\n" + second + "\n}\n}"
		if _, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil); err == nil || !strings.Contains(err.Error(), "duplicate security block") {
			t.Fatalf("second security block silently replaced logging: %v", err)
		}
	}
}

func TestLoggingJSONValidation(t *testing.T) {
	for _, raw := range []string{
		`{"skip":[{"match":"unknown","text":"sentinel-pattern"}]}`,
		`{"skip":[{"match":"exact"}]}`,
		`{"skip":[{"match":"exact","text":"  "}]}`,
		`{"skip":[{"match":"regex","text":"[sentinel-pattern"}]}`,
		`{"skip":[{"match":"exact","text":"sentinel-pattern\nnext"}]}`,
		`{"skip":[null]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			cfg := lifecycleConfig()
			if err := json.Unmarshal([]byte(`{"logging":`+raw+`}`), cfg); err != nil {
				t.Fatal(err)
			}
			// caddy.Validate loads the same module and provisions/validates it
			// without starting listeners. It must reject native JSON as well.
			data, err := json.Marshal(&App{Config: cfg})
			if err != nil {
				t.Fatal(err)
			}
			config := &caddy.Config{AppsRaw: caddy.ModuleMap{"security": data}}
			if err := caddy.Validate(config); err == nil || !strings.Contains(err.Error(), "logging") || strings.Contains(err.Error(), "sentinel-pattern") {
				t.Fatalf("malformed logging accepted or leaked pattern: %v", err)
			}
		})
	}
}

func TestLoggingImportedRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.caddy")
	if err := os.WriteFile(path, []byte("skip prefix text first\nskip suffix text last\n"), 0600); err != nil {
		t.Fatal(err)
	}
	input := "{\nsecurity {\nlogging {\nimport " + path + "\nskip exact text last\n}\n}\n}"
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	var config caddy.Config
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	assertLoggingConfig(t, &logging.Config{Skip: []logging.SkipRule{{Match: "prefix", Text: "first"}, {Match: "suffix", Text: "last"}, {Match: "exact", Text: "last"}}}, app.Config.Logging)
}
