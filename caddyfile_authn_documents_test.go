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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/google/go-cmp/cmp"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
	"go.uber.org/zap"
)

const documentsTestRequired = "enable documents api\ndocuments api database /private/documents.db\ndocuments api public origin https://auth.example.test\ndocuments api realms local\n"

func TestPortalDocumentsParsing(t *testing.T) {
	defaults := &documents.Config{Database: "/private/documents.db", PublicOrigin: "https://auth.example.test", Realms: []string{"local"}}
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	all := *defaults
	all.BasePath = "/tenant/auth"
	all.Realms = []string{"corp, west", "local"}
	all.MaxFileBytes, all.MaxUserBytes, all.MaxTotalBytes = 32, 64, 128
	all.MaxUserFiles, all.MaxTotalFiles, all.MaxKeys, all.MaxRecipients, all.UploadTTLSeconds = 2, 3, 4, 2, 60
	for _, tc := range []struct {
		name, body string
		enabled    bool
		want       *documents.Config
	}{
		{"omitted", "", false, nil},
		{"defaults", documentsTestRequired, true, defaults},
		{"zero defaults", documentsTestRequired + "documents api max file bytes 0\ndocuments api upload ttl seconds 0", true, defaults},
		{"all settings", strings.Replace(documentsTestRequired, "realms local", "realms \"corp, west\" local", 1) +
			"documents api base path /tenant/auth\ndocuments api max file bytes 32\ndocuments api max user bytes 64\ndocuments api max total bytes 128\n" +
			"documents api max user files 2\ndocuments api max total files 3\ndocuments api max keys 4\ndocuments api max recipients 2\ndocuments api upload ttl seconds 60", true, &all},
		{"disabled", "disable documents api", false, &documents.Config{}},
		{"storage only", "documents api database relative-unused", false, &documents.Config{Database: "relative-unused"}},
		{"disabled invalid semantics", "disable documents api\ndocuments api database ignored\ndocuments api public origin http://unused\ndocuments api base path relative\ndocuments api realms local local\ndocuments api upload ttl seconds 1", false,
			&documents.Config{Database: "ignored", PublicOrigin: "http://unused", BasePath: "relative", Realms: []string{"local", "local"}, UploadTTLSeconds: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := tokenRefreshTestApp(t, "enable admin api\nenable admin api private key export\n"+tc.body)
			p := app.Config.AuthenticationPortals[0]
			if !p.API.ProfileEnabled || !p.API.AdminEnabled || !p.API.AdminFetchPrivateKeysEnabled || p.API.DocumentsEnabled != tc.enabled {
				t.Fatal("Documents changed independent API settings or enablement")
			}
			if diff := cmp.Diff(tc.want, p.Documents); diff != "" {
				t.Fatal(diff)
			}
			raw, err := json.Marshal(app)
			if err != nil {
				t.Fatal(err)
			}
			var restored App
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), nil, restored.Config, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, restored.Config.AuthenticationPortals[0].Documents); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestPortalDocumentsParsingRejects(t *testing.T) {
	cases := []string{
		"enable documents", "enable documents api extra", "enable documents api\n", "documents api", "documents api database", "documents api database \"\"",
		"documents api database \" \"", "documents api database /private/a extra", "\"enable documents api\"", "enable \"documents api\"",
		"documents \"api database\" /private/a", "documents api \"public origin\" https://auth.example.test", "documents api unknown 1",
		"documents api max keys -1", "disable documents api\ndocuments api max file bytes -1", "documents api max keys 1000001",
		"documents api max file bytes 999999999999999999999", "documents api max keys 1m",
		"enable documents api\ndisable documents api", "disable documents api\ndisable documents api",
		"documents api database one\ndocuments api database two",
		"enable documents api {\n}", "documents api database /private/a {\n}", "documents api database }",
		"documents api database /private/a\nprivate-continuation-sentinel secret-value",
		"documents api database \"bad\nvalue\"",
	}
	for _, line := range []string{"documents api database /private/documents.db\n", "documents api public origin https://auth.example.test\n", "documents api realms local\n"} {
		cases = append(cases, strings.Replace(documentsTestRequired, line, "", 1))
	}
	for _, suffix := range []string{
		"documents api base path /api", "documents api base path /login-other", "documents api base path /auth/", "documents api base path /semi;colon",
		"documents api base path /caf\u00e9", "documents api upload ttl seconds 59", "documents api max file bytes 15",
	} {
		cases = append(cases, documentsTestRequired+suffix)
	}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput(body)+"\n}"), nil)
			if err == nil || len(data) != 0 {
				t.Fatal("Caddy adapter admitted malformed Documents configuration")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatal("malformed continuation exposed a Documents argument")
			}
		})
	}
}

func TestPortalDocumentsImportsAndNoIO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent", "quoted documents.db")
	body := strings.Replace(documentsTestRequired, "/private/documents.db", fmt.Sprintf("%q", path), 1)
	file := filepath.Join(dir, "documents.Caddyfile")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for _, duplicate := range []bool{false, true} {
		input := fmt.Sprintf("import %q\n", file)
		if duplicate {
			input += "disable documents api\n"
		}
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+cookiePortalInput(input)+"\n}"), nil)
		if (err != nil) != duplicate || !duplicate && len(data) == 0 {
			t.Fatal("import lost Documents duplicate or complete-statement semantics", err)
		}
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("Documents adaptation touched missing storage")
	}
}

func TestPortalDocumentsQuotedBraces(t *testing.T) {
	for _, value := range []string{"{", "}"} {
		t.Run(value, func(t *testing.T) {
			input := cookiePortalInput("disable documents api\ndocuments api database " + fmt.Sprintf("%q", value) + "\nenable admin api")
			data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte("{\n"+input+"\n}"), nil)
			if err != nil || len(data) == 0 {
				t.Fatal("quoted Documents value became a structural brace", err)
			}
			app := tokenRefreshTestApp(t, "disable documents api\ndocuments api database "+fmt.Sprintf("%q", value)+"\nenable admin api")
			if err := resolveDocumentsTestApp(t, app, nil); err != nil {
				t.Fatal(err)
			}
			p := app.Config.AuthenticationPortals[0]
			if p.Documents.Database != value || p.API.DocumentsEnabled || !p.API.AdminEnabled {
				t.Fatal("quoted Documents argument changed or consumed the following directive")
			}
		})
	}
}

func documentsResolutionApp(t *testing.T, native bool, reference func(string) string) *App {
	t.Helper()
	if native {
		app := tokenRefreshTestApp(t, "enable admin api")
		p := app.Config.AuthenticationPortals[0]
		p.API.DocumentsEnabled = true
		p.Documents = &documents.Config{Database: reference("database"), PublicOrigin: reference("origin"), BasePath: reference("mount"), Realms: []string{reference("realm")}, MaxFileBytes: 32}
		return app
	}
	body := "enable admin api\nenable documents api\n"
	for _, field := range []struct{ key, directive string }{{"database", "database"}, {"origin", "public origin"}, {"mount", "base path"}, {"realm", "realms"}, {"bytes", "max file bytes"}} {
		body += "documents api " + field.directive + " " + fmt.Sprintf("%q", reference(field.key)) + "\n"
	}
	return tokenRefreshTestApp(t, body)
}

func resolveDocumentsTestApp(t *testing.T, app *App, values map[string]string) error {
	t.Helper()
	return resolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&oauthRuntimeSecrets{Values: values}}, app.Config, nil, nil, nil, app.PortalDocumentsDirectives, zap.NewNop())
}

func TestPortalDocumentsResolution(t *testing.T) {
	values := map[string]string{"database": "/private/quoted documents.db", "origin": "https://auth.example.test", "mount": "/tenant/auth", "realm": "corp, west", "bytes": "32"}
	for _, native := range []bool{false, true} {
		for _, source := range []string{"environment", "secrets"} {
			t.Run(fmt.Sprintf("native=%t/%s", native, source), func(t *testing.T) {
				for key, value := range values {
					t.Setenv("DOCUMENTS_TEST_"+key, value)
				}
				reference := func(key string) string {
					if source == "environment" {
						return "{env.DOCUMENTS_TEST_" + key + "}"
					}
					return "secrets:oauth:" + key
				}
				app := documentsResolutionApp(t, native, reference)
				before, err := json.Marshal(app)
				if err != nil {
					t.Fatal(err)
				}
				var restored App
				if err := json.Unmarshal(before, &restored); err != nil {
					t.Fatal(err)
				}
				if err := resolveDocumentsTestApp(t, &restored, values); err != nil {
					t.Fatal(err)
				}
				p := restored.Config.AuthenticationPortals[0]
				want := &documents.Config{Database: values["database"], PublicOrigin: values["origin"], BasePath: values["mount"], Realms: []string{values["realm"]}, MaxFileBytes: 32}
				if err := want.Validate(); err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(want, p.Documents); diff != "" {
					t.Fatal(diff)
				}
				if !p.API.DocumentsEnabled || !p.API.AdminEnabled || !p.API.ProfileEnabled {
					t.Fatal("resolved Documents changed independent API flags")
				}
				after, _ := json.Marshal(app)
				if string(before) != string(after) {
					t.Fatal("resolving restored JSON changed its original declaration")
				}
			})
		}
	}
}

func TestPortalDocumentsExactAndDisabledResolution(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			values := map[string]string{"database": "/private/literal {env.NOT_EXPANDED}.db", "origin": "https://auth.example.test", "mount": "/auth", "realm": "corp, west", "bytes": "32"}
			app := documentsResolutionApp(t, native, func(key string) string { return "secrets:oauth:" + key })
			if err := resolveDocumentsTestApp(t, app, values); err != nil {
				t.Fatal("inserted literal brace was expanded again", err)
			}
			if got := app.Config.AuthenticationPortals[0].Documents.Database; got != values["database"] {
				t.Fatal("resolved database argument changed")
			}
			app = documentsResolutionApp(t, native, func(key string) string { return "secrets:oauth:" + key })
			if native {
				app.Config.AuthenticationPortals[0].API.DocumentsEnabled = false
				app.Config.AuthenticationPortals[0].Documents.MaxFileBytes = -1
			} else {
				app.PortalDocumentsDirectives["portal"][0] = "disable documents api"
			}
			values["database"], values["origin"], values["mount"], values["realm"] = "unused", "http://unused", "invalid", "realm"
			if err := resolveDocumentsTestApp(t, app, values); err != nil {
				t.Fatal("disabled settings lost opt-out semantics", err)
			}
			p := app.Config.AuthenticationPortals[0]
			if p.API.DocumentsEnabled || p.Documents.Database != "unused" || p.Documents.BasePath != "invalid" {
				t.Fatal("disabled references were skipped or normalized")
			}
			if !native {
				app = documentsResolutionApp(t, false, func(key string) string { return "secrets:oauth:" + key })
				app.PortalDocumentsDirectives["portal"][0] = "disable documents api"
				values["bytes"] = "-1"
				if err := resolveDocumentsTestApp(t, app, values); err == nil {
					t.Fatal("disabled deferred settings accepted malformed numeric grammar")
				}
			}
		})
	}
}

func TestPortalDocumentsResolutionRejects(t *testing.T) {
	for _, native := range []bool{false, true} {
		for name, edit := range map[string]func(map[string]string){
			"missing":        func(v map[string]string) { delete(v, "database") },
			"empty":          func(v map[string]string) { v["database"] = "" },
			"whitespace":     func(v map[string]string) { v["realm"] = " " },
			"multiline":      func(v map[string]string) { v["mount"] = "/auth\nother" },
			"noncanonical":   func(v map[string]string) { v["origin"] = "https://AUTH.example.test" },
			"reserved mount": func(v map[string]string) { v["mount"] = "/api" },
		} {
			t.Run(fmt.Sprintf("native=%t/%s", native, name), func(t *testing.T) {
				app := documentsResolutionApp(t, native, func(key string) string { return "secrets:oauth:" + key })
				values := map[string]string{"database": "/private/documents.db", "origin": "https://auth.example.test", "mount": "/auth", "realm": "local", "bytes": "32"}
				edit(values)
				if err := resolveDocumentsTestApp(t, app, values); err == nil {
					t.Fatal("invalid resolved Documents settings accepted")
				}
			})
		}
	}
	for name, edit := range map[string]func(*App){
		"unknown target": func(a *App) { a.PortalDocumentsDirectives["absent"] = []string{"disable documents api"} },
		"empty snapshot": func(a *App) { a.PortalDocumentsDirectives["portal"] = nil },
		"native storage": func(a *App) { a.Config.AuthenticationPortals[0].Documents = &documents.Config{} },
		"native enabled": func(a *App) { a.Config.AuthenticationPortals[0].API.DocumentsEnabled = true },
		"duplicate target": func(a *App) {
			a.Config.AuthenticationPortals = append(a.Config.AuthenticationPortals, &authn.PortalConfig{Name: "portal"})
		},
		"raw multiline": func(a *App) {
			a.PortalDocumentsDirectives["portal"] = []string{"disable documents api\nenable documents api"}
		},
		"empty token": func(a *App) { a.PortalDocumentsDirectives["portal"] = []string{"documents api database \"\""} },
		"duplicate realm": func(a *App) {
			a.PortalDocumentsDirectives["portal"] = []string{"enable documents api", "documents api database /private/documents.db", "documents api public origin https://auth.example.test", "documents api realms local local"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			app := tokenRefreshTestApp(t, "")
			app.PortalDocumentsDirectives = map[string][]string{"portal": {"disable documents api"}}
			edit(app)
			if err := resolveDocumentsTestApp(t, app, nil); err == nil {
				t.Fatal("invalid Documents snapshot accepted")
			}
		})
	}
}

func TestPortalDocumentsResolvedRealmCollision(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			app := documentsResolutionApp(t, native, func(key string) string { return "secrets:oauth:" + key })
			if native {
				app.Config.AuthenticationPortals[0].Documents.Realms = append(app.Config.AuthenticationPortals[0].Documents.Realms, "secrets:oauth:second")
			} else {
				app.PortalDocumentsDirectives["portal"][4] += " secrets:oauth:second"
			}
			values := map[string]string{"database": "/private/documents.db", "origin": "https://auth.example.test", "mount": "/auth", "realm": "local", "second": "local", "bytes": "32"}
			if err := resolveDocumentsTestApp(t, app, values); err == nil {
				t.Fatal("duplicate realms created by replacement were accepted")
			}
		})
	}
}
