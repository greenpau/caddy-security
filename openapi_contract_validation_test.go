// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenAPIContractModuleSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		dir  string
	}{
		{"module directory", `{"Path":"github.com/greenpau/go-authcrunch","Version":"v1.0.0","Dir":"/module/cache"}`, "/module/cache"},
		{"replacement takes precedence", `{"Path":"github.com/greenpau/go-authcrunch","Version":"v1.0.0","Dir":"/module/cache","Replace":{"Path":"../authcrunch","Dir":"/local/replacement"}}`, "/local/replacement"},
		{"replacement must resolve", `{"Path":"github.com/greenpau/go-authcrunch","Dir":"/module/cache","Replace":{"Path":"../authcrunch"}}`, ""},
		{"relative directory", `{"Path":"github.com/greenpau/go-authcrunch","Dir":"../private-sentinel"}`, ""},
		{"wrong module", `{"Path":"private-sentinel","Dir":"/module/cache"}`, ""},
		{"reported module error", `{"Path":"github.com/greenpau/go-authcrunch","Dir":"/module/cache","Error":{"Err":"private-sentinel"}}`, ""},
		{"reported replacement error", `{"Path":"github.com/greenpau/go-authcrunch","Replace":{"Dir":"/module/cache","Error":{"Err":"private-sentinel"}}}`, ""},
		{"trailing value", `{"Path":"github.com/greenpau/go-authcrunch","Dir":"/module/cache"} {"private-sentinel":true}`, ""},
		{"malformed metadata", `{"private-sentinel`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			module, err := parseOpenAPIContractModule([]byte(tc.data))
			if tc.dir == "" {
				assertOpenAPIContractError(t, err)
				return
			}
			if err != nil || module.Dir != tc.dir {
				t.Fatal("selected source directory did not match module metadata")
			}
		})
	}
}

func TestOpenAPIContractSelectedSource(t *testing.T) {
	c := newOpenAPIContracts(t)
	if c.module.Path != openAPIContractModule || !filepath.IsAbs(c.module.Dir) || c.version == "" || len(c.docs) == 0 {
		t.Fatal("selected authored source provenance is incomplete")
	}
	digest, err := hex.DecodeString(c.digest)
	if err != nil || len(digest) != 32 {
		t.Fatal("authored snapshot digest is invalid")
	}
	if c.module.Replace != nil && c.module.Dir != c.module.Replace.Dir {
		t.Fatal("selected replacement was not used for authored content")
	}
}

func TestOpenAPIContractResponses(t *testing.T) {
	c := newOpenAPIContracts(t)
	errorBody := `{"error":true,"message":"private-sentinel","timestamp":"2026-10-24T12:34:56.123456789Z"}`
	for _, tc := range []struct {
		name, method, path, media, body, location string
		status                                    int
		valid                                     bool
	}{
		{name: "literal beacon", path: "/beacon", status: 200, media: "application/json", body: "OK", valid: true},
		{name: "quoted beacon is not wire contract", path: "/beacon", status: 200, media: "application/json", body: `"OK"`},
		{name: "beacon wrong marker", path: "/beacon", status: 200, media: "application/json", body: "private-sentinel"},
		{name: "beacon error", path: "/beacon", status: 401, media: "application/json; charset=utf-8", body: errorBody, valid: true},
		{name: "error requires fields", path: "/beacon", status: 401, media: "application/json", body: `{"message":"private-sentinel"}`},
		{name: "error indicator type", path: "/beacon", status: 401, media: "application/json", body: `{"error":"true","message":"private-sentinel","timestamp":"2026-10-24T12:34:56Z"}`},
		{name: "error timestamp format", path: "/beacon", status: 401, media: "application/json", body: `{"error":true,"message":"private-sentinel","timestamp":"yesterday"}`},
		{name: "metadata JSON under text", path: "/api/server/metadata", status: 200, media: "text/plain; charset=utf-8", body: `{"timestamp":"2026-10-24T12:34:56Z","version":"fixture"}`, valid: true},
		{name: "metadata requires timestamp", path: "/api/server/metadata", status: 200, media: "text/plain", body: `{"version":"private-sentinel"}`},
		{name: "metadata wrong shape", path: "/api/server/metadata", status: 200, media: "text/plain", body: `"private-sentinel"`},
		{name: "metadata media is exact", path: "/api/server/metadata", status: 200, media: "application/json", body: `{"timestamp":"2026-10-24T12:34:56Z"}`},
		{name: "JSON cannot become HTML", path: "/beacon", status: 401, media: "text/html", body: "private-sentinel"},
		{name: "status undocumented", path: "/beacon", status: 299, media: "application/json", body: "OK"},
		{name: "operation undocumented", path: "/private-sentinel", status: 200, media: "application/json", body: "OK"},
		{name: "method undocumented", method: "DELETE", path: "/beacon", status: 200, media: "application/json", body: "OK"},
		{name: "missing media", path: "/beacon", status: 200, body: "OK"},
		{name: "invalid media", path: "/beacon", status: 200, media: "private-sentinel;=", body: "OK"},
		{name: "trailing JSON", path: "/beacon", status: 401, media: "application/json", body: errorBody + `{}`},
		{name: "JWKS HEAD", method: "HEAD", path: "/.well-known/jwks.json", status: 200, media: "application/jwk-set+json", valid: true},
		{name: "HEAD cannot carry a body", method: "HEAD", path: "/.well-known/jwks.json", status: 200, media: "application/jwk-set+json", body: "private-sentinel"},
		{name: "JWKS documented empty failure", path: "/.well-known/jwks.json", status: 404, valid: true},
		{name: "JWKS empty failure rejects body", path: "/.well-known/jwks.json", status: 404, body: "private-sentinel"},
		{name: "empty redirect", path: "/whoami", status: 302, location: "https://fixture.example/login", valid: true},
		{name: "empty redirect optional valid media", path: "/whoami", status: 302, location: "https://fixture.example/login", media: "text/html", valid: true},
		{name: "empty redirect cannot omit destination", path: "/whoami", status: 302},
		{name: "empty redirect cannot change media", path: "/whoami", status: 302, location: "https://fixture.example/login", media: "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodGet
			}
			headers := make(http.Header)
			if tc.media != "" {
				headers.Set("Content-Type", tc.media)
			}
			if tc.location != "" {
				headers.Set("Location", tc.location)
			}
			err := c.checkResponse(method, tc.path, tc.status, headers, []byte(tc.body))
			if tc.valid {
				if err != nil {
					t.Fatalf("documented response rejected: %v", err)
				}
			} else {
				assertOpenAPIContractError(t, err)
			}
		})
	}
}

func TestOpenAPIContractRequestsAndComponents(t *testing.T) {
	c := newOpenAPIContracts(t)
	headers := http.Header{"Content-Type": []string{"application/json"}}
	for _, tc := range []struct {
		name, path, body string
		valid            bool
	}{
		{"login start", "/login", `{"username":"alice","realm":"local","refresh_transport":"body"}`, true},
		{"login challenge", "/login", `{"username":"alice","realm":"local","sandbox_id":"fixture","sandbox_secret":"private-sentinel","challenge_kind":"password","challenge_response":"private-sentinel","refresh_transport":"body"}`, true},
		{"login missing realm", "/login", `{"username":"private-sentinel"}`, false},
		{"login unknown field", "/login", `{"username":"alice","realm":"local","password":"private-sentinel"}`, false},
		{"browser refresh", "/api/refresh_token", `{}`, true},
		{"native refresh", "/api/refresh_token", `{"refresh_token":"acr1_` + strings.Repeat("A", 43) + `"}`, true},
		{"invalid refresh secret", "/api/refresh_token", `{"refresh_token":"private-sentinel"}`, false},
		{"refresh unknown field", "/api/refresh_token", `{"private-sentinel":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := c.checkRequest(http.MethodPost, tc.path, headers, []byte(tc.body))
			if tc.valid {
				if err != nil {
					t.Fatalf("documented request rejected: %v", err)
				}
			} else {
				assertOpenAPIContractError(t, err)
			}
		})
	}
	if err := c.checkComponent("ProfileUserInfo", []byte(`{"metadata":{"username":"alice"},"roles":["authp/user"],"token":"{}"}`)); err != nil {
		t.Fatalf("profile component rejected: %v", err)
	}
	assertOpenAPIContractError(t, c.checkComponent("ProfileUserInfo", []byte(`{"token":"private-sentinel"}`)))
	assertOpenAPIContractError(t, c.checkComponent("private-sentinel", []byte(`{}`)))
}

const openAPIContractFixture = `openapi: 3.1.1
info:
  version: fixture
paths:
  /number:
    get:
      responses:
        '200':
          description: Exact integer
          content:
            application/json:
              schema:
                $ref: schemas/number.yaml
components:
  schemas:
    Number:
      $ref: schemas/number.yaml
`

func writeOpenAPIContractFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	for name, data := range files {
		filename := filepath.Join(directory, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal("could not create authored fixture directory")
		}
		if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
			t.Fatal("could not write authored fixture")
		}
	}
	return directory
}

func TestOpenAPIContractNumbersReferencesAndConcurrency(t *testing.T) {
	directory := writeOpenAPIContractFixture(t, map[string]string{
		"openapi.yaml":        openAPIContractFixture,
		"schemas/number.yaml": "$ref: ../types.yaml#/properties/number\n",
		"types.yaml":          "type: object\nproperties:\n  number:\n    type: integer\n    const: 9007199254740993\n  '$ref':\n    type: string\nexamples:\n- '$ref': 'https://literal.example/private-sentinel'\n",
	})
	c, err := loadOpenAPIContracts(directory)
	if err != nil {
		t.Fatalf("contained reference fixture rejected: %v", err)
	}
	if err := c.checkComponent("Number", []byte(`9007199254740993`)); err != nil {
		t.Fatalf("exact large integer rejected: %v", err)
	}
	assertOpenAPIContractError(t, c.checkComponent("Number", []byte(`9007199254740992`)))
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 10 {
				if err := c.checkResponse(http.MethodGet, "/number", 200, http.Header{"Content-Type": []string{"application/json"}}, []byte(`9007199254740993`)); err != nil {
					t.Errorf("concurrent schema validation failed: %v", err)
				}
			}
		})
	}
	group.Wait()
	if err := os.WriteFile(filepath.Join(directory, "types.yaml"), []byte("type: object\nproperties:\n  number:\n    type: integer\n    const: 9007199254740992\n"), 0600); err != nil {
		t.Fatal("could not update authored fixture")
	}
	changed, err := loadOpenAPIContracts(directory)
	if err != nil || c.digest == changed.digest {
		t.Fatal("changing a referenced schema did not change the authored snapshot digest")
	}
	// Existing helpers retain their immutable snapshot, even if a replacement
	// checkout changes while an HTTP capture is using it.
	if err := c.checkComponent("Number", []byte(`9007199254740993`)); err != nil {
		t.Fatal("existing authored snapshot changed after loading")
	}
}

func TestOpenAPIContractRejectsUnsafeSources(t *testing.T) {
	for _, ref := range []string{
		"https://private-sentinel.example/schema.yaml", "file:///private-sentinel.yaml",
		"//private-sentinel.example/schema.yaml", "/private-sentinel.yaml",
		"../../private-sentinel.yaml", "%2e%2e/%2e%2e/private-sentinel.yaml",
		"other.yaml?private-sentinel", "other.yaml?", "other\\private-sentinel.yaml",
		"other.yaml#anchor-private-sentinel", "other.yaml#/private~2sentinel",
	} {
		t.Run(fmt.Sprintf("reference_%d", len(ref))+strings.ReplaceAll(ref[:1], "/", "slash"), func(t *testing.T) {
			quoted, _ := json.Marshal(ref)
			directory := writeOpenAPIContractFixture(t, map[string]string{
				"openapi.yaml": openAPIContractFixture, "schemas/number.yaml": "$ref: " + string(quoted) + "\n",
			})
			_, err := loadOpenAPIContracts(directory)
			assertOpenAPIContractError(t, err)
		})
	}
	for name, schema := range map[string]string{
		"duplicate keys": "type: string\ntype: integer\n",
		"alias":          "allOf:\n- &private-sentinel {type: string}\n- *private-sentinel\n",
		"multiple docs":  "type: string\n---\ntype: integer\n",
		"nonstring key":  "123: private-sentinel\n",
		"resource id":    "$id: https://private-sentinel.example/schema.yaml\ntype: string\n",
		"dynamic ref":    "$dynamicRef: https://private-sentinel.example/schema.yaml\n",
		"numeric NaN":    "const: .nan\n",
	} {
		t.Run(name, func(t *testing.T) {
			directory := writeOpenAPIContractFixture(t, map[string]string{"openapi.yaml": openAPIContractFixture, "schemas/number.yaml": schema})
			_, err := loadOpenAPIContracts(directory)
			assertOpenAPIContractError(t, err)
		})
	}
	for _, directoryLink := range []bool{false, true} {
		t.Run(fmt.Sprintf("symlink_directory_%t", directoryLink), func(t *testing.T) {
			directory := writeOpenAPIContractFixture(t, map[string]string{"openapi.yaml": openAPIContractFixture})
			target := writeOpenAPIContractFixture(t, map[string]string{"number.yaml": "type: integer\n"})
			link := filepath.Join(directory, "schemas")
			if !directoryLink {
				if err := os.Mkdir(link, 0700); err != nil {
					t.Fatal("could not create symlink fixture directory")
				}
				link = filepath.Join(link, "number.yaml")
				target = filepath.Join(target, "number.yaml")
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal("could not create unsafe source fixture")
			}
			_, err := loadOpenAPIContracts(directory)
			assertOpenAPIContractError(t, err)
		})
	}
}

func TestOpenAPIContractRejectsMissingContracts(t *testing.T) {
	for name, schema := range map[string]string{
		"missing file":      "$ref: missing.yaml\n",
		"missing pointer":   "$ref: ../openapi.yaml#/private-sentinel\n",
		"schema wrong type": "type: private-sentinel\n",
	} {
		t.Run(name, func(t *testing.T) {
			directory := writeOpenAPIContractFixture(t, map[string]string{"openapi.yaml": openAPIContractFixture, "schemas/number.yaml": schema})
			c, err := loadOpenAPIContracts(directory)
			if err != nil {
				t.Fatalf("local reference fixture did not load: %v", err)
			}
			assertOpenAPIContractError(t, c.checkComponent("Number", []byte(`9007199254740993`)))
		})
	}
	for name, response := range map[string]string{
		"missing content":  "description: no content schema",
		"missing schema":   "content: {application/json: {}}",
		"structural cycle": "$ref: '#/paths/~1number/get/responses/200'",
	} {
		t.Run(name, func(t *testing.T) {
			doc := "openapi: 3.1.1\ninfo: {version: fixture}\npaths:\n  /number:\n    get:\n      responses:\n        '200':\n          " + response + "\n"
			c, err := loadOpenAPIContracts(writeOpenAPIContractFixture(t, map[string]string{"openapi.yaml": doc}))
			if err != nil {
				t.Fatalf("missing contract fixture did not load: %v", err)
			}
			assertOpenAPIContractError(t, c.checkResponse(http.MethodGet, "/number", 200, http.Header{"Content-Type": []string{"application/json"}}, []byte(`"private-sentinel"`)))
		})
	}
}

func assertOpenAPIContractError(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("invalid contract unexpectedly passed validation")
	}
	if strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("contract error exposed private input")
	}
}
