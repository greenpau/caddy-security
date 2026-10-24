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
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
)

// Exercise direct OAuth callback admission and existing sessions in the actual
// Caddy executable, restoring the native binding solely from serialized JSON.
func TestCaddyExternalAuthorizationOAuthE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/runtime_state_caddy")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Caddy: %v\n%s", err, output)
	}
	service := newExternalPolicyService(t)
	f := newDirectCaddy(t, binary, false)
	var config caddy.Config
	if err := json.Unmarshal(f.configData, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.AppsRaw["security"], &app); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Driver string `json:"driver"`
		*HTTPJSONExternalAuthorization
	}{"httpjson", &HTTPJSONExternalAuthorization{Endpoint: service.server.URL + "/decide", TLS: &ExternalAuthorizationTLS{RootCAFile: service.ca, ClientCertificateFile: service.clientCert, ClientKeyFile: service.clientKey}}})
	if err != nil {
		t.Fatal(err)
	}
	app.ExternalAuthorization = []*ExternalAuthorizationBinding{{Policy: "direct", Config: &external.Config{Policy: "reports", Version: "revision-1", Issuer: f.base, Realm: "upstream", Attributes: []string{"roles"}}, BackendRaw: raw}}
	config.AppsRaw["security"], err = json.Marshal(&app)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(&config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	reload := f.command(t, "reload", "--force", "--config", f.config)
	if output, err := reload.CombinedOutput(); err != nil {
		t.Fatalf("reload native external binding: %v\n%s", err, output)
	}
	browser := f.persistentCaddy.browser(t)
	service.mode.Store("deny")
	callback := f.begin(t, browser, "/files")
	f.request(t, browser, "GET", callback, nil, 403, false)
	f.noSession(t, browser)
	service.mode.Store("allow")
	callback = f.begin(t, browser, "/files")
	f.request(t, browser, "GET", callback, nil, 303, false)
	before := service.hits.Load()
	for range 2 {
		f.request(t, browser, "GET", f.base+"/files", nil, 200, true)
	}
	service.mode.Store("deny")
	f.request(t, browser, "GET", f.base+"/files", nil, 403, false)
	service.mode.Store("allow")
	f.request(t, browser, "GET", f.base+"/files", nil, 200, true)
	if service.hits.Load() != before+4 {
		t.Fatal("existing OAuth session bypassed fresh external decisions")
	}
	before = service.hits.Load()
	f.request(t, browser, "GET", f.base+"/denied", nil, 403, false)
	f.request(t, browser, "GET", f.base+"/public", nil, 200, true)
	if service.hits.Load() != before {
		t.Fatal("local denial or bypass contacted service")
	}
	for _, request := range service.snapshot() {
		if request.Identity.Issuer != f.base || request.Identity.Realm != "upstream" || request.Identity.Subject == "" || request.Resource != "/files" {
			t.Fatal("incorrect OAuth decision identity or callback resource")
		}
	}
	service.mode.Store("status")
	f.request(t, browser, "GET", f.base+"/files", nil, 403, false)
}
