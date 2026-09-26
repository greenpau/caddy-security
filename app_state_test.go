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
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestPersistentAppOwnershipAndDrain(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runtime")
	config := &authcrunch.Config{State: &state.Config{Directory: directory}, AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", RawCryptoKeyStoreConfig: []string{"crypto key verify synthetic-secret"}, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles user"}, Action: "allow stop"}}}}}
	before, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	first := provisionLifecycleApp(t, config)
	if first.server != nil {
		t.Fatal("Provision initialized persistent runtime")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("Provision created state")
	}
	if _, ok := first.acquireRequest(); ok {
		t.Fatal("admitted request before Start")
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	second := provisionLifecycleApp(t, config)
	if err := second.Start(); err == nil || !strings.Contains(err.Error(), "overlapping reload") || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("second owner did not fail with redacted lifecycle error")
	}
	if err := second.Cleanup(); err != nil {
		t.Fatal(err)
	}
	release, ok := first.acquireRequest()
	if !ok {
		t.Fatal("failed candidate disabled old admission")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := first.Cleanup(); err != nil {
			t.Error(err)
		}
	}()
	waitDisposing(t, first)
	if _, ok := first.acquireRequest(); ok {
		t.Fatal("cleanup admitted new request")
	}
	select {
	case <-done:
		t.Fatal("cleanup closed admitted runtime")
	case <-time.After(20 * time.Millisecond):
	}
	// Ownership remains held for callbacks, token and profile calls alike.
	storage, err := state.Open(config.State)
	if err == nil {
		storage.Close()
		t.Fatal("released state before drain")
	}
	release()
	awaitLifecycle(t, done, "persistent cleanup")
	third := provisionLifecycleApp(t, config)
	if err := third.Start(); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("construction mutated declarative config")
	}
}

func TestPersistentAppFailedConstructionReleasesOwner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "runtime")
	config := lifecycleConfig()
	config.UserRegistration = nil
	config.IdentityStores[0].Params["path"] = filepath.Join(t.TempDir(), "users.json")
	config.State = &state.Config{Directory: directory}
	// Validation accepts the UI path; construction must read its template.
	config.AuthenticationPortals[0].UI.Templates = map[string]string{"login": filepath.Join(t.TempDir(), "missing-template")}
	app := provisionLifecycleApp(t, config)
	if err := app.Start(); err == nil {
		t.Fatal("missing runtime template was accepted")
	}
	if _, ok := app.acquireRequest(); ok {
		t.Fatal("partially initialized runtime admitted request")
	}
	storage, err := state.Open(config.State)
	if err != nil {
		t.Fatal("failed constructor retained ownership", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	config.AuthenticationPortals[0].UI.Templates = nil
	retry := provisionLifecycleApp(t, config)
	if err := retry.Start(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentAppUnknownRoute(t *testing.T) {
	config := lifecycleConfig()
	config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "runtime")}
	app := provisionLifecycleApp(t, config)
	if _, err := app.getPortal("missing"); err == nil {
		t.Fatal("unknown portal accepted before Start")
	}
	if _, err := app.getGatekeeper("missing"); err == nil {
		t.Fatal("unknown policy accepted before Start")
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := app.Provision(ctx); err == nil {
		t.Fatal("reprovisioned persistent app")
	}
}

func TestPersistentAppRouteAdmission(t *testing.T) {
	config := lifecycleConfig()
	config.UserRegistration = nil
	config.IdentityStores[0].Params["path"] = filepath.Join(t.TempDir(), "users.json")
	config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "runtime")}
	app := provisionLifecycleApp(t, config)
	portal := &AuthnMiddleware{app: app, PortalName: "portal"}
	policy := &AuthorizationHandler{AuthzMiddleware: AuthzMiddleware{app: app, GatekeeperName: "policy"}}
	for _, phase := range []string{"before start", "after cleanup"} {
		t.Run(phase, func(t *testing.T) {
			for _, handler := range []caddyhttp.MiddlewareHandler{portal, policy} {
				r := httptest.NewRequest("GET", "https://app.example.test/auth/portal", nil)
				r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
				w := httptest.NewRecorder()
				err := handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					t.Error("unavailable app ran protected handler")
					return nil
				}))
				var httpErr caddyhttp.HandlerError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("unavailable app returned %v instead of 503", err)
				}
			}
		})
		if phase == "before start" {
			if err := app.Start(); err != nil {
				t.Fatal(err)
			}
			if err := app.Cleanup(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
