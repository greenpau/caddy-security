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
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/logging"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestAppLoggingInstanceIsolation(t *testing.T) {
	core, entries := observer.New(zap.DebugLevel)
	base := zap.New(core).Named("security")
	newApp := func(rules *logging.Config) *App {
		t.Helper()
		cfg := lifecycleConfig()
		cfg.Logging = rules
		cfg.AuthorizationPolicies[0].AuthRedirectDisabled = true
		app := &App{Config: cfg, logger: base}
		t.Cleanup(func() {
			if err := app.Cleanup(); err != nil {
				t.Error(err)
			}
		})
		if err := app.constructServer(cfg); err != nil {
			t.Fatal(err)
		}
		if app.logger != base {
			t.Fatal("construction replaced the app's base logger")
		}
		return app
	}
	rules := &logging.Config{Skip: []logging.SkipRule{{Match: "exact", Text: "token validation error"}}}
	filtered, unfiltered := newApp(rules), newApp(nil)
	// The live filter must remain an immutable snapshot if its input changes.
	rules.Skip[0].Text = "changed after construction"
	check := func(app *App, want int) {
		t.Helper()
		gate, err := app.server.GetGatekeeperByName("policy")
		if err != nil {
			t.Fatal(err)
		}
		entries.TakeAll()
		r := httptest.NewRequest("GET", "https://example.test/private", nil)
		if err := gate.Authenticate(httptest.NewRecorder(), r, requests.NewAuthorizationRequest()); err == nil {
			t.Fatal("missing-token authorization error was swallowed")
		}
		if got := entries.FilterMessage("token validation error").Len(); got != want {
			t.Fatalf("component errors=%d, want %d", got, want)
		}
	}
	check(filtered, 0)
	check(unfiltered, 1)
	check(filtered, 0)
	// A replacement is always constructed from the original base. Removing
	// rules must not inherit the first instance's suppression or close it.
	replacement := newApp(&logging.Config{})
	check(replacement, 1)
	check(filtered, 0)
	base.Error("token validation error")
	if entries.FilterMessage("token validation error").Len() != 1 {
		t.Fatal("AuthCrunch filter mutated the caller's base logger")
	}
}
