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
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

// Reuse the existing app resource probe, including Caddy's independent module
// cleanup, to test mixed-category construction and retirement order.
type externalTestModule struct{ claimsTestModule }

func (externalTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.external_authorization.test", New: func() caddy.Module { return new(externalTestModule) }}
}
func (m *externalTestModule) NewExternalAuthorizationBackend(ctx context.Context, _ external.Config) (external.Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.state.constructed.Add(1)
	if m.Failure == "nil" {
		return nil, nil
	}
	b := &externalTestBackend{claimsTestBackend: claimsTestBackend{state: m.state, closeError: m.Failure == "close"}}
	if m.Failure == "construct" {
		return b, fmt.Errorf("synthetic-private-diagnostic")
	}
	return b, nil
}

type externalTestBackend struct{ claimsTestBackend }

func (b *externalTestBackend) Decide(context.Context, external.Request) (*external.Result, error) {
	return nil, external.ErrUnavailable
}

type externalWrongModule struct{}

func (externalWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.external_authorization.test_wrong", New: func() caddy.Module { return new(externalWrongModule) }}
}
func init() { caddy.RegisterModule(externalTestModule{}); caddy.RegisterModule(externalWrongModule{}) }

var _ ExternalAuthorizationBackendModule = (*externalTestModule)(nil)

func externalTestBinding(t *testing.T, failure string) (*ExternalAuthorizationBinding, *claimsTestState) {
	t.Helper()
	previous, probe := claimsTestBinding(t, t.Name(), failure)
	return &ExternalAuthorizationBinding{Policy: "policy", BackendRaw: previous.BackendRaw, Config: &external.Config{Policy: "reports", Version: "revision-1", Issuer: "test-issuer", Realm: "local", Attributes: []string{"roles"}}}, probe
}
func externalTestApp(t *testing.T, app *App) (context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = app.Cleanup() })
	return cancel, app.Provision(ctx)
}

func TestAppExternalAuthorizationValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*App)
	}{
		{"null", func(a *App) { a.ExternalAuthorization[0] = nil }},
		{"unknown_policy", func(a *App) { a.ExternalAuthorization[0].Policy = "missing" }},
		{"duplicate", func(a *App) { a.ExternalAuthorization = append(a.ExternalAuthorization, a.ExternalAuthorization[0]) }},
		{"null_config", func(a *App) { a.ExternalAuthorization[0].Config = nil }},
		{"invalid_config", func(a *App) { a.ExternalAuthorization[0].Config.Issuer = "" }},
		{"missing_backend", func(a *App) { a.ExternalAuthorization[0].BackendRaw = nil }},
		{"null_backend", func(a *App) { a.ExternalAuthorization[0].BackendRaw = json.RawMessage(`null`) }},
		{"unknown_driver", func(a *App) { a.ExternalAuthorization[0].BackendRaw = json.RawMessage(`{"driver":"unknown"}`) }},
		{"wrong_interface", func(a *App) { a.ExternalAuthorization[0].BackendRaw = json.RawMessage(`{"driver":"test_wrong"}`) }},
		{"unknown_field", func(a *App) {
			a.ExternalAuthorization[0].BackendRaw = json.RawMessage(`{"driver":"httpjson","endpoint":"https://policy.example","private_value":true}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding, probe := externalTestBinding(t, "")
			app := &App{Config: lifecycleConfig(), ExternalAuthorization: []*ExternalAuthorizationBinding{binding}}
			tc.edit(app)
			if _, err := externalTestApp(t, app); err == nil {
				t.Fatal("invalid binding accepted")
			}
			if app.server != nil || probe.constructed.Load() != 0 {
				t.Fatal("invalid binding constructed runtime")
			}
		})
	}
}

func TestAppExternalAuthorizationOwnership(t *testing.T) {
	binding, probe := externalTestBinding(t, "")
	before, _ := json.Marshal(binding)
	var restored ExternalAuthorizationBinding
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	app := &App{Config: lifecycleConfig(), ExternalAuthorization: []*ExternalAuthorizationBinding{&restored}}
	cancel, err := externalTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(&restored)
	if string(before) != string(after) {
		t.Fatal("module loading modified declarative config")
	}
	restored.Config.Attributes[0] = "changed"
	restored.Config.Issuer = "changed"
	clear(restored.BackendRaw)
	if app.externalAuthorization[0].config.Attributes[0] != "roles" || app.externalAuthorization[0].config.Issuer != "test-issuer" {
		t.Fatal("runtime aliases config")
	}
	probe.onClose = func() {
		if _, err := app.server.GetGatekeeperByName("policy"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("backend closed before root")
		}
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("no admission")
	}
	var once sync.Once
	defer once.Do(release)
	cancel()
	if probe.closed.Load() != 0 || probe.cleaned.Load() != 1 {
		t.Fatal("module cleanup closed live backend")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := app.Cleanup(); err != nil {
			t.Error(err)
		}
	}()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("backend closed before request drain")
	}
	once.Do(release)
	awaitLifecycle(t, done, "external backend cleanup")
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if probe.closed.Load() != 1 {
		t.Fatal("backend not closed exactly once")
	}
}

func TestAppExternalAuthorizationFailedCandidates(t *testing.T) {
	for _, failure := range []string{"provision", "validate", "construct", "nil"} {
		t.Run(failure, func(t *testing.T) {
			binding, probe := externalTestBinding(t, failure)
			claims, first := claimsTestBinding(t, t.Name()+"-claims", "")
			var order []int
			first.onClose = func() { order = append(order, 1) }
			probe.onClose = func() { order = append(order, 2) }
			app := &App{Config: lifecycleConfig(), ClaimsEnrichment: []*ClaimsEnrichmentBinding{claims}, ExternalAuthorization: []*ExternalAuthorizationBinding{binding}}
			_, err := externalTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "synthetic-private-diagnostic") {
				t.Fatal("missing or unredacted error", err)
			}
			if app.server != nil || len(app.pluginClosers) != 0 {
				t.Fatal("failed candidate published resources")
			}
			_ = app.Cleanup()
			switch failure {
			case "construct":
				if !slices.Equal(order, []int{2, 1}) {
					t.Fatal("wrong mixed-backend cleanup order", order)
				}
			case "nil":
				if !slices.Equal(order, []int{1}) {
					t.Fatal("earlier backend leaked", order)
				}
			default:
				if len(order) != 0 || first.constructed.Load() != 0 {
					t.Fatal("invalid config constructed resources")
				}
			}
		})
	}
}

func TestAppExternalAuthorizationPersistent(t *testing.T) {
	binding, probe := externalTestBinding(t, "")
	cfg := &authcrunch.Config{AuthorizationPolicies: lifecycleConfig().AuthorizationPolicies}
	cfg.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
	app := &App{Config: cfg, ExternalAuthorization: []*ExternalAuthorizationBinding{binding}}
	if _, err := externalTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	if probe.constructed.Load() != 0 {
		t.Fatal("persistent provision constructed backend")
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	if probe.constructed.Load() != 1 {
		t.Fatal("start omitted backend")
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if probe.closed.Load() != 1 {
		t.Fatal("persistent backend leaked")
	}
}
