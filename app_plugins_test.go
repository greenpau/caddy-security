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
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

// This factory is registered only in test executables. It deliberately has a
// separate Caddy cleanup callback to exercise unspecified module cleanup order.
type claimsTestModule struct {
	Label        string          `json:"label"`
	Failure      string          `json:"failure,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	ResourceFree bool            `json:"resource_free,omitempty"`
	state        *claimsTestState
}

type claimsTestState struct {
	constructed atomic.Int64
	closed      atomic.Int64
	cleaned     atomic.Int64
	lookups     atomic.Int64
	hold        atomic.Pointer[lifecycleHold]
	onClose     func()
}

var claimsTestStates sync.Map

func (claimsTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.claims_enrichment.test", New: func() caddy.Module { return new(claimsTestModule) }}
}

func (m *claimsTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("test state not registered")
	}
	m.state = value.(*claimsTestState)
	if m.Failure == "provision" {
		return fmt.Errorf("synthetic-private-diagnostic")
	}
	return nil
}

func (m *claimsTestModule) Validate() error {
	if m.Failure == "validate" {
		return fmt.Errorf("synthetic-private-diagnostic")
	}
	return nil
}

func (m *claimsTestModule) Cleanup() error {
	if m.state != nil {
		m.state.cleaned.Add(1)
	}
	return nil
}

func (m *claimsTestModule) NewClaimsEnrichmentBackend(ctx context.Context, _ enrichment.Config) (enrichment.Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.state.constructed.Add(1)
	if m.Failure == "nil" {
		return nil, nil
	}
	backend := &claimsTestBackend{state: m.state, closeError: m.Failure == "close"}
	if m.ResourceFree {
		return struct{ enrichment.Backend }{backend}, nil
	}
	if m.Failure == "construct" {
		return backend, fmt.Errorf("synthetic-private-diagnostic")
	}
	return backend, nil
}

type claimsTestBackend struct {
	state      *claimsTestState
	closeError bool
}

func (b *claimsTestBackend) Lookup(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
	if b.state.closed.Load() != 0 {
		return nil, fmt.Errorf("lookup after close")
	}
	b.state.lookups.Add(1)
	if hold := b.state.hold.Load(); hold != nil {
		hold.once.Do(func() { close(hold.entered) })
		select {
		case <-hold.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	now := time.Now()
	return &enrichment.Result{
		Identity: req.Identity, Audience: req.Audience, Purpose: req.Purpose,
		Source: "test", Version: "v1", ObservedAt: now, ExpiresAt: now.Add(time.Minute),
		Attributes: map[string]any{"enrichment.department": "engineering"},
	}, nil
}

func (b *claimsTestBackend) Close() error {
	b.state.closed.Add(1)
	if b.state.onClose != nil {
		b.state.onClose()
	}
	if b.closeError {
		return fmt.Errorf("synthetic-private-diagnostic")
	}
	return nil
}

type claimsWrongModule struct{}

func (claimsWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.claims_enrichment.test_wrong", New: func() caddy.Module { return new(claimsWrongModule) }}
}

func init() {
	caddy.RegisterModule(claimsTestModule{})
	caddy.RegisterModule(claimsWrongModule{})
}

var _ ClaimsEnrichmentBackendModule = (*claimsTestModule)(nil)

func claimsTestBinding(t *testing.T, label, failure string) (*ClaimsEnrichmentBinding, *claimsTestState) {
	t.Helper()
	probe := new(claimsTestState)
	if _, loaded := claimsTestStates.LoadOrStore(label, probe); loaded {
		t.Fatal("duplicate test label", label)
	}
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	raw, err := json.Marshal(map[string]any{"driver": "test", "label": label, "failure": failure,
		"payload": json.RawMessage(`{"precise":9007199254740993}`)})
	if err != nil {
		t.Fatal(err)
	}
	return &ClaimsEnrichmentBinding{Policy: "policy", BackendRaw: raw, Config: &enrichment.Config{
		Source: "test", Version: "v1", Issuer: "test-issuer", Realm: "local", SubjectClaim: "sub",
		TenantClaim: "tenant", Audience: "test-audience", Timeout: "30s",
		Attributes: []enrichment.AttributeConfig{{Name: "enrichment.department", Type: "string"}},
	}}, probe
}

func claimsTestApp(t *testing.T, cfg *authcrunch.Config, bindings ...*ClaimsEnrichmentBinding) (*App, context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	app := &App{Config: cfg, ClaimsEnrichment: bindings}
	t.Cleanup(func() { _ = app.Cleanup() })
	return app, cancel, app.Provision(ctx)
}

func TestAppPluginsConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*App)
	}{
		{"null", func(a *App) { a.ClaimsEnrichment[0] = nil }},
		{"unknown_policy", func(a *App) { a.ClaimsEnrichment[0].Policy = "missing" }},
		{"duplicate_policy", func(a *App) { a.ClaimsEnrichment = append(a.ClaimsEnrichment, a.ClaimsEnrichment[0]) }},
		{"null_config", func(a *App) { a.ClaimsEnrichment[0].Config = nil }},
		{"invalid_binding", func(a *App) { a.ClaimsEnrichment[0].Config.SubjectClaim = "tenant" }},
		{"missing_backend", func(a *App) { a.ClaimsEnrichment[0].BackendRaw = nil }},
		{"null_backend", func(a *App) { a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`null`) }},
		{"unknown_driver", func(a *App) { a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"missing"}`) }},
		{"wrong_interface", func(a *App) { a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"test_wrong"}`) }},
		{"unknown_field", func(a *App) {
			a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"test","private_value":true}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binding, probe := claimsTestBinding(t, t.Name(), "")
			app := &App{Config: lifecycleConfig(), ClaimsEnrichment: []*ClaimsEnrichmentBinding{binding}}
			tc.edit(app)
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			defer app.Cleanup()
			if err := app.Provision(ctx); err == nil {
				t.Fatal("invalid plugin configuration accepted")
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("invalid binding reached runtime construction")
			}
		})
	}
}

func TestAppPluginsSnapshotsAndDrain(t *testing.T) {
	binding, probe := claimsTestBinding(t, t.Name(), "")
	before, _ := json.Marshal(binding)
	var restored ClaimsEnrichmentBinding
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	app, cancel, err := claimsTestApp(t, lifecycleConfig(), &restored)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(&restored)
	if string(before) != string(after) || !strings.Contains(string(after), "9007199254740993") {
		t.Fatal("module loading changed declarative JSON")
	}
	restored.Config.Attributes[0].Name = "changed"
	restored.Config.Source = "changed"
	clear(restored.BackendRaw)
	if app.claimsEnrichment[0].config.Attributes[0].Name != "enrichment.department" || app.claimsEnrichment[0].config.Source != "test" {
		t.Fatal("runtime binding aliases input")
	}
	probe.onClose = func() {
		if _, err := app.server.GetGatekeeperByName("policy"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("backend closed before root")
		}
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("runtime not admitted")
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	// Caddy is allowed to cancel/clean modules before security has drained.
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module cleanup owns a live backend")
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := app.Cleanup(); err != nil {
				t.Error(err)
			}
		})
	}
	go func() { wg.Wait(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("backend closed before drain")
	}
	if r, ok := app.acquireRequest(); ok {
		r()
		t.Fatal("retired app admitted new work")
	}
	releaseOnce.Do(release)
	awaitLifecycle(t, done, "plugin cleanup")
	if probe.closed.Load() != 1 {
		t.Fatal("backend not closed exactly once")
	}
}

func TestAppPluginsFailedCandidates(t *testing.T) {
	for _, failure := range []string{"provision", "validate", "construct", "nil"} {
		t.Run(failure, func(t *testing.T) {
			binding, probe := claimsTestBinding(t, t.Name(), failure)
			app, _, err := claimsTestApp(t, lifecycleConfig(), binding)
			if err == nil || strings.Contains(err.Error(), "synthetic-private-diagnostic") {
				t.Fatal("missing or unredacted failure", err)
			}
			if app.server != nil || len(app.pluginClosers) != 0 {
				t.Fatal("failed candidate published runtime resources")
			}
			if err := app.Cleanup(); err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if failure == "construct" {
				want = 1
			}
			if probe.closed.Load() != want {
				t.Fatalf("failed backend closes=%d want=%d", probe.closed.Load(), want)
			}
		})
	}
	t.Run("second_backend", func(t *testing.T) {
		first, one := claimsTestBinding(t, t.Name()+"first", "close")
		second, two := claimsTestBinding(t, t.Name()+"second", "construct")
		second.Policy = "second"
		cfg := lifecycleConfig()
		other := *cfg.AuthorizationPolicies[0]
		other.Name = "second"
		cfg.AuthorizationPolicies = append(cfg.AuthorizationPolicies, &other)
		var order []int
		one.onClose = func() { order = append(order, 1) }
		two.onClose = func() { order = append(order, 2) }
		app, _, err := claimsTestApp(t, cfg, first, second)
		if err == nil || !strings.Contains(err.Error(), "cleanup failed") || strings.Contains(err.Error(), "synthetic-private-diagnostic") {
			t.Fatal("candidate failure lost cleanup result or leaked diagnostics", err)
		}
		if !slices.Equal(order, []int{2, 1}) || one.closed.Load() != 1 || two.closed.Load() != 1 {
			t.Fatal("partial candidates did not unwind in reverse order", order)
		}
		_ = app.Cleanup()
		if len(order) != 2 {
			t.Fatal("candidate cleanup closed resources twice")
		}
	})
}

func TestAppPluginsResourceFreeBackend(t *testing.T) {
	binding, probe := claimsTestBinding(t, t.Name(), "")
	raw, err := json.Marshal(map[string]any{"driver": "test", "label": t.Name(), "resource_free": true})
	if err != nil {
		t.Fatal(err)
	}
	binding.BackendRaw = raw
	app, _, err := claimsTestApp(t, lifecycleConfig(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(app.pluginClosers) != 0 || probe.constructed.Load() != 1 {
		t.Fatal("resource-free backend required a closer")
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	assertServerClosed(t, app)
}

func TestAppPluginsPersistentConstruction(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("failure="+failure, func(t *testing.T) {
			binding, probe := claimsTestBinding(t, t.Name(), failure)
			cfg := &authcrunch.Config{
				AuthorizationPolicies: lifecycleConfig().AuthorizationPolicies,
				State:                 &state.Config{Directory: filepath.Join(t.TempDir(), "state")},
			}
			app, _, err := claimsTestApp(t, cfg, binding)
			if err != nil {
				t.Fatal(err)
			}
			if app.server != nil || probe.constructed.Load() != 0 {
				t.Fatal("Provision opened persistent runtime or backend")
			}
			if _, err := os.Stat(cfg.State.Directory); !os.IsNotExist(err) {
				t.Fatal("Provision initialized persistent storage", err)
			}
			err = app.Start()
			if (err != nil) != (failure != "") {
				t.Fatal("unexpected Start result", err)
			}
			if probe.constructed.Load() != 1 {
				t.Fatal("Start did not construct backend")
			}
			if err := app.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if probe.closed.Load() != 1 {
				t.Fatal("backend not closed exactly once")
			}
			// Both successful disposal and failed attachment release root ownership.
			root, err := state.Open(cfg.State)
			if err != nil {
				t.Fatal("candidate retained persistent state ownership", err)
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type claimsCloseFunc func() error

func (f claimsCloseFunc) Close() error { return f() }

func TestAppPluginsCloseFailures(t *testing.T) {
	var order []int
	err := closePluginResources([]io.Closer{
		claimsCloseFunc(func() error { order = append(order, 1); return fmt.Errorf("private-first") }),
		claimsCloseFunc(func() error { order = append(order, 2); return fmt.Errorf("private-second") }),
	})
	if !slices.Equal(order, []int{2, 1}) || err == nil || strings.Contains(err.Error(), "private") || strings.Count(err.Error(), "cleanup failed") != 2 {
		t.Fatal("close did not attempt all resources with redacted errors", order, err)
	}
	binding, probe := claimsTestBinding(t, t.Name(), "close")
	app, _, err := claimsTestApp(t, lifecycleConfig(), binding)
	if err != nil {
		t.Fatal(err)
	}
	err = app.Cleanup()
	if err == nil || strings.Contains(err.Error(), "synthetic-private-diagnostic") || app.Cleanup() != err || probe.closed.Load() != 1 {
		t.Fatal("cleanup error was not stable/redacted or backend closed twice", err)
	}
}
