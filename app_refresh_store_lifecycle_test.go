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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

// Keep actual SQLite metadata, readiness and generation activation beneath an
// observed owner. No transactional behavior is replaced by the lifetime probe.
type lifecycleRefreshStoreModule struct {
	SQLiteRefreshStore
	Label string `json:"label"`
	probe *lifecycleRefreshStoreProbe
}
type lifecycleRefreshStoreProbe struct {
	module                       *lifecycleRefreshStoreModule
	constructed, closed, cleaned atomic.Int32
	closedBeforeRoot             atomic.Bool
	server                       atomic.Pointer[authcrunch.Server]
	handle                       atomic.Pointer[lifecycleRefreshStore]
}

var lifecycleRefreshStoreProbes sync.Map

func (lifecycleRefreshStoreModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.refresh_stores.lifecycle_test", New: func() caddy.Module { return new(lifecycleRefreshStoreModule) }}
}
func (m *lifecycleRefreshStoreModule) Provision(caddy.Context) error {
	value, ok := lifecycleRefreshStoreProbes.Load(m.Label)
	if !ok {
		return fmt.Errorf("store lifecycle probe unavailable")
	}
	m.probe = value.(*lifecycleRefreshStoreProbe)
	m.probe.module = m
	return nil
}
func (m *lifecycleRefreshStoreModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}
func (m *lifecycleRefreshStoreModule) PrepareRefreshStore() (RefreshStoreFactory, error) {
	factory, err := m.SQLiteRefreshStore.PrepareRefreshStore()
	if err != nil {
		return nil, err
	}
	return &lifecycleRefreshStoreFactory{delegate: factory, probe: m.probe}, nil
}

type lifecycleRefreshStoreFactory struct {
	delegate RefreshStoreFactory
	probe    *lifecycleRefreshStoreProbe
}

func (f *lifecycleRefreshStoreFactory) RefreshStoreConfig() (tokenrefresh.ExternalStoreConfig, error) {
	return f.delegate.RefreshStoreConfig()
}
func (f *lifecycleRefreshStoreFactory) NewRefreshStore(ctx context.Context) (tokenrefresh.ManagedStore, error) {
	f.probe.constructed.Add(1)
	store, err := f.delegate.NewRefreshStore(ctx)
	if err != nil {
		return nil, err
	}
	handle := &lifecycleRefreshStore{delegate: store, probe: f.probe}
	f.probe.handle.Store(handle)
	return handle, nil
}

type lifecycleRefreshStore struct {
	delegate tokenrefresh.ManagedStore
	probe    *lifecycleRefreshStoreProbe
	closed   atomic.Bool
}

func (s *lifecycleRefreshStore) Metadata() (tokenrefresh.StoreMetadata, error) {
	return s.delegate.Metadata()
}
func (s *lifecycleRefreshStore) CheckReady(ctx context.Context) error {
	return s.delegate.CheckReady(ctx)
}
func (s *lifecycleRefreshStore) ActivateGeneration(ctx context.Context, g tokenrefresh.Generation) (tokenrefresh.ActiveStore, error) {
	return s.delegate.ActivateGeneration(ctx, g)
}
func (s *lifecycleRefreshStore) Close() error {
	s.probe.closed.Add(1)
	if server := s.probe.server.Load(); server != nil {
		if _, err := server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			s.probe.closedBeforeRoot.Store(true)
		}
	}
	s.closed.Store(true)
	return s.delegate.(io.Closer).Close()
}
func init() { caddy.RegisterModule(lifecycleRefreshStoreModule{}) }

func newLifecycleRefreshStoreApp(t *testing.T) (*App, *lifecycleRefreshStoreProbe) {
	t.Helper()
	dir := registrationTestDirectory(t)
	module := lifecycleRefreshStoreModule{SQLiteRefreshStore: SQLiteRefreshStore{Name: "sessions", Path: filepath.Join(dir, "refresh.db"), MaxSessions: 2, MaxRotations: 3, Timeout: "5s"}, Label: t.Name()}
	probe := new(lifecycleRefreshStoreProbe)
	lifecycleRefreshStoreProbes.Store(module.Label, probe)
	t.Cleanup(func() { lifecycleRefreshStoreProbes.Delete(module.Label) })
	cfg := lifecycleConfig()
	cfg.UserRegistration = nil
	cfg.State = &state.Config{Directory: filepath.Join(dir, "state")}
	cfg.IdentityStores[0].Params["path"] = filepath.Join(dir, "users.json")
	cfg.AuthenticationPortals[0].RefreshTokens = &authn.TokenRefreshConfig{Enabled: true, Store: "sessions", Realms: []string{"local"}, PublicOrigin: "https://auth.example.test", BasePath: "/auth", MaxSessions: 2, MaxRotations: 3}
	return &App{Config: cfg, RefreshStoreConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(&module, "driver", "lifecycle_test", nil)}}, probe
}
func assertLifecycleRefreshStoreUsable(t *testing.T, probe *lifecycleRefreshStoreProbe) {
	t.Helper()
	handle := probe.handle.Load()
	if handle == nil || handle.CheckReady(t.Context()) != nil {
		t.Fatal("admitted runtime lost its refresh store")
	}
	if _, err := handle.Metadata(); err != nil {
		t.Fatal("runtime metadata unavailable")
	}
}

func TestAppRefreshStoreLifecycleDrain(t *testing.T) {
	app, probe := newLifecycleRefreshStoreApp(t)
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal("store app did not construct", err)
	}
	if err := app.Start(); err != nil {
		t.Fatal("refresh store Start failed", err)
	}
	probe.server.Store(app.server)
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) || probe.constructed.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("store provision changed declaration or lifetime")
	}
	release, admitted := app.acquireRequest()
	if !admitted {
		t.Fatal("store app refused active lease")
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module cancellation closed borrowed store")
	}
	assertLifecycleRefreshStoreUsable(t, probe)
	done := make(chan struct{})
	var cleanupErr error
	go func() { cleanupErr = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("store closed before request drain")
	}
	if _, err := app.server.GetPortalByName("portal"); err != nil {
		t.Fatal("root closed before admitted request drain")
	}
	if next, ok := app.acquireRequest(); ok {
		next()
		t.Fatal("retiring app admitted another lease")
	}
	assertLifecycleRefreshStoreUsable(t, probe)
	select {
	case <-done:
		t.Fatal("cleanup completed with an outstanding lease")
	default:
	}
	releaseOnce.Do(release)
	awaitLifecycle(t, done, "store app cleanup")
	if cleanupErr != nil || probe.closed.Load() != 1 || probe.closedBeforeRoot.Load() {
		t.Fatal("store cleanup did not follow root disposal exactly once")
	}
	assertServerClosed(t, app)
	if app.Cleanup() != nil || probe.closed.Load() != 1 {
		t.Fatal("repeated app cleanup closed store twice")
	}
	if err := probe.handle.Load().CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("retired backend remained ready")
	}
}

func TestAppRefreshStoreLifecycleRootRejection(t *testing.T) {
	app, probe := newLifecycleRefreshStoreApp(t)
	// This valid declarative syntax reaches root key loading only after the
	// managed refresh backend has been acquired by deferred Start.
	app.Config.AuthenticationPortals[0].RawCryptoKeyStoreConfig = []string{fmt.Sprintf("crypto key current verify from file %q", filepath.Join(t.TempDir(), "missing-public.pem"))}
	before, _ := json.Marshal(app)
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("declarative fixture rejected", err)
	}
	if err := app.Start(); err == nil {
		t.Fatal("invalid root trust was accepted")
	}
	if probe.constructed.Load() != 1 || probe.closed.Load() != 1 || probe.handle.Load() == nil || !probe.handle.Load().closed.Load() || app.server != nil || len(app.pluginClosers) != 0 {
		t.Fatal("root rejection leaked or published store ownership")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("root failure mutated declarative store input")
	}
	if app.Cleanup() != nil || probe.closed.Load() != 1 {
		t.Fatal("failed candidate cleanup closed store twice")
	}
}

func TestAppRefreshStoreLifecyclePersistentStart(t *testing.T) {
	app, probe := newLifecycleRefreshStoreApp(t)
	dir := registrationTestDirectory(t)
	statePath := filepath.Join(dir, "state")
	usersPath := filepath.Join(dir, "users.json")
	app.Config.State = &state.Config{Directory: statePath}
	app.Config.IdentityStores[0].Params["path"] = usersPath
	before, _ := json.Marshal(app)
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("persistent store declaration rejected", err)
	}
	if probe.constructed.Load() != 0 || app.server != nil || app.runtimeConfig == nil {
		t.Fatal("persistent Provision acquired store or root")
	}
	for _, path := range []string{statePath, usersPath, probe.module.Path} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("persistent preparation created runtime storage")
		}
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("persistent preparation rewrote declaration")
	}
	// The deferred constructor must use its private factory and consumer copies.
	probe.module.Path = filepath.Join(dir, "unchecked", "refresh.db")
	probe.module.Name = "changed"
	probe.module.MaxSessions = 1
	app.RefreshStoreConfigs[0] = json.RawMessage(`{"driver":"absent"}`)
	app.Config.AuthenticationPortals[0].RefreshTokens.Store = "changed"
	app.Config.AuthenticationPortals[0].RefreshTokens.MaxSessions = 1
	if err := app.Start(); err != nil {
		t.Fatal("persistent store Start did not use prepared inputs", err)
	}
	probe.server.Store(app.server)
	if probe.constructed.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("deferred Start lost store ownership")
	}
	assertLifecycleRefreshStoreUsable(t, probe)
	if err := app.Start(); err != nil || probe.constructed.Load() != 1 {
		t.Fatal("repeated Start constructed another store")
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal("persistent store cleanup failed", err)
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal("repeated persistent store cleanup failed", err)
	}
	if probe.closed.Load() != 1 || probe.closedBeforeRoot.Load() {
		t.Fatal("persistent store cleanup ordering or count changed")
	}
}

var _ RefreshStoreBackendModule = (*lifecycleRefreshStoreModule)(nil)
var _ RefreshStoreFactory = (*lifecycleRefreshStoreFactory)(nil)
var _ tokenrefresh.ManagedStore = (*lifecycleRefreshStore)(nil)

func TestAppRefreshStoreSelectionValidation(t *testing.T) {
	for _, scenario := range []string{"valid", "unknown", "disabled", "sessions", "rotations", "missing_state"} {
		t.Run(scenario, func(t *testing.T) {
			app, probe := newLifecycleRefreshStoreApp(t)
			switch scenario {
			case "unknown":
				app.Config.AuthenticationPortals[0].RefreshTokens.Store = "absent"
			case "disabled":
				app.Config.AuthenticationPortals[0].RefreshTokens.Enabled = false
			case "sessions":
				app.Config.AuthenticationPortals[0].RefreshTokens.MaxSessions = 1
			case "rotations":
				app.Config.AuthenticationPortals[0].RefreshTokens.MaxRotations = 1
			case "missing_state":
				app.Config.State = nil
			}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if scenario == "valid" && err != nil || scenario != "valid" && err == nil {
				t.Fatal("unexpected managed selection result", err)
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("preflight acquired a backend or published a root")
			}
			after, _ := json.Marshal(app)
			if !bytes.Equal(before, after) {
				t.Fatal("selection validation mutated declaration")
			}
			var module lifecycleRefreshStoreModule
			if json.Unmarshal(app.RefreshStoreConfigs[0], &module) != nil {
				t.Fatal("invalid test module")
			}
			paths := []string{module.Path, app.Config.IdentityStores[0].Params["path"].(string)}
			if app.Config.State != nil {
				paths = append(paths, app.Config.State.Directory)
			}
			for _, path := range paths {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("preflight opened persistent storage")
				}
			}
		})
	}
}
