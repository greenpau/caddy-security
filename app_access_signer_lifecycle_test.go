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
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

// Keep actual key loading, metadata and PS256 signing beneath an optional
// resource owner. This observes the app's lifetime without replacing the core.
type lifecycleAccessSignerModule struct {
	RSAPSSAccessSigner
	Label string `json:"label"`
	probe *lifecycleAccessSignerProbe
}
type lifecycleAccessSignerProbe struct {
	module                       *lifecycleAccessSignerModule
	constructed, closed, cleaned atomic.Int32
	closedBeforeRoot             atomic.Bool
	server                       atomic.Pointer[authcrunch.Server]
	handle                       atomic.Pointer[lifecycleAccessSigner]
}

var lifecycleAccessSignerProbes sync.Map

func (lifecycleAccessSignerModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.lifecycle_test", New: func() caddy.Module { return new(lifecycleAccessSignerModule) }}
}
func (m *lifecycleAccessSignerModule) Provision(caddy.Context) error {
	value, ok := lifecycleAccessSignerProbes.Load(m.Label)
	if !ok {
		return fmt.Errorf("signer lifecycle probe unavailable")
	}
	m.probe = value.(*lifecycleAccessSignerProbe)
	m.probe.module = m
	return nil
}
func (m *lifecycleAccessSignerModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}
func (m *lifecycleAccessSignerModule) PrepareAccessSigner() (AccessSignerFactory, error) {
	factory, err := m.RSAPSSAccessSigner.PrepareAccessSigner()
	if err != nil {
		return nil, err
	}
	return &lifecycleAccessSignerFactory{delegate: factory, probe: m.probe}, nil
}

type lifecycleAccessSignerFactory struct {
	delegate AccessSignerFactory
	probe    *lifecycleAccessSignerProbe
}

func (f *lifecycleAccessSignerFactory) AccessSignerConfig() (kms.ExternalAccessSignerConfig, error) {
	return f.delegate.AccessSignerConfig()
}
func (f *lifecycleAccessSignerFactory) NewAccessSigner(ctx context.Context) (kms.AccessSigner, error) {
	f.probe.constructed.Add(1)
	signer, err := f.delegate.NewAccessSigner(ctx)
	if err != nil {
		return nil, err
	}
	handle := &lifecycleAccessSigner{delegate: signer, probe: f.probe}
	f.probe.handle.Store(handle)
	return handle, nil
}

type lifecycleAccessSigner struct {
	delegate kms.AccessSigner
	probe    *lifecycleAccessSignerProbe
	closed   atomic.Bool
}

func (s *lifecycleAccessSigner) Metadata() (kms.AccessSignerMetadata, error) {
	return s.delegate.Metadata()
}
func (s *lifecycleAccessSigner) PublicJWKS() ([]byte, error) { return s.delegate.PublicJWKS() }
func (s *lifecycleAccessSigner) Sign(ctx context.Context, claims map[string]any) (string, error) {
	if s.closed.Load() {
		return "", fmt.Errorf("signer lifetime ended")
	}
	return s.delegate.Sign(ctx, claims)
}
func (s *lifecycleAccessSigner) Close() error {
	s.probe.closed.Add(1)
	if server := s.probe.server.Load(); server != nil {
		if _, err := server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			s.probe.closedBeforeRoot.Store(true)
		}
	}
	s.closed.Store(true)
	return nil
}
func init() { caddy.RegisterModule(lifecycleAccessSignerModule{}) }

func newLifecycleAccessSignerApp(t *testing.T) (*App, *lifecycleAccessSignerProbe) {
	t.Helper()
	keys := newJWKSKeyFiles(t, "RSA", "current")
	module := lifecycleAccessSignerModule{RSAPSSAccessSigner: *accessSignerTestModuleConfig(keys.private), Label: t.Name()}
	probe := new(lifecycleAccessSignerProbe)
	lifecycleAccessSignerProbes.Store(module.Label, probe)
	t.Cleanup(func() { lifecycleAccessSignerProbes.Delete(module.Label) })
	cfg := lifecycleConfig()
	cfg.UserRegistration = nil
	profile := accessProfileTestWant()
	profile.KeyIDs = []string{"current"}
	cfg.AuthenticationPortals[0].AccessSigner = "primary"
	cfg.AuthenticationPortals[0].AccessTokenProfile = profile.Clone()
	cfg.AuthenticationPortals[0].RawCryptoKeyStoreConfig = []string{keys.verifier("current")}
	cfg.AuthorizationPolicies[0].AccessTokenProfile = profile.Clone()
	cfg.AuthorizationPolicies[0].RawCryptoKeyStoreConfig = []string{keys.verifier("current")}
	return &App{Config: cfg, AccessSignerConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(&module, "driver", "lifecycle_test", nil)}}, probe
}
func assertLifecycleAccessSignerUsable(t *testing.T, probe *lifecycleAccessSignerProbe) {
	t.Helper()
	handle := probe.handle.Load()
	if handle == nil {
		t.Fatal("signer runtime missing")
	}
	metadata, err := handle.Metadata()
	if err != nil {
		t.Fatal("signer metadata unavailable")
	}
	now := time.Now().Unix()
	token, err := handle.Sign(t.Context(), map[string]any{"iss": metadata.Policy.Issuer, "aud": metadata.Policy.Audience, "sub": "alice", "iat": now, "nbf": now, "exp": now + 60})
	if err != nil || token == "" {
		t.Fatal("admitted runtime lost its signer")
	}
}

func TestAppAccessSignerLifecycleDrain(t *testing.T) {
	app, probe := newLifecycleAccessSignerApp(t)
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal("signer app did not construct", err)
	}
	probe.server.Store(app.server)
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) || probe.constructed.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("signer provision changed declaration or lifetime")
	}
	release, admitted := app.acquireRequest()
	if !admitted {
		t.Fatal("signer app refused active lease")
	}
	var releaseOnce sync.Once
	defer releaseOnce.Do(release)
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module cancellation closed borrowed signer")
	}
	assertLifecycleAccessSignerUsable(t, probe)
	done := make(chan struct{})
	var cleanupErr error
	go func() { cleanupErr = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("signer closed before request drain")
	}
	if _, err := app.server.GetPortalByName("portal"); err != nil {
		t.Fatal("root closed before admitted request drain")
	}
	if next, ok := app.acquireRequest(); ok {
		next()
		t.Fatal("retiring app admitted another lease")
	}
	assertLifecycleAccessSignerUsable(t, probe)
	select {
	case <-done:
		t.Fatal("cleanup completed with an outstanding lease")
	default:
	}
	releaseOnce.Do(release)
	awaitLifecycle(t, done, "signer app cleanup")
	if cleanupErr != nil || probe.closed.Load() != 1 || probe.closedBeforeRoot.Load() {
		t.Fatal("signer cleanup did not follow root disposal exactly once")
	}
	assertServerClosed(t, app)
	if app.Cleanup() != nil || probe.closed.Load() != 1 {
		t.Fatal("repeated app cleanup closed signer twice")
	}
	now := time.Now().Unix()
	metadata, err := probe.handle.Load().Metadata()
	if err != nil {
		t.Fatal("retired fixture metadata unavailable")
	}
	if token, err := probe.handle.Load().Sign(t.Context(), map[string]any{"iss": metadata.Policy.Issuer, "aud": metadata.Policy.Audience, "sub": "alice", "iat": now, "nbf": now, "exp": now + 60}); err == nil || token != "" {
		t.Fatal("retired wrapper accepted signing")
	}
}

func TestAppAccessSignerLifecycleRootRejection(t *testing.T) {
	app, probe := newLifecycleAccessSignerApp(t)
	// This is valid declarative key syntax. Only the actual root key constructor
	// can reject its absent file, after the real private signer was acquired.
	app.Config.AuthenticationPortals[0].RawCryptoKeyStoreConfig = []string{fmt.Sprintf("crypto key current verify from file %q", filepath.Join(t.TempDir(), "missing-public.pem"))}
	before, _ := json.Marshal(app)
	if _, err := credentialTestApp(t, app); err == nil {
		t.Fatal("invalid root trust was accepted")
	}
	if probe.constructed.Load() != 1 || probe.closed.Load() != 1 || probe.handle.Load() == nil || !probe.handle.Load().closed.Load() || app.server != nil || len(app.pluginClosers) != 0 {
		t.Fatal("root rejection leaked or published signer ownership")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("root failure mutated declarative signer input")
	}
	if app.Cleanup() != nil || probe.closed.Load() != 1 {
		t.Fatal("failed candidate cleanup closed signer twice")
	}
}

func TestAppAccessSignerLifecyclePersistentStart(t *testing.T) {
	app, probe := newLifecycleAccessSignerApp(t)
	dir := registrationTestDirectory(t)
	statePath := filepath.Join(dir, "state")
	usersPath := filepath.Join(dir, "users.json")
	app.Config.State = &state.Config{Directory: statePath}
	app.Config.IdentityStores[0].Params["path"] = usersPath
	before, _ := json.Marshal(app)
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("persistent signer declaration rejected", err)
	}
	if probe.constructed.Load() != 0 || app.server != nil || app.runtimeConfig == nil {
		t.Fatal("persistent Provision acquired signer or root")
	}
	for _, path := range []string{statePath, usersPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("persistent preparation created runtime storage")
		}
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("persistent preparation rewrote declaration")
	}
	// The deferred constructor must use its private factory and consumer copies.
	probe.module.KeyFile = filepath.Join(dir, "unchecked-private.pem")
	probe.module.Name = "changed"
	probe.module.Audience = "changed"
	app.AccessSignerConfigs[0] = json.RawMessage(`{"driver":"absent"}`)
	app.Config.AuthenticationPortals[0].AccessSigner = "changed"
	app.Config.AuthenticationPortals[0].AccessTokenProfile.Audience = "changed"
	if err := app.Start(); err != nil {
		t.Fatal("persistent signer Start did not use prepared inputs", err)
	}
	probe.server.Store(app.server)
	if probe.constructed.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("deferred Start lost signer ownership")
	}
	assertLifecycleAccessSignerUsable(t, probe)
	if err := app.Start(); err != nil || probe.constructed.Load() != 1 {
		t.Fatal("repeated Start constructed another signer")
	}
	firstCleanup, secondCleanup := app.Cleanup(), app.Cleanup()
	if firstCleanup != nil || secondCleanup != nil || probe.closed.Load() != 1 || probe.closedBeforeRoot.Load() {
		t.Fatal("persistent signer cleanup ordering or count changed")
	}
}

var _ AccessSignerBackendModule = (*lifecycleAccessSignerModule)(nil)
var _ AccessSignerFactory = (*lifecycleAccessSignerFactory)(nil)
var _ kms.AccessSigner = (*lifecycleAccessSigner)(nil)
