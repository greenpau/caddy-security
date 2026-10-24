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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func credentialTestConfig() *authcrunch.Config {
	cfg := &authcrunch.Config{AuthorizationPolicies: lifecycleConfig().AuthorizationPolicies}
	cfg.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm staff portal keys"}
	return cfg
}
func credentialTestApp(t *testing.T, app *App) (context.CancelFunc, error) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = app.Cleanup() })
	return cancel, app.Provision(ctx)
}

// The real SQLite backend remains underneath this factory. The probe observes
// ownership without adding a second authentication implementation.
type credentialTestModule struct {
	SQLiteCredentialAuthenticator
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *claimsTestState
}

func (credentialTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.credential_authenticators.test", New: func() caddy.Module { return new(credentialTestModule) }}
}
func (m *credentialTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("missing probe")
	}
	m.probe = value.(*claimsTestState)
	return nil
}
func (m *credentialTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}
func (m *credentialTestModule) NewCredentialAuthenticator(ctx context.Context) (CredentialAuthenticator, error) {
	m.probe.constructed.Add(1)
	if m.Failure == "nil" {
		return nil, nil
	}
	b, err := m.SQLiteCredentialAuthenticator.NewCredentialAuthenticator(ctx)
	if err != nil {
		return nil, err
	}
	wrapped := &credentialTestBackend{CredentialAuthenticator: b, probe: m.probe, failure: m.Failure}
	if m.Failure == "construct" {
		return wrapped, fmt.Errorf("private-sentinel")
	}
	return wrapped, nil
}

type credentialTestBackend struct {
	CredentialAuthenticator
	probe   *claimsTestState
	failure string
}

func (b *credentialTestBackend) Close() error {
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.CredentialAuthenticator.Close()
	if b.failure == "close" {
		return fmt.Errorf("private-sentinel")
	}
	return err
}
func (b *credentialTestBackend) RequireFreshAuthentication() bool { return b.failure != "stale" }
func (b *credentialTestBackend) GetName() string {
	if b.failure == "identity" {
		return "wrong"
	}
	return b.CredentialAuthenticator.GetName()
}

type credentialWrongModule struct{}

func (credentialWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.credential_authenticators.test_wrong", New: func() caddy.Module { return new(credentialWrongModule) }}
}
func init() {
	caddy.RegisterModule(credentialTestModule{})
	caddy.RegisterModule(credentialWrongModule{})
}
func credentialTestBinding(t *testing.T, failure string) (json.RawMessage, *claimsTestState, string) {
	t.Helper()
	cfg := sqliteCredentialsConfig(t)
	key := sqliteCredentialsIssue(t, cfg)
	probe := new(claimsTestState)
	label := t.Name() + cfg.Path
	claimsTestStates.Store(label, probe)
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	var doc map[string]any
	_ = json.Unmarshal(sqliteCredentialsRaw(t, cfg), &doc)
	doc["driver"] = "test"
	doc["label"] = label
	doc["failure"] = failure
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw, probe, key
}
func TestAppCredentialBindings(t *testing.T) {
	for _, kind := range []string{"duplicate", "portal_collision", "basic", "mixed_basic", "realm", "unused", "overwritten", "duplicate_statement", "remote_name", "null", "unknown", "wrong_interface", "unknown_field"} {
		t.Run(kind, func(t *testing.T) {
			raw, probe, _ := credentialTestBinding(t, "")
			app := &App{Config: credentialTestConfig(), CredentialAuthenticatorConfigs: []json.RawMessage{raw}}
			p := app.Config.AuthorizationPolicies[0]
			switch kind {
			case "duplicate":
				app.CredentialAuthenticatorConfigs = append(app.CredentialAuthenticatorConfigs, raw)
			case "portal_collision":
				app.Config.AuthenticationPortals = lifecycleConfig().AuthenticationPortals
				app.Config.AuthenticationPortals[0].Name = "keys"
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
			case "basic":
				p.AuthProxyRawConfig = []string{"basic auth realm staff portal keys"}
			case "mixed_basic":
				p.AuthProxyRawConfig = append(p.AuthProxyRawConfig, "basic auth realm staff portal keys")
			case "realm":
				p.AuthProxyRawConfig = []string{"api key auth realm guests portal keys"}
			case "unused":
				p.AuthProxyRawConfig = nil
			case "overwritten":
				p.AuthProxyRawConfig = append(p.AuthProxyRawConfig, "api key auth realm staff portal other")
			case "duplicate_statement":
				p.AuthProxyRawConfig = append(p.AuthProxyRawConfig, p.AuthProxyRawConfig[0])
			case "remote_name":
				app.CredentialAuthenticatorConfigs[0] = json.RawMessage(strings.Replace(string(raw), `"name":"keys"`, `"name":"https://remote"`, 1))
			case "null":
				app.CredentialAuthenticatorConfigs[0] = json.RawMessage(`null`)
			case "unknown":
				app.CredentialAuthenticatorConfigs[0] = json.RawMessage(`{"driver":"unknown"}`)
			case "wrong_interface":
				app.CredentialAuthenticatorConfigs[0] = json.RawMessage(`{"driver":"test_wrong"}`)
			case "unknown_field":
				app.CredentialAuthenticatorConfigs[0] = json.RawMessage(`{"driver":"sqlite","private-sentinel":true}`)
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("bad binding accepted/disclosed", err)
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("invalid binding reached construction")
			}
		})
	}
}
func TestAppCredentialSnapshotsAndDrain(t *testing.T) {
	raw, probe, key := credentialTestBinding(t, "")
	app := &App{Config: credentialTestConfig(), CredentialAuthenticatorConfigs: []json.RawMessage{raw}}
	second := *app.Config.AuthorizationPolicies[0]
	second.Name = "second"
	app.Config.AuthorizationPolicies = append(app.Config.AuthorizationPolicies, &second)
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) {
		t.Fatal("declaration mutated")
	}
	if len(app.credentialAuthenticators) != 1 || len(app.credentialAuthenticators[0].policies) != 2 || probe.constructed.Load() != 1 {
		t.Fatal("backend not shared within app")
	}
	var backend authproxy.Authenticator
	for _, p := range app.credentialAuthenticators[0].policies {
		b, err := p.AuthProxyConfig.GetAuthenticator("staff")
		if err != nil || b == nil {
			t.Fatal("binding lost during root validation")
		}
		if backend != nil && backend != b {
			t.Fatal("policies got independent backends")
		}
		backend = b
	}
	if err := backend.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: key}); err != nil {
		t.Fatal(err)
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("runtime not admitted")
	}
	var once sync.Once
	defer once.Do(release)
	probe.onClose = func() {
		if _, err := app.server.GetGatekeeperByName("policy"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("backend closed before root")
		}
	}
	cancel()
	if err := backend.APIKeyAuth(&authproxy.Request{Realm: "staff", Secret: key}); err != nil {
		t.Fatal("module cancellation disabled a live backend", err)
	}
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("Caddy cleanup closed runtime")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("closed before drain")
	}
	once.Do(release)
	awaitLifecycle(t, done, "credential cleanup")
	_ = app.Cleanup()
	if probe.closed.Load() != 1 {
		t.Fatal("backend not closed exactly once")
	}
	// Fresh JSON decoding must restore bindings; handles are never serialized.
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal(err)
	}
	if probe.constructed.Load() != 2 {
		t.Fatal("new candidate reused runtime")
	}
}
func TestAppCredentialFailedCandidates(t *testing.T) {
	for _, failure := range []string{"nil", "construct", "identity", "stale", "root", "claims", "external"} {
		t.Run(failure, func(t *testing.T) {
			factoryFailure := failure
			if failure == "root" || failure == "claims" || failure == "external" {
				factoryFailure = ""
			}
			raw, probe, _ := credentialTestBinding(t, factoryFailure)
			app := &App{Config: credentialTestConfig(), CredentialAuthenticatorConfigs: []json.RawMessage{raw}}
			var order []int
			probe.onClose = func() { order = append(order, 1) }
			if failure == "construct" {
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
				app.Config.IdentityStores[0].Params["path"] = filepath.Join(t.TempDir(), "users.json")
				probe.onClose = func() {
					order = append(order, 1)
					files, err := reserveIdentityFiles(app.Config)
					if err == nil {
						releaseIdentityFiles(files)
						t.Error("identity reservation released before partial backend disposal")
					}
				}
			}
			if failure == "root" {
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = append(app.Config.AuthorizationPolicies[0].AuthProxyRawConfig, "api key auth realm other portal missing")
			}
			if failure == "claims" {
				binding, p := claimsTestBinding(t, t.Name(), "construct")
				p.onClose = func() { order = append(order, 2) }
				app.ClaimsEnrichment = []*ClaimsEnrichmentBinding{binding}
			}
			if failure == "external" {
				binding, p := externalTestBinding(t, "construct")
				p.onClose = func() { order = append(order, 2) }
				app.ExternalAuthorization = []*ExternalAuthorizationBinding{binding}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("missing/private construction failure", err)
			}
			if app.server != nil || len(app.pluginClosers) != 0 {
				t.Fatal("failed candidate published")
			}
			_ = app.Cleanup()
			want := int64(1)
			if failure == "nil" {
				want = 0
			}
			if probe.closed.Load() != want {
				t.Fatal("resource leaked/double closed", probe.closed.Load())
			}
			if (failure == "claims" || failure == "external") && !slices.Equal(order, []int{2, 1}) {
				t.Fatal("wrong unwind order", order)
			}
		})
	}
}
func TestAppCredentialPersistentStart(t *testing.T) {
	raw, probe, _ := credentialTestBinding(t, "")
	app := &App{Config: credentialTestConfig(), CredentialAuthenticatorConfigs: []json.RawMessage{raw}}
	app.Config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	if probe.constructed.Load() != 0 || app.server != nil {
		t.Fatal("persistent Provision opened credentials")
	}
	if _, err := os.Stat(app.Config.State.Directory); !os.IsNotExist(err) {
		t.Fatal("Provision created state")
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	if probe.constructed.Load() != 1 {
		t.Fatal("Start lost prepared binding")
	}
	if err := app.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if probe.closed.Load() != 1 {
		t.Fatal("Start resource leaked")
	}
}
