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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
)

// Keep the actual SQLite capability beneath the probe, including the optional
// WithRefreshIdentity transaction. Tests must not replace account verification.
type identityStoreTestModule struct {
	SQLiteIdentityStore
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *claimsTestState
}

func (identityStoreTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_stores.test", New: func() caddy.Module { return new(identityStoreTestModule) }}
}

func (m *identityStoreTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("identity probe not found")
	}
	m.probe = value.(*claimsTestState)
	return nil
}

func (m *identityStoreTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}

func (m *identityStoreTestModule) IdentityStoreConfig() (*ids.ExternalIdentityStoreConfig, error) {
	if m.Failure == "descriptor_error" {
		return nil, fmt.Errorf("private-sentinel")
	}
	if m.Failure == "descriptor_nil" {
		return nil, nil
	}
	config, err := m.SQLiteIdentityStore.IdentityStoreConfig()
	if err == nil && m.Failure == "descriptor_builtin" {
		config.Kind = "local"
	}
	return config, err
}

func (m *identityStoreTestModule) NewIdentityStore(ctx context.Context) (ids.IdentityStore, error) {
	m.probe.constructed.Add(1)
	if m.Failure == "nil" {
		return nil, nil
	}
	if m.Failure == "typed_nil" {
		return (*identityStoreTestBackend)(nil), nil
	}
	if m.Failure == "typed_nil_unsafe" {
		return (*identityStoreNilUnsafeBackend)(nil), nil
	}
	store, err := m.SQLiteIdentityStore.NewIdentityStore(ctx)
	if err != nil {
		return nil, err
	}
	backend := &identityStoreTestBackend{Store: store.(*identitysqlite.Store), probe: m.probe, failure: m.Failure}
	if m.Failure == "construct" {
		return backend, fmt.Errorf("private-sentinel")
	}
	return backend, nil
}

type identityStoreTestBackend struct {
	*identitysqlite.Store
	probe   *claimsTestState
	failure string
}

func (b *identityStoreTestBackend) Configured() bool {
	return b != nil && b.failure != "unconfigured" && b.Store.Configured()
}

func (b *identityStoreTestBackend) GetName() string {
	if b.failure == "name" {
		return "other"
	}
	return b.Store.GetName()
}

func (b *identityStoreTestBackend) GetRealm() string {
	if b.failure == "realm" {
		return "other"
	}
	return b.Store.GetRealm()
}

func (b *identityStoreTestBackend) GetKind() string {
	if b.failure == "kind" {
		return "local"
	}
	return b.Store.GetKind()
}

func (b *identityStoreTestBackend) Request(op operator.Type, request *requests.Request) error {
	if err := b.Store.Request(op, request); err != nil {
		return err
	}
	if op == operator.Authenticate {
		b.probe.lookups.Add(1)
		if b.failure == "revoke" {
			return b.Store.DisableUser(request.User.Username, request.User.Email)
		}
	}
	return nil
}

func (b *identityStoreTestBackend) Close() error {
	// A typed nil plugin is rejected by root binding validation. Its optional
	// closer must still be safe during the host's candidate-unwind sequence.
	if b == nil {
		return nil
	}
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.Store.Close()
	if b.failure == "close_panic" {
		panic("private-sentinel")
	}
	if b.failure == "close" {
		return fmt.Errorf("private-sentinel")
	}
	return err
}

// Deliberately violate the factory contract. Neither promoted readiness methods
// nor Close can be called on this typed nil, as in an ordinary embedded wrapper.
type identityStoreNilUnsafeBackend struct{ *identitysqlite.Store }

func (b *identityStoreNilUnsafeBackend) Close() error { return b.Store.Close() }

type identityStoreWrongModule struct{}

func (identityStoreWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_stores.test_wrong", New: func() caddy.Module { return new(identityStoreWrongModule) }}
}

func init() {
	caddy.RegisterModule(identityStoreTestModule{})
	caddy.RegisterModule(identityStoreWrongModule{})
}

func identityStoreTestConfig() *authcrunch.Config {
	config := lifecycleConfig()
	config.UserRegistration = nil
	config.IdentityStores = nil
	config.AuthenticationPortals[0].IdentityStores = []string{"accounts"}
	return config
}

func identityStoreTestBinding(t *testing.T, failure string) (json.RawMessage, *claimsTestState) {
	t.Helper()
	config := sqliteIdentityTestConfig(t)
	sqliteIdentityTestProvision(t, config)
	probe := new(claimsTestState)
	label := t.Name() + config.Path
	claimsTestStates.Store(label, probe)
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	var raw map[string]any
	if err := json.Unmarshal(sqliteIdentityTestRaw(t, config), &raw); err != nil {
		t.Fatal(err)
	}
	raw["driver"], raw["label"], raw["failure"] = "test", label, failure
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return data, probe
}

func identityStoreBasicRequest(t *testing.T, app *App, portal string) *httptest.ResponseRecorder {
	t.Helper()
	runtime, err := app.getPortal(portal)
	if err != nil {
		t.Fatal(err)
	}
	handler := &AuthnMiddleware{app: app, portal: runtime, PortalName: portal}
	request := httptest.NewRequest(http.MethodGet, "https://identity.example.test/auth/basic/login/staff", nil)
	request.SetBasicAuth("alice", lifecyclePassword)
	response := httptest.NewRecorder()
	if err := handler.ServeHTTP(response, request, nil); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAppIdentityStoreBindings(t *testing.T) {
	for _, kind := range []string{"duplicate", "builtin_collision", "realm_collision", "unknown_reference", "descriptor_error", "descriptor_nil", "descriptor_builtin", "native_descriptor", "null", "unknown", "wrong_interface", "unknown_field"} {
		t.Run(kind, func(t *testing.T) {
			failure := ""
			if strings.HasPrefix(kind, "descriptor_") {
				failure = kind
			}
			raw, probe := identityStoreTestBinding(t, failure)
			app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
			switch kind {
			case "duplicate":
				app.IdentityStoreConfigs = append(app.IdentityStoreConfigs, raw)
			case "builtin_collision":
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
				app.Config.IdentityStores[0].Name = "accounts"
			case "realm_collision":
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
				app.Config.IdentityStores[0].Params["realm"] = "staff"
				app.Config.AuthenticationPortals[0].IdentityStores = append(app.Config.AuthenticationPortals[0].IdentityStores, "local")
			case "unknown_reference":
				app.Config.AuthenticationPortals[0].IdentityStores = []string{"missing"}
			case "native_descriptor":
				app.Config.ExternalIdentityStores = []*ids.ExternalIdentityStoreConfig{{Name: "untrusted", Kind: "sqlite", Realm: "staff", ConfigDigest: strings.Repeat("0", 64)}}
			case "null":
				app.IdentityStoreConfigs[0] = json.RawMessage(`null`)
			case "unknown":
				app.IdentityStoreConfigs[0] = json.RawMessage(`{"driver":"unknown"}`)
			case "wrong_interface":
				app.IdentityStoreConfigs[0] = json.RawMessage(`{"driver":"test_wrong"}`)
			case "unknown_field":
				app.IdentityStoreConfigs[0] = json.RawMessage(`{"driver":"sqlite","private-sentinel":true}`)
			}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid binding accepted or private diagnostic disclosed", err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("failed candidate mutated the declarative configuration")
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("invalid declaration reached runtime construction")
			}
		})
	}
}

func TestAppIdentityStoreSnapshotsAndDrain(t *testing.T) {
	raw, probe := identityStoreTestBinding(t, "")
	app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
	second := *app.Config.AuthenticationPortals[0]
	second.Name = "second"
	app.Config.AuthenticationPortals = append(app.Config.AuthenticationPortals, &second)
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) || len(app.Config.ExternalIdentityStores) != 0 {
		t.Fatal("runtime preparation mutated its serializable declaration")
	}
	if len(app.identityStores) != 1 || probe.constructed.Load() != 1 {
		t.Fatal("portals did not share a single app-owned backend")
	}
	for _, name := range []string{"portal", "second"} {
		if response := identityStoreBasicRequest(t, app, name); response.Code != http.StatusSeeOther || response.Header().Get("Authorization") == "" {
			t.Fatalf("selected portal %s could not authenticate with the shared store: HTTP %d", name, response.Code)
		}
	}
	if probe.lookups.Load() != 2 {
		t.Fatal("one portal bypassed the shared backend")
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("runtime admission closed unexpectedly")
	}
	var once sync.Once
	defer once.Do(release)
	probe.onClose = func() {
		if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("host closed the borrowed backend before root disposal")
		}
	}
	cancel()
	if response := identityStoreBasicRequest(t, app, "portal"); response.Code != http.StatusSeeOther {
		t.Fatal("module cancellation closed an admitted runtime")
	}
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("Caddy module cleanup disposed a borrowed runtime handle")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("backend closed before admitted requests drained")
	}
	once.Do(release)
	awaitLifecycle(t, done, "identity store cleanup")
	_ = app.Cleanup()
	if probe.closed.Load() != 1 {
		t.Fatal("backend not closed exactly once")
	}
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal(err)
	}
	if response := identityStoreBasicRequest(t, &restored, "second"); response.Code != http.StatusSeeOther || probe.constructed.Load() != 2 {
		t.Fatal("JSON restoration did not bind a fresh usable backend")
	}
}

func TestAppIdentityStoreFailedCandidates(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_unsafe", "construct", "name", "realm", "kind", "unconfigured", "root", "claims", "external"} {
		t.Run(failure, func(t *testing.T) {
			factoryFailure := failure
			if failure == "root" || failure == "claims" || failure == "external" {
				factoryFailure = ""
			}
			raw, probe := identityStoreTestBinding(t, factoryFailure)
			app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
			var order []int
			probe.onClose = func() { order = append(order, 1) }
			switch failure {
			case "root":
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
			case "claims":
				binding, second := claimsTestBinding(t, t.Name(), "construct")
				second.onClose = func() { order = append(order, 2) }
				app.ClaimsEnrichment = []*ClaimsEnrichmentBinding{binding}
			case "external":
				binding, second := externalTestBinding(t, "construct")
				second.onClose = func() { order = append(order, 2) }
				app.ExternalAuthorization = []*ExternalAuthorizationBinding{binding}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("bad candidate accepted or disclosed private diagnostics", err)
			}
			if app.server != nil || len(app.pluginClosers) != 0 {
				t.Fatal("failed candidate published runtime ownership")
			}
			_ = app.Cleanup()
			wantClosed := int64(1)
			if failure == "nil" || failure == "typed_nil" || failure == "typed_nil_unsafe" {
				wantClosed = 0
			}
			if probe.constructed.Load() != 1 || probe.closed.Load() != wantClosed {
				t.Fatalf("candidate leaked or double-closed resources: constructed=%d closed=%d", probe.constructed.Load(), probe.closed.Load())
			}
			if (failure == "claims" || failure == "external") && !slices.Equal(order, []int{2, 1}) {
				t.Fatal("failed runtime disposed resources in the wrong order", order)
			}
		})
	}
}

func TestAppIdentityStorePersistentStart(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("factory="+failure, func(t *testing.T) {
			raw, probe := identityStoreTestBinding(t, failure)
			app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
			app.Config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("persistent Provision opened an account store")
			}
			if _, err := os.Stat(app.Config.State.Directory); !os.IsNotExist(err) {
				t.Fatal("Provision created persistent state")
			}
			err := app.Start()
			if (err != nil) != (failure != "") || probe.constructed.Load() != 1 {
				t.Fatal("Start lost or ignored the prepared store binding", err)
			}
			if err == nil {
				if response := identityStoreBasicRequest(t, app, "portal"); response.Code != http.StatusSeeOther {
					t.Fatal("started persistent root could not authenticate")
				}
			} else if app.server != nil {
				t.Fatal("failed Start published the runtime")
			}
			if err := app.Cleanup(); err != nil {
				t.Fatal(err)
			}
			if probe.closed.Load() != 1 {
				t.Fatal("persistent candidate leaked its backend")
			}
		})
	}
}

func TestAppIdentityStorePartialBatchCleanup(t *testing.T) {
	firstRaw, first := identityStoreTestBinding(t, "")
	secondRaw, second := identityStoreTestBinding(t, "construct")
	var secondConfig map[string]any
	if err := json.Unmarshal(secondRaw, &secondConfig); err != nil {
		t.Fatal(err)
	}
	secondConfig["name"], secondConfig["realm"] = "second", "guests"
	secondRaw, err := json.Marshal(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	var order []int
	first.onClose = func() { order = append(order, 1) }
	second.onClose = func() { order = append(order, 2) }
	app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{firstRaw, secondRaw}}
	app.Config.AuthenticationPortals[0].IdentityStores = append(app.Config.AuthenticationPortals[0].IdentityStores, "second")
	if _, err := credentialTestApp(t, app); err == nil || strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("partially acquired batch was accepted or disclosed diagnostics", err)
	}
	if app.server != nil || !slices.Equal(order, []int{2, 1}) || first.closed.Load() != 1 || second.closed.Load() != 1 {
		t.Fatal("failed batch did not unwind every acquired handle in reverse order", order)
	}
	_ = app.Cleanup()
	if first.closed.Load() != 1 || second.closed.Load() != 1 {
		t.Fatal("candidate cleanup repeated partial batch disposal")
	}
}

func TestAppIdentityStoreCleanupPanicContinues(t *testing.T) {
	var rawStores []json.RawMessage
	var probes []*claimsTestState
	var order []int
	for i, entry := range []struct{ name, realm, failure string }{
		{"accounts", "staff", ""},
		{"second", "guests", "close_panic"},
		{"third", "contractors", "typed_nil_unsafe"},
	} {
		raw, probe := identityStoreTestBinding(t, entry.failure)
		var config map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		config["name"], config["realm"] = entry.name, entry.realm
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		probe.onClose = func() { order = append(order, i) }
		rawStores = append(rawStores, raw)
		probes = append(probes, probe)
	}
	app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: rawStores}
	app.Config.AuthenticationPortals[0].IdentityStores = []string{"accounts", "second", "third"}
	_, err := credentialTestApp(t, app)
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") || strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("invalid plugin cleanup was not reported with a sanitized error", err)
	}
	if app.server != nil || !slices.Equal(order, []int{1, 0}) {
		t.Fatal("cleanup panic prevented reverse-order disposal of earlier stores", order)
	}
	for i, probe := range probes {
		wantClosed := int64(1)
		if i == 2 {
			wantClosed = 0 // The typed nil never acquired a database.
		}
		if probe.constructed.Load() != 1 || probe.closed.Load() != wantClosed {
			t.Fatalf("plugin %d ownership lost after another plugin's panic", i)
		}
	}
	_ = app.Cleanup()
	if !slices.Equal(order, []int{1, 0}) {
		t.Fatal("repeated candidate cleanup repeated backend disposal")
	}
}

func TestAppIdentityStoreFailedReplacementPreservesServing(t *testing.T) {
	raw, probe := identityStoreTestBinding(t, "")
	active := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
	if _, err := credentialTestApp(t, active); err != nil {
		t.Fatal(err)
	}
	var candidate App
	data, _ := json.Marshal(active)
	if err := json.Unmarshal(data, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
	if _, err := credentialTestApp(t, &candidate); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if probe.constructed.Load() != 2 || probe.closed.Load() != 1 {
		t.Fatal("replacement did not dispose only its own fresh handle")
	}
	if response := identityStoreBasicRequest(t, active, "portal"); response.Code != http.StatusSeeOther || response.Header().Get("Authorization") == "" {
		t.Fatal("failed replacement damaged the serving account store")
	}
}

func TestAppIdentityStoreRechecksBeforeSigning(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("revoke=%v", revoke), func(t *testing.T) {
			failure := ""
			if revoke {
				failure = "revoke"
			}
			raw, probe := identityStoreTestBinding(t, failure)
			app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			response := identityStoreBasicRequest(t, app, "portal")
			if probe.lookups.Load() != 1 {
				t.Fatal("request did not complete real SQLite password authentication")
			}
			if !revoke {
				if response.Code != http.StatusSeeOther || response.Header().Get("Authorization") == "" {
					t.Fatal("positive control failed to issue a credential")
				}
				return
			}
			if response.Code != http.StatusUnauthorized || response.Header().Get("Authorization") != "" {
				t.Fatal("Caddy handler signed after committed account disablement")
			}
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name != "AUTHP_SESSION_ID" && cookie.Value != "" && cookie.MaxAge >= 0 {
					t.Fatal("rejected issuance published an authenticated cookie")
				}
			}
		})
	}
}

func TestAppIdentityStoreCloseFailure(t *testing.T) {
	raw, probe := identityStoreTestBinding(t, "close")
	app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{raw}}
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	err := app.Cleanup()
	if err == nil || strings.Contains(err.Error(), "private-sentinel") {
		t.Fatal("cleanup lost the error or disclosed backend diagnostics", err)
	}
	if err != app.Cleanup() || probe.closed.Load() != 1 {
		t.Fatal("repeated cleanup changed the result or closed the backend twice")
	}
}
