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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/state"
	storage "github.com/greenpau/go-authcrunch/plugins/oauth-login-storage/sqlite"
)

// This module wraps the real public SQLite store. The probe observes only the
// host factory/ownership boundary; it does not emulate transaction semantics.
type oauthLoginTestModule struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Timeout  string `json:"timeout,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
	Label    string `json:"label"`
	Failure  string `json:"failure,omitempty"`
	probe    *oauthLoginTestProbe
}

type oauthLoginTestProbe struct {
	claimsTestState
	module      *oauthLoginTestModule
	mu          sync.Mutex
	backends    []*oauthLoginTestBackend
	namespace   string
	transaction oauth.LoginTransaction
}

var oauthLoginTestProbes sync.Map

func (oauthLoginTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.oauth_login_stores.app_test", New: func() caddy.Module { return new(oauthLoginTestModule) }}
}

func (m *oauthLoginTestModule) Provision(caddy.Context) error {
	value, ok := oauthLoginTestProbes.Load(m.Label)
	if !ok {
		return fmt.Errorf("OAuth login probe unavailable")
	}
	m.probe = value.(*oauthLoginTestProbe)
	m.probe.module = m
	return nil
}

func (m *oauthLoginTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}

func (m *oauthLoginTestModule) PrepareOAuthLoginStore() (OAuthLoginStoreFactory, error) {
	switch m.Failure {
	case "prepare_error":
		return nil, fmt.Errorf("private-oauth-store-diagnostic")
	case "prepare_panic":
		panic("private-oauth-store-diagnostic")
	case "prepare_nil":
		return nil, nil
	case "prepare_typed_nil":
		return (*oauthLoginTestFactory)(nil), nil
	}
	config := storage.Config{Path: m.Path, Timeout: m.Timeout, Capacity: m.Capacity}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	duration, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, err
	}
	config.Timeout = duration.String()
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	descriptor := OAuthLoginStoreConfig{Name: m.Name, Driver: "app_test", ConfigHash: hex.EncodeToString(digest[:])}
	return &oauthLoginTestFactory{config: config, descriptor: descriptor, failure: m.Failure, probe: m.probe}, nil
}

type oauthLoginTestFactory struct {
	config     storage.Config
	descriptor OAuthLoginStoreConfig
	failure    string
	probe      *oauthLoginTestProbe
}

func (f *oauthLoginTestFactory) OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error) {
	switch f.failure {
	case "descriptor_error":
		return OAuthLoginStoreConfig{}, fmt.Errorf("private-oauth-store-diagnostic")
	case "descriptor_panic":
		panic("private-oauth-store-diagnostic")
	case "descriptor_name":
		copy := f.descriptor
		copy.Name = " invalid"
		return copy, nil
	case "descriptor_hash":
		copy := f.descriptor
		copy.ConfigHash = strings.Repeat("A", 64)
		return copy, nil
	}
	return f.descriptor, nil
}

func (f *oauthLoginTestFactory) NewOAuthLoginStore(ctx context.Context) (OAuthLoginStore, error) {
	f.probe.constructed.Add(1)
	switch f.failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*oauthLoginTestBackend)(nil), nil
	case "typed_nil_unsafe":
		return (*oauthLoginNilUnsafeBackend)(nil), nil
	case "typed_nil_unsafe_error":
		return (*oauthLoginNilUnsafeBackend)(nil), fmt.Errorf("private-oauth-store-diagnostic")
	case "resource_free":
		return &oauthLoginMemoryBackend{MemoryLoginStore: oauth.NewMemoryLoginStore(), config: f.descriptor}, nil
	}
	store, err := storage.New(ctx, &f.config)
	if err != nil {
		return nil, err
	}
	backend := &oauthLoginTestBackend{Store: store, config: f.descriptor, failure: f.failure, probe: f.probe}
	f.probe.mu.Lock()
	f.probe.backends = append(f.probe.backends, backend)
	f.probe.mu.Unlock()
	if f.failure == "construct" {
		return backend, fmt.Errorf("private-oauth-store-diagnostic")
	}
	return backend, nil
}

type oauthLoginTestBackend struct {
	*storage.Store
	config  OAuthLoginStoreConfig
	failure string
	probe   *oauthLoginTestProbe
	closed  atomic.Bool
}

func (b *oauthLoginTestBackend) OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error) {
	if b == nil || b.closed.Load() || b.failure == "unready" || b.failure == "metadata_error" {
		return OAuthLoginStoreConfig{}, fmt.Errorf("private-oauth-store-diagnostic")
	}
	copy := b.config
	switch b.failure {
	case "metadata_panic":
		panic("private-oauth-store-diagnostic")
	case "name":
		copy.Name = "wrong"
	case "driver":
		copy.Driver = "wrong"
	case "hash":
		copy.ConfigHash = strings.Repeat("0", 64)
	}
	return copy, nil
}

func (b *oauthLoginTestBackend) Create(ctx context.Context, namespace string, tx oauth.LoginTransaction) error {
	b.probe.lookups.Add(1)
	if hold := b.probe.hold.Load(); hold != nil {
		hold.once.Do(func() { close(hold.entered) })
		select {
		case <-hold.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := b.Store.Create(ctx, namespace, tx); err != nil {
		return err
	}
	b.probe.mu.Lock()
	b.probe.namespace, b.probe.transaction = namespace, tx
	b.probe.mu.Unlock()
	return nil
}

func (b *oauthLoginTestBackend) Close() error {
	if b == nil {
		return nil
	}
	b.closed.Store(true)
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.Store.Close()
	switch b.failure {
	case "close_error":
		return fmt.Errorf("private-oauth-store-diagnostic")
	case "close_panic":
		panic("private-oauth-store-diagnostic")
	}
	return err
}

// Promoted metadata and Close deliberately panic on this typed nil. Recovery
// must still unwind earlier real resources and suppress the plugin's details.
type oauthLoginNilUnsafeBackend struct{ *oauthLoginTestBackend }

// A custom memory store may legitimately own no closable resources. It must
// still attest the exact prepared descriptor; optional Close is not readiness.
type oauthLoginMemoryBackend struct {
	*oauth.MemoryLoginStore
	config OAuthLoginStoreConfig
}

func (b *oauthLoginMemoryBackend) OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error) {
	return b.config, nil
}

type oauthLoginWrongModule struct{}

func (oauthLoginWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.oauth_login_stores.app_wrong", New: func() caddy.Module { return new(oauthLoginWrongModule) }}
}

func init() {
	caddy.RegisterModule(oauthLoginTestModule{})
	caddy.RegisterModule(oauthLoginWrongModule{})
}

var (
	_ OAuthLoginStoreBackendModule = (*oauthLoginTestModule)(nil)
	_ OAuthLoginStoreFactory       = (*oauthLoginTestFactory)(nil)
	_ OAuthLoginStore              = (*oauthLoginTestBackend)(nil)
)

func oauthLoginTestBinding(t *testing.T, name, path, failure string) (json.RawMessage, *oauthLoginTestProbe) {
	t.Helper()
	probe := new(oauthLoginTestProbe)
	label := t.Name() + "/" + name
	if _, exists := oauthLoginTestProbes.LoadOrStore(label, probe); exists {
		t.Fatal("duplicate OAuth login probe")
	}
	t.Cleanup(func() { oauthLoginTestProbes.Delete(label) })
	module := &oauthLoginTestModule{Name: name, Path: path, Label: label, Failure: failure}
	return caddyconfig.JSONModuleObject(module, "driver", "app_test", nil), probe
}

func oauthLoginTestApp(t *testing.T, failure string) (*App, string, *oauthLoginTestProbe) {
	t.Helper()
	config := providerRefreshAppConfig()
	config.IdentityStores = nil
	config.AuthenticationPortals[0].IdentityStores = nil
	config.AuthenticationPortals[0].RefreshTokens = nil
	config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "shared", "namespace": "deployment"}
	path := filepath.Join(registrationTestDirectory(t), "oauth.db")
	raw, probe := oauthLoginTestBinding(t, "shared", path, failure)
	return &App{Config: config, OAuthLoginStoreConfigs: []json.RawMessage{raw}}, path, probe
}

func oauthLoginTestRequest(app *App) (*httptest.ResponseRecorder, error) {
	return oauthLoginTestRequestRealm(app, "upstream")
}

func oauthLoginTestRequestRealm(app *App, realm string) (*httptest.ResponseRecorder, error) {
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.test/auth/oauth2/"+realm, nil)
	request.RequestURI = request.URL.RequestURI()
	mount := "/auth"
	handler := &AuthnMiddleware{app: app, PortalName: "portal", BasePath: &mount}
	response := httptest.NewRecorder()
	return response, handler.ServeHTTP(response, request, nil)
}

func oauthLoginTestBegin(t *testing.T, app *App, probe *oauthLoginTestProbe) (string, oauth.LoginTransaction) {
	t.Helper()
	response, err := oauthLoginTestRequest(app)
	if err != nil || response.Code != http.StatusFound {
		t.Fatal("Caddy handler did not initiate a stored OAuth transaction")
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Host != "issuer.example.test" || location.Query().Get("state") == "" {
		t.Fatal("OAuth initiation lost its trusted provider destination")
	}
	probe.mu.Lock()
	namespace, tx := probe.namespace, probe.transaction
	probe.mu.Unlock()
	if namespace == "" || tx.State != location.Query().Get("state") || tx.Binding.Callback != "https://portal.example.test/auth/oauth2/upstream/authorization-code-callback" {
		t.Fatal("root did not use its injected pending-login backend")
	}
	return namespace, tx
}

func TestAppOAuthLoginStoreReferenceParameters(t *testing.T) {
	valid := oauth.LoginStoreConfig{Name: "shared", Namespace: "deployment"}
	invalidUTF8 := "private-reference-" + string([]byte{0xff})
	for _, tc := range []struct {
		name   string
		params map[string]any
		valid  bool
	}{
		{name: "omitted", valid: true},
		{name: "unrelated", params: map[string]any{"client_id": "application"}, valid: true},
		{name: "typed", params: map[string]any{"login_store": valid}, valid: true},
		{name: "typed_pointer", params: map[string]any{"login_store": &valid}, valid: true},
		{name: "native", params: map[string]any{"login_store": map[string]any{"name": valid.Name, "namespace": valid.Namespace}}, valid: true},
		{name: "string_map", params: map[string]any{"login_store": map[string]string{"name": valid.Name, "namespace": valid.Namespace}}, valid: true},
		{name: "literal_replacement_character", params: map[string]any{"login_store": oauth.LoginStoreConfig{Name: "shared\ufffd", Namespace: "deployment\ufffd"}}, valid: true},
		{name: "null", params: map[string]any{"login_store": nil}},
		{name: "typed_nil", params: map[string]any{"login_store": (*oauth.LoginStoreConfig)(nil)}},
		{name: "nil_native_map", params: map[string]any{"login_store": (map[string]any)(nil)}},
		{name: "nil_string_map", params: map[string]any{"login_store": (map[string]string)(nil)}},
		{name: "empty_typed", params: map[string]any{"login_store": oauth.LoginStoreConfig{}}},
		{name: "empty_native", params: map[string]any{"login_store": map[string]any{}}},
		{name: "partial_typed", params: map[string]any{"login_store": oauth.LoginStoreConfig{Name: valid.Name}}},
		{name: "partial_native", params: map[string]any{"login_store": map[string]any{"namespace": valid.Namespace}}},
		{name: "empty_name", params: map[string]any{"login_store": map[string]string{"name": "", "namespace": valid.Namespace}}},
		{name: "empty_namespace", params: map[string]any{"login_store": map[string]any{"name": valid.Name, "namespace": ""}}},
		{name: "wrong_name_type", params: map[string]any{"login_store": map[string]any{"name": 1, "namespace": valid.Namespace}}},
		{name: "wrong_namespace_type", params: map[string]any{"login_store": map[string]any{"name": valid.Name, "namespace": true}}},
		{name: "array", params: map[string]any{"login_store": []string{valid.Name, valid.Namespace}}},
		{name: "json_string", params: map[string]any{"login_store": `{"name":"shared","namespace":"deployment"}`}},
		{name: "utf8_typed_name", params: map[string]any{"login_store": oauth.LoginStoreConfig{Name: invalidUTF8, Namespace: valid.Namespace}}},
		{name: "utf8_pointer_namespace", params: map[string]any{"login_store": &oauth.LoginStoreConfig{Name: valid.Name, Namespace: invalidUTF8}}},
		{name: "utf8_native_name", params: map[string]any{"login_store": map[string]any{"name": invalidUTF8, "namespace": valid.Namespace}}},
		{name: "utf8_native_namespace", params: map[string]any{"login_store": map[string]any{"name": valid.Name, "namespace": invalidUTF8}}},
		{name: "utf8_string_name", params: map[string]any{"login_store": map[string]string{"name": invalidUTF8, "namespace": valid.Namespace}}},
		{name: "utf8_string_namespace", params: map[string]any{"login_store": map[string]string{"name": valid.Name, "namespace": invalidUTF8}}},
		{name: "whitespace", params: map[string]any{"login_store": oauth.LoginStoreConfig{Name: " shared", Namespace: valid.Namespace}}},
		{name: "control", params: map[string]any{"login_store": oauth.LoginStoreConfig{Name: valid.Name, Namespace: "private-reference-\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOAuthLoginStoreParameters(tc.params)
			if (err == nil) != tc.valid {
				t.Fatal("reference validation did not preserve explicit selection semantics")
			}
			if err != nil && strings.Contains(err.Error(), "private-reference-") {
				t.Fatal("reference validation disclosed supplied text")
			}
		})
	}
	if valid.Name != "shared" || valid.Namespace != "deployment" {
		t.Fatal("reference validation mutated its typed input")
	}
}

func TestAppOAuthLoginStoreBindingsRejectBeforeStorage(t *testing.T) {
	for _, kind := range []string{"duplicate", "missing_reference", "no_modules", "unselected_reference", "null_reference", "empty_reference", "partial_reference", "invalid_reference_type", "null_module", "unknown_driver", "wrong_interface", "unknown_field", "prepare_error", "prepare_panic", "prepare_nil", "prepare_typed_nil", "descriptor_error", "descriptor_panic", "descriptor_name", "descriptor_hash"} {
		t.Run(kind, func(t *testing.T) {
			failure := ""
			if strings.HasPrefix(kind, "prepare_") || strings.HasPrefix(kind, "descriptor_") {
				failure = kind
			}
			app, path, probe := oauthLoginTestApp(t, failure)
			switch kind {
			case "duplicate":
				app.OAuthLoginStoreConfigs = append(app.OAuthLoginStoreConfigs, slices.Clone(app.OAuthLoginStoreConfigs[0]))
			case "missing_reference":
				app.Config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "missing", "namespace": "deployment"}
			case "no_modules":
				app.OAuthLoginStoreConfigs = nil
			case "unselected_reference":
				config := lifecycleConfig()
				config.IdentityProviders = app.Config.IdentityProviders
				config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "missing", "namespace": "deployment"}
				app.Config = config
			case "empty_reference":
				app.Config.IdentityProviders[0].Params["login_store"] = map[string]any{}
			case "null_reference":
				app.Config.IdentityProviders[0].Params["login_store"] = nil
			case "partial_reference":
				app.Config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "shared"}
			case "invalid_reference_type":
				app.Config.IdentityProviders[0].Params["login_store"] = []any{"shared"}
			case "null_module":
				app.OAuthLoginStoreConfigs[0] = json.RawMessage(`null`)
			case "unknown_driver":
				app.OAuthLoginStoreConfigs[0] = json.RawMessage(`{"driver":"absent"}`)
			case "wrong_interface":
				app.OAuthLoginStoreConfigs[0] = json.RawMessage(`{"driver":"app_wrong"}`)
			case "unknown_field":
				app.OAuthLoginStoreConfigs[0] = json.RawMessage(`{"driver":"app_test","private-oauth-store-diagnostic":true}`)
			}
			before, err := json.Marshal(app)
			if err != nil {
				t.Fatal("could not snapshot test configuration")
			}
			_, err = credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-oauth-store-diagnostic") || app.server != nil || probe.constructed.Load() != 0 {
				t.Fatal("invalid OAuth binding constructed a runtime or disclosed details")
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("rejected OAuth binding mutated declarations")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("OAuth preflight created storage")
			}
		})
	}
}

func TestAppOAuthLoginStoreReferencePreflightPreservesBytes(t *testing.T) {
	for _, field := range []string{"name", "namespace"} {
		t.Run(field, func(t *testing.T) {
			app, path, probe := oauthLoginTestApp(t, "")
			reference := map[string]any{"name": "shared", "namespace": "deployment"}
			invalid := "private-reference-" + string([]byte{0xff})
			reference[field] = invalid
			app.Config.IdentityProviders[0].Params["login_store"] = reference
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer cancel()
			err := app.prepareOAuthLoginStores(ctx, app.Config)
			if err == nil || strings.Contains(err.Error(), "private-reference-") || probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("malformed reference bytes escaped preflight or disclosed values")
			}
			if reference[field] != invalid || app.Config.IdentityProviders[0].Params["login_store"].(map[string]any)[field] != invalid {
				t.Fatal("reference preflight rewrote supplied bytes")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("malformed reference preflight opened storage")
			}
		})
	}
}

func TestAppOAuthLoginStoreReferencePreflightDoesNotReadTrust(t *testing.T) {
	app, path, probe := oauthLoginTestApp(t, "")
	app.Config.IdentityProviders[0].Params["jwks_keys"] = map[string]any{"unavailable": filepath.Join(t.TempDir(), "missing.pem")}
	app.Config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "missing", "namespace": "deployment"}
	before, _ := json.Marshal(app)
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	// Call the new pure phase directly. Full provider validation belongs to the
	// existing resolver/root, and must not be added to this binding inspector.
	err := app.prepareOAuthLoginStores(ctx, app.Config)
	if err == nil || !strings.Contains(err.Error(), "declared login store") || probe.constructed.Load() != 0 {
		t.Fatal("reference preflight reached unrelated provider trust validation")
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) {
		t.Fatal("reference preflight mutated declarative configuration")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("reference preflight opened the backend")
	}
}

func TestAppOAuthLoginStoreRuntimeFailures(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_unsafe", "construct", "name", "driver", "hash", "unready", "metadata_error", "metadata_panic", "root", "claims", "external"} {
		t.Run(failure, func(t *testing.T) {
			factoryFailure := failure
			if failure == "root" || failure == "claims" || failure == "external" {
				factoryFailure = ""
			}
			app, _, probe := oauthLoginTestApp(t, factoryFailure)
			switch failure {
			case "root":
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
			case "claims":
				binding, _ := claimsTestBinding(t, t.Name()+"/claims", "construct")
				app.ClaimsEnrichment = []*ClaimsEnrichmentBinding{binding}
			case "external":
				binding, _ := externalTestBinding(t, "construct")
				app.ExternalAuthorization = []*ExternalAuthorizationBinding{binding}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-oauth-store-diagnostic") || app.server != nil {
				t.Fatal("failed OAuth store candidate was published or disclosed details")
			}
			wantClosed := int64(1)
			if failure == "nil" || strings.HasPrefix(failure, "typed_nil") {
				wantClosed = 0
			}
			if probe.constructed.Load() != 1 || probe.closed.Load() != wantClosed {
				t.Fatal("failed OAuth store candidate lost acquired resources")
			}
			_ = app.Cleanup()
			if probe.closed.Load() != wantClosed {
				t.Fatal("candidate cleanup disposed an OAuth store twice")
			}
		})
	}
}

func TestAppOAuthLoginStorePartialBatchReverseCleanup(t *testing.T) {
	for _, failure := range []string{"construct", "typed_nil_unsafe_error"} {
		t.Run(failure, func(t *testing.T) {
			app := new(App)
			var order []int
			var probes []*oauthLoginTestProbe
			for i := range 3 {
				probe := new(oauthLoginTestProbe)
				index := i
				probe.onClose = func() { order = append(order, index) }
				mode := ""
				if i == 0 {
					mode = "close_panic"
				}
				if i == 2 {
					mode = failure
				}
				module := &oauthLoginTestModule{Name: fmt.Sprintf("store%d", i), Path: filepath.Join(registrationTestDirectory(t), "oauth.db"), Failure: mode, probe: probe}
				factory, err := module.PrepareOAuthLoginStore()
				if err != nil {
					t.Fatal("could not prepare ownership fixture")
				}
				config, err := factory.OAuthLoginStoreConfig()
				if err != nil {
					t.Fatal("could not read ownership fixture metadata")
				}
				app.oauthLoginStores = append(app.oauthLoginStores, preparedOAuthLoginStore{config: config, factory: factory})
				probes = append(probes, probe)
			}
			stores, closers, err := app.attachOAuthLoginStores(t.Context())
			if err == nil || stores != nil || strings.Contains(err.Error(), "private-oauth-store-diagnostic") {
				t.Fatal("partial construction error was not contained")
			}
			if err := closePluginResources(closers); err == nil || strings.Contains(err.Error(), "private-oauth-store-diagnostic") {
				t.Fatal("cleanup failed to contain a plugin disposal panic")
			}
			want := []int{2, 1, 0}
			if failure == "typed_nil_unsafe_error" {
				want = []int{1, 0}
			}
			if !slices.Equal(order, want) {
				t.Fatal("partial batch did not unwind in reverse acquisition order")
			}
			for i, probe := range probes {
				closed := int64(1)
				if i == 2 && failure == "typed_nil_unsafe_error" {
					closed = 0
				}
				if probe.constructed.Load() != 1 || probe.closed.Load() != closed {
					t.Fatal("partial batch leaked or duplicated backend ownership")
				}
			}
		})
	}
}

func TestAppOAuthLoginStoreSnapshotsAndDrain(t *testing.T) {
	app, _, probe := oauthLoginTestApp(t, "")
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal("could not provision the OAuth store app", err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) || probe.constructed.Load() != 1 {
		t.Fatal("preparation mutated declarations or duplicated runtime ownership")
	}
	namespace, tx := oauthLoginTestBegin(t, app, probe)
	probe.mu.Lock()
	backend := probe.backends[0]
	probe.mu.Unlock()
	if got, err := backend.Get(t.Context(), namespace, tx.State); err != nil || got != tx {
		t.Fatal("root transaction did not reach the public SQLite backend")
	}
	hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
	probe.hold.Store(hold)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(hold.release) })
	type outcome struct {
		response *httptest.ResponseRecorder
		err      error
	}
	requestDone := make(chan outcome, 1)
	go func() {
		response, err := oauthLoginTestRequest(app)
		requestDone <- outcome{response, err}
	}()
	awaitLifecycle(t, hold.entered, "OAuth request entered backend")
	probe.onClose = func() {
		if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("OAuth backend disposed before its root")
		}
	}
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module context cancellation disposed a live backend")
	}
	if got, err := backend.Get(t.Context(), namespace, tx.State); err != nil || got != tx {
		t.Fatal("module context cancellation invalidated pending evidence")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("OAuth backend closed before admitted request drain")
	}
	if release, admitted := app.acquireRequest(); admitted {
		release()
		t.Fatal("retiring app admitted new work")
	}
	releaseOnce.Do(func() { close(hold.release) })
	select {
	case result := <-requestDone:
		if result.err != nil || result.response.Code != http.StatusFound {
			t.Error("admitted OAuth request failed during retirement")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admitted OAuth request did not return")
	}
	awaitLifecycle(t, done, "OAuth backend cleanup")
	_ = app.Cleanup()
	if probe.closed.Load() != 1 {
		t.Fatal("OAuth backend was not disposed exactly once")
	}
	probe.onClose = nil
	probe.hold.Store(nil)
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal("could not restore declarative app JSON")
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal("restored app did not acquire a fresh backend", err)
	}
	if probe.constructed.Load() != 2 {
		t.Fatal("restored app reused a retired runtime")
	}
	probe.mu.Lock()
	fresh := probe.backends[1]
	probe.mu.Unlock()
	if fresh == backend {
		t.Fatal("factory returned the previous backend instance")
	}
	if got, err := fresh.Get(t.Context(), namespace, tx.State); err != nil || got != tx {
		t.Fatal("app retirement purged durable pending evidence")
	}
}

func TestAppOAuthLoginStorePersistentStart(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("factory="+failure, func(t *testing.T) {
			app, path, probe := oauthLoginTestApp(t, failure)
			statePath := filepath.Join(registrationTestDirectory(t), "state")
			app.Config.State = &state.Config{Directory: statePath}
			before, _ := json.Marshal(app)
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal("persistent preparation failed", err)
			}
			if app.server != nil || app.runtimeConfig == nil || probe.constructed.Load() != 0 {
				t.Fatal("persistent preparation constructed a backend or root")
			}
			for _, target := range []string{path, statePath} {
				if _, err := os.Stat(target); !os.IsNotExist(err) {
					t.Fatal("persistent preparation initialized storage")
				}
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) {
				t.Fatal("persistent preparation rewrote declarations")
			}
			// Neither mutable raw JSON, original Params nor the loaded Caddy
			// module is a constructor input after immutable factory preparation.
			unchecked := filepath.Join(registrationTestDirectory(t), "unchecked.db")
			probe.module.Path = unchecked
			probe.module.Name = "changed"
			probe.module.Capacity = 1
			probe.module.Timeout = "30s"
			app.OAuthLoginStoreConfigs[0] = json.RawMessage(`{"driver":"absent"}`)
			app.Config.IdentityProviders[0].Params["login_store"] = map[string]any{"name": "changed", "namespace": "changed"}
			err := app.Start()
			if (err != nil) != (failure != "") || probe.constructed.Load() != 1 {
				t.Fatal("Start did not use the prepared factory")
			}
			if _, err := os.Stat(unchecked); !os.IsNotExist(err) {
				t.Fatal("mutable source redirected deferred backend construction")
			}
			if err == nil {
				namespace, _ := oauthLoginTestBegin(t, app, probe)
				if !strings.HasPrefix(namespace, "deployment/") {
					t.Fatal("mutable declarations changed the provider namespace")
				}
			} else if app.server != nil {
				t.Fatal("failed persistent Start published a root")
			}
			if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
				t.Fatal("persistent candidate leaked its acquired OAuth backend")
			}
		})
	}
}

func TestAppOAuthLoginStoreFailedReplacementPreservesPending(t *testing.T) {
	active, _, probe := oauthLoginTestApp(t, "")
	snapshot, _ := json.Marshal(active)
	if _, err := credentialTestApp(t, active); err != nil {
		t.Fatal("could not provision active OAuth root", err)
	}
	namespace, tx := oauthLoginTestBegin(t, active, probe)
	var candidate App
	if err := json.Unmarshal(snapshot, &candidate); err != nil {
		t.Fatal("could not restore candidate configuration")
	}
	candidate.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
	if _, err := credentialTestApp(t, &candidate); err == nil {
		t.Fatal("invalid replacement root was accepted")
	}
	if probe.constructed.Load() != 2 || probe.closed.Load() != 1 {
		t.Fatal("candidate failure lost distinct backend ownership")
	}
	probe.mu.Lock()
	backend := probe.backends[0]
	probe.mu.Unlock()
	if backend.closed.Load() {
		t.Fatal("candidate cleanup closed the active backend")
	}
	got, err := backend.Claim(t.Context(), namespace, tx.State, tx.Binding, "claim-after-candidate-failure")
	if err != nil || got.State != tx.State || got.Verifier != tx.Verifier || got.ReturnURL != tx.ReturnURL {
		t.Fatal("candidate cleanup lost active pending evidence")
	}
	if err := backend.Complete(t.Context(), namespace, tx.State, got.Claim); err != nil {
		t.Fatal("candidate cleanup prevented legitimate pending completion")
	}
	oauthLoginTestBegin(t, active, probe)
}

func TestAppOAuthLoginStoreCloseFailure(t *testing.T) {
	for _, failure := range []string{"close_error", "close_panic"} {
		t.Run(failure, func(t *testing.T) {
			app, _, probe := oauthLoginTestApp(t, failure)
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal("could not provision cleanup fixture", err)
			}
			err := app.Cleanup()
			if err == nil || strings.Contains(err.Error(), "private-oauth-store-diagnostic") || probe.closed.Load() != 1 {
				t.Fatal("cleanup error was lost or disclosed private diagnostics")
			}
			if repeat := app.Cleanup(); repeat != err || probe.closed.Load() != 1 {
				t.Fatal("repeated cleanup did not retain its result and ownership")
			}
		})
	}
}

func TestAppOAuthLoginStoreOmissionAndUnusedDeclaration(t *testing.T) {
	for _, unused := range []bool{false, true} {
		t.Run(fmt.Sprintf("unused=%t", unused), func(t *testing.T) {
			app, path, probe := oauthLoginTestApp(t, "")
			delete(app.Config.IdentityProviders[0].Params, "login_store")
			if !unused {
				app.OAuthLoginStoreConfigs = nil
			}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal("omitted backend selection broke private-memory compatibility", err)
			}
			response, err := oauthLoginTestRequest(app)
			if err != nil || response.Code != http.StatusFound || probe.lookups.Load() != 0 {
				t.Fatal("omitted selection used the declared shared backend")
			}
			want := int64(0)
			if unused {
				want = 1
			}
			if probe.constructed.Load() != want {
				t.Fatal("declaration construction depended on provider selection")
			}
			if !unused {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("omitted declaration created shared storage")
				}
			}
		})
	}
}

func TestAppOAuthLoginStoreMixedCategoryCleanup(t *testing.T) {
	app, _, oauthProbe := oauthLoginTestApp(t, "")
	raw, credentialProbe, _ := credentialTestBinding(t, "")
	app.CredentialAuthenticatorConfigs = []json.RawMessage{raw}
	app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm staff portal keys"}
	claimsBinding, claimsProbe := claimsTestBinding(t, t.Name()+"/claims", "")
	app.ClaimsEnrichment = []*ClaimsEnrichmentBinding{claimsBinding}
	externalBinding, externalProbe := externalTestBinding(t, "")
	app.ExternalAuthorization = []*ExternalAuthorizationBinding{externalBinding}
	var order []string
	for _, entry := range []struct {
		name  string
		probe *claimsTestState
	}{
		{"credentials", credentialProbe}, {"oauth", &oauthProbe.claimsTestState},
		{"claims", claimsProbe}, {"external", externalProbe},
	} {
		entry.probe.onClose = func() {
			if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
				t.Error("mixed-category backend disposed before its root")
			}
			order = append(order, entry.name)
		}
	}
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("could not provision mixed backend categories", err)
	}
	if err := app.Cleanup(); err != nil || !slices.Equal(order, []string{"external", "claims", "oauth", "credentials"}) {
		t.Fatal("backend categories lost reverse acquisition order")
	}
	for _, probe := range []*claimsTestState{credentialProbe, &oauthProbe.claimsTestState, claimsProbe, externalProbe} {
		if probe.closed.Load() != 1 {
			t.Fatal("mixed-category cleanup lost exactly-once ownership")
		}
	}
}

func TestAppOAuthLoginStoreResourceFree(t *testing.T) {
	app, path, probe := oauthLoginTestApp(t, "resource_free")
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("resource-free backend was rejected", err)
	}
	response, err := oauthLoginTestRequest(app)
	if err != nil || response.Code != http.StatusFound || probe.constructed.Load() != 1 {
		t.Fatal("root did not consume the resource-free backend")
	}
	if err := app.Cleanup(); err != nil || probe.closed.Load() != 0 {
		t.Fatal("resource-free backend acquired an invented disposal requirement")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("resource-free factory opened storage")
	}
}

func TestAppOAuthLoginStoreSharedConsumers(t *testing.T) {
	app, _, probe := oauthLoginTestApp(t, "")
	provider := *app.Config.IdentityProviders[0]
	encoded, _ := json.Marshal(provider.Params)
	provider.Params = nil
	if err := json.Unmarshal(encoded, &provider.Params); err != nil {
		t.Fatal("could not copy provider configuration")
	}
	provider.Name = "second"
	provider.Params["realm"] = "second"
	app.Config.IdentityProviders = append(app.Config.IdentityProviders, &provider)
	app.Config.AuthenticationPortals[0].IdentityProviders = append(app.Config.AuthenticationPortals[0].IdentityProviders, "second")
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal("could not provision shared backend consumers", err)
	}
	namespace, tx := oauthLoginTestBegin(t, app, probe)
	response, err := oauthLoginTestRequestRealm(app, "second")
	if err != nil || response.Code != http.StatusFound || probe.constructed.Load() != 1 || probe.lookups.Load() != 2 {
		t.Fatal("providers did not share the app's single configured backend")
	}
	probe.mu.Lock()
	otherNamespace, otherTx := probe.namespace, probe.transaction
	backend := probe.backends[0]
	probe.mu.Unlock()
	if namespace == otherNamespace || otherTx.Binding.Callback != "https://portal.example.test/auth/oauth2/second/authorization-code-callback" {
		t.Fatal("shared consumers lost provider-specific namespaces or callback binding")
	}
	for _, record := range []struct {
		namespace string
		tx        oauth.LoginTransaction
	}{{namespace, tx}, {otherNamespace, otherTx}} {
		if got, err := backend.Get(t.Context(), record.namespace, record.tx.State); err != nil || got != record.tx {
			t.Fatal("shared backend did not preserve both consumer transactions")
		}
	}
}
