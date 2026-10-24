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
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/state"
	identitysqlite "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	registrationsqlite "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	"go.uber.org/zap"
)

type appRegistrationTestModule struct {
	SQLiteRegistrationWorkflow
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *claimsTestState
	backend *appRegistrationTestBackend
}

func (appRegistrationTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.registration_workflows.test", New: func() caddy.Module { return new(appRegistrationTestModule) }}
}
func (m *appRegistrationTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("registration probe unavailable")
	}
	m.probe = value.(*claimsTestState)
	return nil
}
func (m *appRegistrationTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}
func (m *appRegistrationTestModule) RegistrationWorkflowConfig() (*registry.ExternalUserRegistryConfig, error) {
	switch m.Failure {
	case "descriptor_error":
		return nil, fmt.Errorf("private-sentinel")
	case "descriptor_nil":
		return nil, nil
	}
	cfg, err := m.SQLiteRegistrationWorkflow.RegistrationWorkflowConfig()
	if err == nil && m.Failure == "descriptor_builtin" {
		cfg.Kind = "local"
	}
	return cfg, err
}
func (m *appRegistrationTestModule) NewRegistrationWorkflow(ctx context.Context, store ids.IdentityStore, provider messaging.Provider) (registry.Provider, error) {
	m.probe.constructed.Add(1)
	switch m.Failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*appRegistrationTestBackend)(nil), nil
	case "typed_nil_unsafe":
		return (*appRegistrationNilUnsafeBackend)(nil), nil
	case "typed_nil_unsafe_error":
		return (*appRegistrationNilUnsafeBackend)(nil), fmt.Errorf("private-sentinel")
	}
	workflow, err := m.SQLiteRegistrationWorkflow.NewRegistrationWorkflow(ctx, store, provider)
	if err != nil {
		return nil, err
	}
	m.backend = &appRegistrationTestBackend{Workflow: workflow.(*registrationsqlite.Workflow), probe: m.probe, failure: m.Failure, accounts: store.(*identitysqlite.Store), outbox: provider.(*messagingsqlite.Outbox)}
	if m.Failure == "construct" {
		return m.backend, fmt.Errorf("private-sentinel")
	}
	return m.backend, nil
}

type appRegistrationTestBackend struct {
	*registrationsqlite.Workflow
	probe    *claimsTestState
	failure  string
	accounts *identitysqlite.Store
	outbox   *messagingsqlite.Outbox
}

func (b *appRegistrationTestBackend) Validate() error {
	if b.failure == "runtime_validate" {
		return fmt.Errorf("private-sentinel")
	}
	if b.failure == "validate_panic" {
		panic("private-sentinel")
	}
	return b.Workflow.Validate()
}
func (b *appRegistrationTestBackend) GetName() string {
	if b.failure == "wrong_name" {
		return "private-sentinel"
	}
	return b.Workflow.GetName()
}
func (b *appRegistrationTestBackend) GetEmailProvider() string {
	if b.failure == "wrong_email" {
		return "private-sentinel"
	}
	return b.Workflow.GetEmailProvider()
}
func (b *appRegistrationTestBackend) Activate(*zap.Logger) error {
	return fmt.Errorf("borrowed workflow must not be activated")
}
func (b *appRegistrationTestBackend) SetCredentials(*credentials.Config) error {
	return fmt.Errorf("borrowed workflow must not acquire credentials")
}
func (b *appRegistrationTestBackend) SetMessaging(*messaging.Config) error {
	return fmt.Errorf("borrowed workflow must not be rebound")
}
func (b *appRegistrationTestBackend) SetRealmName(string) { b.probe.lookups.Add(1) }
func (b *appRegistrationTestBackend) Close() error {
	if b == nil {
		return nil
	}
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.Workflow.Close()
	switch b.failure {
	case "close":
		return fmt.Errorf("private-sentinel")
	case "close_panic":
		panic("private-sentinel")
	}
	return err
}

type appRegistrationNilUnsafeBackend struct{ *registrationsqlite.Workflow }

func (b *appRegistrationNilUnsafeBackend) Close() error { return b.Workflow.Close() }

type appRegistrationWrongModule struct{}

func (appRegistrationWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.registration_workflows.test_wrong", New: func() caddy.Module { return new(appRegistrationWrongModule) }}
}
func init() {
	caddy.RegisterModule(appRegistrationTestModule{})
	caddy.RegisterModule(appRegistrationWrongModule{})
}

func appRegistrationTestBinding(t *testing.T, config *SQLiteRegistrationWorkflow, failure string) (json.RawMessage, *claimsTestState) {
	t.Helper()
	probe := new(claimsTestState)
	label := t.Name() + config.Path
	claimsTestStates.Store(label, probe)
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	module := &appRegistrationTestModule{SQLiteRegistrationWorkflow: *config, Label: label, Failure: failure}
	return caddyconfig.JSONModuleObject(module, "driver", "test", nil), probe
}

func appRegistrationTestApp(t *testing.T, createAccounts bool) (*App, *SQLiteRegistrationWorkflow) {
	t.Helper()
	workflow := sqliteRegistrationTestConfig(t)
	dir := filepath.Dir(workflow.Path)
	accounts := &SQLiteIdentityStore{Name: workflow.IdentityStore, Realm: workflow.Realm, Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"}
	outbox := &SQLiteMessagingProvider{Name: workflow.EmailProvider, Path: filepath.Join(dir, "outbox.db"), Timeout: "5s"}
	if createAccounts {
		cfg, err := accounts.config()
		if err != nil {
			t.Fatal(err)
		}
		store, err := identitysqlite.New(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{Config: identityStoreTestConfig(), IdentityStoreConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(accounts, "driver", "sqlite", nil)}, MessagingProviderConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(outbox, "driver", "sqlite", nil)}, RegistrationWorkflowConfigs: []json.RawMessage{caddyconfig.JSONModuleObject(workflow, "driver", "sqlite", nil)}}
	app.Config.AuthenticationPortals[0].UserRegistries = []string{workflow.Name}
	return app, workflow
}

func TestAppRegistrationBindingsRejectBeforeStorage(t *testing.T) {
	for _, kind := range []string{"duplicate", "same_store", "descriptor_error", "descriptor_nil", "descriptor_builtin", "native_descriptor", "missing_store", "wrong_realm", "missing_mail", "native_nil_email", "builtin_mail", "wrapped_identity", "wrapped_mail", "unknown_selection", "unselected_store", "lexical_alias", "wrong_interface", "unknown_driver", "null", "unknown_field"} {
		t.Run(kind, func(t *testing.T) {
			app, module := appRegistrationTestApp(t, false)
			failure := ""
			if strings.HasPrefix(kind, "descriptor_") {
				failure = kind
			}
			raw, probe := appRegistrationTestBinding(t, module, failure)
			app.RegistrationWorkflowConfigs[0] = raw
			switch kind {
			case "duplicate":
				app.RegistrationWorkflowConfigs = append(app.RegistrationWorkflowConfigs, raw)
			case "same_store":
				copy := *module
				copy.Name = "other"
				copy.Path = filepath.Join(filepath.Dir(copy.Path), "other.db")
				app.RegistrationWorkflowConfigs = append(app.RegistrationWorkflowConfigs, caddyconfig.JSONModuleObject(&copy, "driver", "sqlite", nil))
			case "native_descriptor":
				cfg, err := module.RegistrationWorkflowConfig()
				if err != nil {
					t.Fatal(err)
				}
				app.Config.ExternalUserRegistries = []*registry.ExternalUserRegistryConfig{cfg}
			case "missing_store":
				module.IdentityStore = "missing"
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "wrong_realm":
				module.Realm = "other"
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "missing_mail":
				app.MessagingProviderConfigs = nil
			case "native_nil_email":
				app.MessagingProviderConfigs = nil
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{nil}}
			case "builtin_mail":
				email := appMessagingTestEmail()
				email.Name = "notifications"
				app.MessagingProviderConfigs = nil
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{email}}
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "wrapped_identity":
				var declaration SQLiteIdentityStore
				if err := json.Unmarshal(app.IdentityStoreConfigs[0], &declaration); err != nil {
					t.Fatal(err)
				}
				wrapper := &identityStoreTestModule{SQLiteIdentityStore: declaration, Label: t.Name() + module.Path}
				app.IdentityStoreConfigs[0] = caddyconfig.JSONModuleObject(wrapper, "driver", "test", nil)
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "wrapped_mail":
				var declaration SQLiteMessagingProvider
				if err := json.Unmarshal(app.MessagingProviderConfigs[0], &declaration); err != nil {
					t.Fatal(err)
				}
				wrapper := &appMessagingTestModule{SQLiteMessagingProvider: declaration, Label: t.Name() + module.Path}
				app.MessagingProviderConfigs[0] = caddyconfig.JSONModuleObject(wrapper, "driver", "test", nil)
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "unknown_selection":
				app.Config.AuthenticationPortals[0].UserRegistries = []string{"missing"}
			case "unselected_store":
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
				app.Config.AuthenticationPortals[0].IdentityStores = []string{"local"}
			case "lexical_alias":
				module.Path = filepath.Join(filepath.Dir(module.Path), "accounts.db")
				app.RegistrationWorkflowConfigs[0] = caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)
			case "wrong_interface":
				app.RegistrationWorkflowConfigs[0] = json.RawMessage(`{"driver":"test_wrong"}`)
			case "unknown_driver":
				app.RegistrationWorkflowConfigs[0] = json.RawMessage(`{"driver":"unknown"}`)
			case "null":
				app.RegistrationWorkflowConfigs[0] = json.RawMessage(`null`)
			case "unknown_field":
				app.RegistrationWorkflowConfigs[0] = json.RawMessage(`{"driver":"sqlite","private_key":"private-sentinel"}`)
			}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid workflow declaration accepted or disclosed private details", err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) || probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("rejected declaration mutated snapshots or opened a workflow")
			}
			for _, name := range []string{"pending.db", "accounts.db", "outbox.db"} {
				if _, err := os.Stat(filepath.Join(filepath.Dir(module.Path), name)); !os.IsNotExist(err) {
					t.Fatal("preflight rejection created storage", name)
				}
			}
		})
	}
}

func TestAppRegistrationStorageAliases(t *testing.T) {
	for _, kind := range []string{"distinct", "same", "hardlink", "symlink", "ancestor_symlink", "case_alias", "dangling"} {
		t.Run(kind, func(t *testing.T) {
			dir := registrationTestDirectory(t)
			first := filepath.Join(dir, "pending.db")
			second := filepath.Join(dir, "accounts.db")
			third := filepath.Join(dir, "outbox.db")
			switch kind {
			case "same":
				second = first
			case "case_alias":
				second = filepath.Join(dir, "PENDING.DB")
			case "hardlink", "symlink":
				if err := os.WriteFile(first, []byte("unchanged"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "hardlink" {
					err = os.Link(first, second)
				} else {
					err = os.Symlink(first, second)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "ancestor_symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				second = filepath.Join(alias, "pending.db")
			case "dangling":
				if err := os.Symlink(filepath.Join(dir, "missing"), second); err != nil {
					t.Fatal(err)
				}
			}
			app := &App{registrationWorkflows: []preparedRegistrationWorkflow{{sqliteFiles: []string{first, second, third}}}}
			err := app.validateRegistrationWorkflowFiles()
			if (err != nil) != (kind != "distinct") {
				t.Fatal("runtime storage alias decision was incorrect", err)
			}
			if _, err := os.Stat(third); !os.IsNotExist(err) {
				t.Fatal("read-only alias validation created storage")
			}
			if kind == "hardlink" || kind == "symlink" {
				data, err := os.ReadFile(first)
				if err != nil || string(data) != "unchanged" {
					t.Fatal("alias validation mutated an existing file")
				}
			}
		})
	}
}

func TestAppRegistrationSelectionSnapshotsAndDrain(t *testing.T) {
	app, module := appRegistrationTestApp(t, true)
	raw, probe := appRegistrationTestBinding(t, module, "")
	app.RegistrationWorkflowConfigs[0] = raw
	source, _ := json.Marshal(app.Config.AuthenticationPortals[0])
	for _, name := range []string{"shared", "disabled"} {
		var portal authn.PortalConfig
		if err := json.Unmarshal(source, &portal); err != nil {
			t.Fatal(err)
		}
		portal.Name = name
		if name == "disabled" {
			portal.UserRegistries = nil
		}
		app.Config.AuthenticationPortals = append(app.Config.AuthenticationPortals, &portal)
	}
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) || len(app.registrationWorkflows) != 1 || probe.constructed.Load() != 1 || probe.lookups.Load() != 0 {
		t.Fatal("binding mutated declarations, reconstructed shared provider or rebound borrowed realm")
	}
	portal, err := app.getPortal("portal")
	if err != nil {
		t.Fatal(err)
	}
	provider := portal.GetUserRegistryByRealmName("staff")
	if provider == nil {
		t.Fatal("explicitly selected registry missing")
	}
	shared, err := app.getPortal("shared")
	if err != nil || shared.GetUserRegistryByRealmName("staff") != provider {
		t.Fatal("portals did not share the owned provider", err)
	}
	disabled, err := app.getPortal("disabled")
	if err != nil || disabled.GetUserRegistryByRealmName("staff") != nil {
		t.Fatal("unselected portal acquired enrollment", err)
	}
	backend := app.registrationWorkflows[0].module.(*appRegistrationTestModule).backend
	id := strings.Repeat("b", 64)
	data := sqliteRegistrationTestEntry(id)
	if err := provider.AddRegistrationEntry(id, data); err != nil {
		t.Fatal(err)
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("runtime rejected producer")
	}
	var once sync.Once
	defer once.Do(release)
	probe.onClose = func() {
		if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("workflow closed before root")
		}
		if !backend.accounts.Configured() || backend.outbox.CheckReady(t.Context()) != nil {
			t.Error("borrowed dependencies closed before workflow")
		}
	}
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module cancellation closed the app-owned workflow")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if release, ok := app.acquireRequest(); ok {
		release()
		t.Fatal("retiring runtime admitted a request")
	}
	if probe.closed.Load() != 0 {
		t.Fatal("workflow closed before request drain")
	}
	if err := provider.Notify(data); err != nil {
		t.Fatal("admitted notification lost dependencies during drain", err)
	}
	once.Do(release)
	awaitLifecycle(t, done, "registration producer drain")
	if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
		t.Fatal("workflow was not closed exactly once", err)
	}
	probe.onClose = nil
	if backend.accounts.Configured() || backend.outbox.CheckReady(t.Context()) == nil || backend.Validate() == nil {
		t.Fatal("cleanup retained runtime storage handles")
	}
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal(err)
	}
	current := restored.registrationWorkflows[0].module.(*appRegistrationTestModule).backend
	if current == backend || probe.constructed.Load() != 2 {
		t.Fatal("restore reused a retired workflow")
	}
	if _, err := current.GetRegistrationEntry(id); err != nil {
		t.Fatal("pending enrollment did not survive reopening", err)
	}
	message, err := current.outbox.Claim(t.Context())
	if err != nil || !slices.Equal(message.Recipients, []string{"alice@example.test"}) {
		t.Fatal("drain lost queued confirmation", err)
	}
}

func TestAppRegistrationFailedCandidates(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_unsafe", "construct", "wrong_name", "wrong_email", "runtime_validate", "validate_panic", "root"} {
		t.Run(failure, func(t *testing.T) {
			app, module := appRegistrationTestApp(t, true)
			raw, probe := appRegistrationTestBinding(t, module, failure)
			app.RegistrationWorkflowConfigs[0] = raw
			if failure == "root" {
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") || app.server != nil {
				t.Fatal("failed registry published runtime or disclosed plugin detail", err)
			}
			want := int64(1)
			if failure == "nil" || strings.HasPrefix(failure, "typed_nil") {
				want = 0
			}
			if probe.constructed.Load() != 1 || probe.closed.Load() != want {
				t.Fatal("failed candidate leaked or double-closed its workflow")
			}
			_ = app.Cleanup()
			if probe.closed.Load() != want {
				t.Fatal("failed candidate closed the handle again")
			}
		})
	}
}

func TestAppRegistrationPartialBatchReverseCleanup(t *testing.T) {
	for _, failure := range []string{"construct", "typed_nil_unsafe_error"} {
		t.Run(failure, func(t *testing.T) {
			module := sqliteRegistrationTestConfig(t)
			store, outbox := sqliteRegistrationTestDependencies(t, module)
			config := &authcrunch.Config{Messaging: &messaging.Config{}}
			if err := config.Messaging.AddProvider("notifications", outbox); err != nil {
				t.Fatal(err)
			}
			app := new(App)
			var probes []*claimsTestState
			var order []int
			for i := range 3 {
				copy := *module
				copy.Name = fmt.Sprintf("signup%d", i)
				copy.Path = filepath.Join(filepath.Dir(module.Path), fmt.Sprintf("pending%d.db", i))
				probe := new(claimsTestState)
				index := i
				probe.onClose = func() {
					order = append(order, index)
					if outbox.CheckReady(t.Context()) != nil || !store.Configured() {
						t.Error("workflow cleanup disposed borrowed dependencies")
					}
				}
				mode := ""
				if i == 0 {
					mode = "close_panic"
				}
				if i == 2 {
					mode = failure
				}
				factory := &appRegistrationTestModule{SQLiteRegistrationWorkflow: copy, probe: probe, Failure: mode}
				descriptor, err := factory.RegistrationWorkflowConfig()
				if err != nil {
					t.Fatal(err)
				}
				app.registrationWorkflows = append(app.registrationWorkflows, preparedRegistrationWorkflow{config: *descriptor, module: factory})
				probes = append(probes, probe)
			}
			providers, closers, err := app.attachRegistrationWorkflows(t.Context(), map[string]ids.IdentityStore{"accounts": store}, config)
			if err == nil || providers != nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("partial construction did not return a safe failure", err)
			}
			err = closePluginResources(closers)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("cleanup did not contain plugin failure", err)
			}
			expected := []int{2, 1, 0}
			if failure == "typed_nil_unsafe_error" {
				expected = []int{1, 0}
			}
			if !slices.Equal(order, expected) {
				t.Fatal("cleanup did not continue in reverse acquisition order", order)
			}
			for i, probe := range probes {
				want := int64(1)
				if i == 2 && failure == "typed_nil_unsafe_error" {
					want = 0
				}
				if probe.constructed.Load() != 1 || probe.closed.Load() != want {
					t.Fatal("partial batch ownership count changed")
				}
			}
		})
	}
}

func TestAppRegistrationPersistentStart(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("factory="+failure, func(t *testing.T) {
			app, module := appRegistrationTestApp(t, true)
			raw, probe := appRegistrationTestBinding(t, module, failure)
			app.RegistrationWorkflowConfigs[0] = raw
			app.Config.State = &state.Config{Directory: filepath.Join(registrationTestDirectory(t), "state")}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("persistent Provision opened a workflow")
			}
			for _, path := range []string{module.Path, filepath.Join(filepath.Dir(module.Path), "outbox.db"), app.Config.State.Directory} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("persistent preparation created runtime storage")
				}
			}
			err := app.Start()
			if (err != nil) != (failure != "") || probe.constructed.Load() != 1 {
				t.Fatal("Start lost prepared workflow", err)
			}
			if err == nil {
				portal, err := app.getPortal("portal")
				if err != nil || portal.GetUserRegistryByRealmName("staff") == nil {
					t.Fatal("started root lost enrollment", err)
				}
			} else if app.server != nil {
				t.Fatal("failed Start published runtime")
			}
			if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
				t.Fatal("persistent root leaked workflow", err)
			}
		})
	}
}

func TestAppRegistrationFailedReplacementPreservesServing(t *testing.T) {
	active, module := appRegistrationTestApp(t, true)
	raw, probe := appRegistrationTestBinding(t, module, "")
	active.RegistrationWorkflowConfigs[0] = raw
	snapshot, _ := json.Marshal(active)
	if _, err := credentialTestApp(t, active); err != nil {
		t.Fatal(err)
	}
	var candidate App
	if err := json.Unmarshal(snapshot, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
	if _, err := credentialTestApp(t, &candidate); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if probe.constructed.Load() != 2 || probe.closed.Load() != 1 {
		t.Fatal("rejected replacement disposed the active provider")
	}
	portal, err := active.getPortal("portal")
	if err != nil {
		t.Fatal(err)
	}
	provider := portal.GetUserRegistryByRealmName("staff")
	if provider == nil {
		t.Fatal("rejected replacement removed enrollment")
	}
	id := strings.Repeat("c", 64)
	data := sqliteRegistrationTestEntry(id)
	if err := provider.AddRegistrationEntry(id, data); err != nil {
		t.Fatal(err)
	}
	if err := provider.Notify(data); err != nil {
		t.Fatal("failed replacement interrupted active enrollment", err)
	}
}

func TestAppRegistrationCloseFailure(t *testing.T) {
	app, module := appRegistrationTestApp(t, true)
	raw, probe := appRegistrationTestBinding(t, module, "close")
	app.RegistrationWorkflowConfigs[0] = raw
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	backend := app.registrationWorkflows[0].module.(*appRegistrationTestModule).backend
	err := app.Cleanup()
	if err == nil || strings.Contains(err.Error(), "private-sentinel") || probe.closed.Load() != 1 {
		t.Fatal("cleanup failed to retain a sanitized plugin error", err)
	}
	if backend.accounts.Configured() || backend.outbox.CheckReady(t.Context()) == nil {
		t.Fatal("workflow cleanup error prevented dependency disposal")
	}
	if repeated := app.Cleanup(); repeated != err || probe.closed.Load() != 1 {
		t.Fatal("repeated cleanup changed result or ownership")
	}
}
