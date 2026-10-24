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
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/state"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
)

// Keep actual queue operations underneath the probe. This generic companion
// deliberately embeds the SQLite factory without opting into its host worker.
type appMessagingTestModule struct {
	SQLiteMessagingProvider
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *claimsTestState
	backend *appMessagingTestBackend
}

func (appMessagingTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.messaging.test", New: func() caddy.Module { return new(appMessagingTestModule) }}
}

func (m *appMessagingTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("messaging probe not found")
	}
	m.probe = value.(*claimsTestState)
	return nil
}

func (m *appMessagingTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}

func (m *appMessagingTestModule) MessagingProviderName() (string, error) {
	switch m.Failure {
	case "name_error":
		return "", fmt.Errorf("private-sentinel")
	case "name_invalid":
		return " invalid ", nil
	}
	return m.SQLiteMessagingProvider.MessagingProviderName()
}

func (m *appMessagingTestModule) NewMessagingProvider(ctx context.Context) (messaging.Provider, error) {
	m.probe.constructed.Add(1)
	switch m.Failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*appMessagingTestBackend)(nil), nil
	case "typed_nil_unsafe":
		return (*appMessagingNilUnsafeBackend)(nil), nil
	}
	provider, err := m.SQLiteMessagingProvider.NewMessagingProvider(ctx)
	if err != nil {
		return nil, err
	}
	m.backend = &appMessagingTestBackend{Outbox: provider.(*messagingsqlite.Outbox), probe: m.probe, failure: m.Failure}
	if m.Failure == "construct" {
		return m.backend, fmt.Errorf("private-sentinel")
	}
	return m.backend, nil
}

type appMessagingTestBackend struct {
	*messagingsqlite.Outbox
	probe       *claimsTestState
	failure     string
	validations int
}

func (b *appMessagingTestBackend) Validate() error {
	if b.failure == "runtime_validate" {
		return fmt.Errorf("private-sentinel")
	}
	if b.failure == "revalidate_panic" {
		b.validations++
		if b.validations > 1 {
			panic("private-sentinel")
		}
	}
	return b.Outbox.Validate()
}

func (b *appMessagingTestBackend) Kind() string {
	if b.failure == "reserved_kind" {
		return "email"
	}
	return b.Outbox.Kind()
}

func (b *appMessagingTestBackend) Send(input *messaging.SendInput) error {
	if err := b.Outbox.Send(input); err != nil {
		return err
	}
	b.probe.lookups.Add(1)
	return nil
}

func (b *appMessagingTestBackend) Close() error {
	if b == nil {
		return nil
	}
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.Outbox.Close()
	switch b.failure {
	case "close":
		return fmt.Errorf("private-sentinel")
	case "close_panic":
		panic("private-sentinel")
	}
	return err
}

type appMessagingNilUnsafeBackend struct{ *messagingsqlite.Outbox }

func (b *appMessagingNilUnsafeBackend) Close() error { return b.Outbox.Close() }

type appMessagingWrongModule struct{}

func (appMessagingWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.messaging.test_wrong", New: func() caddy.Module { return new(appMessagingWrongModule) }}
}

func init() {
	caddy.RegisterModule(appMessagingTestModule{})
	caddy.RegisterModule(appMessagingWrongModule{})
}

func appMessagingTestConfig() *authcrunch.Config {
	config := lifecycleConfig()
	config.UserRegistration.RawConfigs[0][3] = "email provider notifications"
	return config
}

func appMessagingTestBinding(t *testing.T, name, failure string) (json.RawMessage, *claimsTestState, string) {
	t.Helper()
	config := sqliteMessagingTestConfig(t)
	config.Name = name
	// A generic module may use this same field for an independently owned
	// transport. The host must not infer SQLite worker capabilities by embedding.
	config.Delivery = "generic-module-owned"
	probe := new(claimsTestState)
	label := t.Name() + config.Path
	claimsTestStates.Store(label, probe)
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	module := &appMessagingTestModule{SQLiteMessagingProvider: *config, Label: label, Failure: failure}
	return caddyconfig.JSONModuleObject(module, "driver", "test", nil), probe, config.Path
}

func appMessagingTestEmail() *messaging.EmailProvider {
	return &messaging.EmailProvider{Name: "smtp-local", Address: "127.0.0.1:1025", Protocol: "smtp", Passwordless: true, SenderEmail: "portal@example.test"}
}

func appMessagingTestNotification() map[string]string {
	return map[string]string{
		"template": "registration_confirmation", "session_id": "session-id", "request_id": "request-id", "timestamp": "now",
		"registration_id": "registration-id", "registration_code": "123456", "username": "alice", "email": "alice@example.test",
		"registration_url": "https://portal.example.test/auth/register", "realm_name": "local", "src_ip": "192.0.2.10", "src_conn_ip": "192.0.2.11",
	}
}

func TestAppMessagingBindingsRejectBeforeStorage(t *testing.T) {
	for _, kind := range []string{"duplicate", "builtin_collision", "builtin_duplicate", "native_nil_email", "native_invalid_email", "name_error", "name_invalid", "null", "unknown", "wrong_interface", "unknown_field"} {
		t.Run(kind, func(t *testing.T) {
			failure := ""
			if strings.HasPrefix(kind, "name_") {
				failure = kind
			}
			raw, probe, path := appMessagingTestBinding(t, "notifications", failure)
			app := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
			switch kind {
			case "duplicate":
				app.MessagingProviderConfigs = append(app.MessagingProviderConfigs, raw)
			case "builtin_collision":
				provider := appMessagingTestEmail()
				provider.Name = "notifications"
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{provider}}
			case "builtin_duplicate":
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{appMessagingTestEmail(), appMessagingTestEmail()}}
			case "native_nil_email":
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{nil}}
			case "native_invalid_email":
				provider := appMessagingTestEmail()
				provider.Protocol = "private-sentinel"
				app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{provider}}
			case "null":
				app.MessagingProviderConfigs[0] = json.RawMessage(`null`)
			case "unknown":
				app.MessagingProviderConfigs[0] = json.RawMessage(`{"driver":"not_registered"}`)
			case "wrong_interface":
				app.MessagingProviderConfigs[0] = json.RawMessage(`{"driver":"test_wrong"}`)
			case "unknown_field":
				app.MessagingProviderConfigs[0] = json.RawMessage(`{"driver":"sqlite","credentials":"private-sentinel"}`)
			}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid binding accepted or exposed private diagnostics", err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) || probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("rejected binding mutated declarations or reached runtime construction")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("invalid binding created queue storage")
			}
		})
	}
}

func TestAppMessagingDeliveryBindings(t *testing.T) {
	for _, kind := range []string{"native", "raw_resolved", "passwordless", "missing", "file", "queue", "missing_credentials", "duplicate_credentials", "invalid_credentials"} {
		t.Run(kind, func(t *testing.T) {
			module := sqliteMessagingTestConfig(t)
			module.Delivery = "smtp-local"
			provider := appMessagingTestEmail()
			provider.Passwordless, provider.Credentials = false, "smtp-creds"
			cred := &credentials.GenericCredential{Name: "smtp-creds", Username: "synthetic-user", Password: "synthetic-password", Domain: "example.test"}
			app := &App{Config: appMessagingTestConfig()}
			app.Config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
			app.Config.Messaging = &messaging.Config{EmailProviders: []*messaging.EmailProvider{provider}}
			app.Config.Credentials = &credentials.Config{Generic: []*credentials.GenericCredential{cred}}
			valid := kind == "native" || kind == "raw_resolved" || kind == "passwordless"
			switch kind {
			case "raw_resolved":
				t.Setenv("AUTHCRUNCH_TEST_SMTP_ADDRESS", "127.0.0.1:2525")
				t.Setenv("AUTHCRUNCH_TEST_SMTP_USERNAME", "resolved-user")
				t.Setenv("AUTHCRUNCH_TEST_SMTP_PASSWORD", "resolved-password")
				app.Config.Messaging = &messaging.Config{RawConfigs: [][]string{{"name smtp-local", "kind email", "address {env.AUTHCRUNCH_TEST_SMTP_ADDRESS}", "protocol smtp", "credentials smtp-creds", "sender portal@example.test"}}}
				app.Config.Credentials = &credentials.Config{RawCredentialConfigs: [][]string{{"name smtp-creds", "kind generic", "username {env.AUTHCRUNCH_TEST_SMTP_USERNAME}", "password {env.AUTHCRUNCH_TEST_SMTP_PASSWORD}"}}}
			case "passwordless":
				provider.Passwordless, provider.Credentials = true, ""
				app.Config.Credentials = nil
			case "missing":
				module.Delivery = "not-declared"
			case "file":
				app.Config.Messaging = &messaging.Config{FileProviders: []*messaging.FileProvider{{Name: "smtp-local", RootDir: filepath.Join(t.TempDir(), "mail"), SenderEmail: "portal@example.test"}}}
			case "queue":
				module.Delivery = module.Name
			case "missing_credentials":
				app.Config.Credentials = nil
			case "duplicate_credentials":
				copy := *cred
				app.Config.Credentials.Generic = append(app.Config.Credentials.Generic, &copy)
			case "invalid_credentials":
				cred.Username = ""
			}
			app.MessagingProviderConfigs = []json.RawMessage{caddyconfig.JSONModuleObject(module, "driver", "sqlite", nil)}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if (err == nil) != valid {
				t.Fatalf("delivery binding %s: %v", kind, err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) || app.server != nil || len(app.messagingWorkers) != 0 {
				t.Fatal("preparation changed declarations or opened persistent runtime resources")
			}
			for _, path := range []string{module.Path, app.Config.State.Directory} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("delivery preparation touched storage")
				}
			}
			if !valid {
				return
			}
			if len(app.messagingProviders) != 1 || app.messagingProviders[0].delivery == nil {
				t.Fatal("valid native delivery binding disappeared")
			}
			binding := app.messagingProviders[0]
			if binding.delivery == provider || binding.credentials == cred {
				t.Fatal("prepared transport aliases declarative configuration")
			}
			switch kind {
			case "native":
				if binding.delivery.Address != "127.0.0.1:1025" || binding.credentials == nil || *binding.credentials != *cred {
					t.Fatal("native built-in transport or credential values were lost")
				}
			case "raw_resolved":
				if binding.delivery.Address != "127.0.0.1:2525" || binding.credentials == nil || binding.credentials.Username != "resolved-user" || binding.credentials.Password != "resolved-password" {
					t.Fatal("existing runtime credential/transport replacement was bypassed")
				}
			case "passwordless":
				if binding.credentials != nil {
					t.Fatal("passwordless delivery acquired credentials")
				}
			}
		})
	}
}

func TestAppMessagingSnapshotsAndDrain(t *testing.T) {
	raw, probe, _ := appMessagingTestBinding(t, "notifications", "")
	app := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) || len(app.messagingProviders) != 1 || len(app.messagingWorkers) != 0 || probe.constructed.Load() != 1 {
		t.Fatal("generic binding changed declarations, reused handles or assumed a delivery worker")
	}
	portal, err := app.getPortal("portal")
	if err != nil {
		t.Fatal(err)
	}
	registry := portal.GetUserRegistryByRealmName("local")
	if registry == nil {
		t.Fatal("root did not attach the notification consumer")
	}
	backend := app.messagingProviders[0].module.(*appMessagingTestModule).backend
	if err := registry.Notify(appMessagingTestNotification()); err != nil || probe.lookups.Load() != 1 {
		t.Fatal("root registry lost the generic provider binding", err)
	}
	release, ok := app.acquireRequest()
	if !ok {
		t.Fatal("runtime did not admit a producer")
	}
	var once sync.Once
	defer once.Do(release)
	probe.onClose = func() {
		if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("queue closed before its root consumer")
		}
	}
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("Caddy module cancellation closed an app-owned queue")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if release, admitted := app.acquireRequest(); admitted {
		release()
		t.Fatal("retiring runtime admitted a new producer")
	}
	if probe.closed.Load() != 0 {
		t.Fatal("queue closed before producer drain")
	}
	if err := registry.Notify(appMessagingTestNotification()); err != nil || probe.lookups.Load() != 2 {
		t.Fatal("admitted producer lost its queue while cleanup waited", err)
	}
	once.Do(release)
	awaitLifecycle(t, done, "messaging producer drain")
	if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
		t.Fatal("queue was not closed exactly once", err)
	}
	if _, err := backend.Claim(t.Context()); !errors.Is(err, messagingsqlite.ErrUnavailable) {
		t.Fatal("disposed queue remained available", err)
	}
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal(err)
	}
	worker := restored.messagingProviders[0].module.(*appMessagingTestModule).backend
	if worker == backend || probe.constructed.Load() != 2 {
		t.Fatal("JSON restoration reused the retired backend")
	}
	for range 2 {
		message, err := worker.Claim(t.Context())
		if err != nil || !slices.Equal(message.Recipients, []string{"alice@example.test"}) {
			t.Fatal("producer drain lost a durably accepted notification", err)
		}
		if err := worker.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := worker.Claim(t.Context()); !errors.Is(err, messagingsqlite.ErrEmpty) {
		t.Fatal("restoration replayed an acknowledged notification", err)
	}
}

func TestAppMessagingFailedCandidates(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_unsafe", "construct", "runtime_validate", "revalidate_panic", "reserved_kind", "root", "claims", "external"} {
		t.Run(failure, func(t *testing.T) {
			factoryFailure := failure
			if failure == "root" || failure == "claims" || failure == "external" {
				factoryFailure = ""
			}
			raw, probe, _ := appMessagingTestBinding(t, "notifications", factoryFailure)
			app := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
			var order []int
			probe.onClose = func() { order = append(order, 1) }
			switch failure {
			case "root":
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
			case "claims":
				binding, next := claimsTestBinding(t, t.Name(), "construct")
				next.onClose = func() { order = append(order, 2) }
				app.ClaimsEnrichment = []*ClaimsEnrichmentBinding{binding}
			case "external":
				binding, next := externalTestBinding(t, "construct")
				next.onClose = func() { order = append(order, 2) }
				app.ExternalAuthorization = []*ExternalAuthorizationBinding{binding}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid candidate published or disclosed private diagnostics", err)
			}
			if app.server != nil || len(app.pluginClosers) != 0 || len(app.messagingWorkers) != 0 {
				t.Fatal("failed candidate retained runtime ownership")
			}
			_ = app.Cleanup()
			wantClosed := int64(1)
			if failure == "nil" || failure == "typed_nil" || failure == "typed_nil_unsafe" {
				wantClosed = 0
			}
			if probe.constructed.Load() != 1 || probe.closed.Load() != wantClosed {
				t.Fatal("failed candidate leaked or double-closed a queue")
			}
			if (failure == "claims" || failure == "external") && !slices.Equal(order, []int{2, 1}) {
				t.Fatal("post-root failure did not unwind backends in reverse order", order)
			}
		})
	}
}

func TestAppMessagingCleanupContinues(t *testing.T) {
	for _, lastFailure := range []string{"construct", "typed_nil_unsafe", "revalidate_panic"} {
		t.Run(lastFailure, func(t *testing.T) {
			app := &App{Config: appMessagingTestConfig()}
			var order []int
			var probes []*claimsTestState
			for i, failure := range []string{"", "close_panic", lastFailure} {
				raw, probe, _ := appMessagingTestBinding(t, fmt.Sprintf("queue-%d", i), failure)
				probe.onClose = func() { order = append(order, i) }
				probes = append(probes, probe)
				app.MessagingProviderConfigs = append(app.MessagingProviderConfigs, raw)
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") || !strings.Contains(err.Error(), "cleanup failed") {
				t.Fatal("broken cleanup was hidden, leaked diagnostics or escaped its boundary", err)
			}
			wantOrder := []int{2, 1, 0}
			if lastFailure == "typed_nil_unsafe" {
				wantOrder = []int{1, 0}
			}
			if !slices.Equal(order, wantOrder) || app.server != nil {
				t.Fatal("cleanup panic interrupted reverse resource disposal", order)
			}
			_ = app.Cleanup()
			for i, probe := range probes {
				wantClosed := int64(1)
				if i == 2 && lastFailure == "typed_nil_unsafe" {
					wantClosed = 0
				}
				if probe.constructed.Load() != 1 || probe.closed.Load() != wantClosed {
					t.Fatal("partial batch leaked or closed a provider twice")
				}
			}
		})
	}
}

func TestAppMessagingPersistentStart(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("factory="+failure, func(t *testing.T) {
			raw, probe, path := appMessagingTestBinding(t, "notifications", failure)
			app := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
			// Durable roots bind the local account epoch to an identity file;
			// the shared volatile fixture's :memory: store cannot supply that.
			identityPath := filepath.Join(registrationTestDirectory(t), "users.json")
			app.Config.IdentityStores[0].Params["path"] = identityPath
			app.Config.State = &state.Config{Directory: filepath.Join(t.TempDir(), "state")}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			if probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("persistent Provision constructed a queue")
			}
			for _, path := range []string{path, identityPath, app.Config.State.Directory} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("persistent Provision created runtime storage")
				}
			}
			err := app.Start()
			if (err != nil) != (failure != "") || probe.constructed.Load() != 1 {
				t.Fatal("Start lost or ignored the prepared messaging factory", err)
			}
			if err == nil {
				portal, err := app.getPortal("portal")
				if err != nil {
					t.Fatal(err)
				}
				registry := portal.GetUserRegistryByRealmName("local")
				if registry == nil {
					t.Fatal("persistent root lost its registry")
				}
				if err := registry.Notify(appMessagingTestNotification()); err != nil || probe.lookups.Load() != 1 {
					t.Fatal("started persistent runtime could not queue a notification", err)
				}
			} else if app.server != nil {
				t.Fatal("failed Start published a runtime")
			}
			if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
				t.Fatal("persistent candidate leaked its provider", err)
			}
		})
	}
}

func TestAppMessagingFailedReplacementPreservesServing(t *testing.T) {
	raw, probe, _ := appMessagingTestBinding(t, "notifications", "")
	active := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
	if _, err := credentialTestApp(t, active); err != nil {
		t.Fatal(err)
	}
	candidate := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
	candidate.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
	if _, err := credentialTestApp(t, candidate); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	if probe.constructed.Load() != 2 || probe.closed.Load() != 1 || active.server == nil {
		t.Fatal("replacement disposed the active queue instead of its own handle")
	}
	portal, err := active.getPortal("portal")
	if err != nil {
		t.Fatal(err)
	}
	registry := portal.GetUserRegistryByRealmName("local")
	if registry == nil {
		t.Fatal("active registry was retired by a rejected candidate")
	}
	if err := registry.Notify(appMessagingTestNotification()); err != nil || probe.lookups.Load() != 1 {
		t.Fatal("rejected replacement interrupted serving notifications", err)
	}
}

func TestAppMessagingCloseFailure(t *testing.T) {
	raw, probe, _ := appMessagingTestBinding(t, "notifications", "close")
	app := &App{Config: appMessagingTestConfig(), MessagingProviderConfigs: []json.RawMessage{raw}}
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	err := app.Cleanup()
	if err == nil || strings.Contains(err.Error(), "private-sentinel") || probe.closed.Load() != 1 {
		t.Fatal("close failure was hidden, disclosed private details or lost ownership", err)
	}
	if repeated := app.Cleanup(); repeated != err || probe.closed.Load() != 1 {
		t.Fatal("repeated cleanup changed the result or disposed twice")
	}
}
