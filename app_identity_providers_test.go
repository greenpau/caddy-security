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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/state"
	tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
)

// Embed the concrete provider, preserving HTTPLoginProvider and attachment.Consumer.
// Losing either optional capability would change the signed identity boundary.
type identityProviderTestModule struct {
	SQLiteTicketIdentityProvider
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *claimsTestState
	backend *identityProviderTestBackend
}

func (identityProviderTestModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_providers.test", New: func() caddy.Module { return new(identityProviderTestModule) }}
}
func (m *identityProviderTestModule) Provision(caddy.Context) error {
	value, ok := claimsTestStates.Load(m.Label)
	if !ok {
		return fmt.Errorf("provider probe unavailable")
	}
	m.probe = value.(*claimsTestState)
	return nil
}
func (m *identityProviderTestModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned.Add(1)
	}
	return nil
}
func (m *identityProviderTestModule) IdentityProviderConfig() (*idp.ExternalIdentityProviderConfig, error) {
	switch m.Failure {
	case "descriptor_error":
		return nil, fmt.Errorf("private-sentinel")
	case "descriptor_nil":
		return nil, nil
	}
	descriptor, err := m.SQLiteTicketIdentityProvider.IdentityProviderConfig()
	if err == nil && m.Failure == "descriptor_builtin" {
		descriptor.Kind = "oauth"
	}
	return descriptor, err
}
func (m *identityProviderTestModule) NewIdentityProvider(ctx context.Context) (idp.IdentityProvider, error) {
	m.probe.constructed.Add(1)
	switch m.Failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*identityProviderTestBackend)(nil), nil
	case "typed_nil_unsafe":
		return (*identityProviderNilUnsafeBackend)(nil), nil
	case "typed_nil_unsafe_error":
		return (*identityProviderNilUnsafeBackend)(nil), fmt.Errorf("private-sentinel")
	}
	provider, err := m.SQLiteTicketIdentityProvider.NewIdentityProvider(ctx)
	if err != nil {
		return nil, err
	}
	m.backend = &identityProviderTestBackend{Provider: provider.(*tickets.Provider), probe: m.probe, failure: m.Failure}
	if m.Failure == "prebound_attachment" {
		store, err := identity.NewDatabase(":memory:")
		if err != nil {
			return m.backend, fmt.Errorf("fixture attachment initialization failed")
		}
		if err := attachment.BindStore(m.backend.IdentityAttachment(), store); err != nil {
			return m.backend, fmt.Errorf("fixture attachment binding failed")
		}
		m.backend.callerStore = store
	}
	if m.Failure == "construct" {
		return m.backend, fmt.Errorf("private-sentinel")
	}
	return m.backend, nil
}

type identityProviderTestBackend struct {
	*tickets.Provider
	probe       *claimsTestState
	failure     string
	callerStore *identity.Database
}

func (b *identityProviderTestBackend) Configure() error {
	return fmt.Errorf("borrowed provider must not be configured by root")
}
func (b *identityProviderTestBackend) Configured() bool {
	if b.failure == "unready" {
		return false
	}
	if b.failure == "readiness_panic" {
		panic("private-sentinel")
	}
	return b.Provider.Configured()
}
func (b *identityProviderTestBackend) GetName() string {
	if b.failure == "name" {
		return "private-sentinel"
	}
	return b.Provider.GetName()
}
func (b *identityProviderTestBackend) GetRealm() string {
	if b.failure == "realm" {
		return "other"
	}
	return b.Provider.GetRealm()
}
func (b *identityProviderTestBackend) GetKind() string {
	if b.failure == "kind" {
		return "oauth"
	}
	return b.Provider.GetKind()
}
func (b *identityProviderTestBackend) GetDriver() string {
	if b.failure == "driver" {
		return "other"
	}
	return b.Provider.GetDriver()
}
func (b *identityProviderTestBackend) Login(ctx context.Context, r *http.Request) (*idp.HTTPLoginResult, error) {
	b.probe.lookups.Add(1)
	if hold := b.probe.hold.Load(); hold != nil {
		hold.once.Do(func() { close(hold.entered) })
		select {
		case <-hold.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	result, err := b.Provider.Login(ctx, r)
	if err == nil && result.Identity != nil && b.failure == "revoke" {
		store, err := b.IdentityAttachment().Store()
		if err != nil {
			return nil, err
		}
		if err := store.(*identity.Database).RevokeUserSessions(ctx, result.ExternalIdentity.Evidence.UserID); err != nil {
			return nil, err
		}
	}
	return result, err
}
func (b *identityProviderTestBackend) Close() error {
	if b == nil {
		return nil
	}
	b.probe.closed.Add(1)
	if b.probe.onClose != nil {
		b.probe.onClose()
	}
	err := b.Provider.Close()
	switch b.failure {
	case "close":
		return fmt.Errorf("private-sentinel")
	case "close_panic":
		panic("private-sentinel")
	}
	return err
}

type identityProviderNilUnsafeBackend struct{ *tickets.Provider }

func (b *identityProviderNilUnsafeBackend) Close() error { return b.Provider.Close() }

type identityProviderWrongModule struct{}

func (identityProviderWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_providers.test_wrong", New: func() caddy.Module { return new(identityProviderWrongModule) }}
}
func init() {
	caddy.RegisterModule(identityProviderTestModule{})
	caddy.RegisterModule(identityProviderWrongModule{})
}

func identityProviderTestConfig() *authcrunch.Config {
	config := lifecycleConfig()
	config.UserRegistration = nil
	config.IdentityStores = nil
	config.AuthenticationPortals[0].IdentityStores = nil
	config.AuthenticationPortals[0].IdentityProviders = []string{"application"}
	return config
}
func identityProviderTestBinding(t *testing.T, config *SQLiteTicketIdentityProvider, failure string) (json.RawMessage, *claimsTestState) {
	t.Helper()
	probe := new(claimsTestState)
	label := t.Name() + config.Path
	claimsTestStates.Store(label, probe)
	t.Cleanup(func() { claimsTestStates.Delete(label) })
	module := &identityProviderTestModule{SQLiteTicketIdentityProvider: *config, Label: label, Failure: failure}
	return caddyconfig.JSONModuleObject(module, "driver", "test", nil), probe
}
func identityProviderTestApp(t *testing.T, failure string) (*App, *SQLiteTicketIdentityProvider, *claimsTestState) {
	t.Helper()
	module := sqliteTicketTestConfig(t)
	raw, probe := identityProviderTestBinding(t, module, failure)
	return &App{Config: identityProviderTestConfig(), IdentityProviderConfigs: []json.RawMessage{raw}}, module, probe
}
func identityProviderTestRequest(app *App, portal, uri string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, error) {
	request := httptest.NewRequest(http.MethodGet, uri, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler := &AuthnMiddleware{app: app, PortalName: portal}
	return response, handler.ServeHTTP(response, request, nil)
}
func identityProviderTestBegin(t *testing.T, app *App, portal string, provider *tickets.Provider) (string, *http.Cookie) {
	t.Helper()
	response, err := identityProviderTestRequest(app, portal, provider.CallbackURL())
	if err != nil || response.Code != http.StatusFound {
		t.Fatal("Caddy handler did not begin provider login", response.Code, err)
	}
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil || target.Query().Get("request") == "" || target.Query().Get("callback") != provider.CallbackURL() {
		t.Fatal("Caddy handler lost issuer redirect binding", err)
	}
	var binding *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == provider.GetLoginCookieName() {
			binding = cookie
		}
	}
	if binding == nil {
		t.Fatal("Caddy handler lost browser binding cookie")
	}
	return target.Query().Get("request"), binding
}
func identityProviderTestIssue(t *testing.T, provider *tickets.Provider, request string) string {
	t.Helper()
	ticket, err := provider.Issue(t.Context(), request, &idp.LoginIdentity{Subject: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	return provider.CallbackURL() + "?" + url.Values{"state": {request}, "ticket": {ticket}}.Encode()
}
func identityProviderTestClaims(t *testing.T, response *httptest.ResponseRecorder) jwt.MapClaims {
	t.Helper()
	if response.Code != http.StatusSeeOther {
		t.Fatal("Caddy handler failed ticket completion", response.Code)
	}
	raw := strings.TrimPrefix(response.Header().Get("Authorization"), "Bearer ")
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return []byte("synthetic-lifecycle-signing-secret"), nil }, jwt.WithValidMethods([]string{"HS512"}))
	if err != nil || !token.Valid {
		t.Fatal("ticket callback did not issue independently valid JWT", err)
	}
	claims := token.Claims.(jwt.MapClaims)
	id, _ := claims["id"].(string)
	nonce, _ := claims["nonce"].(string)
	methods, ok := claims["amr"].([]any)
	if id == "" || id == "alice" || nonce == "" || claims["sub"] != "alice" || claims["origin"] != "application" || !ok || len(methods) != 1 || methods[0] != "federated" {
		t.Fatal("ticket callback lost local identity or fabricated authentication evidence")
	}
	return claims
}

func TestAppIdentityProviderBindingsRejectBeforeStorage(t *testing.T) {
	for _, kind := range []string{"duplicate", "builtin_collision", "realm_collision", "store_realm_collision", "unknown_reference", "descriptor_error", "descriptor_nil", "descriptor_builtin", "native_descriptor", "null", "unknown_driver", "wrong_interface", "unknown_field"} {
		t.Run(kind, func(t *testing.T) {
			failure := ""
			if strings.HasPrefix(kind, "descriptor_") {
				failure = kind
			}
			app, module, probe := identityProviderTestApp(t, failure)
			switch kind {
			case "duplicate":
				app.IdentityProviderConfigs = append(app.IdentityProviderConfigs, app.IdentityProviderConfigs[0])
			case "builtin_collision":
				app.Config.IdentityProviders = []*idp.IdentityProviderConfig{lifecycleOAuth("https://unused.example.test", "application", 0)}
			case "realm_collision":
				builtin := lifecycleOAuth("https://unused.example.test", "other", 0)
				builtin.Params["realm"] = "application"
				app.Config.IdentityProviders = []*idp.IdentityProviderConfig{builtin}
				app.Config.AuthenticationPortals[0].IdentityProviders = append(app.Config.AuthenticationPortals[0].IdentityProviders, "other")
			case "store_realm_collision":
				app.Config.IdentityStores = lifecycleConfig().IdentityStores
				app.Config.IdentityStores[0].Params["realm"] = "application"
				app.Config.AuthenticationPortals[0].IdentityStores = []string{"local"}
			case "unknown_reference":
				app.Config.AuthenticationPortals[0].IdentityProviders = []string{"missing"}
			case "native_descriptor":
				descriptor, err := module.IdentityProviderConfig()
				if err != nil {
					t.Fatal(err)
				}
				app.Config.ExternalIdentityProviders = []*idp.ExternalIdentityProviderConfig{descriptor}
			case "null":
				app.IdentityProviderConfigs[0] = json.RawMessage(`null`)
			case "unknown_driver":
				app.IdentityProviderConfigs[0] = json.RawMessage(`{"driver":"unknown"}`)
			case "wrong_interface":
				app.IdentityProviderConfigs[0] = json.RawMessage(`{"driver":"test_wrong"}`)
			case "unknown_field":
				app.IdentityProviderConfigs[0] = json.RawMessage(`{"driver":"sqlite","password":"private-sentinel"}`)
			}
			before, _ := json.Marshal(app)
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("invalid binding accepted or disclosed private plugin details", err)
			}
			after, _ := json.Marshal(app)
			if string(before) != string(after) || probe.constructed.Load() != 0 || app.server != nil {
				t.Fatal("preflight rejection mutated declarations or constructed a provider")
			}
			if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
				t.Fatal("preflight rejection created ticket storage")
			}
		})
	}
}

func TestAppIdentityProviderSelectionDefaults(t *testing.T) {
	app, _, probe := identityProviderTestApp(t, "")
	app.Config.AuthenticationPortals[0].IdentityProviders = nil
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
	identityProviderTestBegin(t, app, "portal", backend.Provider)
	if probe.constructed.Load() != 1 || probe.lookups.Load() != 1 {
		t.Fatal("omitted backend selection lost declared provider default")
	}
}

func TestAppIdentityProviderExplicitSelection(t *testing.T) {
	app, _, probe := identityProviderTestApp(t, "")
	other := sqliteTicketTestConfig(t)
	other.Name, other.Realm = "other", "other"
	app.IdentityProviderConfigs = append(app.IdentityProviderConfigs, caddyconfig.JSONModuleObject(other, "driver", "sqlite", nil))
	app.Config.AuthenticationPortals[0].IdentityProviders = []string{"other"}
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
	response, err := identityProviderTestRequest(app, "portal", backend.CallbackURL())
	if err != nil || response.Code != http.StatusBadRequest || probe.lookups.Load() != 0 || response.Header().Get("Location") != "" {
		t.Fatal("explicit selection exposed an unselected provider", response.Code, err)
	}
}

func TestAppIdentityProviderSharedIdentitySnapshotsAndDrain(t *testing.T) {
	app, module, probe := identityProviderTestApp(t, "")
	source, _ := json.Marshal(app.Config.AuthenticationPortals[0])
	var shared authn.PortalConfig
	if err := json.Unmarshal(source, &shared); err != nil {
		t.Fatal(err)
	}
	shared.Name = "shared"
	app.Config.AuthenticationPortals = append(app.Config.AuthenticationPortals, &shared)
	before, _ := json.Marshal(app)
	cancel, err := credentialTestApp(t, app)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(app)
	if string(before) != string(after) || probe.constructed.Load() != 1 {
		t.Fatal("shared provider binding mutated declarations or constructed multiple handles")
	}
	backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
	var claims jwt.MapClaims
	for _, portal := range []string{"portal", "shared"} {
		request, cookie := identityProviderTestBegin(t, app, portal, backend.Provider)
		callback := identityProviderTestIssue(t, backend.Provider, request)
		response, err := identityProviderTestRequest(app, portal, callback, cookie)
		if err != nil {
			t.Fatal(err)
		}
		current := identityProviderTestClaims(t, response)
		if claims != nil && (current["id"] != claims["id"] || current["nonce"] == claims["nonce"]) {
			t.Fatal("shared provider lost its attachment or reused access-token nonce")
		}
		claims = current
	}
	attached, err := backend.IdentityAttachment().Store()
	if err != nil {
		t.Fatal(err)
	}
	previous, err := attached.ResolveExternalAccount(t.Context(), identity.ExternalAccount{Provider: module.Name, Kind: "sqlite-ticket", Issuer: module.IssuerURL, Subject: "alice"}, false)
	if err != nil || previous.Evidence.UserID != claims["id"] {
		t.Fatal("signed identity was not bound to the provider attachment", err)
	}
	// A real admitted handler waits inside Login while app cleanup closes admission.
	hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
	backend.probe.hold.Store(hold)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(hold.release) })
	type result struct {
		response *httptest.ResponseRecorder
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		response, err := identityProviderTestRequest(app, "portal", backend.CallbackURL())
		completed <- result{response, err}
	}()
	awaitLifecycle(t, hold.entered, "admitted provider request")
	probe.onClose = func() {
		if _, err := app.server.GetPortalByName("portal"); !errors.Is(err, authcrunch.ErrServerClosed) {
			t.Error("provider closed before root consumer")
		}
	}
	cancel()
	if probe.cleaned.Load() != 1 || probe.closed.Load() != 0 {
		t.Fatal("module cancellation closed runtime provider")
	}
	done := make(chan struct{})
	go func() { _ = app.Cleanup(); close(done) }()
	waitDisposing(t, app)
	if probe.closed.Load() != 0 {
		t.Fatal("provider closed before request drain")
	}
	if _, err := identityProviderTestRequest(app, "portal", backend.CallbackURL()); err == nil {
		t.Fatal("retiring app admitted another handler")
	}
	releaseOnce.Do(func() { close(hold.release) })
	awaitLifecycle(t, done, "provider handler drain")
	outcome := <-completed
	if outcome.err != nil || outcome.response.Code != http.StatusFound {
		t.Fatal("admitted handler lost provider while cleanup waited", outcome.err)
	}
	if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 || backend.Configured() {
		t.Fatal("retired provider was not closed exactly once", err)
	}
	probe.onClose = nil
	probe.hold.Store(nil)
	target, err := url.Parse(outcome.response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, entry := range outcome.response.Result().Cookies() {
		if entry.Name == module.CookieName {
			cookie = entry
		}
	}
	if cookie == nil {
		t.Fatal("admitted request lost its pending cookie")
	}
	var restored App
	if err := json.Unmarshal(before, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err := credentialTestApp(t, &restored); err != nil {
		t.Fatal(err)
	}
	current := restored.identityProviders[0].module.(*identityProviderTestModule).backend
	if current == backend || probe.constructed.Load() != 2 {
		t.Fatal("JSON restoration reused the retired provider")
	}
	callback := identityProviderTestIssue(t, current.Provider, target.Query().Get("request"))
	response, err := identityProviderTestRequest(&restored, "portal", callback, cookie)
	if err != nil {
		t.Fatal(err)
	}
	fresh := identityProviderTestClaims(t, response)
	if fresh["id"] == claims["id"] {
		t.Fatal("pending ticket persistence incorrectly preserved private in-memory identity")
	}
	restoredAttachment, err := current.IdentityAttachment().Store()
	if err != nil {
		t.Fatal(err)
	}
	accepted := false
	err = restoredAttachment.WithRefreshIdentity(t.Context(), previous.Evidence, func(identity.RefreshIdentity) error { accepted = true; return nil })
	if !errors.Is(err, identity.ErrRefreshIdentityDenied) || accepted {
		t.Fatal("retired provider proof authenticated against new private memory", err)
	}
}

func TestAppIdentityProviderFailedCandidates(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_unsafe", "construct", "name", "realm", "kind", "driver", "unready", "readiness_panic", "cookie_collision", "root"} {
		t.Run(failure, func(t *testing.T) {
			app, _, probe := identityProviderTestApp(t, failure)
			switch failure {
			case "cookie_collision":
				app.Config.AuthenticationPortals[0].CookieConfig.AccessTokenCookieName = "APP_TICKET_BINDING"
			case "root":
				app.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
			}
			_, err := credentialTestApp(t, app)
			if err == nil || strings.Contains(err.Error(), "private-sentinel") || app.server != nil {
				t.Fatal("failed candidate published runtime or disclosed private plugin data", err)
			}
			expected := int64(1)
			if failure == "nil" || strings.HasPrefix(failure, "typed_nil") {
				expected = 0
			}
			if probe.constructed.Load() != 1 || probe.closed.Load() != expected {
				t.Fatal("failed candidate lost factory or closer ownership")
			}
			_ = app.Cleanup()
			if probe.closed.Load() != expected {
				t.Fatal("failed candidate disposed provider twice")
			}
		})
	}
}

func TestAppIdentityProviderPartialBatchReverseCleanup(t *testing.T) {
	for _, failure := range []string{"construct", "typed_nil_unsafe_error"} {
		t.Run(failure, func(t *testing.T) {
			app := new(App)
			var order []int
			var probes []*claimsTestState
			for i := range 3 {
				config := sqliteTicketTestConfig(t)
				config.Name = fmt.Sprintf("provider%d", i)
				config.Realm = config.Name
				probe := new(claimsTestState)
				index := i
				probe.onClose = func() { order = append(order, index) }
				mode := ""
				if i == 0 {
					mode = "close_panic"
				}
				if i == 2 {
					mode = failure
				}
				module := &identityProviderTestModule{SQLiteTicketIdentityProvider: *config, probe: probe, Failure: mode}
				descriptor, err := module.IdentityProviderConfig()
				if err != nil {
					t.Fatal(err)
				}
				app.identityProviders = append(app.identityProviders, preparedIdentityProvider{config: *descriptor, module: module})
				probes = append(probes, probe)
			}
			providers, closers, err := app.attachIdentityProviders(t.Context())
			if err == nil || providers != nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("partial construction failure was lost", err)
			}
			if err := closePluginResources(closers); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("cleanup did not contain disposal failure", err)
			}
			expected := []int{2, 1, 0}
			if failure == "typed_nil_unsafe_error" {
				expected = []int{1, 0}
			}
			if !slices.Equal(order, expected) {
				t.Fatal("cleanup did not continue in reverse order", order)
			}
			for i, probe := range probes {
				want := int64(1)
				if i == 2 && failure == "typed_nil_unsafe_error" {
					want = 0
				}
				if probe.constructed.Load() != 1 || probe.closed.Load() != want {
					t.Fatal("partial batch leaked or double closed provider")
				}
			}
		})
	}
}

func TestAppIdentityProviderPersistentStart(t *testing.T) {
	for _, failure := range []string{"", "construct"} {
		t.Run("factory="+failure, func(t *testing.T) {
			app, module, probe := identityProviderTestApp(t, failure)
			app.Config.State = &state.Config{Directory: filepath.Join(registrationTestDirectory(t), "state")}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			if app.server != nil || probe.constructed.Load() != 0 {
				t.Fatal("persistent Provision constructed ticket runtime")
			}
			for _, path := range []string{module.Path, app.Config.State.Directory} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("persistent Provision created storage")
				}
			}
			err := app.Start()
			if (err != nil) != (failure != "") || probe.constructed.Load() != 1 {
				t.Fatal("Start lost prepared provider", err)
			}
			if err == nil {
				backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
				identityProviderTestBegin(t, app, "portal", backend.Provider)
			} else if app.server != nil {
				t.Fatal("failed Start published runtime")
			}
			if err := app.Cleanup(); err != nil || probe.closed.Load() != 1 {
				t.Fatal("persistent root leaked provider", err)
			}
		})
	}
}

func TestAppIdentityProviderFailedReplacementPreservesPending(t *testing.T) {
	active, _, probe := identityProviderTestApp(t, "")
	snapshot, _ := json.Marshal(active)
	if _, err := credentialTestApp(t, active); err != nil {
		t.Fatal(err)
	}
	backend := active.identityProviders[0].module.(*identityProviderTestModule).backend
	request, cookie := identityProviderTestBegin(t, active, "portal", backend.Provider)
	callback := identityProviderTestIssue(t, backend.Provider, request)
	var candidate App
	if err := json.Unmarshal(snapshot, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate.Config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"api key auth realm other portal missing"}
	if _, err := credentialTestApp(t, &candidate); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if probe.constructed.Load() != 2 || probe.closed.Load() != 1 || !backend.Configured() {
		t.Fatal("rejected candidate closed active provider")
	}
	response, err := identityProviderTestRequest(active, "portal", callback, cookie)
	if err != nil {
		t.Fatal(err)
	}
	identityProviderTestClaims(t, response)
}

func TestAppIdentityProviderRechecksAttachedIdentityBeforeSigning(t *testing.T) {
	for _, mode := range []string{"revoked", "mfa"} {
		t.Run(mode, func(t *testing.T) {
			failure := ""
			if mode == "revoked" {
				failure = "revoke"
			}
			app, _, _ := identityProviderTestApp(t, failure)
			if mode == "mfa" {
				app.Config.AuthenticationPortals[0].UserTransformerConfigs = []*transformer.Config{{Matchers: []string{"exact match realm application"}, Actions: []string{"require totp"}}}
			}
			if _, err := credentialTestApp(t, app); err != nil {
				t.Fatal(err)
			}
			backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
			request, cookie := identityProviderTestBegin(t, app, "portal", backend.Provider)
			callback := identityProviderTestIssue(t, backend.Provider, request)
			response, err := identityProviderTestRequest(app, "portal", callback, cookie)
			expected := http.StatusUnauthorized
			if mode == "mfa" {
				expected = http.StatusForbidden
			}
			if err != nil || response.Code != expected || response.Header().Get("Authorization") != "" {
				t.Fatal("ticket bypassed current local proof or actual factor requirements", response.Code, err)
			}
			replay, err := identityProviderTestRequest(app, "portal", callback, cookie)
			if err != nil || replay.Code != http.StatusUnauthorized || replay.Header().Get("Authorization") != "" {
				t.Fatal("post-consumption denial restored ticket authority", replay.Code, err)
			}
		})
	}
}

func TestAppIdentityProviderCloseFailure(t *testing.T) {
	app, _, probe := identityProviderTestApp(t, "close")
	if _, err := credentialTestApp(t, app); err != nil {
		t.Fatal(err)
	}
	backend := app.identityProviders[0].module.(*identityProviderTestModule).backend
	err := app.Cleanup()
	if err == nil || strings.Contains(err.Error(), "private-sentinel") || probe.closed.Load() != 1 || backend.Configured() {
		t.Fatal("cleanup lost sanitized error or runtime ownership", err)
	}
	if repeated := app.Cleanup(); repeated != err || probe.closed.Load() != 1 {
		t.Fatal("repeated cleanup changed outcome or ownership")
	}
}
