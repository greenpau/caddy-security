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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// The subprocess runs actual Caddy listeners, routes, and config replacement.
// Keep Caddy's process-global state and failure cases out of other package tests.
func TestCaddyLifecycleE2E(t *testing.T) {
	t.Setenv("CADDY_SECURITY_LIFECYCLE_EMPTY", "")
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyLifecycleProcess$", "-test.v", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_LIFECYCLE_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Caddy lifecycle subprocess: %v\n%s", err, output)
	}
}

var lifecycleProbes = struct {
	sync.Mutex
	apps map[string]*App
}{apps: make(map[string]*App)}

type lifecycleHold struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

var lifecycleHolds sync.Map

type lifecycleProbe struct {
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
}

func (lifecycleProbe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.security_lifecycle_probe", New: func() caddy.Module { return new(lifecycleProbe) }}
}

func (p *lifecycleProbe) Provision(ctx caddy.Context) error {
	app, err := ctx.App("security")
	if err != nil {
		return err
	}
	lifecycleProbes.Lock()
	lifecycleProbes.apps[p.Label] = app.(*App)
	lifecycleProbes.Unlock()
	if p.Failure == "provision" {
		return fmt.Errorf("injected downstream provisioning failure")
	}
	return nil
}

func (p *lifecycleProbe) Validate() error {
	if p.Failure == "validate" {
		return fmt.Errorf("injected downstream validation failure")
	}
	return nil
}

func (p *lifecycleProbe) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	w.Header().Set("X-Lifecycle", p.Label)
	if raw, ok := lifecycleHolds.Load(r.Header.Get("X-Lifecycle-Hold")); ok {
		w = &lifecycleHeldWriter{ResponseWriter: w, hold: raw.(*lifecycleHold), ctx: r.Context()}
	}
	return next.ServeHTTP(w, r)
}

type lifecycleHeldWriter struct {
	http.ResponseWriter
	hold *lifecycleHold
	ctx  context.Context
}

func (w *lifecycleHeldWriter) wait() {
	w.hold.once.Do(func() {
		close(w.hold.entered)
		select {
		case <-w.hold.release:
		case <-w.ctx.Done():
		}
	})
}

func (w *lifecycleHeldWriter) WriteHeader(status int) {
	w.wait()
	w.ResponseWriter.WriteHeader(status)
}

func (w *lifecycleHeldWriter) Write(data []byte) (int, error) {
	w.wait()
	return w.ResponseWriter.Write(data)
}

type lifecycleHeaderCounter struct {
	http.ResponseWriter
	headers int
}

func (w *lifecycleHeaderCounter) WriteHeader(status int) {
	w.headers++
	w.ResponseWriter.WriteHeader(status)
}

func TestLifecycleHeldWriter(t *testing.T) {
	for _, status := range []int{0, http.StatusCreated} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			recorder := httptest.NewRecorder()
			counter := &lifecycleHeaderCounter{ResponseWriter: recorder}
			hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
			close(hold.release)
			writer := &lifecycleHeldWriter{ResponseWriter: counter, hold: hold, ctx: t.Context()}
			wantHeaders, wantStatus := 0, http.StatusOK
			if status != 0 {
				writer.WriteHeader(status)
				wantHeaders, wantStatus = 1, status
			}
			for _, body := range []string{"first", "second"} {
				if _, err := writer.Write([]byte(body)); err != nil {
					t.Fatal(err)
				}
			}
			if counter.headers != wantHeaders || recorder.Code != wantStatus || recorder.Body.String() != "firstsecond" {
				t.Fatalf("hold changed HTTP response: headers=%d status=%d body=%q", counter.headers, recorder.Code, recorder.Body.String())
			}
		})
	}
}

type lifecycleFailStart struct {
	lifecycleProbe
}

func (lifecycleFailStart) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security_lifecycle_fail_start", New: func() caddy.Module { return new(lifecycleFailStart) }}
}

func (*lifecycleFailStart) Start() error { return fmt.Errorf("injected app start failure") }
func (*lifecycleFailStart) Stop() error  { return nil }

func init() {
	caddy.RegisterModule(lifecycleProbe{})
	caddy.RegisterModule(lifecycleFailStart{})
}

func capturedLifecycleApp(t *testing.T, label string) *App {
	t.Helper()
	lifecycleProbes.Lock()
	defer lifecycleProbes.Unlock()
	app := lifecycleProbes.apps[label]
	if app == nil {
		t.Fatalf("security runtime not captured for %s", label)
	}
	return app
}

func lifecycleAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func lifecycleCaddyConfig(t *testing.T, addr, label, failure string, cfg *authcrunch.Config, secrets ...json.RawMessage) []byte {
	t.Helper()
	apps := map[string]any{
		"security": map[string]any{"config": cfg, "secrets_managers": secrets},
		"http": map[string]any{
			"grace_period": "10ms",
			"servers": map[string]any{"test": map[string]any{
				"listen": []string{addr}, "automatic_https": map[string]bool{"disable": true}, "protocols": []string{"h1"},
				"routes": []any{map[string]any{"handle": []any{
					map[string]any{"handler": "security_lifecycle_probe", "label": label, "failure": failure},
					map[string]any{"handler": "subroute", "routes": []any{
						map[string]any{"match": []any{map[string]any{"path": []string{"/auth/*"}}}, "handle": []any{
							map[string]any{"handler": "authenticator", "route_matcher": "*", "portal_name": "portal"},
						}},
						map[string]any{"match": []any{map[string]any{"path": []string{"/protected"}}}, "handle": []any{
							map[string]any{"handler": "authentication", "providers": map[string]any{"authorizer": map[string]any{"route_matcher": "*", "gatekeeper_name": "policy"}}},
							map[string]any{"handler": "static_response", "status_code": 204},
						}},
					}},
				}}},
			}},
		},
	}
	if failure == "start" {
		apps["security_lifecycle_fail_start"] = map[string]any{"label": label}
	}
	data, err := json.Marshal(map[string]any{
		"admin":   map[string]any{"disabled": true, "config": map[string]bool{"persist": false}},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps":    apps,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func lifecycleHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func lifecycleGET(t *testing.T, client *http.Client, url, label, token string, status int) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal("incomplete HTTP response", err)
	}
	if resp.StatusCode != status || resp.Header.Get("X-Lifecycle") != label {
		t.Fatalf("%s: status=%d deployment=%q, want %d/%s", url, resp.StatusCode, resp.Header.Get("X-Lifecycle"), status, label)
	}
}

func lifecycleLogin(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	login, err := authclient.NewClient(&authclient.Config{BaseURL: base + "/auth", Realm: "local", Username: "alice", Password: lifecyclePassword}, authclient.Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := login.Authenticate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return credentials.AccessToken
}

func TestCaddyLifecycleProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_LIFECYCLE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	addr := lifecycleAddress(t)
	base := "http://" + addr
	client := lifecycleHTTPClient()
	defer client.CloseIdleConnections()
	load := func(label, failure string, cfg *authcrunch.Config) error {
		return caddy.Load(lifecycleCaddyConfig(t, addr, label, failure, cfg), true)
	}
	initialConfig := lifecycleConfig()
	initialConfig.UserRegistration = nil
	if err := json.Unmarshal([]byte(`{"credentials":{},"messaging":{},"user_registration":{}}`), initialConfig); err != nil {
		t.Fatal(err)
	}
	if err := load("initial", "", initialConfig); err != nil {
		t.Fatal(err)
	}
	token := lifecycleLogin(t, client, base)
	lifecycleGET(t, client, base+"/protected", "initial", token, http.StatusNoContent)
	initial := capturedLifecycleApp(t, "initial")

	t.Run("borrowed_route_context_cleanup", func(t *testing.T) {
		ctx, cancel := caddy.NewContext(caddy.ActiveContext())
		defer cancel()
		_, err := ctx.LoadModuleByID("http.handlers.authenticator", json.RawMessage(`{"route_matcher":"*","portal_name":"portal"}`))
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		if _, err := initial.getPortal("portal"); err != nil {
			t.Fatal("cleaning up one borrowed route disposed the app", err)
		}
		lifecycleGET(t, client, base+"/protected", "initial", token, http.StatusNoContent)
	})

	t.Run("invalid_and_abandoned_candidates", func(t *testing.T) {
		bad := lifecycleConfig()
		bad.AuthorizationPolicies[0].AccessListRules[0].Conditions = []string{"invalid lifecycle condition"}
		if err := load("invalid", "", bad); err == nil {
			t.Fatal("invalid runtime loaded")
		}
		for _, tc := range lifecycleInvalidConfigs {
			t.Run(tc.name, func(t *testing.T) {
				cfg := lifecycleConfig()
				if err := json.Unmarshal([]byte(tc.patch), cfg); err != nil {
					t.Fatal(err)
				}
				if err := load("invalid-"+tc.name, "", cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("invalid replacement: %v; want path %s", err, tc.want)
				}
				lifecycleGET(t, client, base+"/protected", "initial", token, http.StatusNoContent)
			})
		}
		for _, phase := range []string{"provision", "validate", "start"} {
			if err := load(phase, phase, lifecycleConfig()); err == nil {
				t.Fatalf("%s failure accepted", phase)
			}
			assertServerClosed(t, capturedLifecycleApp(t, phase))
			lifecycleGET(t, client, base+"/protected", "initial", token, http.StatusNoContent)
		}
		var config caddy.Config
		if err := json.Unmarshal(lifecycleCaddyConfig(t, addr, "validation-only", "", lifecycleConfig()), &config); err != nil {
			t.Fatal(err)
		}
		if err := caddy.Validate(&config); err != nil {
			t.Fatal(err)
		}
		assertServerClosed(t, capturedLifecycleApp(t, "validation-only"))
		lifecycleGET(t, client, base+"/protected", "initial", token, http.StatusNoContent)
	})

	t.Run("reload_with_portal_and_gatekeeper_in_flight", func(t *testing.T) {
		oldPortal, _ := initial.getPortal("portal")
		oldGate, _ := initial.getGatekeeper("policy")
		var held []*lifecycleHold
		results := make(chan error, 2)
		for _, path := range []string{"/auth/login", "/protected"} {
			hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
			held = append(held, hold)
			lifecycleHolds.Store(path, hold)
			t.Cleanup(func() { lifecycleHolds.Delete(path) })
			go func() {
				req, _ := http.NewRequest(http.MethodGet, base+path, nil)
				req.Header.Set("X-Lifecycle-Hold", path)
				resp, err := client.Do(req)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
					want := http.StatusOK
					if path == "/protected" {
						want = http.StatusFound
					}
					if resp.StatusCode != want || resp.Header.Get("X-Lifecycle") != "initial" {
						err = fmt.Errorf("old in-flight request: status=%d deployment=%q", resp.StatusCode, resp.Header.Get("X-Lifecycle"))
					}
				}
				results <- err
			}()
		}
		var releaseOnce sync.Once
		release := func() {
			releaseOnce.Do(func() {
				for _, hold := range held {
					close(hold.release)
				}
			})
		}
		defer release()
		for _, hold := range held {
			awaitLifecycle(t, hold.entered, "request inside AuthCrunch")
		}
		done := make(chan struct{})
		var loadErr error
		// The JSON API permits omitted UI/cookie settings. Test defaults through
		// an actual replacement and subsequent login, not just construction.
		cfg := lifecycleParsedConfig(t)
		cfg.AuthenticationPortals[0].UI = nil
		cfg.AuthenticationPortals[0].CookieConfig = nil
		go func() { loadErr = load("replacement", "", cfg); close(done) }()
		waitDisposing(t, initial)
		// Exceed Caddy's 10ms HTTP grace period. Cleanup must still drain calls.
		time.Sleep(30 * time.Millisecond)
		if _, err := initial.server.GetPortalByName("portal"); err != nil {
			t.Fatal("old runtime closed before request drain", err)
		}
		select {
		case <-done:
			t.Fatal("reload returned before owned request drain")
		default:
		}
		// Caddy has published and is serving the new HTTP stack during old cleanup.
		lifecycleGET(t, client, base+"/protected", "replacement", token, http.StatusNoContent)
		release()
		awaitLifecycle(t, done, "Caddy reload")
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		for range held {
			select {
			case err := <-results:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("old HTTP worker survived reload")
			}
		}
		assertServerClosed(t, initial)
		r := httptest.NewRequest(http.MethodGet, base+"/auth/login", nil)
		w := httptest.NewRecorder()
		if err := oldPortal.ServeHTTP(t.Context(), w, r, requests.NewRequest()); err != nil || w.Code != http.StatusServiceUnavailable {
			t.Fatal("retained portal served after reload", err, w.Code)
		}
		w = httptest.NewRecorder()
		ar := requests.NewAuthorizationRequest()
		if err := oldGate.Authenticate(w, r, ar); err != nil || w.Code != http.StatusServiceUnavailable || ar.Response.Authorized {
			t.Fatal("retained gatekeeper served after reload", err, w.Code)
		}
		lifecycleLogin(t, client, base)
	})

	t.Run("failed_construction_cancels_earlier_provider", func(t *testing.T) {
		entered, canceled, abort := make(chan struct{}), make(chan struct{}), make(chan struct{})
		upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/first" {
				close(entered)
				select {
				case <-r.Context().Done():
				case <-abort:
				}
				close(canceled)
				return
			}
			select {
			case <-entered:
			case <-r.Context().Done():
				return
			case <-abort:
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer upstream.Close()
		defer close(abort)
		cfg := lifecycleConfig()
		for _, name := range []string{"first", "second"} {
			delay := 0
			if name == "first" {
				delay = 1
			}
			provider := lifecycleOAuth(upstream.URL, name, delay)
			provider.Params["metadata_url"] = upstream.URL + "/" + name
			cfg.IdentityProviders = append(cfg.IdentityProviders, provider)
		}
		done := make(chan struct{})
		var err error
		go func() { err = load("failed-provider", "", cfg); close(done) }()
		awaitLifecycle(t, done, "failed Caddy construction")
		if err == nil {
			t.Fatal("broken provider constructed")
		}
		awaitLifecycle(t, canceled, "earlier provider cancellation")
		lifecycleGET(t, client, base+"/protected", "replacement", token, http.StatusNoContent)
	})

	t.Run("late_host_failure_cancels_discovery", func(t *testing.T) {
		entered, canceled, abort := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var upstream *httptest.Server
		upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/slow" {
				close(entered)
				select {
				case <-r.Context().Done():
				case <-abort:
				}
				close(canceled)
				return
			}
			if r.URL.Path == "/metadata" {
				select {
				case <-entered:
				case <-r.Context().Done():
					return
				case <-abort:
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"authorization_endpoint": upstream.URL + "/authorize", "token_endpoint": upstream.URL + "/token", "jwks_uri": upstream.URL + "/keys"})
				return
			}
			_, _ = w.Write([]byte(lifecycleJWKS))
		}))
		defer upstream.Close()
		defer close(abort)
		cfg := lifecycleConfig()
		// The synchronous second provider waits for the first provider's delayed
		// request. Both construct successfully before a later host module fails.
		slow := lifecycleOAuth(upstream.URL, "slow", 1)
		slow.Params["metadata_url"] = upstream.URL + "/slow"
		cfg.IdentityProviders = []*idp.IdentityProviderConfig{slow, lifecycleOAuth(upstream.URL, "ready", 0)}
		if err := load("abandoned-worker", "validate", cfg); err == nil {
			t.Fatal("late host failure accepted")
		}
		assertServerClosed(t, capturedLifecycleApp(t, "abandoned-worker"))
		awaitLifecycle(t, canceled, "abandoned candidate network cancellation")
		lifecycleGET(t, client, base+"/protected", "replacement", token, http.StatusNoContent)
	})

	t.Run("cleanup_before_delayed_discovery", func(t *testing.T) {
		cfg := lifecycleConfig()
		// A leaked worker would still be sleeping at the final stack check.
		cfg.IdentityProviders = []*idp.IdentityProviderConfig{lifecycleOAuth("https://127.0.0.1:1", "delayed", 3600)}
		if err := load("abandoned-delay", "validate", cfg); err == nil {
			t.Fatal("late host failure accepted")
		}
		assertServerClosed(t, capturedLifecycleApp(t, "abandoned-delay"))
	})

	t.Run("persistent_files_and_writer_exclusion", func(t *testing.T) {
		dir := t.TempDir()
		keyFile, registrationFile := filepath.Join(dir, "oidc.pem"), filepath.Join(dir, "applications.json")
		if err := oidc.GenerateSigningKeyFile(keyFile); err != nil {
			t.Fatal(err)
		}
		registration, err := oidc.NewClientConfig(oidc.ClientConfig{RedirectURIs: []string{"https://client.example.test/callback"}})
		if err != nil {
			t.Fatal(err)
		}
		cfg := lifecycleConfig()
		cfg.OAuthApplications = []*oidc.OAuthApplicationConfig{{Name: "website", Client: registration}}
		cfg.AuthenticationPortals[0].OIDCProvider = &oidc.Config{Enabled: true, Issuer: "https://portal.example.test/auth", Realms: []string{"local"}, SigningKeyFiles: []string{keyFile}, Clients: []*oidc.ClientConfig{registration}}
		serialized, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(registrationFile, serialized, 0600); err != nil {
			t.Fatal(err)
		}
		keyBefore := lifecycleReadFile(t, keyFile)
		if err := load("oidc-first", "", cfg); err != nil {
			t.Fatal(err)
		}
		first := capturedLifecycleApp(t, "oidc-first")
		var restored authcrunch.Config
		if err := json.Unmarshal(lifecycleReadFile(t, registrationFile), &restored); err != nil {
			t.Fatal(err)
		}
		if err := load("oidc-second", "", &restored); err != nil {
			t.Fatal(err)
		}
		assertServerClosed(t, first)
		second := capturedLifecycleApp(t, "oidc-second")
		runtimeData, err := json.Marshal(second.server.GetConfig())
		if err != nil {
			t.Fatal(err)
		}
		var runtimeCfg authcrunch.Config
		if err := json.Unmarshal(runtimeData, &runtimeCfg); err != nil {
			t.Fatal(err)
		}
		clientAfter := runtimeCfg.AuthenticationPortals[0].OIDCProvider.Clients[0]
		if clientAfter.ClientID != registration.ClientID || clientAfter.ClientSecret != registration.ClientSecret {
			t.Fatal("registration rotated on reload")
		}
		keyAfter := lifecycleReadFile(t, keyFile)
		registrationAfter := lifecycleReadFile(t, registrationFile)
		if !bytes.Equal(keyBefore, keyAfter) || !bytes.Equal(serialized, registrationAfter) {
			t.Fatal("persistent key or registration modified")
		}

		cfg = lifecycleConfig()
		usersFile := dir + "/identities//users.json"
		dangling := filepath.Join(dir, "dangling.json")
		if err := os.Symlink(usersFile, dangling); err != nil {
			t.Fatal(err)
		}
		cfg.IdentityStores[0].Params["path"] = dangling
		if err := load("dangling-file", "", cfg); err == nil || !strings.Contains(err.Error(), "cannot resolve identity path") {
			t.Fatalf("unresolved identity symlink accepted: %v", err)
		}
		if _, err := os.Stat(usersFile); !os.IsNotExist(err) {
			t.Fatalf("failed candidate wrote identity file: %v", err)
		}
		lifecycleGET(t, client, base+"/protected", "oidc-second", token, http.StatusNoContent)
		for _, pair := range [][2]string{
			{usersFile, dir + "/identities/USERS.JSON"},
			{dir + "/caf\u00e9.json", dir + "/cafe\u0301.json"},
		} {
			cfg.IdentityStores[0].Params["path"] = pair[0]
			aliasStore := lifecycleConfig().IdentityStores[0]
			aliasStore.Name = "alias"
			aliasStore.Params["realm"] = "alias"
			aliasStore.Params["path"] = pair[1]
			cfg.IdentityStores = append(cfg.IdentityStores[:1], aliasStore)
			if err := load("missing-file-alias", "", cfg); err == nil || !strings.Contains(err.Error(), "used by multiple stores") {
				t.Fatalf("aliases accepted before identity file creation: %v", err)
			}
			for _, path := range pair {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("alias candidate wrote identity file: %v", err)
				}
			}
			lifecycleGET(t, client, base+"/protected", "oidc-second", token, http.StatusNoContent)
		}
		cfg.IdentityStores = cfg.IdentityStores[:1]
		cfg.IdentityStores[0].Params["path"] = usersFile
		if err := load("file-owner", "", cfg); err != nil {
			t.Fatal(err)
		}
		fileToken := lifecycleLogin(t, client, base)
		before := lifecycleReadFile(t, usersFile)
		for _, path := range []string{usersFile, lifecycleParentAlias(t, filepath.Dir(usersFile)) + "/users.json"} {
			candidate := lifecycleConfig()
			candidate.IdentityStores[0].Params["path"] = path
			user := candidate.IdentityStores[0].Params["users"].([]any)[0].(map[string]any)
			user["password_overwrite_enabled"] = true
			user["password"] = "CandidateMustNotOverwrite42!"
			if err := load("file-conflict", "", candidate); err == nil || !strings.Contains(err.Error(), "already belongs") {
				t.Fatalf("writer conflict: %v", err)
			}
			if !bytes.Equal(before, lifecycleReadFile(t, usersFile)) {
				t.Fatal("failed candidate modified the live identity file")
			}
			lifecycleLogin(t, client, base)
		}
		lifecycleGET(t, client, base+"/protected", "file-owner", fileToken, http.StatusNoContent)
		owner := capturedLifecycleApp(t, "file-owner")
		if err := caddy.Stop(); err != nil {
			t.Fatal(err)
		}
		assertServerClosed(t, owner)
		if err := load("file-reopened", "", cfg); err != nil {
			t.Fatal(err)
		}
		after := lifecycleReadFile(t, usersFile)
		if !bytes.Equal(before, after) {
			t.Fatal("identity file changed across shutdown/reopen")
		}
		lifecycleGET(t, client, base+"/protected", "file-reopened", fileToken, http.StatusNoContent)
	})

	t.Run("resolved_instructions", func(t *testing.T) {
		t.Setenv("CADDY_SECURITY_INSTRUCTION_VALUE", lifecycleInstructionValue)
		previous := capturedLifecycleApp(t, "file-reopened")
		for _, tc := range []struct{ name, reference string }{
			{"environment", "{env.CADDY_SECURITY_INSTRUCTION_VALUE}"},
			{"secret", "secrets:lifecycle:input"},
		} {
			cfg := lifecycleInstructionsConfig(tc.reference)
			label := "instructions-" + tc.name
			data := lifecycleCaddyConfig(t, addr, label, "", cfg, json.RawMessage(`{"driver":"security_lifecycle"}`))
			if err := caddy.Load(data, true); err != nil {
				t.Fatal(err)
			}
			assertServerClosed(t, previous)
			previous = capturedLifecycleApp(t, label)
			data, err := json.Marshal(previous.server.GetConfig())
			if err != nil {
				t.Fatal(err)
			}
			var actual authcrunch.Config
			if err := json.Unmarshal(data, &actual); err != nil {
				t.Fatal(err)
			}
			assertLifecycleInstructions(t, &actual)
			lifecycleGET(t, client, base+"/protected", label, lifecycleLogin(t, client, base), http.StatusNoContent)
		}
		bad := lifecycleInstructionsConfig("secrets:lifecycle:missing")
		data := lifecycleCaddyConfig(t, addr, "missing-secret", "", bad, json.RawMessage(`{"driver":"security_lifecycle"}`))
		if err := caddy.Load(data, true); err == nil || !strings.Contains(err.Error(), "RawCredentialConfigs[0][2]") {
			t.Fatalf("missing raw credential secret accepted: %v", err)
		}
		lifecycleGET(t, client, base+"/protected", "instructions-secret", lifecycleLogin(t, client, base), http.StatusNoContent)
	})

	final := capturedLifecycleApp(t, "instructions-secret")
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	assertServerClosed(t, final)
	if err := final.Cleanup(); err != nil {
		t.Fatal(err)
	}
	// Close promises worker completion, not merely a closed admission flag.
	// Inspect only this library's stacks; Caddy owns other process-wide workers.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var stacks bytes.Buffer
		if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stacks.String(), "github.com/greenpau/go-authcrunch/") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("AuthCrunch workers survived final cleanup:\n%s", stacks.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func lifecycleReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatalf("persistent file %q is empty", path)
	}
	return data
}
