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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func caddyRefreshBrowserExecutable(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("AUTHCRUNCH_TEST_BROWSER"); configured != "" {
		return configured
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	if runtime.GOOS == "darwin" {
		path := "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Fatal("Chrome/Chromium is required for browser E2E; set AUTHCRUNCH_TEST_BROWSER to its executable")
	return ""
}

// Start with a bounded readiness wait and reap the process before reading its
// diagnostics. Chrome can exit before creating DevToolsActivePort; waiting only
// for the file hides the actual startup failure behind a timeout.
func startCaddyRefreshBrowser(ctx context.Context, chrome *exec.Cmd, profile string) (string, func(), error) {
	var diagnostic bytes.Buffer
	chrome.Stdout = &diagnostic
	chrome.Stderr = &diagnostic
	chrome.WaitDelay = time.Second
	if err := chrome.Start(); err != nil {
		return "", nil, fmt.Errorf("start browser %q: %w", chrome.Path, err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = chrome.Wait()
		close(done)
	}()
	stop := func() {
		select {
		case <-done:
		default:
			_ = chrome.Process.Kill()
			<-done
		}
	}
	failure := func(err error) (string, func(), error) {
		stop()
		return "", nil, fmt.Errorf("browser %q startup failed: %w\n%s", chrome.Path, err, diagnostic.String())
	}
	// Keep startup bounded inside the overall E2E deadline, including on
	// loaded CI runners.
	startup, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			if startup.Err() != nil {
				return failure(fmt.Errorf("waiting for debugging endpoint: %w", startup.Err()))
			}
			if waitErr != nil {
				return failure(fmt.Errorf("exited before exposing a debugging endpoint: %w", waitErr))
			}
			return failure(fmt.Errorf("exited before exposing a debugging endpoint"))
		case <-startup.Done():
			return failure(fmt.Errorf("waiting for debugging endpoint: %w", startup.Err()))
		case <-ticker.C:
			data, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
			if err != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) == 2 && lines[0] != "" && strings.HasPrefix(lines[1], "/devtools/browser/") {
				return "ws://127.0.0.1:" + lines[0] + lines[1], stop, nil
			}
		}
	}
}

// Only the test binary registers this module. Faults surround the real Caddy
// authenticator; they never mint credentials or implement refresh semantics.
type tokenRefreshBrowserProbe struct {
	Mount string `json:"mount"`
	state *tokenRefreshBrowserState
}
type tokenRefreshBrowserState struct {
	mu                                                               sync.Mutex
	rotations, rotationRequests, lookups, logouts, active, maxActive int
	staleRendered, cutNext, holdNext, held                           bool
	staleRelease, rotationRelease                                    chan struct{}
	loginRequests                                                    int
	holdLoginNext                                                    bool
	loginStarted, loginRelease                                       chan struct{}
}

var currentTokenRefreshBrowserProbe atomic.Pointer[tokenRefreshBrowserState]

func init() { caddy.RegisterModule(tokenRefreshBrowserProbe{}) }
func (tokenRefreshBrowserProbe) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.token_refresh_probe", New: func() caddy.Module { return &tokenRefreshBrowserProbe{state: currentTokenRefreshBrowserProbe.Load()} }}
}
func (m *tokenRefreshBrowserProbe) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	s := m.state
	control := m.Mount + "/_test/"
	if strings.HasPrefix(r.URL.Path, control) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		switch strings.TrimPrefix(r.URL.Path, control) {
		case "status":
			w.Header().Set("Content-Type", "application/json")
			return json.NewEncoder(w).Encode(map[string]any{"rotations": s.rotations, "requests": s.rotationRequests, "lookups": s.lookups, "logouts": s.logouts, "stale_rendered": s.staleRendered, "held": s.held, "max_active": s.maxActive})
		case "cut":
			s.cutNext = true
		case "hold":
			s.holdNext = true
			s.held = false
			s.rotationRelease = make(chan struct{})
		case "release_rotation":
			if s.rotationRelease != nil {
				close(s.rotationRelease)
				s.rotationRelease = nil
			}
		case "release":
			if s.staleRelease != nil {
				close(s.staleRelease)
				s.staleRelease = nil
			}
		case "signed-out":
			w.WriteHeader(200)
			return nil
		default:
			w.WriteHeader(404)
			return nil
		}
		w.WriteHeader(204)
		return nil
	}
	rotation := r.URL.Path == m.Mount+"/api/refresh_token"
	login := r.URL.Path == m.Mount+"/login"
	logout := r.URL.Path == m.Mount+"/api/logout"
	stale := r.URL.Path == m.Mount+"/portal" && r.URL.Query().Get("deferred") == "1"
	s.mu.Lock()
	cut := rotation && s.cutNext
	if rotation {
		s.rotationRequests++
		s.cutNext = false
	}
	if rotation || logout {
		s.active++
		s.maxActive = max(s.maxActive, s.active)
	}
	if r.URL.Path == m.Mount+"/api/refresh_session" {
		s.lookups++
	}
	if logout {
		s.logouts++
	}
	var hold <-chan struct{}
	if login {
		s.loginRequests++
		if s.holdLoginNext {
			s.holdLoginNext = false
			hold = s.loginRelease
			close(s.loginStarted)
		}
	}
	if rotation && s.holdNext {
		s.holdNext = false
		s.held = true
		hold = s.rotationRelease
	}
	s.mu.Unlock()
	if rotation || logout {
		defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
	}
	if hold != nil {
		select {
		case <-hold:
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
	if !rotation && !stale {
		return next.ServeHTTP(w, r)
	}
	recorder := httptest.NewRecorder()
	if err := next.ServeHTTP(recorder, r); err != nil {
		return err
	}
	s.mu.Lock()
	if rotation && recorder.Code == 200 {
		s.rotations++
	}
	release := s.staleRelease
	if stale {
		s.staleRendered = true
	}
	s.mu.Unlock()
	if stale {
		select {
		case <-release:
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
	for k, v := range recorder.Header() {
		w.Header()[k] = append([]string(nil), v...)
	}
	if cut {
		if recorder.Code != 200 {
			return fmt.Errorf("fault injection requires a committed refresh")
		}
		// Deliver the genuine Set-Cookie headers, then interrupt the response body.
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(200)
		_, err := w.Write([]byte("{"))
		return err
	}
	w.WriteHeader(recorder.Code)
	_, err := w.Write(recorder.Body.Bytes())
	return err
}

func tokenRefreshBrowserAdapter(t *testing.T, mount string) func([]byte) []byte {
	t.Helper()
	return func(data []byte) []byte {
		var config map[string]any
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatal(err)
		}
		count := 0
		var walk func(any)
		walk = func(value any) {
			switch v := value.(type) {
			case map[string]any:
				for k, child := range v {
					if k == "handle" {
						if handlers, ok := child.([]any); ok {
							for _, handler := range handlers {
								if h, ok := handler.(map[string]any); ok && h["handler"] == "authenticator" {
									v[k] = append([]any{map[string]any{"handler": "token_refresh_probe", "mount": mount}}, handlers...)
									count++
									break
								}
							}
						}
					}
					walk(child)
				}
			case []any:
				for _, child := range v {
					walk(child)
				}
			}
		}
		walk(config)
		if count != 1 {
			t.Fatalf("expected one real Caddy authenticator, got %d", count)
		}
		out, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
}

func TestCaddyTokenRefreshBrowserE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 360*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyTokenRefreshBrowserProcess$", "-test.v", "-test.timeout=340s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_REFRESH_BROWSER_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy browser refresh: %v\n%s", err, output)
	}
}

func TestCaddyTokenRefreshBrowserProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_REFRESH_BROWSER_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	browser := caddyRefreshBrowserExecutable(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	for _, tc := range []struct {
		name, mount, cookies, refresh, access, scenario string
		lifetime                                        int
	}{
		{"default root", "/", "", "AUTHP_REFRESH_TOKEN", "AUTHP_ACCESS_TOKEN", "coordination", 300},
		{"custom nested", "/tenant/auth", "cookie prefix BROWSER\ncookie refresh token name BROWSER_REFRESH", "BROWSER_REFRESH", "BROWSER_ACCESS_TOKEN", "coordination", 300},
		{"expired access continuation", "/auth", "", "AUTHP_REFRESH_TOKEN", "AUTHP_ACCESS_TOKEN", "continuation", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mount := strings.TrimSuffix(tc.mount, "/")
			state := &tokenRefreshBrowserState{staleRelease: make(chan struct{})}
			currentTokenRefreshBrowserProbe.Store(state)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
			defer cancel()
			body := tokenRefreshTestBlock(fmt.Sprintf("realms employees contractors\npublic origin PUBLIC_ORIGIN\nbase path BASE_PATH\naccess lifetime %d\nidle timeout 600\nabsolute timeout 1800\nbody transport enabled\nmax sessions 1", tc.lifetime))
			cookies := tc.cookies + "\ntrust logout redirect uri domain exact PUBLIC_HOST path exact " + mount + "/_test/signed-out" + "\ntrust login redirect uri domain exact PUBLIC_HOST path exact " + mount + "/_test/signed-out"
			f := newCaddyTokenRefreshFixture(t, tc.mount, body, cookies, 600, cert, key, roots, tokenRefreshBrowserAdapter(t, mount))
			if tc.scenario == "coordination" {
				testCaddyTokenRefreshHTTP(t, f, tc.refresh)
			}
			runCaddyRefreshBrowser(t, ctx, browser, cert, f.base, mount, tc.refresh, tc.access, tc.scenario)
		})
	}
}

func testCaddyTokenRefreshHTTP(t *testing.T, f *caddyTokenRefreshFixture, cookieName string) {
	t.Helper()
	browser := f.browser(t)
	login, issued := f.login(t, browser, "employees", "", 200)
	credential := tokenRefreshActiveCookie(t, issued, cookieName).Value
	headers := f.headers()
	headers.Set("Authorization", "Bearer expired-or-invalid")
	metadata, cookies := f.post(t, browser, "/api/refresh_session", struct{}{}, headers, 200)
	if metadata.SessionID != login.SessionID || metadata.RefreshToken != "" || metadata.AccessToken != "" || len(cookies) != 0 {
		t.Fatal("session lookup changed credentials or disclosed tokens")
	}
	for _, tc := range tokenRefreshHTTPCases(f.base, f.mount, cookieName, credential) {
		t.Run(tc.name, func(t *testing.T) {
			// Real valid cookies prove malformed input is rejected before rotation.
			request := tokenRefreshCaseRequest(t, f.base, tc)
			client := browser
			if _, explicit := tc.headers["Cookie"]; explicit {
				// The case already supplies real credentials. A jar would append
				// another cookie, masking mixed transport behind duplicate-cookie
				// validation and changing the duplicate count under test.
				client = f.client
			}
			if strings.HasPrefix(tc.name, "protected") {
				client = f.client
				request.Header.Del("Cookie")
				for _, cookie := range browser.Jar.Cookies(request.URL) {
					if cookie.Name == cookieName {
						request.AddCookie(cookie)
					}
				}
			}
			resp, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, expected %d", resp.StatusCode, tc.status)
			}
			if tc.status == 405 && resp.Header.Get("Allow") != "POST" {
				t.Fatal("wrong allowed method")
			}
			if resp.Header.Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unexpected CORS allowance")
			}
			if !strings.HasPrefix(tc.name, "protected") && resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("refresh response permits caching")
			}
		})
	}
	// An older SID cannot consume the new family's cookie; the same credential
	// must still succeed immediately with the actual SID.
	headers = f.headers()
	headers.Set("X-Authcrunch-Refresh-Session", "older-family")
	f.post(t, browser, "/api/refresh_token", struct{}{}, headers, 401)
	headers.Set("X-Authcrunch-Refresh-Session", login.SessionID)
	rotated, _ := f.post(t, browser, "/api/refresh_token", struct{}{}, headers, 200)
	if rotated.SessionID != login.SessionID {
		t.Fatal("rejected request consumed the family")
	}
	f.post(t, browser, "/api/logout", struct{}{}, f.headers(), 200)
	// Lookup is browser-only, even when native issuance is enabled.
	native, _ := f.login(t, f.client, "employees", "body", 200)
	f.post(t, f.client, "/api/refresh_session", map[string]string{"refresh_token": native.RefreshToken}, nil, 403)
	f.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": native.RefreshToken}, http.Header{"X-Authcrunch-Refresh-Session": {native.SessionID}}, 400)
	f.post(t, f.client, "/api/logout", map[string]string{"refresh_token": native.RefreshToken}, nil, 200)
}

func runCaddyRefreshBrowser(t *testing.T, ctx context.Context, browser, cert, base, mount, refresh, access, scenario string) {
	t.Helper()
	pemBytes, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	profile := t.TempDir()
	chrome := exec.CommandContext(ctx, browser, "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(sum[:]),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	driver := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_e2e.cjs", endpoint, base, mount, refresh, access, scenario)
	driver.Stdin = strings.NewReader(lifecyclePassword)
	driver.WaitDelay = time.Second
	output, err := driver.CombinedOutput()
	if err != nil {
		t.Fatalf("real Chromium flow: %v\n%s", err, output)
	}
	var result struct {
		Passed   bool   `json:"passed"`
		Scenario string `json:"scenario"`
	}
	if json.Unmarshal(output, &result) != nil || !result.Passed || result.Scenario != scenario {
		t.Fatalf("browser did not complete scenario: %s", output)
	}
}
