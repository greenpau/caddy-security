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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authz"
)

func TestCaddyPluginsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyPluginsProcess$", "-test.v", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_PLUGINS_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS plugin lifecycle: %v\n%s", err, output)
	}
}

func TestCaddyPluginsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_PLUGINS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	addr := lifecycleAddress(t)
	base := "https://" + addr
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	config := func(label, backendFailure, hostFailure string) ([]byte, *claimsTestState) {
		t.Helper()
		binding, probe := claimsTestBinding(t, label, backendFailure)
		policy := lifecycleConfig().AuthorizationPolicies[0]
		policy.AuthRedirectDisabled = true
		policy.RawCryptoKeyStoreConfig = []string{"crypto key verify " + authorizationPathKey}
		apps := map[string]any{
			"security": &App{Config: &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}}, ClaimsEnrichment: []*ClaimsEnrichmentBinding{binding}},
			"tls": map[string]any{"certificates": map[string]any{"load_files": []any{map[string]any{
				"certificate": cert, "key": key, "tags": []string{"plugins"},
			}}}},
			"http": map[string]any{"grace_period": "10ms", "servers": map[string]any{"plugins": map[string]any{
				"listen": []string{addr}, "protocols": []string{"h1"}, "automatic_https": map[string]bool{"disable": true},
				"tls_connection_policies": []any{map[string]any{"certificate_selection": map[string]any{"any_tag": []string{"plugins"}}}},
				"routes": []any{map[string]any{"handle": []any{
					map[string]any{"handler": "security_lifecycle_probe", "label": label, "failure": hostFailure},
					map[string]any{"handler": "authorization", "gatekeeper_name": "policy", "route_matcher": "*"},
					map[string]any{"handler": "static_response", "status_code": 204},
				}}},
			}}},
		}
		if hostFailure == "start" {
			apps["security_lifecycle_fail_start"] = map[string]any{"label": label}
		}
		data, err := json.Marshal(map[string]any{
			"admin":   map[string]any{"disabled": true, "config": map[string]bool{"persist": false}},
			"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}}, "apps": apps,
		})
		if err != nil {
			t.Fatal(err)
		}
		return data, probe
	}
	// Independent signed credentials exercise the assembled host without adding
	// a portal or relying on the future static adapter's authentication fixtures.
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "immutable-test-account", "tenant": "test-tenant", "iss": "test-issuer", "origin": "local",
		"aud": []string{"test-audience"}, "roles": []string{"authp/user"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}).SignedString([]byte(authorizationPathKey))
	if err != nil {
		t.Fatal(err)
	}
	request := func(label string) error {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/protected", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			return err
		}
		if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 || resp.StatusCode != 204 || resp.Header.Get("X-Lifecycle") != label {
			return fmt.Errorf("TLS request status=%d deployment=%s, want 204/%s", resp.StatusCode, resp.Header.Get("X-Lifecycle"), label)
		}
		return nil
	}
	initialData, initialProbe := config("initial", "", "")
	if err := caddy.Load(initialData, true); err != nil {
		t.Fatal(err)
	}
	initial := capturedLifecycleApp(t, "initial")
	for range 2 {
		if err := request("initial"); err != nil {
			t.Fatal(err)
		}
	}
	if initialProbe.lookups.Load() != 2 {
		t.Fatal("binding was not attached before serving/cache reuse")
	}
	for _, tc := range []struct{ name, backend, host string }{
		{"module-provision", "provision", ""}, {"module-validate", "validate", ""},
		{"backend-construct", "construct", ""}, {"nil-backend", "nil", ""},
		{"later-provision", "", "provision"}, {"later-validation", "", "validate"}, {"later-start", "", "start"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, probe := config(tc.name, tc.backend, tc.host)
			if err := caddy.Load(data, true); err == nil {
				t.Fatal("failed candidate published")
			}
			wantClose := int64(1)
			if tc.backend == "provision" || tc.backend == "validate" || tc.backend == "nil" {
				wantClose = 0
			}
			if probe.closed.Load() != wantClose || initialProbe.closed.Load() != 0 {
				t.Fatal("candidate cleanup or active ownership failed", probe.closed.Load(), initialProbe.closed.Load())
			}
			if err := request("initial"); err != nil {
				t.Fatal("failed candidate disrupted active deployment", err)
			}
		})
	}
	t.Run("validation_only", func(t *testing.T) {
		data, probe := config("validation-only", "", "")
		var candidate caddy.Config
		if err := json.Unmarshal(data, &candidate); err != nil {
			t.Fatal(err)
		}
		if err := caddy.Validate(&candidate); err != nil {
			t.Fatal(err)
		}
		if probe.constructed.Load() != 1 || probe.closed.Load() != 1 || initialProbe.closed.Load() != 0 {
			t.Fatal("validation-only candidate leaked or closed active backend")
		}
	})

	hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
	initialProbe.hold.Store(hold)
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(hold.release) })
	requestDone := make(chan error, 1)
	go func() { requestDone <- request("initial") }()
	awaitLifecycle(t, hold.entered, "backend lookup")
	replacementData, replacementProbe := config("replacement", "", "")
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- caddy.Load(replacementData, true) }()
	waitDisposing(t, initial)
	if initialProbe.closed.Load() != 0 {
		t.Fatal("reload closed a backend during its lookup")
	}
	select {
	case err := <-reloadDone:
		t.Fatal("reload returned before drain", err)
	default:
	}
	if err := request("replacement"); err != nil {
		t.Fatal("replacement could not serve while old lookup drained", err)
	}
	releaseOnce.Do(func() { close(hold.release) })
	for _, done := range []<-chan error{requestDone, reloadDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("request/reload failed to complete after drain")
		}
	}
	if initialProbe.closed.Load() != 1 || replacementProbe.closed.Load() != 0 {
		t.Fatal("replacement closed wrong backend or retained old backend")
	}
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	if replacementProbe.closed.Load() != 1 {
		t.Fatal("stop did not close replacement backend")
	}
}
