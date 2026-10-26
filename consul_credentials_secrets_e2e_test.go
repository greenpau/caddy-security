// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consultest"
	credentials "github.com/greenpau/caddy-security/plugins/credential-authenticators-consul"
	secrets "github.com/greenpau/caddy-security/plugins/secrets-consul"
)

// The production command and disposable Consul agent exercise real TLS requests.
// A bounded proxy simulates backend unavailability without replacing auth results.
func TestCaddyConsulCredentialsSecretsE2E(t *testing.T) {
	address := consultest.Start(t)
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-o", binary, "./testdata/companion_caddy")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.WaitDelay = 5 * time.Second
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build production Caddy: %v\n%s", err, output)
	}
	backendURL, _ := url.Parse("http://" + address)
	reverse := httputil.NewSingleHostReverseProxy(backendURL)
	var unavailable atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unavailable.Load() {
			http.Error(w, "synthetic backend unavailable", http.StatusServiceUnavailable)
			return
		}
		reverse.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	config := consulapi.DefaultConfig()
	config.Address = address
	client, err := consulapi.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	storage := &storageconsul.ConsulStorage{ConsulClient: client, Prefix: "credentials-secrets-e2e", AESKey: []byte(consulCompanionKey)}
	storageBlock := fmt.Sprintf("storage consul {\naddress %q\nprefix credentials-secrets-e2e\naes_key %s\n}", strings.TrimPrefix(proxy.URL, "http://"), consulCompanionKey)
	cert, key, roots := cookieTLSCertificate(t)
	reload := func(t *testing.T, f *persistentCaddy, data []byte, success bool, markers []string) {
		t.Helper()
		if err := os.WriteFile(f.config, data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "reload", "--force", "--config", f.config, "--address", f.admin)
		cmd.WaitDelay = 5 * time.Second
		output, err := cmd.CombinedOutput()
		assertAdminRedacted(t, output, markers)
		if (err == nil) != success {
			t.Fatalf("reload success=%v: %v\n%s", success, err, output)
		}
	}
	inspect := func(t *testing.T, f *persistentCaddy, markers []string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, "GET", "http://"+f.admin+"/config/", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != 200 {
			t.Fatal("config inspection failed", readErr)
		}
		assertAdminRedacted(t, data, markers)
		logData, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
		if err != nil {
			t.Fatal(err)
		}
		assertAdminRedacted(t, logData, markers)
	}
	t.Run("fresh_credentials_across_replicas", func(t *testing.T) {
		defer unavailable.Store(false)
		management, err := credentials.New(t.Context(), &credentials.ConsulCredentialAuthenticator{Name: "keys", Realm: "staff", Capacity: 8, Timeout: "2s"}, storage)
		if err != nil {
			t.Fatal(err)
		}
		defer management.Close()
		issue := func(roles []string) string {
			t.Helper()
			key, err := management.Issue(t.Context(), "alice", "alice@example.test", roles, time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			return key
		}
		accepted, denied := issue([]string{"authp/user"}), issue([]string{"unprivileged"})
		markers := []string{accepted, denied, "malformed-private-key"}
		nodes := []*persistentCaddy{newPersistentCaddy(t, binary, cert, key, roots), newPersistentCaddy(t, binary, cert, key, roots)}
		baselines := map[*persistentCaddy][]byte{}
		for _, f := range nodes {
			source := fmt.Sprintf(`{
 admin %s
 auto_https off
 %s
 log {
  level DEBUG
  format filter {
   wrap json
   fields {
    request>headers>X-Api-Key delete
    request>headers>X-Private-Key delete
   }
  }
 }
 security {
  credential authenticator consul keys {
   realm staff
   capacity 8
   timeout 2s
  }
  authorization policy api {
   crypto key verify synthetic-consul-api-key-signing-secret
   with api key auth portal keys realm staff
   allow roles authp/user
   disable auth redirect
   enable strip token
  }
  authorization policy custom {
   crypto key verify synthetic-consul-api-key-signing-secret
   with api key auth portal keys realm staff
   with api key header name X-Private-Key
   with auth realm header name X-Private-Realm
   allow roles authp/user
   disable auth redirect
   enable strip token
  }
 }
}
%s {
 tls %q %q
 log {
  format filter {
   wrap json
   fields {
    request>headers>X-Api-Key delete
    request>headers>X-Private-Key delete
   }
  }
 }
 route /ready {
  respond "ready"
 }
 route /resource {
  authorize with api
  respond "key={http.request.header.X-Api-Key}"
 }
 route /custom {
  authorize with custom
  respond "key={http.request.header.X-Private-Key}"
 }
}`, f.admin, storageBlock, f.base, cert, key)
			baselines[f] = f.write(t, source)
			assertAdminRedacted(t, baselines[f], markers)
			f.start(t)
		}
		request := func(f *persistentCaddy, value, realm string, status int) {
			t.Helper()
			response := persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"X-Api-Key": {value}, "X-Auth-Realm": {realm}}, status)
			if status == 200 && string(response.body) != "key=" {
				t.Fatal("API credential reached downstream")
			}
		}
		for _, f := range nodes {
			request(f, accepted, "staff", 200)
			request(f, denied, "staff", 403)
			request(f, accepted, "wrong", 401)
			request(f, "malformed-private-key", "staff", 401)
			persistentRequest(t, f.client, "GET", f.base+"/custom", nil, http.Header{"X-Private-Key": {accepted}, "X-Private-Realm": {"staff"}}, 200)
		}
		unavailable.Store(true)
		for _, f := range nodes {
			request(f, accepted, "staff", 401)
		}
		unavailable.Store(false)
		for _, f := range nodes {
			request(f, accepted, "staff", 200)
		}
		var candidate map[string]any
		if err := json.Unmarshal(baselines[nodes[0]], &candidate); err != nil {
			t.Fatal(err)
		}
		candidate["apps"].(map[string]any)["security"].(map[string]any)["credential_authenticators"].([]any)[0].(map[string]any)["realm"] = "wrong"
		bad, _ := json.Marshal(candidate)
		reload(t, nodes[0], bad, false, markers)
		request(nodes[0], accepted, "staff", 200)
		if err := management.Revoke(t.Context(), accepted); err != nil {
			t.Fatal(err)
		}
		for _, f := range nodes {
			request(f, accepted, "staff", 401)
		}
		replacement := issue([]string{"authp/user"})
		markers = append(markers, replacement)
		for _, f := range nodes {
			request(f, replacement, "staff", 200)
		}
		reload(t, nodes[0], baselines[nodes[0]], true, markers)
		nodes[1].restart(t)
		for _, f := range nodes {
			request(f, replacement, "staff", 200)
			request(f, accepted, "staff", 401)
			inspect(t, f, markers)
		}
	})
	t.Run("secret_snapshot_rotation_and_failed_reload", func(t *testing.T) {
		defer unavailable.Store(false)
		management, err := secrets.New(t.Context(), &secrets.Config{Name: "signing", Record: "tokens", Timeout: "2s"}, storage)
		if err != nil {
			t.Fatal(err)
		}
		defer management.Close()
		keyA := "consul-private-signing-key-A-0123456789\t\u00a0"
		keyB := "consul-private-signing-key-B-0123456789"
		markers := []string{strings.TrimSpace(keyA), keyB}
		put := func(value any) {
			t.Helper()
			if err := management.Put(t.Context(), map[string]any{"key": value}); err != nil {
				t.Fatal(err)
			}
		}
		put(keyA)
		f := newPersistentCaddy(t, binary, cert, key, roots)
		source := fmt.Sprintf(`{
 admin %s
 auto_https off
 %s
 log {
  level DEBUG
 }
 security {
  secrets consul signing {
   record tokens
   timeout 2s
  }
  local identity store localdb {
   realm local
   path :memory:
   user keyadmin {
    email keyadmin@example.test
    password %q
    roles authp/admin authp/user
   }
  }
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify secrets:signing:key
  }
  authorization policy policy {
   crypto key verify secrets:signing:key
   allow roles authp/user
   validate bearer header
   disable auth redirect
  }
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /auth/* {
  authenticate with myportal
 }
 route /resource {
  authorize with policy
  respond "secret-backed access"
 }
}`, f.admin, storageBlock, lifecyclePassword, f.base, cert, key)
		baseline := f.write(t, source)
		assertAdminRedacted(t, baseline, markers)
		f.start(t)
		login := func(secret string) string {
			t.Helper()
			response := persistentRequest(t, f.client, "GET", f.base+"/auth/basic/login/local", nil, http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("keyadmin:"+lifecyclePassword))}}, 303)
			token := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
			parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS512"}))
			if err != nil || !parsed.Valid {
				t.Fatal("JWT did not preserve exact secret")
			}
			return token
		}
		resource := func(token string, status int) {
			t.Helper()
			persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}}, status)
		}
		old := login(keyA)
		resource(old, 200)
		put(keyB)
		resource(login(keyA), 200)
		reload(t, f, baseline, true, markers)
		current := login(keyB)
		resource(current, 200)
		resource(old, 401)
		put(json.Number("9007199254740993"))
		reload(t, f, baseline, false, markers)
		resource(login(keyB), 200)
		if err := management.Delete(t.Context()); err != nil {
			t.Fatal(err)
		}
		reload(t, f, baseline, false, markers)
		resource(current, 200)
		put(keyB)
		unavailable.Store(true)
		resource(login(keyB), 200)
		reload(t, f, baseline, false, markers)
		unavailable.Store(false)
		resource(current, 200)
		reload(t, f, baseline, true, markers)
		f.restart(t)
		resource(login(keyB), 200)
		inspect(t, f, markers)
	})
}
