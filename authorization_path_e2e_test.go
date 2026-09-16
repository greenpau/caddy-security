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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestCaddyAuthorizationPathE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthorizationPathProcess$", "-test.v", "-test.timeout=50s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_AUTHORIZATION_PATH_CHILD=1")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS path authorization: %v\n%s", err, output)
	}
}

func TestCaddyAuthorizationPathProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_AUTHORIZATION_PATH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	base := "https://" + lifecycleAddress(t)
	input := fmt.Sprintf(`{
 admin off
 persist_config off
 auto_https off
 log {
  level ERROR
 }
 security {
  authorization policy bypass {
   crypto key verify %[1]s
   disable auth redirect
   allow roles viewer
   bypass uri prefix /public/
  }
  authorization policy method {
   crypto key verify %[1]s
   disable auth redirect
   validate bearer header
   acl rule {
    prefix match path /admin
    deny stop
   }
   allow roles viewer with GET to /public/
  }
  authorization policy claim {
   crypto key verify %[1]s
   disable auth redirect
   validate bearer header
   validate path acl
   allow roles viewer
  }
 }
}
%[2]s {
 tls %[3]q %[4]q
 @bypass header X-Test-Policy bypass
 @method header X-Test-Policy method
 @claim header X-Test-Policy claim
 route {
  route @bypass {
   authorize with bypass
  }
  route @method {
   authorize with method
  }
  route @claim {
   authorize with claim
  }
  header X-Path-Reached yes
  respond "{http.request.uri}" 200
 }
}`, authorizationPathKey, base, cert, key)
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: http2}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			request := func(t *testing.T, mode, token, target string, allow bool) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), "GET", base+target, nil)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("X-Test-Policy", mode)
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
				if err != nil {
					t.Fatal(err)
				}
				want := http.StatusForbidden
				if mode == "bypass" {
					want = http.StatusUnauthorized
				}
				if allow {
					want = http.StatusOK
				}
				if response.StatusCode != want || (response.Header.Get("X-Path-Reached") == "yes") != allow {
					t.Fatalf("%s %s: status=%d reached=%t, want status=%d", mode, target, response.StatusCode, response.Header.Get("X-Path-Reached") == "yes", want)
				}
				if allow && string(body) != target {
					t.Fatal("authorization changed the downstream URI")
				}
				if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || (response.ProtoMajor == 2) != http2 {
					t.Fatal("request did not use verified TLS and the selected HTTP protocol")
				}
			}
			for _, mode := range []string{"bypass", "method", "claim"} {
				t.Run(mode, func(t *testing.T) {
					token := authorizationPathToken(t, "/public/**", "/public/100%")
					if mode == "bypass" {
						token = ""
					}
					for round := range 2 {
						for _, tc := range authorizationPathCases() {
							t.Run(fmt.Sprintf("%d%s", round, tc.target), func(t *testing.T) { request(t, mode, token, tc.target, tc.allow) })
						}
					}
				})
			}
			for _, tc := range []struct{ pattern, allowed, denied string }{
				{"/tenant.v1/**", "/tenant.v1/file", "/tenantXv1/file"},
				{"/public/**|/admin", "/public/file%7C/admin", "/admin"},
				{"/public/(admin)/*", "/public/(admin)/file", "/public/admin/file"},
			} {
				t.Run(tc.pattern, func(t *testing.T) {
					t.Parallel()
					token := authorizationPathToken(t, tc.pattern)
					for range 2 {
						request(t, "claim", token, tc.denied, false)
						request(t, "claim", token, tc.allowed, true)
					}
				})
			}
		})
	}
}
