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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
)

func redirectTargets() []string {
	return []string{"/", "/nested/resource", "/files/a%2fb?x=one%26two&x=three+four", "//other.example/private", "/empty?"}
}

// Execute the emitted program, including its encodeURIComponent and fragment
// logic. Extracting quoted values alone would not test what a browser follows.
func executeAuthorizationRedirect(t *testing.T, body, fragment string) string {
	t.Helper()
	input, err := json.Marshal(map[string]string{"body": body, "fragment": fragment})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "testdata/browser/authorization_redirect_script.cjs")
	cmd.Stdin = strings.NewReader(string(input))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("execute redirect script: %v\n%s", err, output)
	}
	return string(output)
}

func assertAuthorizationRedirect(t *testing.T, location, authURL, parameter, target string) {
	t.Helper()
	got, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	want, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	query := got.Query()
	if values := query[parameter]; len(values) != 1 || values[0] != target {
		t.Fatalf("decoded %s = %q, want %q", parameter, values, target)
	}
	query.Del(parameter)
	if got.Scheme != want.Scheme || got.Host != want.Host || got.EscapedPath() != want.EscapedPath() || got.Fragment != want.Fragment || query.Encode() != want.Query().Encode() {
		t.Fatalf("outer redirect = %q, want authentication destination %q", location, authURL)
	}
}

// Keep quic-go v0.62's absolute URL/origin-form RequestURI regression even
// though v0.63 leaves ordinary URLs relative. The live Caddy suite uses the
// selected transport without any request-shape changes.
func TestAuthzRedirectRequestTargets(t *testing.T) {
	const origin = "https://app.example.test:8443"
	const authURL = "https://auth.example.test:9443/oauth2/upstream/authorization-code-callback?source=app"
	for _, js := range []bool{false, true} {
		t.Run(fmt.Sprintf("javascript=%t", js), func(t *testing.T) {
			policy := &authz.PolicyConfig{Name: "redirect", AuthURLPath: authURL, RedirectWithJavascript: js,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
			}
			app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
			gate, err := app.getGatekeeper("redirect")
			if err != nil {
				t.Fatal(err)
			}
			handler := AuthorizationHandler{AuthzMiddleware: AuthzMiddleware{app: app, gatekeeper: gate}}
			for _, shape := range []string{"origin", "http3", "absolute"} {
				for _, target := range redirectTargets() {
					t.Run(shape+target, func(t *testing.T) {
						r := httptest.NewRequest("GET", origin+target, nil)
						switch shape {
						case "origin":
							r.RequestURI = r.URL.RequestURI()
							r.URL.Scheme = ""
							r.URL.Host = ""
						case "http3":
							r.RequestURI = r.URL.RequestURI()
							r.Proto = "HTTP/3.0"
							r.ProtoMajor = 3
							r.ProtoMinor = 0
						}
						originalURL, originalTarget := r.URL.String(), r.RequestURI
						r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
						w := httptest.NewRecorder()
						called := false
						err := handler.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nil }))
						if err != nil || called || w.Code != 302 || w.Header().Get("Cache-Control") != "no-store" {
							t.Fatalf("redirect contract: error=%v downstream=%t status=%d", err, called, w.Code)
						}
						location, expected := w.Header().Get("Location"), origin+target
						if js {
							location = executeAuthorizationRedirect(t, w.Body.String(), "#section%202")
							expected += "#section%202"
						}
						assertAuthorizationRedirect(t, location, authURL, "redirect_url", expected)
						if r.URL.String() != originalURL || r.RequestURI != originalTarget {
							t.Fatal("wrapper rewrote the request target")
						}
					})
				}
			}
		})
	}
}
