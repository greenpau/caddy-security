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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestAuthzSourceTrust(t *testing.T) {
	policy := &authz.PolicyConfig{Name: "source", AuthRedirectDisabled: true, ValidateBearerHeader: true, ValidateSourceAddress: true,
		RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
		AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
	}
	app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
	gate, err := app.getGatekeeper("source")
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "source-viewer", "roles": []string{"viewer"}, "addr": "198.51.100.14",
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	}).SignedString([]byte(authorizationPathKey))
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &AuthzMiddleware{app: app, gatekeeper: gate}
	for round := range 2 {
		for _, tc := range []struct {
			name, peer, clientIP string
			trusted, allowed     bool
		}{
			{"trusted", "127.0.0.1:1234", "198.51.100.14", true, true},
			{"changed trusted address", "127.0.0.1:1234", "198.51.100.15", true, false},
			{"untrusted spoof", "127.0.0.1:1234", "198.51.100.14", false, false},
			{"missing resolved address", "127.0.0.1:1234", "", true, false},
			{"matching direct peer", "198.51.100.14:1234", "", false, true},
		} {
			t.Run(fmt.Sprintf("%d/%s", round, tc.name), func(t *testing.T) {
				r := httptest.NewRequest("GET", "https://app.example.test/protected", nil)
				r.RequestURI = r.URL.RequestURI()
				r.RemoteAddr = tc.peer
				r.Header.Set("Authorization", "Bearer "+token)
				r.Header["X-Forwarded-For"] = []string{"198.51.100.14", "198.51.100.14, 127.0.0.1"}
				r.Header.Set("X-Real-Ip", "198.51.100.14")
				r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{
					caddyhttp.TrustedProxyVarKey: tc.trusted, caddyhttp.ClientIPVarKey: tc.clientIP,
				}))
				w := httptest.NewRecorder()
				w.Code = 0
				u, allowed, err := wrapper.Authenticate(w, r)
				if allowed != tc.allowed || (err == nil) != tc.allowed {
					t.Fatalf("source-bound decision: allowed=%t error=%t", allowed, err != nil)
				}
				// Source mismatch is an authentication error with no handled
				// response. Caddy's enclosing authentication handler supplies 401.
				if !allowed && (u.ID != "" || len(u.Metadata) != 0 || w.Code != 0 || w.Header().Get("Cache-Control") != "no-store") {
					t.Fatal("source-bound denial leaked identity or lost its response contract")
				}
			})
		}
	}
}

// Check the public gatekeeper result independently of the wrapper. In
// particular, nil error and a handled response are not permission to continue.
func TestAuthzResponseContract(t *testing.T) {
	for _, tc := range []struct {
		name, token                                             string
		closed, bypass, redirect, forbidden, allowed, gateError bool
		status                                                  int
	}{
		{name: "missing", gateError: true},
		{name: "invalid", token: "synthetic-secret-invalid-token", gateError: true},
		{name: "redirect", redirect: true, gateError: true, status: 302},
		{name: "forbidden", token: "valid", forbidden: true, gateError: true, status: 403},
		{name: "closed", closed: true, status: 503},
		{name: "bypassed", bypass: true, allowed: true},
		{name: "authorized", token: "valid", allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &authz.PolicyConfig{Name: "contract", AuthRedirectDisabled: !tc.redirect, ValidateBearerHeader: true,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
			}
			if tc.bypass {
				policy.BypassConfigs = []*bypass.Config{{MatchType: "exact", URI: "/protected"}}
			}
			if tc.forbidden {
				policy.AccessListRules[0].Conditions = []string{"match roles administrator"}
			}
			app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
			gate, err := app.getGatekeeper("contract")
			if err != nil {
				t.Fatal(err)
			}
			if tc.closed {
				gate.Close()
			}
			request := func() *http.Request {
				r := httptest.NewRequest("GET", "https://app.example.test/protected", nil)
				token := tc.token
				if token == "valid" {
					token = authorizationPathToken(t)
				}
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				return r
			}
			ar := requests.NewAuthorizationRequest()
			raw := httptest.NewRecorder()
			raw.Code = 0 // distinguish no write from an explicit response
			err = gate.Authenticate(raw, request(), ar)
			if (err != nil) != tc.gateError || ar.Response.Bypassed != tc.bypass || ar.Response.Authorized != (tc.allowed && !tc.bypass) || raw.Code != tc.status {
				t.Fatalf("gate error=%t authorized=%t bypassed=%t status=%d", err != nil, ar.Response.Authorized, ar.Response.Bypassed, raw.Code)
			}
			wrapper := &AuthzMiddleware{app: app, gatekeeper: gate}
			// Exercise the actual route handler, including the handled response
			// outcome that the legacy Caddy authentication provider cannot express.
			routeResponse := httptest.NewRecorder()
			routeRequest := request()
			repl := caddy.NewReplacer()
			routeRequest = routeRequest.WithContext(context.WithValue(routeRequest.Context(), caddy.ReplacerCtxKey, repl))
			called := false
			routeErr := (AuthorizationHandler{AuthzMiddleware: *wrapper}).ServeHTTP(routeResponse, routeRequest, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nil }))
			if called != tc.allowed || (routeErr != nil) != (tc.status == 0 && !tc.allowed) {
				t.Fatal("route handler changed three-outcome contract")
			}
			if tc.status != 0 && (routeResponse.Code != tc.status || routeResponse.Body.String() != raw.Body.String()) {
				t.Fatal("route handler changed handled status/body")
			}
			if tc.gateError && tc.status == 0 {
				if value, ok := repl.Get("http.auth.authorizer.error"); !ok || value == "" {
					t.Fatal("unhandled denial lost authentication error placeholder")
				}
			}
			response := httptest.NewRecorder()
			response.Code = 0
			response.Header().Set("Cache-Control", "public, max-age=60")
			user, allowed, err := wrapper.Authenticate(response, request())
			if allowed != tc.allowed || response.Code != tc.status || (err != nil) != tc.gateError {
				t.Fatal("wrapper changed gatekeeper decision or response")
			}
			if !allowed && (user.ID != "" || len(user.Metadata) != 0) {
				t.Fatal("denial returned identity metadata")
			}
			cacheControl := "no-store"
			if allowed {
				cacheControl = "public, max-age=60"
			}
			if response.Header().Get("Cache-Control") != cacheControl {
				t.Fatal("authorization response cache policy did not follow denial")
			}
			if tc.status != 0 {
				if response.Result().Header.Get("Cache-Control") != "no-store" {
					t.Fatal("handled denial committed cacheable headers")
				}
				if response.Body.String() != raw.Body.String() {
					t.Fatal("wrapper changed the handled response body")
				}
			}
		})
	}
}

const authorizationPathKey = "synthetic-authorization-path-signing-key"

// Independently signed fixtures isolate authorization from login. These are
// access tokens with path claims, never OIDC authentication evidence.
func authorizationPathToken(t *testing.T, paths ...string) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "path-viewer", "roles": []string{"viewer"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"acl": map[string]any{"paths": paths},
	}).SignedString([]byte(authorizationPathKey))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type authorizationPathCase struct {
	target string
	allow  bool
}

func authorizationPathCases() []authorizationPathCase {
	return []authorizationPathCase{
		{"/admin", false},
		{"/admin/../public/file", false},
		{"/admin/%2e%2e/public/file", false},
		{"/public%2Ffile", false},
		{"/public/%252e%252e/admin", false},
		{"/public/..%252fadmin", false},
		{"/public/%252e%252e/admin/%25252e%25252e/public/file", false},
		{"/public/a%252fb/../%252e%252e/admin", false},
		{"/public/%25zz/%252e%252e/admin", false},
		{"/public/%25252525252e%25252525252e/admin", false},
		{"/public/%FF/file", false},
		{"/public/%2580/file", false},
		{"/public/file", true},
		{"/public/assets/app.css?return=%2fadmin", true},
		{"/public/./assets/app.css", true},
		{"/public/100%25", true},
	}
}

func TestAuthzPathDelegation(t *testing.T) {
	for _, mode := range []string{"bypass", "method", "claim"} {
		t.Run(mode, func(t *testing.T) {
			policy := &authz.PolicyConfig{Name: mode, AuthRedirectDisabled: true, ValidateBearerHeader: true,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
			}
			token := authorizationPathToken(t, "/public/**", "/public/100%")
			switch mode {
			case "bypass":
				policy.BypassConfigs = []*bypass.Config{{MatchType: "prefix", URI: "/public/"}}
				token = ""
			case "method":
				policy.ValidateMethodPath = true
				policy.AccessListRules[0].Conditions = append(policy.AccessListRules[0].Conditions, "prefix match path /public/", "match method GET")
			case "claim":
				policy.ValidateAccessListPathClaim = true
			}
			app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
			gatekeeper, err := app.getGatekeeper(mode)
			if err != nil {
				t.Fatal(err)
			}
			middleware := &AuthzMiddleware{app: app, gatekeeper: gatekeeper}
			// Repeat with a cached identity: request paths must still be checked.
			for round := range 2 {
				for _, tc := range authorizationPathCases() {
					t.Run(fmt.Sprintf("%d%s", round, tc.target), func(t *testing.T) {
						r := httptest.NewRequest("GET", "https://app.example.test"+tc.target, nil)
						if token != "" {
							r.Header.Set("Authorization", "Bearer "+token)
						}
						original, target := *r.URL, r.RequestURI
						usr, allowed, err := middleware.Authenticate(httptest.NewRecorder(), r)
						if allowed != tc.allow || (err == nil) != tc.allow {
							t.Fatalf("authorized=%t error=%v, want authorized=%t", allowed, err, tc.allow)
						}
						if *r.URL != original || r.RequestURI != target {
							t.Fatal("authorization rewrote the downstream request target")
						}
						if (!allowed || mode == "bypass") && (usr.ID != "" || len(usr.Metadata) != 0) {
							t.Fatal("denied or bypassed request received authenticated metadata")
						}
					})
				}
			}
		})
	}
}

func TestAuthorizationHandlerAdmissionAndDrain(t *testing.T) {
	for _, mode := range []string{"bypassed", "authorized"} {
		for _, outcome := range []string{"return", "error", "panic"} {
			t.Run(mode+"/"+outcome, func(t *testing.T) {
				policy := &authz.PolicyConfig{Name: "drain", ValidateBearerHeader: true,
					RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
					AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
				}
				if mode == "bypassed" {
					policy.BypassConfigs = []*bypass.Config{{MatchType: "exact", URI: "/public"}}
				}
				app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
				handler := AuthorizationHandler{AuthzMiddleware: AuthzMiddleware{app: app, GatekeeperName: "drain"}}
				token := authorizationPathToken(t)
				request := func() *http.Request {
					r := httptest.NewRequest("GET", "https://app.example/public", nil)
					if mode == "authorized" {
						r.Header.Set("Authorization", "Bearer "+token)
					}
					return r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
				}
				type result struct {
					err        error
					panicValue any
				}
				entered, release := make(chan struct{}), make(chan struct{})
				finished := make(chan result, 1)
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				downstreamError := errors.New("synthetic downstream error")
				go func() {
					var got result
					defer func() { got.panicValue = recover(); finished <- got }()
					got.err = handler.ServeHTTP(httptest.NewRecorder(), request(), caddyhttp.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) error {
						close(entered)
						<-release
						// These values must survive disposal of the borrowed runtime.
						repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
						roles, exists := repl.Get("http.auth.user.roles")
						if (mode == "authorized" && (!exists || roles != "viewer")) || (mode == "bypassed" && exists) {
							return fmt.Errorf("downstream identity changed after cleanup")
						}
						switch outcome {
						case "error":
							return downstreamError
						case "panic":
							panic("synthetic downstream panic")
						}
						return nil
					}))
				}()
				awaitLifecycle(t, entered, "downstream handler")
				cleanup := make(chan error, 1)
				go func() { cleanup <- app.Cleanup() }()
				select {
				case err := <-cleanup:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("cleanup waited for downstream after authorization finished")
				}
				if _, err := app.server.GetGatekeeperByName("drain"); !errors.Is(err, authcrunch.ErrServerClosed) {
					t.Fatal("runtime remained open after authorization drained")
				}
				select {
				case <-finished:
					t.Fatal("downstream returned before its explicit release")
				default:
				}
				response, retained := httptest.NewRecorder(), request()
				calls := 0
				err := handler.ServeHTTP(response, retained, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { calls++; return nil }))
				denial, ok := err.(caddyhttp.HandlerError)
				if !ok || denial.StatusCode != 503 || calls != 0 || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("retained handler admitted shutdown request or lost its denial contract")
				}
				if value, ok := retained.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer).Get("http.auth.authorizer.error"); !ok || value == "" {
					t.Fatal("shutdown denial lost the error-route placeholder")
				}
				unblock()
				select {
				case got := <-finished:
					if outcome == "panic" {
						if got.panicValue != "synthetic downstream panic" {
							t.Fatal("downstream panic was changed")
						}
					} else if got.panicValue != nil || (outcome == "error" && got.err != downstreamError) || (outcome == "return" && got.err != nil) {
						t.Fatal("downstream result was changed", got.err, got.panicValue)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("downstream handler did not return")
				}
				if err := app.Cleanup(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestAuthorizationHandlerDrainsAuthorization(t *testing.T) {
	policy := &authz.PolicyConfig{Name: "drain", RawCryptoKeyStoreConfig: []string{"crypto key verify " + authorizationPathKey},
		AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles viewer"}, Action: "allow stop"}},
	}
	app := provisionLifecycleApp(t, &authcrunch.Config{AuthorizationPolicies: []*authz.PolicyConfig{policy}})
	handler := AuthorizationHandler{AuthzMiddleware: AuthzMiddleware{app: app, GatekeeperName: "drain"}}
	hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(hold.release) }) }
	defer unblock()
	response := httptest.NewRecorder()
	writer := &lifecycleHeldWriter{ResponseWriter: response, hold: hold, ctx: t.Context()}
	r := httptest.NewRequest("GET", "https://app.example/private", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	finished := make(chan error, 1)
	go func() {
		finished <- handler.ServeHTTP(writer, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			return errors.New("denied request reached downstream")
		}))
	}()
	awaitLifecycle(t, hold.entered, "gatekeeper response")
	cleanup := make(chan error, 1)
	go func() { cleanup <- app.Cleanup() }()
	waitDisposing(t, app)
	select {
	case <-cleanup:
		t.Fatal("runtime closed while authorization was still writing its response")
	default:
	}
	if _, err := app.server.GetGatekeeperByName("drain"); err != nil {
		t.Fatal("runtime closed before authorization drained", err)
	}
	unblock()
	select {
	case err := <-finished:
		if err != nil || response.Code != http.StatusFound || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("held gatekeeper response changed", err, response.Code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorization did not return")
	}
	select {
	case err := <-cleanup:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("authorization admission leaked")
	}
}
