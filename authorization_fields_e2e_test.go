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
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz"
)

func TestCaddyAuthorizationFieldsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyAuthorizationFieldsProcess$", "-test.v", "-test.timeout=80s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_ACL_FIELDS_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS typed ACL fields: %v\n%s", err, output)
	}
}

func TestCaddyAuthorizationFieldsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_ACL_FIELDS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	const secret = "synthetic-caddy-typed-acl-fields-signing-key"
	const rolesKey = "https://example.org/roles"
	const otherKey = "https://other.example/roles"
	const departmentKey = "https://example.org/profile.department|value, literal"
	var requestSequence atomic.Uint64
	var upstreamRequests sync.Map // request ID -> *atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if value, ok := upstreamRequests.Load(r.Header.Get("X-Test-Request-ID")); ok {
			value.(*atomic.Int64).Add(1)
		} else {
			t.Error("upstream received an untracked request")
		}
		w.Header().Set("X-Upstream-Reached", "yes")
		w.Header().Set("X-Upstream-Roles", r.Header.Get("X-Token-User-Roles"))
		w.Header().Set("X-Upstream-Subject", r.Header.Get("X-Token-Subject"))
		w.Header().Set("X-Upstream-URI", r.RequestURI)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	cert, key, roots := cookieTLSCertificate(t)
	address := lifecycleAddress(t)
	base := "https://" + address
	logPath := filepath.Join(t.TempDir(), "caddy.jsonl")
	var policies, routes strings.Builder
	add := func(name, body string) {
		fmt.Fprintf(&policies, "authorization policy %s {\ncrypto key verify %s\ndisable auth redirect\nvalidate bearer header\ninject headers with claims\n%s\n}\n", name, secret, body)
		fmt.Fprintf(&routes, "@%s header X-Test-Policy %s\nroute @%s {\nauthorize with %s\nreverse_proxy %s\n}\n", name, name, name, name, upstream.URL)
	}
	for flags := range 8 {
		body := ""
		if flags&1 != 0 {
			body += "validate method path\n"
		}
		if flags&2 != 0 {
			body += "validate source address\n"
		}
		if flags&4 != 0 {
			body += "validate path acl\n"
		}
		body += "acl rule {\nmatch external_roles admin\nmatch department engineering\nmatch roles viewer\n"
		if flags&1 != 0 {
			body += "match method GET\nprefix match path /private/\n"
		}
		// Definitions deliberately follow rules, including a stopping allow/default.
		body += "allow stop\n}\nacl default deny\n" + aclFieldBlock("external_roles", rolesKey, "string list") + aclFieldBlock("department", departmentKey, "string")
		add(fmt.Sprint("guard", flags), body)
	}
	field := aclFieldBlock("external_roles", rolesKey, "string list")
	add("fallback", field+"deny external_roles blocked\nallow roles viewer")
	add("isolated", aclFieldBlock("external_roles", otherKey, "string list")+"allow external_roles admin")
	add("legacy", "allow roles viewer")
	add("shortcut", field+"allow external_roles admin with GET to /private/")
	add("ordered", field+"allow external_roles admin\nacl default deny")
	add("negative", field+"acl rule {\nno match external_roles blocked\nallow stop\n}")
	add("absent", field+"acl rule {\nfield external_roles not exists\nallow stop\n}")
	add("unused", field+"allow roles viewer")
	add("early_stop", field+"acl rule {\nmatch roles viewer\nallow stop\n}\ndeny external_roles blocked")
	add("early", field+"acl default allow\nacl rule {\nmatch external_roles blocked\ndeny stop\n}")
	add("empty_scalar", aclFieldBlock("department", departmentKey, "string")+"acl rule {\nregex match department ^$\nallow stop\n}")
	add("imported", "allow imported_roles admin\nimport typed_fields "+rolesKey)
	input := fmt.Sprintf("{\nadmin off\npersist_config off\nauto_https off\nservers {\ntrusted_proxies static 127.0.0.1/32\ntrusted_proxies_strict\n}\nlog {\nlevel DEBUG\noutput file %q\nformat json\n}\nsecurity {\n%s}\n}\n%s {\ntls %q %q\n%s\nrespond 404\n}\n", logPath, policies.String(), base, cert, key, routes.String())
	input = "(typed_fields) {\nacl field imported_roles {\nclaim \"{args[0]}\"\ntype string list\n}\n}\n" + input
	data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Caddy's "validate path acl" also enables method/path validation. Use
	// native JSON for the two path-claim-only combinations so all eight
	// guardian variants are exercised, instead of testing two variants twice.
	var document caddy.Config
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	var adapted App
	if err := json.Unmarshal(document.AppsRaw["security"], &adapted); err != nil {
		t.Fatal(err)
	}
	for flags := range 8 {
		p := adapted.Config.AuthorizationPolicies[flags]
		if p.Name != fmt.Sprint("guard", flags) || p.ValidateMethodPath != (flags&5 != 0) || p.ValidateSourceAddress != (flags&2 != 0) || p.ValidateAccessListPathClaim != (flags&4 != 0) {
			t.Fatalf("unexpected Caddyfile guardian options for %s", p.Name)
		}
		if flags == 4 || flags == 6 {
			p.ValidateMethodPath = false
		}
	}
	document.AppsRaw["security"], err = json.Marshal(&adapted)
	if err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	invalidCaddyfiles := []struct{ name, input, want string }{
		// Caddy rejects structural syntax before calling the security parser.
		{"second field block", strings.Replace(input, field, field+"{\nclaim sensitive-claim-sentinel\n}\n", 1), "Unexpected '{'"},
		{"empty field token", strings.Replace(input, field, aclFieldBlock("external_roles", "", "string list"), 1), "guard0"},
		{"deferred OAuth invalid ACL", strings.Replace(input, "authorization policy guard0 {", "authorization policy guard0 {\nuse oauth identity provider {env.ACL_TEST_PROVIDER}\nallow unregistered admin", 1), "guard0"},
		{"quoted policy opening", strings.Replace(input, "authorization policy guard0 {", `authorization policy guard0 "{"`, 1), "guard0"},
		{"quoted policy closing", strings.Replace(input, "\n}\nauthorization policy guard1", "\n\"}\"\nauthorization policy guard1", 1), "guard0"},
	}
	rejectCaddyfile := func(t *testing.T, input, want string) {
		t.Helper()
		_, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "Caddyfile:") || strings.Contains(err.Error(), "sensitive-claim-sentinel") {
			t.Fatalf("expected redacted Caddyfile rejection containing %q with source context: %v", want, err)
		}
	}
	assertNoListener := func(t *testing.T) {
		t.Helper()
		connection, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			connection.Close()
			t.Fatal("invalid configuration opened a listener")
		}
	}
	for _, tc := range invalidCaddyfiles {
		t.Run("Caddyfile startup/"+tc.name, func(t *testing.T) {
			rejectCaddyfile(t, tc.input, tc.want)
			assertNoListener(t)
		})
	}
	// Native JSON candidates use public typed fields, independent of the adapter.
	candidate := func(change func(*authz.PolicyConfig)) []byte {
		t.Helper()
		var doc caddy.Config
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		var app App
		if err := json.Unmarshal(doc.AppsRaw["security"], &app); err != nil {
			t.Fatal(err)
		}
		change(app.Config.AuthorizationPolicies[0])
		raw, err := json.Marshal(&app)
		if err != nil {
			t.Fatal(err)
		}
		doc.AppsRaw["security"] = raw
		result, err := json.Marshal(&doc)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	invalid := []struct {
		name   string
		change func(*authz.PolicyConfig)
		want   string
	}{
		{"null field", func(p *authz.PolicyConfig) { p.AccessListFields[0] = nil }, "access_list_fields[0]"},
		{"null rule", func(p *authz.PolicyConfig) { p.AccessListRules[0] = nil }, "access_list_rules[0]"},
		{"reserved", func(p *authz.PolicyConfig) { p.AccessListFields[0].Name = "roles" }, "reserved"},
		{"unsupported type", func(p *authz.PolicyConfig) { p.AccessListFields[0].Type = "number" }, "type"},
		{"duplicate", func(p *authz.PolicyConfig) { p.AccessListFields = append(p.AccessListFields, p.AccessListFields[0]) }, "duplicate"},
		{"undefined", func(p *authz.PolicyConfig) { p.AccessListFields = nil }, "external_roles"},
		{"invalid claim", func(p *authz.PolicyConfig) { p.AccessListFields[0].Claim = "sensitive-claim-sentinel\n" }, "claim"},
	}
	reject := func(t *testing.T, raw []byte, want string) {
		t.Helper()
		err := caddy.Load(raw, true)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "sensitive-claim-sentinel") {
			t.Fatalf("expected redacted configuration rejection containing %q: %v", want, err)
		}
	}
	for _, tc := range invalid {
		t.Run("startup/"+tc.name, func(t *testing.T) {
			reject(t, candidate(tc.change), tc.want)
			assertNoListener(t)
		})
	}
	if err := caddy.Load(data, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	loaded, err := caddy.ActiveContext().App("security")
	if err != nil {
		t.Fatal(err)
	}
	for flags := range 8 {
		p := loaded.(*App).Config.AuthorizationPolicies[flags]
		if p.Name != fmt.Sprint("guard", flags) || p.ValidateMethodPath != (flags&1 != 0) || p.ValidateSourceAddress != (flags&2 != 0) || p.ValidateAccessListPathClaim != (flags&4 != 0) {
			t.Fatalf("guardian options changed during provisioning: %s", p.Name)
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Independent HS512 signing preserves deliberately invalid JSON claim types.
	sign := func(claims map[string]any, key string) string {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		input := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS512","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
		mac := hmac.New(sha512.New, []byte(key))
		_, _ = mac.Write([]byte(input))
		return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	claims := map[string]any{
		"sub": "typed-acl-user", "roles": []string{"viewer"}, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"addr": "127.0.0.1", "acl": map[string]any{"paths": []string{"/private/**"}},
		rolesKey: []string{"admin"}, departmentKey: "engineering",
		"method": "GET", "path": "/private/document",
	}
	token := sign(claims, secret)
	requestFrom := func(t *testing.T, policy, method, path, token string, allowed bool, source string) {
		t.Helper()
		requestID := fmt.Sprint(requestSequence.Add(1))
		var hits atomic.Int64
		upstreamRequests.Store(requestID, &hits)
		defer upstreamRequests.Delete(requestID)
		var wantHits int64
		if allowed {
			wantHits = 1
		}
		defer func() {
			if got := hits.Load(); got != wantHits {
				t.Errorf("%s %s %s: upstream calls=%d, want %d for this request", policy, method, path, got, wantHits)
			}
		}()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Test-Policy", policy)
		req.Header.Set("X-Test-Request-ID", requestID)
		req.Header.Set("X-Token-User-Roles", "spoofed-admin")
		req.Header.Set("X-Token-Subject", "spoofed-subject")
		if source != "" {
			req.Header.Set("X-Forwarded-For", source)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Error(err)
			return
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
		if readErr != nil {
			t.Error(readErr)
		}
		if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
			t.Error("TLS was not verified")
		}
		if allowed {
			if resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Upstream-Reached") != "yes" || resp.Header.Get("X-Upstream-Roles") != "viewer" || resp.Header.Get("X-Upstream-URI") != path {
				t.Errorf("%s %s %s: status=%d reached=%q roles=%q URI=%q", policy, method, path, resp.StatusCode, resp.Header.Get("X-Upstream-Reached"), resp.Header.Get("X-Upstream-Roles"), resp.Header.Get("X-Upstream-URI"))
			}
			if got := resp.Header.Get("X-Upstream-Subject"); resp.StatusCode == http.StatusNoContent && got != "typed-acl-user" {
				t.Errorf("%s: upstream subject=%q, want authenticated subject", policy, got)
			}
		} else if (resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized) || resp.Header.Get("X-Upstream-Reached") != "" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s %s: denied request status=%d reached=%q cache=%q", policy, method, path, resp.StatusCode, resp.Header.Get("X-Upstream-Reached"), resp.Header.Get("Cache-Control"))
		}
	}
	request := func(t *testing.T, policy, method, path, token string, allowed bool) {
		t.Helper()
		requestFrom(t, policy, method, path, token, allowed, "")
	}
	misses := func() int {
		t.Helper()
		logs, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Count(logs, []byte(`"msg":"cache miss for JWT credentials"`))
	}
	for flags := range 8 {
		t.Run(fmt.Sprint("guardian", flags), func(t *testing.T) {
			policy := fmt.Sprint("guard", flags)
			before := misses()
			request(t, policy, "GET", "/private/document", token, true)
			first := misses()
			if first != before+1 {
				t.Fatalf("fresh credentials did not produce exactly one cache miss: %d -> %d", before, first)
			}
			request(t, policy, "GET", "/private/document", token, true)
			if misses() != first {
				t.Fatal("repeated credentials were not cached")
			}
			if flags&1 != 0 {
				request(t, policy, "POST", "/private/document", token, false)
			}
			if flags&5 != 0 {
				request(t, policy, "GET", "/public/document", token, false)
			}
			// The exact same cached token must be restricted by Caddy's current
			// trusted client address, without trusting a token's own address.
			requestFrom(t, policy, "GET", "/private/document", token, flags&2 == 0, "192.0.2.9")
			request(t, policy, "GET", "/private/document", token, true)
			if misses() != first {
				t.Fatal("request checks did not exercise cached credentials")
			}
			for _, value := range []any{nil, "admin", []any{"admin", 7}, []any{"admin", nil}, []string{}, []string{"reader"}, map[string]any{"role": "admin"}, true} {
				bad := maps.Clone(claims)
				bad[rolesKey] = value
				for range 2 {
					request(t, policy, "GET", "/private/document", sign(bad, secret), false)
				}
			}
			missing := maps.Clone(claims)
			delete(missing, rolesKey)
			missing["external_roles"] = []string{"admin"}
			request(t, policy, "GET", "/private/document", sign(missing, secret), false)
			for _, value := range []any{nil, []string{"engineering"}, false, "sales"} {
				bad := maps.Clone(claims)
				bad[departmentKey] = value
				request(t, policy, "GET", "/private/document", sign(bad, secret), false)
			}
			if flags&2 != 0 {
				bad := maps.Clone(claims)
				bad["addr"] = "192.0.2.9"
				request(t, policy, "GET", "/private/document", sign(bad, secret), false)
			}
			if flags&4 != 0 {
				bad := maps.Clone(claims)
				bad["acl"] = map[string]any{"paths": []string{"/other/**"}}
				request(t, policy, "GET", "/private/document", sign(bad, secret), false)
			}
		})
	}
	t.Run("malformed values before stopping allow", func(t *testing.T) {
		request(t, "early_stop", "GET", "/private/document", token, true)
		bad := maps.Clone(claims)
		bad[rolesKey] = []any{"admin", 7}
		request(t, "early_stop", "GET", "/private/document", sign(bad, secret), false)
	})
	t.Run("imported field definitions", func(t *testing.T) {
		request(t, "imported", "GET", "/private/document", token, true)
		bad := maps.Clone(claims)
		delete(bad, rolesKey)
		bad["imported_roles"] = []string{"admin"}
		request(t, "imported", "GET", "/private/document", sign(bad, secret), false)
	})
	t.Run("ordering and standard roles", func(t *testing.T) {
		for _, policy := range []string{"fallback"} {
			request(t, policy, "GET", "/private/document", token, true)
			for _, value := range []any{nil, "allowed", []any{"allowed", 7}, []string{"blocked"}} {
				bad := maps.Clone(claims)
				bad[rolesKey] = value
				request(t, policy, "GET", "/private/document", sign(bad, secret), false)
			}
		}
		request(t, "shortcut", "GET", "/private/document", token, true)
		request(t, "shortcut", "POST", "/private/document", token, false)
		request(t, "shortcut", "GET", "/public/document", token, false)
		bad := maps.Clone(claims)
		bad[rolesKey] = []any{"admin", 7}
		request(t, "legacy", "GET", "/private/document", sign(bad, secret), true)
		request(t, "unused", "GET", "/private/document", sign(bad, secret), true)
	})
	// Default rules must evaluate even though normalized ACL data omits exp.
	// Preserve ordering and deny malformed custom claims before any allow.
	t.Run("default deny overrides shortcut allow", func(t *testing.T) {
		request(t, "ordered", "GET", "/private/document", token, false)
	})
	t.Run("default allow and malformed deny", func(t *testing.T) {
		request(t, "early", "GET", "/private/document", token, true)
		for _, value := range []any{nil, "allowed", []any{"allowed", 7}, []string{"blocked"}} {
			bad := maps.Clone(claims)
			bad[rolesKey] = value
			request(t, "early", "GET", "/private/document", sign(bad, secret), false)
		}
	})
	t.Run("missing empty and negative", func(t *testing.T) {
		request(t, "negative", "GET", "/private/document", token, true)
		for _, value := range []any{nil, []string{}, []string{"blocked"}} {
			bad := maps.Clone(claims)
			bad[rolesKey] = value
			request(t, "negative", "GET", "/private/document", sign(bad, secret), false)
			request(t, "absent", "GET", "/private/document", sign(bad, secret), false)
		}
		missing := maps.Clone(claims)
		delete(missing, rolesKey)
		request(t, "negative", "GET", "/private/document", sign(missing, secret), false)
		request(t, "absent", "GET", "/private/document", sign(missing, secret), true)
		empty := maps.Clone(claims)
		empty[departmentKey] = ""
		request(t, "empty_scalar", "GET", "/private/document", sign(empty, secret), true)
	})
	t.Run("verified credentials", func(t *testing.T) {
		request(t, "guard0", "GET", "/private/document", sign(claims, "wrong-signature"), false)
		expired := maps.Clone(claims)
		expired["exp"] = time.Now().Add(-time.Hour).Unix()
		request(t, "guard0", "GET", "/private/document", sign(expired, secret), false)
	})
	other := maps.Clone(claims)
	delete(other, rolesKey)
	other[otherKey] = []string{"admin"}
	otherToken := sign(other, secret)
	t.Run("concurrent policy isolation", func(t *testing.T) {
		var workers sync.WaitGroup
		for range 12 {
			workers.Go(func() {
				for range 3 {
					request(t, "guard0", "GET", "/private/document", token, true)
					request(t, "guard0", "GET", "/private/document", otherToken, false)
					request(t, "isolated", "GET", "/private/document", otherToken, true)
					request(t, "isolated", "GET", "/private/document", token, false)
				}
			})
		}
		workers.Wait()
	})
	active, err := caddy.ActiveContext().App("security")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range invalidCaddyfiles {
		t.Run("rejected Caddyfile reload/"+tc.name, func(t *testing.T) {
			rejectCaddyfile(t, tc.input, tc.want)
			current, err := caddy.ActiveContext().App("security")
			if err != nil {
				t.Fatal(err)
			}
			if current != active {
				t.Fatal("failed adaptation replaced the active app")
			}
			request(t, "guard0", "GET", "/private/document", token, true)
			request(t, "guard0", "GET", "/private/document", otherToken, false)
		})
	}
	for _, tc := range invalid {
		t.Run("rejected reload/"+tc.name, func(t *testing.T) {
			reject(t, candidate(tc.change), tc.want)
			current, err := caddy.ActiveContext().App("security")
			if err != nil {
				t.Fatal(err)
			}
			if current != active {
				t.Fatal("failed reload replaced the active app")
			}
			request(t, "guard0", "GET", "/private/document", token, true)
			request(t, "guard0", "GET", "/private/document", otherToken, false)
		})
	}
	t.Run("changed JSON binding", func(t *testing.T) {
		changed := candidate(func(p *authz.PolicyConfig) {
			p.AccessListFields[0] = &acl.FieldConfig{Name: "external_roles", Claim: otherKey, Type: acl.FieldTypeStringList}
		})
		if err := caddy.Load(changed, true); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			request(t, "guard0", "GET", "/private/document", token, false)
			request(t, "guard0", "GET", "/private/document", otherToken, true)
			request(t, "guard1", "GET", "/private/document", token, true)
			request(t, "guard1", "GET", "/private/document", otherToken, false)
		}
		if err := caddy.Load(data, true); err != nil {
			t.Fatal(err)
		}
		request(t, "guard0", "GET", "/private/document", token, true)
		request(t, "guard0", "GET", "/private/document", otherToken, false)
	})
}
