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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/golang-jwt/jwt/v5"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// This test-only module decorates the real static backend before publication.
// Faults never enter production configuration or mutate a serving gatekeeper.
type staticFaultModule struct {
	Config StaticClaimsEnrichment `json:"config"`
}
type staticFaultBackend struct{ enrichment.Backend }

var staticFaultMode atomic.Int64
var staticFaultCalls atomic.Int64
var staticFaultCanceled atomic.Int64
var staticFaultHold atomic.Pointer[lifecycleHold]

func (staticFaultModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.claims_enrichment.static_fault_test", New: func() caddy.Module { return new(staticFaultModule) }}
}
func (m *staticFaultModule) NewClaimsEnrichmentBackend(ctx context.Context, config enrichment.Config) (enrichment.Backend, error) {
	backend, err := m.Config.NewClaimsEnrichmentBackend(ctx, config)
	if err != nil {
		return nil, err
	}
	return &staticFaultBackend{backend}, nil
}
func (b *staticFaultBackend) Lookup(ctx context.Context, req enrichment.Request) (*enrichment.Result, error) {
	staticFaultCalls.Add(1)
	switch staticFaultMode.Load() {
	case 1:
		return nil, fmt.Errorf("private-backend-error-sentinel")
	case 2, 4:
		if hold := staticFaultHold.Load(); hold != nil {
			hold.once.Do(func() { close(hold.entered) })
		}
		<-ctx.Done()
		staticFaultCanceled.Add(1)
		if hold := staticFaultHold.Load(); hold != nil {
			close(hold.release)
		}
		return nil, ctx.Err()
	}
	result, err := b.Backend.Lookup(ctx, req)
	if err == nil && result.Attributes["quota"] != json.Number("9007199254740993") {
		return nil, fmt.Errorf("Caddy load rounded a configured JSON number")
	}
	if err == nil && staticFaultMode.Load() == 3 {
		result.Attributes["enrichment.department"] = "blocked"
	}
	return result, err
}
func init() { caddy.RegisterModule(staticFaultModule{}) }

func TestCaddyStaticClaimsE2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaddyStaticClaimsProcess$", "-test.v", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "CADDY_SECURITY_STATIC_CLAIMS_CHILD=1")
	collectSubprocessCoverage(t, cmd)
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Caddy TLS static claims: %v\n%s", err, output)
	}
}

func TestCaddyStaticClaimsProcess(t *testing.T) {
	if os.Getenv("CADDY_SECURITY_STATIC_CLAIMS_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cert, key, roots := cookieTLSCertificate(t)
	address := lifecycleAddress(t)
	base := "https://" + address
	logPath := filepath.Join(t.TempDir(), "static-claims.jsonl")
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Error(err)
		}
	})
	const secret = "synthetic-static-claims-signing-key"
	path := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: lifecyclePassword, Roles: []string{"viewer"}}}); err != nil {
		t.Fatal(err)
	}
	immutableID := db.Users[0].ID
	var forwarded atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.Header().Set("X-Upstream-Reached", "yes")
		for _, key := range []string{"Authorization", "X-Token-User-Roles", "X-Token-Subject", "X-Enriched-Department", "X-Plain-Department"} {
			w.Header().Set("X-Seen-"+key, r.Header.Get(key))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	// Fixture-only issuance maps the single known account's actual database ID.
	// The binding never uses a mutable username/email as its stable subject.
	portal := fmt.Sprintf(`local identity store localdb {
 realm local
 path %q
}
authentication portal myportal {
 crypto key sign-verify %s
 enable identity store localdb
 transform user {
  match realm local
  add directory_id %s as string
  add tenant north as string
  add aud api
 }
}
`, path, secret, immutableID)
	var policies, routes strings.Builder
	for _, name := range []string{"enriched", "plain", "early", "legacy"} {
		fmt.Fprintf(&policies, "authorization policy %s {\ncrypto key verify %s\ndisable auth redirect\nvalidate bearer header\ninject headers with claims\ninject header X-Enriched-Department from enrichment.department\ninject header X-Plain-Department from department\nbypass uri exact /public\n", name, secret)
		if name != "legacy" {
			claim := "enrichment.department"
			if name == "plain" {
				claim = "department"
			}
			block := strings.ReplaceAll(staticClaimsBlock, "test-issuer", base+"/auth/login")
			block = strings.ReplaceAll(block, "department", claim)
			block = strings.Replace(block, "source static", "source static\ntimeout 50ms\nattribute quota json\nclaim quota json 9007199254740993", 1)
			fmt.Fprintln(&policies, block)
			fmt.Fprint(&policies, aclFieldBlock("department", claim, "string"))
		}
		switch name {
		case "early", "legacy":
			fmt.Fprintln(&policies, "acl rule {\nmatch roles viewer\nallow stop\n}")
		default:
			fmt.Fprintln(&policies, "acl rule {\nmatch department engineering\nmatch roles viewer\nallow stop\n}\nacl default deny")
		}
		fmt.Fprintln(&policies, "}")
		fmt.Fprintf(&routes, "@%s header X-Test-Policy %s\nroute @%s {\nauthorize with %s\nreverse_proxy %s\n}\n", name, name, name, name, upstream.URL)
	}
	makeConfig := func(withPortal bool) []byte {
		t.Helper()
		declarations, mount := "", ""
		if withPortal {
			declarations = portal
			mount = "route /auth* {\nauthenticate with myportal\n}\n"
		}
		input := fmt.Sprintf("{\nadmin off\npersist_config off\nauto_https off\nlog {\nlevel DEBUG\noutput file %q\nformat json\n}\nsecurity {\n%s%s}\n}\n%s {\ntls %q %q\n%s%srespond 404\n}\n", logPath, declarations, policies.String(), base, cert, key, mount, routes.String())
		data, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	initial := makeConfig(true)
	if err := caddy.Load(initial, true); err != nil {
		t.Fatal(err)
	}
	token := lifecycleLogin(t, client, base)
	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) { return []byte(secret), nil }, jwt.WithValidMethods([]string{"HS256", "HS512"}), jwt.WithIssuer(base+"/auth/login"), jwt.WithAudience("api"))
	if err != nil || !parsed.Valid {
		t.Fatalf("independent token verification: %v", err)
	}
	signed := parsed.Claims.(jwt.MapClaims)
	if signed["directory_id"] != immutableID || signed["tenant"] != "north" {
		t.Fatal("login lost immutable identity or tenant")
	}
	for _, name := range []string{"department", "enrichment.department", "quota"} {
		if _, exists := signed[name]; exists {
			t.Fatal("login issued enrichment claims")
		}
	}
	request := func(policy, credential, path string, want int) http.Header {
		t.Helper()
		before := forwarded.Load()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-Policy", policy)
		req.Header.Set("X-Enriched-Department", "spoofed")
		req.Header.Set("X-Plain-Department", "spoofed")
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
			t.Fatal("TLS was not verified")
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", policy, path, resp.StatusCode, want, body)
		}
		if strings.Contains(string(body), "private-backend-error-sentinel") {
			t.Fatal("backend error leaked")
		}
		reached := int64(0)
		if want == 204 {
			reached = 1
		}
		if forwarded.Load() != before+reached {
			t.Fatal("authorization result did not control downstream dispatch")
		}
		return resp.Header
	}
	checkUnchanged := func(headers http.Header, credential, department string) {
		t.Helper()
		if headers.Get("X-Seen-Authorization") != "Bearer "+credential || headers.Get("X-Seen-X-Token-Subject") != signed["sub"] || headers.Get("X-Seen-X-Token-User-Roles") != "viewer" || headers.Get("X-Seen-X-Enriched-Department") != department || headers.Get("X-Seen-X-Plain-Department") != "" {
			t.Fatalf("signed headers changed: %v", headers)
		}
	}
	for _, policy := range []string{"enriched", "plain", "early", "legacy"} {
		for range 2 {
			checkUnchanged(request(policy, token, "/protected", 204), token, "")
		}
	}
	request("enriched", "", "/protected", 401)
	request("enriched", "", "/public", 204)
	resign := func(change func(jwt.MapClaims)) string {
		t.Helper()
		claims := jwt.MapClaims{}
		for key, value := range signed {
			claims[key] = value
		}
		change(claims)
		value, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, tc := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"issuer", func(c jwt.MapClaims) { c["iss"] = "other" }},
		{"realm", func(c jwt.MapClaims) { c["origin"] = "other" }},
		{"audience", func(c jwt.MapClaims) { c["aud"] = []string{"other"} }},
		{"missing tenant", func(c jwt.MapClaims) { delete(c, "tenant") }},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "directory_id") }},
		{"wrong subject type", func(c jwt.MapClaims) { c["directory_id"] = 123 }},
		{"local ACL denial", func(c jwt.MapClaims) { c["roles"] = []string{"blocked"} }},
	} {
		t.Run(tc.name, func(t *testing.T) { request("enriched", resign(tc.change), "/protected", 403) })
	}
	colliding := resign(func(c jwt.MapClaims) { c["department"] = "engineering" })
	request("plain", colliding, "/protected", 403)
	namespaced := resign(func(c jwt.MapClaims) { c["enrichment.department"] = "signed-original" })
	checkUnchanged(request("enriched", namespaced, "/protected", 204), namespaced, "signed-original")
	// A second identity in the same bound realm receives the same static claims;
	// this backend is explicitly not a per-account directory lookup.
	request("enriched", resign(func(c jwt.MapClaims) { c["directory_id"] = "other-immutable-account"; c["tenant"] = "south" }), "/protected", 204)

	policyOnly := makeConfig(false)
	candidate := func(change func(*App)) []byte {
		t.Helper()
		var doc caddy.Config
		if err := json.Unmarshal(policyOnly, &doc); err != nil {
			t.Fatal(err)
		}
		var app App
		if err := json.Unmarshal(doc.AppsRaw["security"], &app); err != nil {
			t.Fatal(err)
		}
		change(&app)
		doc.AppsRaw["security"], err = json.Marshal(&app)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(&doc)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name   string
		change func(*App)
	}{
		{"protected claim", func(a *App) {
			a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"static","claims_json":"{\"roles\":[\"private-sentinel\"]}"}`)
		}},
		{"unknown backend field", func(a *App) {
			a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"static","secret":"private-sentinel","claims_json":"{\"department\":\"engineering\"}"}`)
		}},
		{"wrong source", func(a *App) { a.ClaimsEnrichment[0].Config.Source = "private-sentinel" }},
		{"missing attribute", func(a *App) { a.ClaimsEnrichment[0].Config.Attributes[0].Name = "private-sentinel" }},
		{"short max age", func(a *App) { a.ClaimsEnrichment[0].Config.MaxAge = "1s" }},
		{"incompatible type", func(a *App) { a.ClaimsEnrichment[0].Config.Attributes[0].Type = "string_list" }},
	} {
		t.Run("failed reload/"+tc.name, func(t *testing.T) {
			if err := caddy.Load(candidate(tc.change), true); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatalf("expected redacted rejection: %v", err)
			}
			checkUnchanged(request("enriched", token, "/protected", 204), token, "")
		})
	}
	blocked := candidate(func(a *App) {
		a.ClaimsEnrichment[0].BackendRaw = json.RawMessage(`{"driver":"static","claims_json":"{\"enrichment.department\":\"blocked\",\"quota\":9007199254740993}"}`)
	})
	if err := caddy.Load(blocked, true); err != nil {
		t.Fatal(err)
	}
	request("enriched", token, "/protected", 403)
	request("plain", token, "/protected", 204)
	faults := candidate(func(a *App) {
		for _, binding := range a.ClaimsEnrichment {
			var backend map[string]json.RawMessage
			if err := json.Unmarshal(binding.BackendRaw, &backend); err != nil {
				t.Fatal(err)
			}
			binding.BackendRaw = json.RawMessage(`{"driver":"static_fault_test","config":{"claims_json":` + string(backend["claims_json"]) + `}}`)
		}
	})
	if err := caddy.Load(faults, true); err != nil {
		t.Fatal(err)
	}
	// The first authorized request populates the gatekeeper token cache. Change
	// only the test decorator's response and reuse exactly that signed credential.
	staticFaultMode.Store(0)
	cacheMisses := func() int {
		t.Helper()
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[:len(lines)-1] {
			var record struct {
				Message string `json:"msg"`
			}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Fatal(err)
			}
			if record.Message == "cache miss for JWT credentials" {
				count++
			}
		}
		return count
	}
	missesBefore := cacheMisses()
	before := staticFaultCalls.Load()
	for range 2 {
		checkUnchanged(request("enriched", token, "/protected", 204), token, "")
	}
	if staticFaultCalls.Load() != before+2 {
		t.Fatal("cache reuse skipped enrichment")
	}
	if cacheMisses() != missesBefore+1 {
		t.Fatal("repeated credential did not exercise the JWT cache")
	}
	for _, mode := range []int64{3, 1, 2} {
		staticFaultMode.Store(mode)
		before := staticFaultCalls.Load()
		start := time.Now()
		request("enriched", token, "/protected", 403)
		if staticFaultCalls.Load() != before+1 {
			t.Fatal("cached identity skipped required lookup")
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("lookup timeout was not bounded")
		}
		if mode != 3 {
			request("early", token, "/protected", 403)
		}
		before = staticFaultCalls.Load()
		request("enriched", "", "/public", 204)
		request("legacy", token, "/protected", 204)
		if staticFaultCalls.Load() != before {
			t.Fatal("bypass or unbound policy invoked backend")
		}
	}
	if staticFaultCanceled.Load() != 2 {
		t.Fatal("lookup deadline was not delivered to backend")
	}
	// Reload a fresh factory with a long binding deadline, then cancel the actual
	// TLS client request after its lookup starts. This proves client cancellation
	// reaches the backend independently of the enrichment timeout.
	cancellation := candidate(func(a *App) {
		for _, binding := range a.ClaimsEnrichment {
			var backend map[string]json.RawMessage
			if err := json.Unmarshal(binding.BackendRaw, &backend); err != nil {
				t.Fatal(err)
			}
			binding.BackendRaw = json.RawMessage(`{"driver":"static_fault_test","config":{"claims_json":` + string(backend["claims_json"]) + `}}`)
			binding.Config.Timeout = "30s"
		}
	})
	if err := caddy.Load(cancellation, true); err != nil {
		t.Fatal(err)
	}
	hold := &lifecycleHold{entered: make(chan struct{}), release: make(chan struct{})}
	staticFaultHold.Store(hold)
	staticFaultMode.Store(4)
	requestCtx, cancelRequest := context.WithCancel(t.Context())
	defer cancelRequest()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, base+"/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-Policy", "enriched")
	req.Header.Set("Authorization", "Bearer "+token)
	before = forwarded.Load()
	done := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	awaitLifecycle(t, hold.entered, "cancelable static lookup")
	cancelRequest()
	awaitLifecycle(t, hold.release, "backend request cancellation")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled client request succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not complete")
	}
	if forwarded.Load() != before || staticFaultCanceled.Load() != 3 {
		t.Fatal("canceled request escaped enrichment")
	}
	staticFaultHold.Store(nil)
	staticFaultMode.Store(0)
	checkUnchanged(request("enriched", token, "/protected", 204), token, "")
}
