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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

// These tests deliberately retain the host error. Caddy v2.11.4's private
// authentication logger has no supported wrapping hook, and CoreRaw tees rather
// than wraps the existing core. Never change the expected host count to zero
// until an integration at that actual ownership boundary is implemented.
func TestCaddyLoggingE2E(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "caddy")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-race", "-o", binary, "./cmd/authcrunch")
	cmd.WaitDelay = 5 * time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build actual Caddy: %v\n%s", err, output)
	}
	t.Run("scope_and_replacement", func(t *testing.T) { testCaddyLoggingReplacement(t, binary) })
	t.Run("persistent_sessions", func(t *testing.T) { testCaddyLoggingSessions(t, binary) })
}

func loggingCaddyConfig(t *testing.T, f *persistentCaddy, cert, key, database, upstream, rules string, persistent bool) []byte {
	t.Helper()
	state, refresh := "", ""
	if persistent {
		state = fmt.Sprintf("state {\ndirectory %q\n}\n", f.directory)
		refresh = fmt.Sprintf(`token refresh {
 realms local
 public origin %s
 base path /auth
 body transport enabled
 access lifetime 600
 idle timeout 1800
 absolute timeout 3600
}`, f.base)
	}
	policy := `crypto key verify synthetic-logging-signing-key
 validate bearer header
 disable auth redirect
 allow roles authp/user`
	input := fmt.Sprintf(`{
 admin %s
 auto_https off
 persist_config off
 log {
  format json
  level DEBUG
 }
 security {
  %s
  %s
  local identity store localdb {
   realm local
   path %q
  }
  authentication portal myportal {
   enable identity store localdb
   crypto key sign-verify synthetic-logging-signing-key
   %s
  }
  authorization policy app_policy {
   %s
  }
  authorization policy legacy_policy {
   %s
  }
 }
}
%s {
 tls %q %q
 log {
  format json
 }
 route /ready {
  respond ready
 }
 route /auth/* {
  authenticate with myportal
 }
 route /legacy {
  authorize with legacy_policy
  reverse_proxy %s
 }
 route /private {
  authorize with app_policy
  reverse_proxy %s
 }
}`, f.admin, state, rules, database, refresh, policy, policy, f.base, cert, key, upstream, upstream)
	raw, _, err := caddyconfig.GetAdapter("caddyfile").Adapt([]byte(input), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Current authorize syntax uses the response-preserving route handler.
	// Install the still-supported legacy JSON chain to reproduce issue #280
	// through Caddy's own Authentication.ServeHTTP, with the real authorizer.
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	var legacy int
	var rewrite func(any)
	rewrite = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if value["handler"] == "authorization" && value["gatekeeper_name"] == "legacy_policy" {
				delete(value, "gatekeeper_name")
				delete(value, "route_matcher")
				value["handler"] = "authentication"
				value["providers"] = map[string]any{"authorizer": map[string]any{"gatekeeper_name": "legacy_policy", "route_matcher": "*"}}
				legacy++
				return
			}
			for _, child := range value {
				rewrite(child)
			}
		case []any:
			for _, child := range value {
				rewrite(child)
			}
		}
	}
	rewrite(document)
	if legacy != 1 {
		t.Fatalf("legacy host chain count = %d", legacy)
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeLoggingCaddy(t *testing.T, f *persistentCaddy, raw []byte) {
	t.Helper()
	if err := os.WriteFile(f.config, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func reloadLoggingCaddy(t *testing.T, f *persistentCaddy, raw []byte, want int) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "http://"+f.admin+"/load", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("reload HTTP %d, want %d: %s", resp.StatusCode, want, body)
	}
	if want == http.StatusOK {
		writeLoggingCaddy(t, f, raw)
	}
	return body
}

type loggingCounts struct{ hostMissing, hostMalformed, component, access, login, app int }

func readLoggingCounts(t *testing.T, f *persistentCaddy) loggingCounts {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.workspace, "process.log"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("WARNING: DATA RACE")) {
		t.Fatal("Caddy logging process reported a data race")
	}
	var counts loggingCounts
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var entry struct {
			Logger, Msg, Error string
		}
		if err := decoder.Decode(&entry); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("captured Caddy output is not JSON: %v", err)
		}
		switch {
		case entry.Logger == "http.handlers.authentication" && entry.Msg == "auth provider returned error":
			switch {
			case strings.Contains(entry.Error, "reason: no token found"):
				counts.hostMissing++
			case strings.Contains(entry.Error, "reason: keystore: failed to parse token"):
				counts.hostMalformed++
			default:
				t.Fatalf("unexpected host authentication error: %s", entry.Error)
			}
		case entry.Logger == "security" && entry.Msg == "token validation error":
			counts.component++
		case strings.HasPrefix(entry.Logger, "http.log.access"):
			counts.access++
		case entry.Logger == "security" && strings.Contains(entry.Msg, "authenticated"):
			counts.login++
		case entry.Logger == "security" && entry.Msg == "provisioned app instance":
			counts.app++
		}
	}
	return counts
}

func loggingJourney(t *testing.T, f *persistentCaddy, hits *atomic.Int64, wantComponent int, wantLogin bool) {
	t.Helper()
	before, oldHits := readLoggingCounts(t, f), hits.Load()
	for _, path := range []string{"/legacy", "/private"} {
		for _, token := range []string{"", "malformed-token"} {
			headers := make(http.Header)
			if token != "" {
				headers.Set("Authorization", "Bearer "+token)
			}
			r := persistentRequest(t, f.client, "GET", f.base+path, nil, headers, http.StatusUnauthorized)
			if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Location") != "" {
				t.Fatal("filter changed denial cache/redirect behavior")
			}
		}
	}
	if hits.Load() != oldHits {
		t.Fatal("denied request reached protected handler")
	}
	client, err := authclient.NewClient(&authclient.Config{BaseURL: f.base + "/auth", Realm: "local", Username: "alice", Password: lifecyclePassword}, authclient.Options{HTTPClient: f.client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := client.Authenticate(t.Context())
	if err != nil {
		t.Fatal("real TLS login failed", err)
	}
	for _, path := range []string{"/legacy", "/private"} {
		r := persistentRequest(t, f.client, "GET", f.base+path, nil, http.Header{"Authorization": {"Bearer " + credentials.AccessToken}}, http.StatusOK)
		if string(r.body) != "protected application" {
			t.Fatal("successful authorization response changed")
		}
	}
	if hits.Load() != oldHits+2 {
		t.Fatal("successful requests did not invoke the protected handler exactly once")
	}
	after := readLoggingCounts(t, f)
	// The two independent errors from the actual same Caddy host logger must
	// remain visible until its upstream logging extension exists.
	if after.hostMissing-before.hostMissing != 1 || after.hostMalformed-before.hostMalformed != 1 || after.component-before.component != wantComponent {
		t.Fatalf("logging counts before=%+v after=%+v; want host missing=1 malformed=1, component=%d", before, after, wantComponent)
	}
	if after.access-before.access < 6 || (after.login > before.login) != wantLogin {
		t.Fatalf("access/login logging changed: before=%+v after=%+v", before, after)
	}
	t.Logf("real Caddy: host no-token=1 malformed=1 (upstream hook required), AuthCrunch errors=%d, protected calls=2", wantComponent)
}

func testCaddyLoggingReplacement(t *testing.T, binary string) {
	cert, key, roots := cookieTLSCertificate(t)
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "protected application")
	}))
	defer upstream.Close()
	other := newPersistentCaddy(t, binary, cert, key, roots)
	db := filepath.Join(other.workspace, "users.json")
	seedLocalIdentity(t, db, false)
	writeLoggingCaddy(t, other, loggingCaddyConfig(t, other, cert, key, db, upstream.URL, "", false))
	other.start(t)
	loggingJourney(t, other, &hits, 4, true)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	baselineDB := filepath.Join(f.workspace, "baseline.json")
	seedLocalIdentity(t, baselineDB, false)
	writeLoggingCaddy(t, f, loggingCaddyConfig(t, f, cert, key, baselineDB, upstream.URL, "", false))
	f.start(t)
	t.Run("baseline", func(t *testing.T) { loggingJourney(t, f, &hits, 4, true) })
	for i, tc := range []struct {
		name, rules string
		component   int
	}{
		{"error_text_alone_host_boundary", `skip partial text "reason: no token found"`, 4},
		{"message_alone_host_boundary", `skip partial text "auth provider returned error"`, 4},
		{"issue_example_host_boundary", "skip partial text \"auth provider returned error\"\nskip partial text \"reason: no token found\"", 4},
		{"exact_component_message", `skip exact text "token validation error"`, 0},
		{"partial_component_error", `skip partial text "no token found"`, 2},
		{"prefix_component_message", `skip prefix text "token validation"`, 0},
		{"suffix_component_message", `skip suffix text "validation error"`, 0},
		{"regex_component_message", `skip regex text "^token\s+validation error$"`, 0},
		{"case_sensitive", `skip partial text "Token Validation Error"`, 4},
		{"additive", "skip partial text \"no token found\"\nskip partial text \"failed to parse token\"\nskip partial text \"no token found\"", 0},
		{"all_components_only", `skip regex text ".*"`, 0},
		{"empty_restores", "", 4},
		{"omitted_restores", "", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Live file-backed reload cannot share snapshots. Seed a distinct
			// file per candidate; logging-only persistent replacement is tested
			// separately through the documented stop/start boundary.
			database := filepath.Join(f.workspace, fmt.Sprintf("users-%d.json", i))
			seedLocalIdentity(t, database, false)
			block := "logging {\n" + tc.rules + "\n}"
			if tc.name == "omitted_restores" {
				block = ""
			}
			raw := loggingCaddyConfig(t, f, cert, key, database, upstream.URL, block, false)
			reloadLoggingCaddy(t, f, raw, 200)
			loggingJourney(t, f, &hits, tc.component, tc.name != "all_components_only")
			if readLoggingCounts(t, f).app != i+2 {
				t.Fatal("library filter changed app-owned lifecycle logs")
			}
			if tc.name == "all_components_only" {
				loggingJourney(t, other, &hits, 4, true)
			}
		})
	}
	// A rejected native JSON replacement must leave the old runtime serving.
	data, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	app := config["apps"].(map[string]any)["security"].(map[string]any)["config"].(map[string]any)
	app["logging"] = map[string]any{"skip": []any{map[string]any{"match": "regex", "text": "["}}}
	invalid, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if body := reloadLoggingCaddy(t, f, invalid, 400); !bytes.Contains(body, []byte("logging skip rule 1 has invalid regex")) {
		t.Fatal("malformed native logging rejected for the wrong reason")
	}
	loggingJourney(t, f, &hits, 4, true)
}

func testCaddyLoggingSessions(t *testing.T, binary string) {
	cert, key, roots := cookieTLSCertificate(t)
	f := newPersistentCaddy(t, binary, cert, key, roots)
	database := filepath.Join(f.workspace, "users.json")
	seedLocalIdentity(t, database, false)
	config := func(rules string) []byte {
		return loggingCaddyConfig(t, f, cert, key, database, "127.0.0.1:1", rules, true)
	}
	writeLoggingCaddy(t, f, config(""))
	f.start(t)
	tf := &caddyTokenRefreshFixture{base: f.base, mount: "/auth", client: f.client}
	login, _ := tf.login(t, f.client, "local", "body", 200)
	if !login.Authenticated || login.RefreshToken == "" || login.SessionID == "" {
		t.Fatal("missing persistent login evidence")
	}
	for _, rules := range []string{
		"logging {\nskip exact text \"token validation error\"\n}",
		"logging {\nskip partial text \"no token found\"\n}",
		"logging {\n}",
		"",
	} {
		// Persistent roots require complete disposal before replacement.
		f.kill(t)
		writeLoggingCaddy(t, f, config(rules))
		f.start(t)
		rotated, _ := tf.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, nil, 200)
		if rotated.SessionID != login.SessionID || rotated.RefreshToken == "" || rotated.RefreshToken == login.RefreshToken {
			t.Fatal("logging-only restart invalidated or failed to rotate persistent session")
		}
		login = rotated
	}
}
