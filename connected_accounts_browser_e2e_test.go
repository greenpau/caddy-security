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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type connectedAccountsBrowserRecord struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Value   string `json:"value,omitempty"`
	Label   string `json:"label,omitempty"`
	Token   string `json:"token,omitempty"`
	Session string `json:"session,omitempty"`
}

// Read the private incremental inventory even when Chrome failed. A missing
// completion marker rejects success, without losing earlier cleanup evidence.
func readConnectedAccountsBrowserEvidence(t *testing.T, path string, f *caddyConnectedAccountsFixture) (map[string]connectedAccountsBrowserRecord, bool) {
	t.Helper()
	logins := make(map[string]connectedAccountsBrowserRecord)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() == 0 || info.Size() > 256*1024 {
		t.Error("connected browser evidence was missing, oversized or not private")
		return logins, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Error("cannot read connected browser evidence")
		return logins, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	complete := false
	for {
		var record connectedAccountsBrowserRecord
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil || record.Version != 1 || complete {
			t.Error("invalid connected browser evidence record")
			return logins, false
		}
		switch record.Kind {
		case "secret":
			if record.Value == "" || len(record.Value) > 32*1024 || record.Label != "" || record.Token != "" || record.Session != "" {
				t.Error("invalid private connected secret record")
				return logins, false
			}
			f.secrets = append(f.secrets, record.Value)
		case "login":
			if !slices.Contains([]string{"automatic", "local-confirmation", "connected-external"}, record.Label) || record.Token == "" || record.Session == "" || record.Value != "" || logins[record.Label].Token != "" {
				t.Error("invalid connected browser login evidence")
				return logins, false
			}
			f.secrets = append(f.secrets, record.Token)
			logins[record.Label] = record
		case "complete":
			if record.Value != "" || record.Label != "" || record.Token != "" || record.Session != "" {
				t.Error("invalid connected browser completion")
				return logins, false
			}
			complete = true
		default:
			t.Error("unknown connected browser evidence kind")
			return logins, false
		}
	}
	return logins, complete
}

func runCaddyConnectedAccountsBrowser(t *testing.T, f *caddyConnectedAccountsFixture) {
	t.Helper()
	before := localIdentityRecord(t, f.database, "alice")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "connected-accounts-browser-")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("remove private connected browser profile", err)
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, f.cert)
	trust.WaitDelay = time.Second
	if output, err := trust.CombinedOutput(); err != nil {
		t.Fatalf("private Chrome trust: %v\n%s", err, output)
	}
	var invalidTLSHits atomic.Int64
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		invalidTLSHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	defer untrusted.Close()
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop()
		if invalidTLSHits.Load() != 0 {
			t.Error("connected browser accepted an untrusted certificate")
		}
	}()
	evidenceFile := filepath.Join(profile, "evidence.jsonl")
	configuration, err := json.Marshal(map[string]string{"origin": f.base, "mount": f.mount, "evidenceFile": evidenceFile, "untrustedURL": untrusted.URL})
	if err != nil {
		t.Fatal("cannot encode connected browser configuration")
	}
	payload, err := json.Marshal(map[string]string{"password": lifecyclePassword, "totpSecret": authenticationClientTOTPSecret})
	if err != nil {
		t.Fatal("cannot encode private connected browser input")
	}
	driver := exec.CommandContext(ctx, "node", "testdata/browser/connected_accounts_browser_e2e.cjs", endpoint, string(configuration))
	driver.Stdin = bytes.NewReader(payload)
	driver.WaitDelay = time.Second
	output, driverErr := driver.CombinedOutput()
	logins, complete := readConnectedAccountsBrowserEvidence(t, evidenceFile, f)
	assertAdminRedacted(t, output, f.secrets)
	if driverErr != nil {
		t.Fatalf("connected browser: %v\n%s", driverErr, output)
	}
	if !complete || len(logins) != 3 || string(output) != "Connected accounts browser passed\n" {
		t.Fatal("connected browser omitted a required phase")
	}
	automatic := f.verifyAccess(t, logins["automatic"].Token)
	local := f.verifyAccess(t, logins["local-confirmation"].Token)
	connected := f.verifyAccess(t, logins["connected-external"].Token)
	if automatic["id"] == before.ID || automatic["id"] == f.upstream.fixedSubject || local["id"] != before.ID || connected["id"] != before.ID || connected["origin"] != "upstream" || connected["sid"] != nil {
		t.Fatal("browser connection changed identity or authentication authority")
	}
	methods, ok := connected["amr"].([]any)
	if !ok || len(methods) != 3 || !slices.Contains(methods, any("federated")) || !slices.Contains(methods, any("pwd")) || !slices.Contains(methods, any("otp")) {
		t.Fatal("connected browser lost verified external and local-factor methods")
	}
	localMethods, ok := local["amr"].([]any)
	if !ok || len(localMethods) != 2 || !slices.Contains(localMethods, any("pwd")) || !slices.Contains(localMethods, any("otp")) {
		t.Fatal("connection lacked completed local factor proof")
	}
	retired := connectedAccountsRecordID(t, f.localIdentityFixture, automatic["id"].(string))
	connectedAccountsMove(t, before, localIdentityRecord(t, f.database, "alice"), retired, 1)
	if !retired.ExternallyProvisioned || len(retired.EmailAddresses) != 0 || len(retired.Passwords) != 0 || len(retired.MfaTokens) != 0 {
		t.Fatal("automatic browser account acquired target credentials")
	}
	// These are negative uses of exact observed cookies, after the natural UI
	// journey. Local factors on a federated login do not grant local-only APIs.
	final := logins["connected-external"]
	headers := http.Header{"Cookie": {"AUTHP_SESSION_ID=" + final.Session + "; AUTHP_ACCESS_TOKEN=" + final.Token}, "Origin": {f.base}, "Content-Type": {"application/json"}}
	profileResponse := f.send(t, f.plain, "POST", "/api/profile", strings.NewReader(`{"kind":"fetch_user_api_keys"}`), headers)
	profileResponse.requireStatus(t, 501)
	providerDestinationNoIssuance(t, profileResponse)
	params := f.authorization("trusted")
	params.Set("prompt", "none")
	f.secrets = append(f.secrets, params.Get("state"), params.Get("nonce"))
	response := f.send(t, f.plain, "GET", "/oidc/authorize?"+params.Encode(), nil, headers)
	f.callback(t, response, params, "login_required")
}
