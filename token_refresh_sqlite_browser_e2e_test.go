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
	"bufio"
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
	"sync/atomic"
	"testing"
	"time"
)

type sqliteCommitBrowserRecord struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	Phase     string `json:"phase,omitempty"`
	Value     string `json:"value,omitempty"`
	Access    string `json:"access,omitempty"`
	Refresh   string `json:"refresh,omitempty"`
	SessionID string `json:"sessionID,omitempty"`
}

func sqliteCommitBrowserEvidence(t *testing.T, f *sqliteCommitFixture, path string) map[string]sqliteCommitBrowserRecord {
	t.Helper()
	result := make(map[string]sqliteCommitBrowserRecord)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 128<<10 {
		t.Error("private browser evidence is missing or invalid")
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Error("private browser evidence cannot be read")
		return result
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	complete := false
	for {
		var record sqliteCommitBrowserRecord
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil || record.Version != 1 || complete {
			t.Error("private browser evidence is malformed")
			break
		}
		switch record.Kind {
		case "secret":
			if record.Value == "" || len(record.Value) > 64<<10 {
				t.Error("browser secret evidence is invalid")
				return result
			}
			f.secrets = append(f.secrets, record.Value)
		case "grant":
			f.secrets = append(f.secrets, record.Access, record.Refresh)
			if (record.Phase != "initial" && record.Phase != "fresh" && record.Phase != "rotated") || record.Access == "" || record.Refresh == "" || record.SessionID == "" || result[record.Phase].Kind != "" {
				t.Error("browser grant evidence is invalid")
				return result
			}
			result[record.Phase] = record
		case "phase":
			if record.Phase != "complete" {
				t.Error("browser completion evidence is invalid")
				return result
			}
			result["complete"] = record
			complete = true
		default:
			t.Error("browser evidence contains an unknown record")
			return result
		}
	}
	return result
}

// One actual Chrome context survives Caddy root Stop/Load. Process pipes carry
// only fixed phase names and stdin credentials; no HTTP control route exists.
func runSQLiteCommitBrowser(t *testing.T, f *sqliteCommitFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal("cannot prepare private browser root")
	}
	profile, err := os.MkdirTemp("tmp", "sqlite-commit-browser-")
	if err != nil {
		t.Fatal("cannot create private browser profile")
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal("cannot resolve private browser profile")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("cannot remove private browser profile")
		}
	})
	trust := exec.CommandContext(ctx, "node", "testdata/browser/token_refresh_browser_trust.cjs", profile, f.cert)
	trust.WaitDelay = time.Second
	if _, err := trust.CombinedOutput(); err != nil {
		t.Fatal("private Chrome trust installation failed")
	}
	var invalidTLSHits atomic.Int64
	untrusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { invalidTLSHits.Add(1); w.WriteHeader(204) }))
	untrusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	untrusted.StartTLS()
	defer untrusted.Close()
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t), "--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal("private Chrome startup failed")
	}
	defer stop()
	evidencePath := filepath.Join(profile, "refresh-evidence.jsonl")
	config, err := json.Marshal(map[string]string{"origin": f.base, "mount": f.mount, "accessCookie": f.cookie, "refreshCookie": "AUTHP_REFRESH_TOKEN", "evidenceFile": evidencePath, "untrustedURL": untrusted.URL})
	if err != nil {
		t.Fatal("cannot encode browser configuration")
	}
	driverContext, driverCancel := context.WithCancel(ctx)
	defer driverCancel()
	driver := exec.CommandContext(driverContext, "node", "testdata/browser/token_refresh_sqlite_browser_e2e.cjs", endpoint, string(config))
	driver.WaitDelay = time.Second
	input, err := driver.StdinPipe()
	if err != nil {
		t.Fatal("cannot open private browser input")
	}
	output, err := driver.StdoutPipe()
	if err != nil {
		t.Fatal("cannot open browser phase output")
	}
	var diagnostic bytes.Buffer
	driver.Stderr = &diagnostic
	if err := driver.Start(); err != nil {
		t.Fatal("cannot start browser driver")
	}
	phases := make(chan string, 8)
	readDone := make(chan struct{})
	var phaseError bool
	go func() {
		defer close(readDone)
		defer close(phases)
		scanner := bufio.NewScanner(output)
		scanner.Buffer(make([]byte, 1024), 4096)
		for scanner.Scan() {
			var message struct {
				Phase string `json:"phase"`
			}
			decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&message) != nil || decoder.Decode(new(any)) != io.EOF {
				phaseError = true
				return
			}
			switch message.Phase {
			case "ready", "uncertain", "blocked_after_reopen", "complete":
			default:
				phaseError = true
				return
			}
			select {
			case phases <- message.Phase:
			case <-driverContext.Done():
				return
			}
		}
		phaseError = scanner.Err() != nil
	}()
	done := make(chan error, 1)
	go func() { <-readDone; done <- driver.Wait() }()
	var finished bool
	defer func() {
		_ = input.Close()
		driverCancel()
		if !finished {
			<-done
		}
		<-readDone
		_ = sqliteCommitBrowserEvidence(t, f, evidencePath)
		f.capture()
		assertAdminRedacted(t, diagnostic.Bytes(), f.secrets)
		if t.Failed() && diagnostic.Len() != 0 {
			t.Logf("browser driver diagnostics: %s", diagnostic.Bytes())
		}
		if phaseError {
			t.Error("browser emitted invalid phase data")
		}
		if invalidTLSHits.Load() != 0 {
			t.Error("browser reached an untrusted TLS handler")
		}
	}()
	send := func(phase string, password string) {
		t.Helper()
		message := map[string]string{"phase": phase}
		if password != "" {
			message["password"] = password
		}
		if err := json.NewEncoder(input).Encode(message); err != nil {
			t.Fatal("browser private control input failed")
		}
	}
	receive := func(expected string) {
		t.Helper()
		timer := time.NewTimer(35 * time.Second)
		defer timer.Stop()
		select {
		case phase, ok := <-phases:
			if !ok || phase != expected {
				t.Fatalf("browser did not complete phase %s", expected)
			}
		case <-ctx.Done():
			t.Fatalf("browser deadline at phase %s", expected)
		case <-timer.C:
			t.Fatalf("browser phase deadline at %s", expected)
		}
	}
	send("credentials", lifecyclePassword)
	receive("ready")
	before := f.ArmCommitFailure(t)
	send("attempt", "")
	receive("uncertain")
	f.AssertUncertain(t, before)
	// Both existing tabs already refused repeated refresh calls. Reopen preserves
	// their metadata and cookies; never resolve uncertainty by replaying them.
	blocked := f.witness.snapshot()
	f.RestartSameConfig(t)
	send("reopened", "")
	receive("blocked_after_reopen")
	f.assertNoExchange(t, blocked)
	send("fresh", "")
	receive("complete")
	_ = input.Close()
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal("browser recovery assertions or cleanup failed")
		}
	case <-ctx.Done():
		t.Fatal("browser driver did not exit after recovery")
	}
	<-readDone
	observed := sqliteCommitBrowserEvidence(t, f, evidencePath)
	if len(observed) != 4 || observed["complete"].Kind != "phase" {
		t.Fatal("browser did not retain complete private recovery evidence")
	}
	for _, phase := range []string{"initial", "fresh", "rotated"} {
		record := observed[phase]
		claims := f.verify(t, record.Access)
		if claims["sid"] != record.SessionID {
			t.Fatal("browser metadata did not match its independently verified grant")
		}
	}
	initial, fresh, rotated := observed["initial"], observed["fresh"], observed["rotated"]
	if initial.SessionID == fresh.SessionID || fresh.SessionID != rotated.SessionID || initial.Refresh == fresh.Refresh || fresh.Refresh == rotated.Refresh {
		t.Fatal("browser recovery family ownership changed")
	}
	f.assertOriginalExchangedOnce(t, initial.Refresh)
	snapshot := f.witness.snapshot()
	if snapshot.RefreshRequests != before.RefreshRequests+2 || snapshot.RotateCalls != before.RotateCalls+2 || snapshot.Uncertain != before.Uncertain+1 {
		t.Fatal("browser recovery performed an unexpected exchange")
	}
	for _, record := range []sqliteCommitBrowserRecord{initial, fresh, rotated} {
		if record.Access == snapshot.Staged {
			t.Fatal("browser published the uncommitted staged access token")
		}
	}
	f.resource(t, rotated.Access, http.StatusOK)
}
