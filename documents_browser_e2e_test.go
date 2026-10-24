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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Private JSONL transfers observations out of the browser before assertions.
// A missing completion marker fails the journey but does not discard already
// observed secrets from cleanup's database and log scans.
type documentsBrowserRecord struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	Encoding    string `json:"encoding,omitempty"`
	Value       string `json:"value,omitempty"`
	Account     string `json:"account,omitempty"`
	UserID      string `json:"userID,omitempty"`
	PortalID    string `json:"portalID,omitempty"`
	KeyID       string `json:"keyID,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	RecoveryKey string `json:"recoveryKey,omitempty"`
	Access      string `json:"access,omitempty"`
	FileID      string `json:"fileID,omitempty"`
	Empty       bool   `json:"empty,omitempty"`
	Phase       string `json:"phase,omitempty"`
}

type documentsBrowserEvidence struct {
	recovery []documentsBrowserRecord
	files    []documentsBrowserRecord
	logins   map[string]string
	complete bool
}

// Only this fixture's private fresh path is read. Reject symlinks, broad modes,
// oversized data, unknown fields and incomplete JSON instead of dumping data.
func readDocumentsBrowserEvidence(t *testing.T, path, phase string, f *caddyDocumentsFixture, material *[][]byte) documentsBrowserEvidence {
	t.Helper()
	result := documentsBrowserEvidence{logins: make(map[string]string)}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() == 0 || info.Size() > 128*1024 {
		t.Error("Documents browser evidence was missing, oversized or not private")
		return result
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Error("Documents browser evidence could not be read")
		return result
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	for {
		var record documentsBrowserRecord
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil || record.Version != 1 || result.complete {
			t.Error("Documents browser evidence contained an invalid record")
			return result
		}
		switch record.Kind {
		case "secret":
			if record.Value == "" || len(record.Value) > 16*1024 {
				t.Error("Documents browser secret inventory contained an invalid entry")
				return result
			}
			f.secrets = append(f.secrets, record.Value)
			switch record.Encoding {
			case "utf8":
			case "base64url":
				raw, err := base64.RawURLEncoding.Strict().DecodeString(record.Value)
				if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != record.Value {
					t.Error("Documents browser key inventory contained invalid material")
					return result
				}
				*material = append(*material, raw)
				f.secrets = append(f.secrets, hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw))
			default:
				t.Error("Documents browser evidence contained an unknown encoding")
				return result
			}
		case "login":
			if f.expectedUsers[record.Account] == "" || record.Access == "" || result.logins[record.Account] != "" {
				t.Error("Documents browser login evidence was invalid")
				return result
			}
			f.secrets = append(f.secrets, record.Access)
			result.logins[record.Account] = record.Access
		case "recovery":
			if record.UserID != f.expectedUsers[record.Account] || record.RecoveryKey == "" || record.KeyID == "" || record.PublicKey == "" || record.PortalID == "" {
				t.Error("Documents browser recovery evidence lacked immutable identity")
				return result
			}
			result.recovery = append(result.recovery, record)
		case "file":
			if record.FileID == "" {
				t.Error("Documents browser file evidence was empty")
				return result
			}
			result.files = append(result.files, record)
		case "phase":
			if record.Phase != phase {
				t.Error("Documents browser completion belonged to the wrong phase")
				return result
			}
			result.complete = true
		default:
			t.Error("Documents browser evidence contained an unknown record")
			return result
		}
	}
	return result
}

// The enclosing isolated Caddy child supplies a dedicated nested fixture. No
// token is injected into Chrome, and no browser context or CryptoKey survives
// between phases. Stop/Load proves root replacement, not OS-process restart.
func runCaddyDocumentsBrowser(t *testing.T, f *caddyDocumentsFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	if err := os.MkdirAll("tmp", 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := os.MkdirTemp("tmp", "documents-browser-")
	if err != nil {
		t.Fatal(err)
	}
	profile, err = filepath.Abs(profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(profile); err != nil {
			t.Error("remove private Documents browser profile", err)
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
	chrome := exec.CommandContext(ctx, caddyRefreshBrowserExecutable(t),
		"--headless=new", "--remote-debugging-port=0", "--user-data-dir="+profile,
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-sync", "--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--password-store=basic", "--use-mock-keychain", "about:blank")
	endpoint, stop, err := startCaddyRefreshBrowser(ctx, chrome, profile)
	if err != nil {
		t.Fatal(err)
	}
	var material [][]byte
	defer func() {
		stop()
		f.stop(t)
		f.scan(t, material)
		if invalidTLSHits.Load() != 0 {
			t.Error("Documents browser accepted an untrusted certificate")
		}
	}()
	var created documentsBrowserEvidence
	for _, phase := range []string{"create", "recover"} {
		if phase == "recover" {
			f.stop(t)
			f.scan(t, material)
			f.start(t)
			for _, token := range created.logins {
				f.doc(t, token, "bootstrap", nil, nil, http.StatusUnauthorized)
			}
		}
		config := map[string]any{
			"origin": f.base, "mount": f.mount, "fixtureURL": f.fixtureURL, "cryptoURL": f.cryptoURL,
			"phase": phase, "evidenceFile": filepath.Join(profile, phase+"-evidence.jsonl"),
			"expectedUsers": f.expectedUsers, "untrustedURL": untrusted.URL,
		}
		payload := map[string]any{"credentials": map[string]string{
			"alice": lifecyclePassword, "bob": localIdentityBobPassword, "admin": lifecyclePassword,
		}}
		if phase == "recover" {
			payload["recovery"], payload["files"] = created.recovery, created.files
		}
		encodedConfig, err := json.Marshal(config)
		if err != nil {
			t.Fatal("cannot encode Documents browser configuration")
		}
		encodedInput, err := json.Marshal(payload)
		if err != nil {
			t.Fatal("cannot encode private Documents browser input")
		}
		deadline := 100 * time.Second
		if phase == "recover" {
			deadline = 60 * time.Second
		}
		phaseCtx, phaseCancel := context.WithTimeout(ctx, deadline)
		driver := exec.CommandContext(phaseCtx, "node", "testdata/browser/documents_browser_e2e.cjs", endpoint, string(encodedConfig))
		driver.Stdin = bytes.NewReader(encodedInput)
		driver.WaitDelay = time.Second
		output, driverErr := driver.CombinedOutput()
		phaseCancel()
		observed := readDocumentsBrowserEvidence(t, config["evidenceFile"].(string), phase, f, &material)
		assertAdminRedacted(t, output, f.secrets)
		if driverErr != nil {
			t.Fatalf("Documents browser %s: %v\n%s", phase, driverErr, output)
		}
		if !observed.complete || string(output) != "Documents browser "+phase+" passed\n" {
			t.Fatal("Documents browser did not complete its phase assertions")
		}
		for account, token := range observed.logins {
			claims := f.verifyAccess(t, token)
			if claims["id"] != f.expectedUsers[account] || claims["origin"] != "local" {
				t.Fatal("independently verified browser credential had the wrong local identity")
			}
		}
		if phase == "create" {
			if len(observed.logins) != 3 || len(observed.recovery) != 2 || len(observed.files) != 2 ||
				observed.recovery[0].PortalID != observed.recovery[1].PortalID ||
				observed.files[0].Empty || !observed.files[1].Empty || observed.files[0].FileID == observed.files[1].FileID {
				t.Fatal("Documents creation evidence omitted an account, vault or file")
			}
			created = observed
		} else if len(observed.logins) != 2 || strings.TrimSpace(observed.logins["alice"]) == "" || observed.logins["bob"] == "" {
			t.Fatal("Documents recovery omitted fresh owner or recipient login")
		}
	}
}
