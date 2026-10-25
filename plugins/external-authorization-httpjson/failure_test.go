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

package httpjson

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	backend "github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
)

func setupBinding() external.Config {
	return external.Config{Policy: "reports", Version: "v1", Issuer: "fixture", Realm: "staff"}
}

func TestExternalAuthorizationPlainConstructorFailure(t *testing.T) {
	module := &HTTPJSONExternalAuthorization{Endpoint: "http://127.0.0.1:1/decide"}
	failure := errors.New("constructor failed")
	result, err := module.newExternalAuthorizationBackend(t.Context(), setupBinding(), readExternalAuthorizationTLSFile,
		func(cfg *backend.Config, client *http.Client) (*backend.Backend, error) {
			if cfg.Endpoint != module.Endpoint || client != nil {
				t.Fatal("ordinary construction received the wrong configuration or client")
			}
			return nil, failure
		})
	if result != nil || !errors.Is(err, failure) {
		t.Fatal("constructor failure published a backend or lost its error", err)
	}
	// A failed invocation cannot replace the factory used by a peer invocation.
	peer, err := module.NewExternalAuthorizationBackend(t.Context(), setupBinding())
	if err != nil || peer == nil {
		t.Fatal("failed setup affected the next factory call", err)
	}
	if err := peer.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
}

func setupTLSService(t *testing.T) (*httptest.Server, string, <-chan struct{}) {
	t.Helper()
	closed := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return server, path, closed
}

func TestExternalAuthorizationTLSConstructorFailureClosesTransport(t *testing.T) {
	server, path, closed := setupTLSService(t)
	module := &HTTPJSONExternalAuthorization{Endpoint: server.URL, TLS: &ExternalAuthorizationTLS{RootCAFile: path}}
	failure := errors.New("constructor failed after acquiring a connection")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	requestTimeout := time.AfterFunc(3*time.Second, cancel)
	defer requestTimeout.Stop()
	result, err := module.newExternalAuthorizationBackend(t.Context(), setupBinding(), readExternalAuthorizationTLSFile,
		func(_ *backend.Config, client *http.Client) (*backend.Backend, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("trusted fixture connection failed", err)
			}
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.Close {
				t.Fatal("fixture connection was not reusable", readErr, closeErr)
			}
			// Stop the request deadline without canceling its context. Only the
			// adapter's failure cleanup may close this now-idle connection.
			if !requestTimeout.Stop() {
				t.Fatal("fixture request exhausted its deadline")
			}
			return nil, failure
		})
	if result != nil || !errors.Is(err, failure) {
		t.Fatal("TLS constructor failure published a backend", err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("failed setup retained an idle TLS connection")
	}
}

func TestExternalAuthorizationCancellationAfterTLSRead(t *testing.T) {
	server, path, _ := setupTLSService(t)
	module := &HTTPJSONExternalAuthorization{Endpoint: server.URL, TLS: &ExternalAuthorizationTLS{RootCAFile: path}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	constructed := false
	result, err := module.newExternalAuthorizationBackend(ctx, setupBinding(), func(path string) ([]byte, error) {
		data, err := readExternalAuthorizationTLSFile(path)
		cancel()
		return data, err
	}, func(*backend.Config, *http.Client) (*backend.Backend, error) {
		constructed = true
		return nil, errors.New("unexpected constructor")
	})
	if result != nil || !errors.Is(err, context.Canceled) || constructed {
		t.Fatal("setup canceled after a successful TLS read reached construction", err)
	}
}

type faultTLSFile struct {
	reader            io.Reader
	info              os.FileInfo
	statErr           error
	closes, bytesRead int
}

func (f *faultTLSFile) Read(p []byte) (int, error) {
	n, err := f.reader.Read(p)
	f.bytesRead += n
	return n, err
}
func (f *faultTLSFile) Stat() (os.FileInfo, error) { return f.info, f.statErr }
func (f *faultTLSFile) Close() error               { f.closes++; return nil }

type sizedTLSFileInfo struct {
	os.FileInfo
	size int64
}

func (f sizedTLSFileInfo) Size() int64 { return f.size }

type tlsReadFailure struct{ err error }

func (r tlsReadFailure) Read([]byte) (int, error) { return 0, r.err }

func TestTLSFileFailuresAfterPathValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-canary.pem")
	if err := os.WriteFile(path, []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"open", "stat", "replaced_by_directory", "grew_before_stat", "read", "grew_during_read"} {
		t.Run(phase, func(t *testing.T) {
			failure := errors.New("private-canary I/O diagnostic")
			file := &faultTLSFile{reader: strings.NewReader("small"), info: info}
			switch phase {
			case "stat":
				file.statErr = failure
			case "replaced_by_directory":
				file.info = directory
			case "grew_before_stat":
				file.info = sizedTLSFileInfo{FileInfo: info, size: (1 << 20) + 1}
			case "read":
				file.reader = tlsReadFailure{err: failure}
			case "grew_during_read":
				file.reader = strings.NewReader(strings.Repeat("x", (1<<20)+32))
			}
			data, err := readExternalAuthorizationTLSFileWith(path, func(string) (externalAuthorizationTLSFile, error) {
				if phase == "open" {
					return nil, failure
				}
				return file, nil
			})
			if data != nil || err == nil || strings.Contains(err.Error(), "private-canary") || strings.Contains(err.Error(), path) {
				t.Fatal("failed TLS read returned data or disclosed private diagnostics", err)
			}
			wantCloses := 1
			if phase == "open" {
				wantCloses = 0
			}
			if file.closes != wantCloses {
				t.Fatal("acquired TLS file was not closed exactly once")
			}
			if phase == "grew_during_read" && file.bytesRead != (1<<20)+1 {
				t.Fatal("growing file was not read to the bounded rejection byte")
			}
			if phase != "grew_during_read" && file.bytesRead != 0 {
				t.Fatal("rejected file yielded bytes")
			}
		})
	}
}
