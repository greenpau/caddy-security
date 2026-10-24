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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
)

func externalHTTPTestBinding() external.Config {
	return external.Config{Policy: "reports", Version: "revision-1", Issuer: "test-issuer", Realm: "local"}
}

func TestHTTPJSONExternalAuthorizationConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		module HTTPJSONExternalAuthorization
	}{
		{"missing_endpoint", HTTPJSONExternalAuthorization{}},
		{"userinfo", HTTPJSONExternalAuthorization{Endpoint: "https://private-sentinel@example.test"}},
		{"invalid_timeout", HTTPJSONExternalAuthorization{Endpoint: "https://example.test", Timeout: "0s"}},
		{"HTTP_TLS", HTTPJSONExternalAuthorization{Endpoint: "http://127.0.0.1", TLS: &ExternalAuthorizationTLS{}}},
		{"missing_key", HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &ExternalAuthorizationTLS{ClientCertificateFile: "private-sentinel"}}},
		{"missing_certificate", HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &ExternalAuthorizationTLS{ClientKeyFile: "private-sentinel"}}},
		{"invalid_path", HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &ExternalAuthorizationTLS{RootCAFile: "private-sentinel\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.module.Validate(); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("missing or unredacted validation", err)
			}
		})
	}
	for _, kind := range []string{"missing", "invalid_ca", "directory", "oversize", "invalid_pair"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-sentinel")
			module := &HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &ExternalAuthorizationTLS{RootCAFile: path}}
			switch kind {
			case "invalid_ca":
				if err := os.WriteFile(path, []byte("private-sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = filepath.Dir(path)
				module.TLS.RootCAFile = path
			case "oversize":
				if err := os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid_pair":
				cert, key, _ := cookieTLSCertificate(t)
				module.TLS = &ExternalAuthorizationTLS{ClientCertificateFile: cert, ClientKeyFile: key}
				if err := os.WriteFile(key, []byte("private-sentinel"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := module.Validate(); err != nil {
				t.Fatal("validation performed runtime I/O", err)
			}
			backend, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding())
			if backend != nil || err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("missing or unredacted construction failure", err)
			}
		})
	}
	module := &HTTPJSONExternalAuthorization{Endpoint: "https://example.test"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if backend, err := module.NewExternalAuthorizationBackend(ctx, externalHTTPTestBinding()); backend != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("construction ignored cancellation")
	}
}

func TestHTTPJSONExternalAuthorizationOwnership(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":"allow","policy":"reports","version":"revision-1"}`)
	}))
	defer server.Close()
	module := &HTTPJSONExternalAuthorization{Endpoint: server.URL}
	backend, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding())
	if err != nil {
		t.Fatal(err)
	}
	module.Endpoint = "https://invalid.example.test"
	request := external.Request{Policy: "reports", Version: "revision-1", Identity: external.Identity{Issuer: "test-issuer", Realm: "local", Subject: "alice"}, Action: "GET", Resource: "/reports"}
	if result, err := backend.Decide(t.Context(), request); err != nil || result.Decision != "allow" {
		t.Fatal("backend did not snapshot config", err)
	}
	closer := backend.(io.Closer)
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Decide(t.Context(), request); err == nil {
		t.Fatal("closed backend accepted work")
	}
	if calls.Load() != 1 {
		t.Fatal("closed backend reached network")
	}
}

func TestHTTPJSONExternalAuthorizationTLS(t *testing.T) {
	service := newExternalPolicyService(t)
	wrongCA, wrongKey, _ := cookieTLSCertificate(t)
	for _, name := range []string{"trusted_mTLS", "untrusted_server", "missing_client", "wrong_client"} {
		t.Run(name, func(t *testing.T) {
			tlsConfig := &ExternalAuthorizationTLS{RootCAFile: service.ca, ClientCertificateFile: service.clientCert, ClientKeyFile: service.clientKey}
			switch name {
			case "untrusted_server":
				tlsConfig.RootCAFile = wrongCA
			case "missing_client":
				tlsConfig.ClientCertificateFile = ""
				tlsConfig.ClientKeyFile = ""
			case "wrong_client":
				tlsConfig.ClientCertificateFile = wrongCA
				tlsConfig.ClientKeyFile = wrongKey
			}
			module := &HTTPJSONExternalAuthorization{Endpoint: service.server.URL + "/decide", TLS: tlsConfig}
			backend, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding())
			if err != nil {
				t.Fatal(err)
			}
			before := service.hits.Load()
			request := external.Request{Policy: "reports", Version: "revision-1", Identity: external.Identity{Issuer: "test-issuer", Realm: "local", Subject: "alice"}, Action: "GET", Resource: "/reports"}
			result, err := backend.Decide(t.Context(), request)
			if name == "trusted_mTLS" {
				if err != nil || result.Decision != "allow" {
					t.Fatal("trusted mTLS request failed", err)
				}
			} else {
				if err == nil || service.hits.Load() != before {
					t.Fatal("invalid TLS trust reached policy service")
				}
				if strings.Contains(err.Error(), service.server.URL) {
					t.Fatal("TLS failure exposed endpoint")
				}
			}
			if err := backend.(io.Closer).Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.After(2 * time.Second)
			for service.connections.Load() != 0 {
				select {
				case <-deadline:
					t.Fatal("owned transport retained idle connections")
				case <-time.After(time.Millisecond):
				}
			}
			if _, err := backend.Decide(t.Context(), request); err == nil {
				t.Fatal("closed TLS backend accepted work")
			}
		})
	}
}
