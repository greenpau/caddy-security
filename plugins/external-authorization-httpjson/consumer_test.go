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

package httpjson_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"

	companion "github.com/greenpau/caddy-security/plugins/external-authorization-httpjson"
)

func externalHTTPTestBinding() external.Config {
	return external.Config{Policy: "reports", Version: "revision-1", Issuer: "test-issuer", Realm: "local"}
}

func TestHTTPJSONExternalAuthorizationConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		module companion.HTTPJSONExternalAuthorization
	}{
		{"missing_endpoint", companion.HTTPJSONExternalAuthorization{}},
		{"userinfo", companion.HTTPJSONExternalAuthorization{Endpoint: "https://private-sentinel@example.test"}},
		{"invalid_timeout", companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test", Timeout: "0s"}},
		{"HTTP_TLS", companion.HTTPJSONExternalAuthorization{Endpoint: "http://127.0.0.1", TLS: &companion.ExternalAuthorizationTLS{}}},
		{"missing_key", companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &companion.ExternalAuthorizationTLS{ClientCertificateFile: "private-sentinel"}}},
		{"missing_certificate", companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &companion.ExternalAuthorizationTLS{ClientKeyFile: "private-sentinel"}}},
		{"invalid_path", companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &companion.ExternalAuthorizationTLS{RootCAFile: "private-sentinel\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.module.Validate(); err == nil || strings.Contains(err.Error(), "private-sentinel") {
				t.Fatal("missing or unredacted validation", err)
			}
		})
	}
	for _, kind := range []string{"missing", "invalid_ca", "directory", "oversize", "invalid_pair", "missing_certificate", "missing_key"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-sentinel")
			module := &companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test", TLS: &companion.ExternalAuthorizationTLS{RootCAFile: path}}
			switch kind {
			case "missing_certificate":
				module.TLS = &companion.ExternalAuthorizationTLS{ClientCertificateFile: path, ClientKeyFile: path + ".key"}
			case "missing_key":
				cert, _, _ := tlsFiles(t)
				module.TLS = &companion.ExternalAuthorizationTLS{ClientCertificateFile: cert, ClientKeyFile: path}
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
				cert, key, _ := tlsFiles(t)
				module.TLS = &companion.ExternalAuthorizationTLS{ClientCertificateFile: cert, ClientKeyFile: key}
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
	module := &companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if backend, err := module.NewExternalAuthorizationBackend(ctx, externalHTTPTestBinding()); backend != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("construction ignored cancellation")
	}
}

func TestHTTPJSONInvalidFactoryInput(t *testing.T) {
	module := &companion.HTTPJSONExternalAuthorization{Endpoint: "https://example.test"}
	if backend, err := module.NewExternalAuthorizationBackend(t.Context(), external.Config{}); backend != nil || err == nil {
		t.Fatal("invalid binding published runtime", err)
	}
	module.Endpoint = "https://private-canary@example.test"
	if backend, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding()); backend != nil || err == nil || strings.Contains(err.Error(), "private-canary") {
		t.Fatal("invalid backend published runtime or disclosed credentials", err)
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
	module := &companion.HTTPJSONExternalAuthorization{Endpoint: server.URL}
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

func tlsFiles(t *testing.T, usages ...x509.ExtKeyUsage) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Cookie test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if len(usages) != 0 {
		template.ExtKeyUsage = usages
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("certificate not trusted")
	}
	return certFile, keyFile, roots
}
