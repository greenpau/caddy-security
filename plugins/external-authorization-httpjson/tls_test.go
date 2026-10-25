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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"

	companion "github.com/greenpau/caddy-security/plugins/external-authorization-httpjson"
)

func TestHTTPJSONMutualTLSAndIndependentTransports(t *testing.T) {
	cert, key, _ := tlsFiles(t)
	clientCert, clientKey, clientRoots := tlsFiles(t, x509.ExtKeyUsageClientAuth)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	entered := make(chan struct{}, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if len(r.TLS.VerifiedChains) == 0 {
			t.Error("client identity was not verified")
		}
		var request external.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.Resource == "/hold" {
			entered <- struct{}{}
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
				t.Error("canceled request retained policy connection")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"decision":"allow","policy":"reports","version":"revision-1"}`)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientCAs: clientRoots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	module := &companion.HTTPJSONExternalAuthorization{Endpoint: server.URL, TLS: &companion.ExternalAuthorizationTLS{RootCAFile: cert, ClientCertificateFile: clientCert, ClientKeyFile: clientKey}}
	setup, stop := context.WithCancel(t.Context())
	first, err := module.NewExternalAuthorizationBackend(setup, externalHTTPTestBinding())
	stop()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.(io.Closer).Close() })
	second, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.(io.Closer).Close() })
	if first == second {
		t.Fatal("factory shared a closable transport")
	}
	request := external.Request{Policy: "reports", Version: "revision-1", Identity: external.Identity{Issuer: "test-issuer", Realm: "local", Subject: "alice"}, Action: "GET", Resource: "/reports"}
	if result, err := first.Decide(t.Context(), request); err != nil || result.Decision != "allow" {
		t.Fatal("trusted TLS decision failed after setup cancellation", err)
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := second.Decide(t.Context(), request); err != nil || result.Decision != "allow" {
		t.Fatal("closing one transport retired its peer", err)
	}
	wrongCert, wrongKey, _ := tlsFiles(t, x509.ExtKeyUsageClientAuth)
	for _, kind := range []string{"untrusted server", "missing client", "untrusted client"} {
		t.Run(kind, func(t *testing.T) {
			copy := *module
			tlsConfig := *module.TLS
			copy.TLS = &tlsConfig
			switch kind {
			case "untrusted server":
				tlsConfig.RootCAFile = wrongCert
			case "missing client":
				tlsConfig.ClientCertificateFile, tlsConfig.ClientKeyFile = "", ""
			case "untrusted client":
				tlsConfig.ClientCertificateFile, tlsConfig.ClientKeyFile = wrongCert, wrongKey
			}
			backend, err := copy.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding())
			if err != nil {
				t.Fatal(err)
			}
			defer backend.(io.Closer).Close()
			before := hits.Load()
			result, err := backend.Decide(t.Context(), request)
			if err == nil || result != nil || hits.Load() != before || strings.Contains(err.Error(), server.URL) {
				t.Fatal("failed TLS trust reached service or disclosed endpoint", err)
			}
		})
	}
	request.Resource = "/hold"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := second.Decide(ctx, request); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("policy request never arrived")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled policy request allowed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("policy cancellation did not finish")
	}
	// Failed key setup must not alter the already constructed peer's transport.
	if err := os.WriteFile(clientKey, []byte("private-key-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if backend, err := module.NewExternalAuthorizationBackend(t.Context(), externalHTTPTestBinding()); backend != nil || err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("invalid key setup published backend or disclosed key", err)
	}
	request.Resource = "/reports"
	if result, err := second.Decide(t.Context(), request); err != nil || result.Decision != "allow" {
		t.Fatal("failed replacement affected existing TLS runtime", err)
	}
}
