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
	"io"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
)

func externalHTTPTestBinding() external.Config {
	return external.Config{Policy: "reports", Version: "revision-1", Issuer: "test-issuer", Realm: "local"}
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
