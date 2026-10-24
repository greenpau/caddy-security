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
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/authz/external"
	"github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson"
)

// HTTPJSONExternalAuthorization constructs a required policy-service backend.
// Values are literal operator configuration, never derived from an HTTP request.
// TLS files are read only when the app constructs its private runtime candidate.
type HTTPJSONExternalAuthorization struct {
	Endpoint string                    `json:"endpoint"`
	Timeout  string                    `json:"timeout,omitempty"`
	TLS      *ExternalAuthorizationTLS `json:"tls,omitempty"`
}

// ExternalAuthorizationTLS configures server trust and optional mTLS service
// credentials. A root CA file replaces system roots for this backend only.
// Certificate/key files must be supplied together; key bytes never enter JSON.
type ExternalAuthorizationTLS struct {
	RootCAFile            string `json:"root_ca_file,omitempty"`
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	ClientKeyFile         string `json:"client_key_file,omitempty"`
}

func init() { caddy.RegisterModule(HTTPJSONExternalAuthorization{}) }

// CaddyModule returns the HTTP JSON external authorization factory information.
func (HTTPJSONExternalAuthorization) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.external_authorization.httpjson", New: func() caddy.Module { return new(HTTPJSONExternalAuthorization) }}
}

// Validate checks configuration without opening files or creating transports.
func (m *HTTPJSONExternalAuthorization) Validate() error {
	config := httpjson.Config{Endpoint: m.Endpoint, Timeout: m.Timeout}
	if err := config.Validate(); err != nil {
		return err
	}
	if m.TLS == nil {
		return nil
	}
	if !strings.HasPrefix(m.Endpoint, "https://") {
		return fmt.Errorf("external authorization TLS requires an HTTPS endpoint")
	}
	c := m.TLS
	if (c.ClientCertificateFile == "") != (c.ClientKeyFile == "") {
		return fmt.Errorf("external authorization requires both client certificate and key files")
	}
	for _, path := range []string{c.RootCAFile, c.ClientCertificateFile, c.ClientKeyFile} {
		if len(path) > 4096 || !utf8.ValidString(path) || strings.TrimSpace(path) != path || strings.ContainsFunc(path, unicode.IsControl) {
			return fmt.Errorf("external authorization TLS file path is invalid")
		}
	}
	return nil
}

// NewExternalAuthorizationBackend returns a distinct app-owned backend. Its
// transport has no ambient proxy, cookies, redirects, or user credentials.
func (m *HTTPJSONExternalAuthorization) NewExternalAuthorizationBackend(ctx context.Context, binding external.Config) (external.Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	config := &httpjson.Config{Endpoint: m.Endpoint, Timeout: m.Timeout}
	if m.TLS == nil {
		backend, err := httpjson.New(config, nil)
		if err != nil {
			return nil, err
		}
		return &httpJSONExternalBackend{Backend: backend}, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if m.TLS.RootCAFile != "" {
		data, err := readExternalAuthorizationTLSFile(m.TLS.RootCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("external authorization CA file contains no certificates")
		}
	}
	if m.TLS.ClientCertificateFile != "" {
		cert, err := readExternalAuthorizationTLSFile(m.TLS.ClientCertificateFile)
		if err != nil {
			return nil, err
		}
		key, err := readExternalAuthorizationTLSFile(m.TLS.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("external authorization client certificate/key pair is invalid")
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		DialContext:  (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 16, IdleConnTimeout: 90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second, ExpectContinueTimeout: time.Second,
	}
	backend, err := httpjson.New(config, &http.Client{Transport: transport})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return &httpJSONExternalBackend{Backend: backend, transport: transport}, nil
}

// Bound certificate/key reads and reject nonregular files. Symlinks to regular
// files allow atomic operator-managed certificate rotation on a later reload.
func readExternalAuthorizationTLSFile(path string) ([]byte, error) {
	const limit = 1 << 20
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("external authorization TLS file must be regular and at most 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("external authorization TLS file could not be opened")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("external authorization TLS file must be regular and at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(data) > limit {
		return nil, fmt.Errorf("external authorization TLS file could not be read within its limit")
	}
	return data, nil
}

// The reference backend's Close has no error return. This wrapper adapts it to
// the app's io.Closer ownership and also retires an injected transport, if any.
type httpJSONExternalBackend struct {
	*httpjson.Backend
	transport *http.Transport
	once      sync.Once
}

func (b *httpJSONExternalBackend) Close() error {
	b.once.Do(func() {
		b.Backend.Close()
		if b.transport != nil {
			b.transport.CloseIdleConnections()
		}
	})
	return nil
}

var (
	_ caddy.Module                       = (*HTTPJSONExternalAuthorization)(nil)
	_ caddy.Validator                    = (*HTTPJSONExternalAuthorization)(nil)
	_ ExternalAuthorizationBackendModule = (*HTTPJSONExternalAuthorization)(nil)
	_ external.Backend                   = (*httpJSONExternalBackend)(nil)
	_ io.Closer                          = (*httpJSONExternalBackend)(nil)
)
