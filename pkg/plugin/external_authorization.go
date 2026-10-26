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

package plugin

import (
	"context"

	"github.com/greenpau/go-authcrunch/pkg/authz/external"
)

// ExternalAuthorizationBackendModule is implemented by Caddy backend factories.
// Provision/Validate must only prepare configuration, without opening runtime
// resources. NewExternalAuthorizationBackend creates a fresh, exclusively app-owned
// backend and checks any backend-specific binding constraints. Its context is
// for construction only; do not retain it as a runtime cancellation signal.
//
// The app calls io.Closer.Close, when implemented by the returned backend, after
// draining requests and closing the AuthCrunch root. Module Cleanup must never
// close that backend. On error, return acquired resources as a closable backend
// or unwind them before returning nil. Return real nil, not a typed nil. Do not
// share a closable backend between calls; each call transfers one ownership.
type ExternalAuthorizationBackendModule interface {
	NewExternalAuthorizationBackend(context.Context, external.Config) (external.Backend, error)
}

// ExternalAuthorizationTLS describes server trust and a paired mTLS service
// identity. Files are read only when the selected backend constructs a runtime.
type ExternalAuthorizationTLS struct {
	RootCAFile            string `json:"root_ca_file,omitempty"`
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	ClientKeyFile         string `json:"client_key_file,omitempty"`
}
