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
	"io"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
)

// CredentialAuthenticator is an app-owned fresh API-key backend. Basic methods
// exist only for the upstream interface; host bindings never enable them.
// Each lookup receives the protected request's context and bypasses caches.
type CredentialAuthenticator interface {
	authproxy.ContextAuthenticator
	authproxy.FreshAuthenticator
	io.Closer
	GetConfig() map[string]any
}

// CredentialAuthenticatorBackendModule prepares configuration without opening
// runtime resources. Each factory call transfers a distinct backend to the app,
// shared only by that app's matching policies. Setup context is not a shutdown
// signal; module Cleanup must not close the returned handle. On failure return
// a closable partial result or unwind acquisition, using a real nil interface.
type CredentialAuthenticatorBackendModule interface {
	CredentialIdentity() (name, realm string)
	NewCredentialAuthenticator(context.Context) (CredentialAuthenticator, error)
}
