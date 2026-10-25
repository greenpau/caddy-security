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

	"github.com/greenpau/go-authcrunch/pkg/idp"
)

// IdentityProviderBackendModule prepares an external provider without opening
// runtime resources. Its descriptor fingerprints normalized configuration.
// Each factory call transfers a fresh, configured handle to the app, preserving
// optional HTTP login and attachment capabilities. Return a safely closable
// partial handle or a real nil after unwinding acquisition on failure. Module
// Cleanup must not close the runtime; the app drains requests before disposal.
type IdentityProviderBackendModule interface {
	IdentityProviderConfig() (*idp.ExternalIdentityProviderConfig, error)
	NewIdentityProvider(context.Context) (idp.IdentityProvider, error)
}
