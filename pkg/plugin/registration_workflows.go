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

	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
)

// RegistrationWorkflowBackendModule prepares enrollment without opening storage.
// Each factory call receives only its selected, borrowed dependencies and returns
// a fresh provider. On failure return a safely closable partial handle or a real
// nil after unwinding acquisition. Module Cleanup must not dispose the provider.
// Neither factories nor providers may close their borrowed store or messaging
// provider. The app drains requests before closing workflows and dependencies.
type RegistrationWorkflowBackendModule interface {
	RegistrationWorkflowConfig() (*registry.ExternalUserRegistryConfig, error)
	NewRegistrationWorkflow(context.Context, ids.IdentityStore, messaging.Provider) (registry.Provider, error)
}
