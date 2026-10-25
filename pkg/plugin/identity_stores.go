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
)

// IdentityStoreBackendModule prepares a store without opening runtime storage.
// The descriptor fingerprints normalized configuration for root persistence.
// Each successful factory call transfers a distinct handle to the app. On
// failure return a partial handle safe to close or unwind acquisition before
// returning a real nil interface, never a typed nil. Cleanup panics from an
// invalid plugin are contained so other acquired stores can still be closed.
// Runtime calls use request contexts; the setup context is not a shutdown signal.
// Module Cleanup must not close the returned store.
type IdentityStoreBackendModule interface {
	IdentityStoreConfig() (*ids.ExternalIdentityStoreConfig, error)
	NewIdentityStore(context.Context) (ids.IdentityStore, error)
}
