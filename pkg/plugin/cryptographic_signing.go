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

	"github.com/greenpau/go-authcrunch/pkg/kms"
)

// AccessSignerBackendModule prepares an immutable factory without loading keys
// or acquiring resources. Module cleanup never owns returned signer handles.
type AccessSignerBackendModule interface {
	PrepareAccessSigner() (AccessSignerFactory, error)
}

// AccessSignerFactory freezes copied configuration and core metadata. Every
// constructor call transfers a fresh signer to the app; later module mutations
// cannot change it. A failed constructor returns a safely closable partial
// handle, or real nil after unwinding acquisition. The context applies to setup,
// not runtime lifetime. Optional io.Closer ownership belongs solely to the app.
type AccessSignerFactory interface {
	AccessSignerConfig() (kms.ExternalAccessSignerConfig, error)
	NewAccessSigner(context.Context) (kms.AccessSigner, error)
}
