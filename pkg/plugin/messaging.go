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

	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

// MessagingProviderBackendModule validates configuration without opening storage.
// Each factory call transfers a fresh provider and optional io.Closer to the app.
// On failure, return a closable partial result or unwind before returning nil.
// Module Cleanup must not close returned providers. The constructor context only
// bounds setup; the app owns worker cancellation separately from Caddy cleanup.
type MessagingProviderBackendModule interface {
	MessagingProviderName() (string, error)
	NewMessagingProvider(context.Context) (messaging.Provider, error)
}

// MessagingDeliveryMetadata names the email transport selected by an outbox.
// The host enables its SQLite delivery worker only for the SQLite module ID.
type MessagingDeliveryMetadata interface {
	DeliveryProviderName() string
}
