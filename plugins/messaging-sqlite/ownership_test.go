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

package sqlite_test

import (
	"os"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/messaging"
	backend "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/messaging-sqlite"
)

func TestMessagingFactoryIndependentHandles(t *testing.T) {
	module := sqliteMessagingTestConfig(t)
	first, err := module.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	producer := first.(*backend.Outbox)
	t.Cleanup(func() { _ = producer.Close() })
	second, err := module.NewMessagingProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	consumer := second.(*backend.Outbox)
	t.Cleanup(func() { _ = consumer.Close() })
	if first == second {
		t.Fatal("factory shared ownership")
	}
	if err := first.Send(&messaging.SendInput{Subject: "durable acceptance", Body: "body", Recipients: []string{"alice@example.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	message, err := consumer.Claim(t.Context())
	if err != nil || message.Subject != "durable acceptance" {
		t.Fatal("closing producer lost peer queue", err)
	}
	if err := consumer.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
		t.Fatal(err)
	}
}

func TestMessagingInvalidDeclarationBeforeConstruction(t *testing.T) {
	module := sqliteMessagingTestConfig(t)
	module.Name = ""
	if err := module.Validate(); err == nil {
		t.Fatal("invalid native declaration accepted")
	}
	if value, err := module.NewMessagingProvider(t.Context()); value != nil || err == nil {
		t.Fatal("invalid declaration published runtime", err)
	}
	if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
		t.Fatal("invalid declaration touched storage")
	}
}

func TestMessagingNilDeclaration(t *testing.T) {
	var module *companion.SQLiteMessagingProvider
	if config, err := module.BackendConfig(); err == nil || config != nil {
		t.Fatal("nil declaration published backend configuration", err)
	}
	if err := module.Validate(); err == nil {
		t.Fatal("nil declaration passed validation")
	}
	if name, err := module.MessagingProviderName(); err == nil || name != "" {
		t.Fatal("nil declaration published a queue name", err)
	}
	if provider, err := module.NewMessagingProvider(t.Context()); err == nil || provider != nil {
		t.Fatal("nil declaration published a queue", err)
	}
}
