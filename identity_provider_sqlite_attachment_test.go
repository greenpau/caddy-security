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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
)

func TestSQLiteTicketAttachmentConfiguration(t *testing.T) {
	for _, target := range []string{"accounts", "accounts with spaces,comma", "}", "{env.ATTACHMENT_STORE}"} {
		t.Run(target, func(t *testing.T) {
			m := sqliteTicketTestConfig(t)
			input := "application {\nrealm application\npath " + m.Path + "\npublic_origin " + m.PublicOrigin + "\nissuer_url " + m.IssuerURL + "\nattach to local identity store " + string(mustAttachmentJSON(t, target)) + "\n}"
			var parsed SQLiteTicketIdentityProvider
			if err := parsed.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err != nil {
				t.Fatal(err)
			}
			if parsed.Attachment == nil || parsed.Attachment.LocalIdentityStore != target {
				t.Fatal("complete attachment name changed")
			}
			loaded, _, err := sqliteTicketTestLoad(t, caddyconfig.JSONModuleObject(&parsed, "driver", "sqlite", nil))
			if err != nil {
				t.Fatal(err)
			}
			native := loaded.(*SQLiteTicketIdentityProvider)
			before := mustAttachmentJSON(t, native)
			cfg, err := native.config()
			if err != nil || cfg.Attachment == nil || cfg.Attachment == native.Attachment || cfg.Attachment.LocalIdentityStore != target {
				t.Fatal("runtime config did not detach attachment", err)
			}
			cfg.Attachment.LocalIdentityStore = "changed"
			if string(before) != string(mustAttachmentJSON(t, native)) {
				t.Fatal("normalization mutated native attachment")
			}
			runtime, err := native.NewIdentityProvider(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			consumer, ok := runtime.(attachment.Consumer)
			if !ok || consumer.IdentityAttachment() == nil || consumer.IdentityAttachment().StoreName() != target {
				t.Fatal("factory lost original attachment capability")
			}
			if _, err := consumer.IdentityAttachment().Store(); err == nil {
				t.Fatal("explicit attachment silently fell back to memory")
			}
			if closer, ok := runtime.(interface{ Close() error }); !ok {
				t.Fatal("factory lost closer")
			} else if err := closer.Close(); err != nil {
				t.Fatal("close attachment fixture failed")
			}
		})
	}
}

func mustAttachmentJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSQLiteTicketAttachmentDescriptor(t *testing.T) {
	m := sqliteTicketTestConfig(t)
	m.Path = filepath.Join(filepath.Dir(m.Path), "missing", "tickets.db")
	implicit, err := m.IdentityProviderConfig()
	if err != nil {
		t.Fatal(err)
	}
	m.Attachment = &attachment.Config{}
	before := mustAttachmentJSON(t, m)
	empty, err := m.IdentityProviderConfig()
	if err != nil || *empty != *implicit {
		t.Fatal("empty native attachment changed implicit configuration digest", err)
	}
	if string(before) != string(mustAttachmentJSON(t, m)) {
		t.Fatal("empty normalization rewrote native declaration")
	}
	previous := implicit.ConfigDigest
	for _, target := range []string{"accounts", "other-accounts"} {
		m.Attachment = &attachment.Config{LocalIdentityStore: target}
		descriptor, err := m.IdentityProviderConfig()
		if err != nil || descriptor.ConfigDigest == previous {
			t.Fatal("explicit attachment target missing from root binding", err)
		}
		if strings.Contains(string(mustAttachmentJSON(t, descriptor)), target) {
			t.Fatal("descriptor exposed attachment declaration")
		}
		previous = descriptor.ConfigDigest
	}
	if _, err := os.Stat(filepath.Dir(m.Path)); !os.IsNotExist(err) {
		t.Fatal("attachment validation created storage")
	}
	for _, target := range []string{":memory:", " accounts", "accounts ", "bad\nname", strings.Repeat("x", 257)} {
		m.Attachment = &attachment.Config{LocalIdentityStore: target}
		if err := m.Validate(); err == nil {
			t.Fatal("invalid native attachment name accepted")
		}
	}
}
