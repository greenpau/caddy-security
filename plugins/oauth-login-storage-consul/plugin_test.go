// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

package consul

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"
)

func TestConsulOAuthConfiguration(t *testing.T) {
	for name, input := range map[string]string{
		"defaults":     "pending {\n}",
		"configured":   "pending {\nprefix custom/pending\ntimeout 1000ms\ncapacity 7\n}",
		"duplicate":    "pending {\ncapacity 2\ncapacity 2\n}",
		"traversal":    "pending {\nprefix ../escape\n}",
		"absolute":     "pending {\nprefix /escape\n}",
		"unknown":      "pending {\naddress localhost:8500\n}",
		"timeout":      "pending {\ntimeout 31s\n}",
		"zero":         "pending {\ncapacity 0\n}",
		"oversized":    "pending {\ncapacity 1001\n}",
		"nested":       "pending {\nprefix nested {\n}\n}",
		"bare":         "pending",
		"extra_header": "pending extra {\n}",
	} {
		t.Run(name, func(t *testing.T) {
			var module ConsulOAuthLoginStore
			err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input))
			valid := name == "defaults" || name == "configured" || name == "bare"
			if !valid {
				if err == nil {
					t.Fatal("malformed declaration accepted")
				}
				return
			}
			if err != nil || module.Validate() != nil {
				t.Fatal("valid declaration rejected", err)
			}
			if name == "defaults" && (module.Prefix != "security/oauth-logins" || module.Timeout != "3s" || module.Capacity != 1000) {
				t.Fatal("defaults changed")
			}
			encoded, err := json.Marshal(module)
			if err != nil || strings.Contains(string(encoded), "ConsulClient") {
				t.Fatal("runtime leaked into configuration", err)
			}
			if _, err := module.PrepareOAuthLoginStore(); err == nil {
				t.Fatal("unprovisioned module prepared a runtime")
			}
		})
	}
}

func TestConsulOAuthFactory(t *testing.T) {
	client, err := consulapi.NewClient(&consulapi.Config{Address: "127.0.0.1:1", Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	storage := storageconsul.New()
	storage.ConsulClient = client
	m := &ConsulOAuthLoginStore{Name: "shared", storage: storage}
	prepared, err := m.PrepareOAuthLoginStore()
	if err != nil {
		t.Fatal(err)
	}
	f := prepared.(*factory)
	kv := &memoryKV{rows: make(map[string]*consulapi.KVPair)}
	f.kv = kv
	descriptor, err := f.OAuthLoginStoreConfig()
	if err != nil || descriptor.Validate() != nil {
		t.Fatal("invalid factory metadata", err)
	}
	m.Name = "retargeted"
	m.Prefix = "retargeted"
	storage.AESKey = []byte("invalid")
	a, err := f.NewOAuthLoginStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.NewOAuthLoginStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, clock := newTestStore(t, 1)
	tx := loginTransaction(clock, "factory")
	if err := a.Create(t.Context(), "cluster", tx); err != nil {
		t.Fatal(err)
	}
	if err := a.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.OAuthLoginStoreConfig(); !errors.Is(err, oauth.ErrLoginUnavailable) {
		t.Fatal("closed metadata stayed ready", err)
	}
	got, err := b.Get(t.Context(), "cluster", tx.State)
	if err != nil || got.Verifier != tx.Verifier {
		t.Fatal("factory reread mutable encryption or closed a peer", err)
	}
	actual, err := b.OAuthLoginStoreConfig()
	if err != nil || actual != descriptor {
		t.Fatal("factory descriptor mutated", err)
	}
	if _, err := m.PrepareOAuthLoginStore(); err == nil {
		t.Fatal("invalid storage encryption key accepted")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.NewOAuthLoginStore(canceled); err == nil {
		t.Fatal("canceled construction published handle")
	}
}
