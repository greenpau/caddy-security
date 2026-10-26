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

package plugins_test

import (
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/filestorage"
	tickets "github.com/greenpau/caddy-security/plugins/identity-providers-consul"
	accounts "github.com/greenpau/caddy-security/plugins/identity-stores-consul"
	refresh "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-consul"
	"path/filepath"
	"strings"
	"testing"
)

// Standalone companions must fail closed instead of silently selecting private
// memory when Caddy has not selected the supported global Consul storage module.
type consulModuleLoader struct {
	ID     string          `json:"id"`
	Config json.RawMessage `json:"config"`
}

func init() { caddy.RegisterModule(consulModuleLoader{}) }
func (consulModuleLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "consul_companion_test_loader", New: func() caddy.Module { return new(consulModuleLoader) }}
}
func (m *consulModuleLoader) Provision(ctx caddy.Context) error {
	_, err := ctx.LoadModuleByID(m.ID, m.Config)
	return err
}
func (*consulModuleLoader) Start() error { return nil }
func (*consulModuleLoader) Stop() error  { return nil }

func TestConsulCompanionsRequireGlobalStorage(t *testing.T) {
	if _, err := caddy.GetModule("security"); err == nil {
		t.Fatal("companions imported the parent app")
	}
	for _, m := range []caddy.Module{&accounts.ConsulIdentityStore{Name: "accounts", Realm: "staff"}, &tickets.ConsulTicketIdentityProvider{Name: "tickets", Realm: "application", PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/signin"}, &refresh.ConsulRefreshStore{Name: "sessions"}} {
		t.Run(string(m.CaddyModule().ID), func(t *testing.T) {
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			loader, err := json.Marshal(consulModuleLoader{ID: string(m.CaddyModule().ID), Config: raw})
			if err != nil {
				t.Fatal(err)
			}
			storage, err := json.Marshal(map[string]string{"module": "file_system", "root": filepath.Join(t.TempDir(), "storage")})
			if err != nil {
				t.Fatal(err)
			}
			config, err := json.Marshal(caddy.Config{StorageRaw: storage, AppsRaw: map[string]json.RawMessage{"consul_companion_test_loader": loader}})
			if err != nil {
				t.Fatal(err)
			}
			if err := caddy.Load(config, true); err == nil || !strings.Contains(err.Error(), "requires configured pteich/caddy-tlsconsul storage") {
				t.Fatal("missing global storage did not fail closed", err)
			}
		})
	}
}
