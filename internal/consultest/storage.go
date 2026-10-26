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

package consultest

import (
	"github.com/greenpau/caddy-security/internal/consulstate"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"
	"testing"
)

// Binding captures a private client for a disposable Consul agent, with a test key.
func Binding(t testing.TB, address, prefix string) *consulstate.Binding {
	t.Helper()
	config := consulapi.DefaultConfig()
	config.Address = address
	client, err := consulapi.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := consulstate.Capture(&storageconsul.ConsulStorage{ConsulClient: client, Prefix: prefix, AESKey: []byte("0123456789abcdef0123456789abcdef")})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
