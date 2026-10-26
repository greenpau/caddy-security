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

package security

import (
	"testing"

	"github.com/greenpau/caddy-security/internal/consultest"
)

// Uses a real disposable Consul agent and independently provisioned Caddy OS
// processes. No synthetic callback, shared process memory or disabled TLS trust.
func TestCaddyConsulOAuthLoginStoreE2E(t *testing.T) {
	address := consultest.Start(t)
	binary := buildSharedOAuthCaddy(t)
	configure := func(f *caddySharedOAuthPair) { f.consulAddress = address }
	t.Run("cross_process_callback_replay_reload", func(t *testing.T) {
		f := newCaddySharedOAuthPair(t, binary, "/tenant/auth", 8, false, configure)
		f.qualifyTLS(t)
		f.direction(t, 0, f.destination("consul-first"))
		f.direction(t, 1, f.destination("consul-second"))
		f.concurrentCallbacks(t)
		f.shutdownAndReload(t)
		f.isolation(t)
	})
	// A distinct store prefix isolates the capacity-one journey from prior work.
	t.Run("capacity_and_direct_policy", func(t *testing.T) {
		other := consultest.Start(t)
		f := newCaddySharedOAuthPair(t, binary, "/tenant/auth", 1, true, func(f *caddySharedOAuthPair) { f.consulAddress = other })
		f.capacityAndDirectPolicy(t)
	})
}
