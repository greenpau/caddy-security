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

package sqlite

import (
	"errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

func TestUnavailableRuntime(t *testing.T) {
	for name, store := range map[string]*sqliteOAuthLoginStore{"nil": nil, "uninitialized": {}} {
		t.Run(name, func(t *testing.T) {
			tx := oauth.LoginTransaction{State: "unavailable"}
			if _, err := store.OAuthLoginStoreConfig(); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable runtime published a descriptor")
			}
			if err := store.Create(t.Context(), "n", tx); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Create accepted")
			}
			if _, err := store.Get(t.Context(), "n", tx.State); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Get accepted")
			}
			if _, err := store.Claim(t.Context(), "n", tx.State, tx.Binding, "claim"); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Claim accepted")
			}
			if err := store.Complete(t.Context(), "n", tx.State, "claim"); !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Complete accepted")
			}
			if accepted, err := store.Cancel(t.Context(), "n", tx.State, tx.Binding); accepted || !errors.Is(err, oauth.ErrLoginUnavailable) {
				t.Fatal("unavailable Cancel accepted")
			}
			if err := store.Close(); err != nil {
				t.Fatal("unavailable cleanup failed")
			}
		})
	}
}
