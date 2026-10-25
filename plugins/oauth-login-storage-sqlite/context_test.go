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
	"context"
	"errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

func TestOAuthLoginStoreContextAndNamespace(t *testing.T) {
	store := sqliteOAuthLoginTestOpen(t, sqliteOAuthLoginTestFactory(t, sqliteOAuthLoginTestModule(t)))
	tx := sqliteOAuthLoginTestTransaction("pending")
	const namespace = "deployment-a"
	if err := store.Create(t.Context(), namespace, tx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.Create(ctx, namespace, sqliteOAuthLoginTestTransaction("canceled")); !errors.Is(err, context.Canceled) {
		t.Fatal("Create lost context", err)
	}
	if result, err := store.Get(ctx, namespace, tx.State); result != (oauth.LoginTransaction{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("Get lost context or published evidence", err)
	}
	if result, err := store.Claim(ctx, namespace, tx.State, tx.Binding, "owner"); result != (oauth.LoginTransaction{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("Claim lost context or published evidence", err)
	}
	if ok, err := store.Cancel(ctx, namespace, tx.State, tx.Binding); ok || !errors.Is(err, context.Canceled) {
		t.Fatal("Cancel ignored context", err)
	}
	if _, err := store.Get(t.Context(), "deployment-b", tx.State); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("namespace crossed storage boundary", err)
	}
	if _, err := store.Claim(t.Context(), "deployment-b", tx.State, tx.Binding, "owner"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("wrong namespace claimed evidence", err)
	}
	wrong := tx.Binding
	wrong.Callback += "/other"
	if _, err := store.Claim(t.Context(), namespace, tx.State, wrong, "owner"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("callback binding changed", err)
	}
	claimed, err := store.Claim(t.Context(), namespace, tx.State, tx.Binding, "owner")
	if err != nil || claimed.Claim != "owner" {
		t.Fatal("rejections consumed legitimate transaction", err)
	}
	if err := store.Complete(ctx, namespace, tx.State, "owner"); !errors.Is(err, context.Canceled) {
		t.Fatal("Complete lost context", err)
	}
	if err := store.Complete(t.Context(), namespace, tx.State, "owner"); err != nil {
		t.Fatal("canceled completion changed committed ownership", err)
	}
	if _, err := store.Claim(t.Context(), namespace, tx.State, tx.Binding, "again"); !errors.Is(err, oauth.ErrLoginInvalid) {
		t.Fatal("completion replay accepted", err)
	}
}
