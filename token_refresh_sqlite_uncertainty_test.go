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
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
)

func TestSQLiteRefreshCommitFault(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private SQLite refresh backend requires POSIX file ownership")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "refresh.sqlite")
	factory := refreshStoreTestFactory(t, &SQLiteRefreshStore{Name: "selected", Path: path})
	store, err := factory.NewRefreshStore(ctx)
	if err != nil {
		t.Fatal("cannot open COMMIT fault fixture", err)
	}
	defer store.(io.Closer).Close()
	generation := tokenrefresh.Generation{Namespace: strings.Repeat("a", 64), ID: strings.Repeat("1", 64)}
	view, err := store.ActivateGeneration(ctx, generation)
	if err != nil {
		t.Fatal("cannot activate COMMIT fault fixture", err)
	}
	now := time.Now().Unix()
	session := tokenrefresh.Session{
		ID: "fixture-family", Current: sha256.Sum256([]byte("current")), IdleExpiresAt: now + 300, AbsoluteExpiresAt: now + 600,
		Principal: tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: "alice", Subject: "alice", AuthTime: now, Methods: []string{"pwd"}},
		Binding: tokenrefresh.Binding{Portal: "myportal", Origin: "https://login.example.test", BasePath: "/auth", Transport: tokenrefresh.BodyTransport,
			Namespace: generation.Namespace, Generation: generation.ID},
	}
	if err := view.Create(ctx, session, now+60); err != nil {
		t.Fatal("cannot create COMMIT fault fixture session", err)
	}
	db, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path}).String()+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := sqliteCommitFaultSchema(ctx, db, true); err != nil {
		t.Fatal("cannot install COMMIT fault", err)
	}
	witness := new(sqliteCommitWitness)
	observed := &sqliteCommitActiveStore{ActiveStore: view, witness: witness}
	err = observed.Rotate(ctx, session, sha256.Sum256([]byte("next")), session.IdleExpiresAt, now+60)
	if !errors.Is(err, tokenrefresh.ErrCommitUncertain) || ctx.Err() != nil {
		t.Fatalf("fault did not reject a real COMMIT with a live context: %v (context: %v)", err, ctx.Err())
	}
	if got := witness.snapshot(); got.RotateCalls != 1 || got.Uncertain != 1 || got.Canceled != 0 {
		t.Fatal("COMMIT witness did not observe exactly one uncertain rotation")
	}
	if err := sqliteCommitFaultSchema(ctx, db, false); err != nil {
		t.Fatal("cannot remove COMMIT fault", err)
	}
	if err := store.CheckReady(ctx); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("removing the fault cleared the handle's quarantine", err)
	}
	reopened, err := factory.NewRefreshStore(ctx)
	if err != nil {
		t.Fatal("fault cleanup left an invalid database schema", err)
	}
	defer reopened.(io.Closer).Close()
	if err := reopened.CheckReady(ctx); err != nil {
		t.Fatal("cleaned database did not reopen healthy", err)
	}
}
