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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	tokenrefresh "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"

	companion "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-sqlite"
)

func TestRefreshCaddyfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "sessions, {env.LITERAL}.db")
	good := fmt.Sprintf("sessions {\npath %q\n}", path)
	var module companion.SQLiteRefreshStore
	if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	if module.Path != path || module.Timeout != "1s" || module.MaxSessions != 10000 || module.MaxRotations != 1024 {
		t.Fatal("lost defaults or literal path")
	}
	for name, input := range map[string]string{
		"empty": "", "extra header": strings.Replace(good, "sessions {", "sessions extra {", 1),
		"duplicate":  strings.Replace(good, "\n}", "\npath /private/second.db\n}", 1),
		"zero limit": strings.Replace(good, "\n}", "\nmax sessions 0\n}", 1),
		"unknown":    strings.Replace(good, "\n}", "\nunknown private-canary\n}", 1),
		"nested":     strings.Replace(good, "\n}", "\nmax sessions {\n2\n}\n}", 1),
		"unclosed":   strings.TrimSuffix(good, "}"),
		"bad name":   strings.Replace(good, "sessions {", "\" sessions\" {", 1),
	} {
		t.Run(name, func(t *testing.T) {
			before := module
			if err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)); err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("invalid declaration accepted or disclosed", err)
			}
			if module != before {
				t.Fatal("rejected parse mutated module")
			}
		})
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("parser opened storage")
	}
}

func TestRefreshFactoryPeerOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	factory := refreshStoreTestFactory(t, &companion.SQLiteRefreshStore{Name: "sessions", Path: filepath.Join(dir, "refresh.db"), MaxSessions: 2, MaxRotations: 3})
	first, err := factory.NewRefreshStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.(io.Closer).Close() })
	second, err := factory.NewRefreshStore(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.(io.Closer).Close() })
	generation := tokenrefresh.Generation{Namespace: strings.Repeat("a", 64), ID: strings.Repeat("1", 64)}
	initial, err := first.ActivateGeneration(t.Context(), generation)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	session := tokenrefresh.Session{
		ID: "fresh-family", Current: sha256.Sum256([]byte("fresh-credential")), IdleExpiresAt: now + 300, AbsoluteExpiresAt: now + 600,
		Principal: tokenrefresh.Principal{Backend: "local", Realm: "local", UserID: "immutable-alice", Subject: "alice", BackendVersion: "epoch", CredentialVersion: 1, AuthTime: now, Methods: []string{"pwd"}, Challenges: []string{"password"}},
		Binding:   tokenrefresh.Binding{Portal: "myportal", Origin: "https://auth.example.test", BasePath: "/auth", Transport: tokenrefresh.BodyTransport, Namespace: generation.Namespace, Generation: generation.ID},
	}
	if err := initial.Create(t.Context(), session, now+60); err != nil {
		t.Fatal(err)
	}
	if err := first.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.CheckReady(t.Context()); err != nil {
		t.Fatal("closing peer retired storage", err)
	}
	view, err := second.ActivateGeneration(t.Context(), generation)
	if err != nil || view.Generation() != generation {
		t.Fatal("peer lost generation", err)
	}
	current, err := view.Lookup(t.Context(), session.Current, session.Binding)
	if err != nil || current.ID != session.ID {
		t.Fatal("peer lost committed family", err)
	}
	next := sha256.Sum256([]byte("rotated-credential"))
	if err := view.Rotate(t.Context(), current, next, session.IdleExpiresAt, now+60); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Lookup(t.Context(), next, session.Binding); err != nil {
		t.Fatal("rotated family unavailable", err)
	}
	if _, err := view.Lookup(t.Context(), session.Current, session.Binding); err == nil {
		t.Fatal("spent credential accepted")
	}
	if _, err := view.Lookup(t.Context(), next, session.Binding); err == nil {
		t.Fatal("replay did not retire the family")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := second.ActivateGeneration(canceled, generation); err == nil {
		t.Fatal("activation ignored context")
	}
	if err := second.CheckReady(t.Context()); err != nil {
		t.Fatal("canceled activation poisoned owned handle", err)
	}
	if err := first.CheckReady(t.Context()); !errors.Is(err, tokenrefresh.ErrUnavailable) {
		t.Fatal("closed store attested readiness", err)
	}
}
