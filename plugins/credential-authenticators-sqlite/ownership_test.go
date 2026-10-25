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
	"os"
	"path/filepath"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	credentials "github.com/greenpau/go-authcrunch/plugins/credential-authenticators/sqlite"

	companion "github.com/greenpau/caddy-security/plugins/credential-authenticators-sqlite"
)

func TestCredentialFactoryIndependentHandles(t *testing.T) {
	cfg := sqliteCredentialsConfig(t)
	key := sqliteCredentialsIssue(t, cfg)
	module := &companion.SQLiteCredentialAuthenticator{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path, Timeout: cfg.Timeout}
	name, realm := module.CredentialIdentity()
	if name != cfg.Name || realm != cfg.Realm {
		t.Fatal("binding identity changed")
	}
	snapshot, err := module.BackendConfig()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Realm, snapshot.Path = "changed", "changed"
	if module.Realm != realm || module.Path != cfg.Path {
		t.Fatal("configuration snapshot aliases module")
	}
	setup, stop := context.WithCancel(t.Context())
	first, err := module.NewCredentialAuthenticator(setup)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := module.NewCredentialAuthenticator(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first == second || !first.RequireFreshAuthentication() || !second.RequireFreshAuthentication() {
		t.Fatal("factory shared ownership or permitted cached credentials")
	}
	if err := first.APIKeyAuthContext(t.Context(), &authproxy.Request{Realm: realm, Secret: key}); err != nil {
		t.Fatal("setup cancellation retired runtime", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	request := &authproxy.Request{Realm: realm, Secret: key}
	if err := second.APIKeyAuthContext(t.Context(), request); err != nil || request.Response.Payload == "" {
		t.Fatal("closing one handle retired its peer", err)
	}
	request.Realm = "other"
	if err := second.APIKeyAuthContext(t.Context(), request); !errors.Is(err, credentials.ErrDenied) || request.Response.Payload != "" {
		t.Fatal("wrong realm retained identity", err)
	}
}

func TestCredentialFactoryRejectsUnsafeStorage(t *testing.T) {
	for _, kind := range []string{"canceled", "directory", "symlink", "public", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			cfg := sqliteCredentialsConfig(t)
			_ = sqliteCredentialsIssue(t, cfg)
			module := &companion.SQLiteCredentialAuthenticator{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path}
			ctx := t.Context()
			switch kind {
			case "canceled":
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			case "directory":
				module.Path = filepath.Dir(cfg.Path)
			case "symlink":
				module.Path = filepath.Join(filepath.Dir(cfg.Path), "alias.db")
				if err := os.Symlink(cfg.Path, module.Path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(cfg.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(cfg.Path, []byte("private-diagnostic-canary"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if value, err := module.NewCredentialAuthenticator(ctx); value != nil || !errors.Is(err, credentials.ErrUnavailable) {
				t.Fatal("unsafe storage published a runtime", err)
			}
		})
	}
}

func TestCredentialInvalidDeclarationBeforeConstruction(t *testing.T) {
	cfg := sqliteCredentialsConfig(t)
	module := &companion.SQLiteCredentialAuthenticator{Name: cfg.Name, Realm: cfg.Realm, Path: cfg.Path}
	module.Realm = ""
	if err := module.Validate(); err == nil {
		t.Fatal("invalid native declaration accepted")
	}
	if value, err := module.NewCredentialAuthenticator(t.Context()); value != nil || err == nil {
		t.Fatal("invalid declaration published runtime", err)
	}
	if _, err := os.Stat(module.Path); !os.IsNotExist(err) {
		t.Fatal("invalid declaration touched storage")
	}
}
