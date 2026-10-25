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

package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	backend "github.com/greenpau/go-authcrunch/plugins/secrets/sqlite"
)

type snapshotCloseFault struct {
	*backend.Client
	cancel   context.CancelFunc
	closeErr error
	closes   int
}

func (c *snapshotCloseFault) Close() error {
	c.closes++
	err := c.Client.Close()
	if c.cancel != nil {
		c.cancel()
	}
	if err != nil {
		return err
	}
	return c.closeErr
}

func TestSecretsRejectsSnapshotAfterLateSetupFailure(t *testing.T) {
	for _, phase := range []string{"canceled_after_close", "close_failure"} {
		t.Run(phase, func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			cfg := &backend.Config{Name: "vault", Path: filepath.Join(directory, "secrets.db"), Record: "credentials"}
			writer, err := backend.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			putErr := writer.Put(t.Context(), map[string]any{"key": "private-canary-value"})
			closeErr := writer.Close()
			if putErr != nil || closeErr != nil {
				t.Fatal(putErr, closeErr)
			}
			module := &SQLiteSecretsManager{Name: cfg.Name, Path: cfg.Path, Record: cfg.Record}
			t.Cleanup(func() { _ = module.Cleanup() })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var client *snapshotCloseFault
			err = module.provision(ctx, func(ctx context.Context, cfg *backend.Config) (secretSnapshotClient, error) {
				opened, err := backend.New(ctx, cfg)
				if err != nil {
					return nil, err
				}
				client = &snapshotCloseFault{Client: opened}
				if phase == "canceled_after_close" {
					client.cancel = cancel
				} else {
					client.closeErr = errors.New("private-canary close diagnostic")
				}
				return client, nil
			})
			want := backend.ErrUnavailable
			if phase == "canceled_after_close" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("late setup failure was lost or disclosed", err)
			}
			if client == nil || client.closes != 1 {
				t.Fatal("snapshot client was not closed exactly once")
			}
			if _, err := client.Client.GetSecrets(t.Context()); !errors.Is(err, backend.ErrUnavailable) {
				t.Fatal("snapshot database handle survived setup failure", err)
			}
			if module.values != nil || module.metadata != nil {
				t.Fatal("failed candidate published a partial snapshot")
			}
			if value, err := module.GetSecret(t.Context()); value != nil || !errors.Is(err, backend.ErrUnavailable) {
				t.Fatal("failed candidate served secrets", err)
			}
			if value, err := module.GetSecretByKey(t.Context(), "key"); value != nil || !errors.Is(err, backend.ErrUnavailable) {
				t.Fatal("failed candidate served an individual secret", err)
			}
			// Failure did not modify the record or leave a serving snapshot behind.
			fresh, stop := caddy.NewContext(caddy.Context{Context: t.Context()})
			defer stop()
			if err := module.Provision(fresh); err != nil {
				t.Fatal("failed attempt poisoned a fresh provisioning attempt", err)
			}
			if value, err := module.GetSecretByKey(t.Context(), "key"); err != nil || value != "private-canary-value" {
				t.Fatal("failed attempt changed durable storage", err)
			}
		})
	}
}
