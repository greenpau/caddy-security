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
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
)

type secretTransport struct {
	drop      atomic.Bool
	readsFail atomic.Bool
	writes    atomic.Int64
}

func (r *secretTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.readsFail.Load() && req.Method == "GET" {
		return nil, errors.New("synthetic read failure")
	}
	response, err := http.DefaultTransport.RoundTrip(req)
	if req.Method == "PUT" && req.URL.Path == "/v1/txn" {
		r.writes.Add(1)
		if r.drop.Swap(false) {
			if response != nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			return nil, errors.New("synthetic lost committed response")
		}
	}
	return response, err
}
func TestConsulSecretsUncertainWrites(t *testing.T) {
	address := consultest.Start(t)
	transport := new(secretTransport)
	cfg := consulapi.DefaultConfig()
	cfg.Address = address
	cfg.HttpClient = &http.Client{Transport: transport}
	client, err := consulapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	storage := &storageconsul.ConsulStorage{ConsulClient: client, Prefix: "secret-uncertain", AESKey: []byte("0123456789abcdef0123456789abcdef")}
	a, err := New(t.Context(), &Config{Name: "signing", Record: "tokens"}, storage)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Put(t.Context(), map[string]any{"key": "before"}); err != nil {
		t.Fatal(err)
	}
	binding, err := consulstate.Capture(storage)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &ConsulSecretsManager{Name: "signing", Record: "tokens"}
	if err := snapshot.provision(t.Context(), binding); err != nil {
		t.Fatal(err)
	}
	defer snapshot.Cleanup()
	before := transport.writes.Load()
	transport.drop.Store(true)
	if err := a.Put(t.Context(), map[string]any{"key": "committed-but-unknown"}); !errors.Is(err, consulstate.ErrUnavailable) || transport.writes.Load() != before+1 {
		t.Fatal("uncertain secret write retried or returned success", err)
	}
	if value, err := a.GetSecret(t.Context(), "key"); err != nil || value != "committed-but-unknown" {
		t.Fatal("uncertainty fixture did not commit", err)
	}
	if value, err := snapshot.GetSecretByKey(t.Context(), "key"); err != nil || value != "before" {
		t.Fatal("uncertain mutation changed serving snapshot", err)
	}
	transport.readsFail.Store(true)
	failed := &ConsulSecretsManager{Name: "new", Record: "tokens"}
	if err := failed.provision(t.Context(), binding); !errors.Is(err, consulstate.ErrUnavailable) {
		t.Fatal("unavailable candidate initialized", err)
	}
	if _, err := failed.GetSecret(t.Context()); err == nil {
		t.Fatal("failed candidate published a snapshot")
	}
	transport.readsFail.Store(false)
	if value, err := snapshot.GetSecretByKey(t.Context(), "key"); err != nil || value != "before" {
		t.Fatal("failed candidate changed serving snapshot", err)
	}
}
