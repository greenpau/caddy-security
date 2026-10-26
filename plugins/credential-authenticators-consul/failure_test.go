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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
)

type credentialTransport struct {
	drop      atomic.Bool
	readsFail atomic.Bool
	writes    atomic.Int64
}

func (r *credentialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
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
func TestConsulCredentialUncertainWrites(t *testing.T) {
	address := consultest.Start(t)
	transport := new(credentialTransport)
	cfg := consulapi.DefaultConfig()
	cfg.Address = address
	cfg.HttpClient = &http.Client{Transport: transport}
	client, err := consulapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	storage := &storageconsul.ConsulStorage{ConsulClient: client, Prefix: "credential-uncertain", AESKey: []byte("0123456789abcdef0123456789abcdef")}
	a, err := New(t.Context(), &ConsulCredentialAuthenticator{Name: "keys", Realm: "staff", Capacity: 2}, storage)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	before := transport.writes.Load()
	transport.drop.Store(true)
	key, err := a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if !errors.Is(err, consulstate.ErrUnavailable) || key != "" || transport.writes.Load() != before+1 {
		t.Fatal("uncertain issuance published a key or retried", err)
	}
	var count int
	if err := a.run(t.Context(), func(d *document) (bool, error) { count = len(d.Keys); return false, nil }); err != nil || count != 1 {
		t.Fatal("uncertainty fixture did not commit", err)
	}
	key, err = a.Issue(t.Context(), "alice", "alice@example.test", []string{"viewer"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	request := &authproxy.Request{Realm: "staff", Secret: key, Response: authproxy.Response{Payload: "previous-success"}}
	transport.drop.Store(true)
	if err := a.APIKeyAuthContext(t.Context(), request); !errors.Is(err, consulstate.ErrUnavailable) || request.Response.Payload != "" {
		t.Fatal("uncertain authentication published stale claims", err)
	}
	transport.readsFail.Store(true)
	if err := a.APIKeyAuthContext(t.Context(), request); !errors.Is(err, consulstate.ErrUnavailable) || request.Response.Payload != "" {
		t.Fatal("unavailable backend reused claims", err)
	}
	transport.readsFail.Store(false)
	if err := a.APIKeyAuthContext(t.Context(), request); err != nil {
		t.Fatal("backend did not recover", err)
	}
}
