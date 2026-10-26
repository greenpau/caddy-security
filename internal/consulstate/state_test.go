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

package consulstate_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/internal/consultest"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"
)

type document struct {
	Version int
	Secret  string
	Count   int
}
type uncertainTransport struct {
	next   http.RoundTripper
	armed  atomic.Bool
	writes atomic.Int64
}

func (r *uncertainTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := r.next.RoundTrip(req)
	if req.Method == "PUT" && req.URL.Path == "/v1/txn" && r.armed.Swap(false) {
		r.writes.Add(1)
		if response != nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		return nil, errors.New("synthetic lost committed response")
	}
	return response, err
}
func TestConsulStateTransactions(t *testing.T) {
	address := consultest.Start(t)
	cfg := consulapi.DefaultConfig()
	cfg.Address = address
	transport := &uncertainTransport{next: http.DefaultTransport}
	cfg.HttpClient = &http.Client{Transport: transport}
	client, err := consulapi.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	storage := &storageconsul.ConsulStorage{ConsulClient: client, Prefix: "state-tests", AESKey: []byte("0123456789abcdef0123456789abcdef")}
	binding, err := consulstate.Capture(storage)
	if err != nil {
		t.Fatal(err)
	}
	open := func(category string) *consulstate.Handle {
		h, err := binding.Open(category, "one", "documents", "2s")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = h.Close() })
		return h
	}
	a, b := open("accounts"), open("accounts")
	initial := func() document { return document{Version: 1} }
	put := func(value string) error {
		return consulstate.Update(t.Context(), a, initial, func(d *document) (bool, error) { d.Secret = value; d.Count++; return true, nil })
	}
	if err := put("private-evidence"); err != nil {
		t.Fatal(err)
	}
	var result document
	index, err := b.Load(t.Context(), &result)
	if err != nil || result.Count != 1 || result.Secret != "private-evidence" {
		t.Fatal("peer document lost", err)
	}
	digest := sha256.Sum256([]byte("one"))
	key := "state-tests/documents/accounts/" + hex.EncodeToString(digest[:]) + "/state"
	pair, _, err := client.KV().Get(key, nil)
	if err != nil || pair == nil || strings.Contains(string(pair.Value), "private-evidence") {
		t.Fatal("document not encrypted", err)
	}
	if err := put(strings.Repeat("x", consulstate.MaxPayload)); !errors.Is(err, consulstate.ErrCapacity) {
		t.Fatal("oversized document committed", err)
	}
	transport.armed.Store(true)
	if err := put("uncertain-commit"); !errors.Is(err, consulstate.ErrUnavailable) {
		t.Fatal("ambiguous write returned success", err)
	}
	if transport.writes.Load() != 1 {
		t.Fatal("uncertain write retried")
	}
	if _, err := b.Load(t.Context(), &result); err != nil || result.Count != 2 {
		t.Fatal("ambiguous fixture did not commit", err)
	}
	if ok, err := b.Check(t.Context(), index); err != nil || ok {
		t.Fatal("stale version accepted", err)
	}
	other := open("tickets")
	if _, err := other.Load(t.Context(), &document{}); err != nil {
		t.Fatal("category isolation failed", err)
	}
	pair, _, _ = client.KV().Get(key, nil)
	pair.Value[len(pair.Value)-1] ^= 1
	if _, err := client.KV().Put(pair, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(t.Context(), &result); !errors.Is(err, consulstate.ErrUnavailable) {
		t.Fatal("tampering accepted", err)
	}
	_ = a.Close()
	if a.Ready() {
		t.Fatal("closed handle ready")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := other.Load(ctx, &result); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestConsulStateConfiguration(t *testing.T) {
	for _, prefix := range []string{"../escape", "/absolute", ".", "bad\\path", "bad//path", "trailing/"} {
		if _, _, err := consulstate.Normalize("one", prefix, "3s", "default"); err == nil {
			t.Fatal("invalid prefix accepted")
		}
	}
	if _, err := consulstate.Capture(nil); err == nil {
		t.Fatal("missing client accepted")
	}
}
