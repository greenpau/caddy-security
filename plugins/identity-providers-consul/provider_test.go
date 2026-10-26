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
	"crypto/tls"
	"errors"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/internal/consultest"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestConsulTicketParser(t *testing.T) {
	good := "tickets {\nrealm application\npublic_origin https://auth.example.test\nissuer_url https://issuer.example.test/signin\n}"
	if err := new(ConsulTicketIdentityProvider).UnmarshalCaddyfile(caddyfile.NewTestDispenser(good)); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"tickets", "tickets {\nrealm application\npublic_origin http://auth.example.test\nissuer_url https://issuer.example.test/signin\n}", "tickets {\nrealm application\npublic_origin https://auth.example.test\nissuer_url https://issuer.example.test/signin\ncapacity 0\n}"} {
		if new(ConsulTicketIdentityProvider).UnmarshalCaddyfile(caddyfile.NewTestDispenser(input)) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
}
func TestConsulTicketProvider(t *testing.T) {
	address := consultest.Start(t)
	binding := consultest.Binding(t, address, "ticket-tests")
	open := func() *Provider {
		m := &ConsulTicketIdentityProvider{Name: "tickets", Realm: "application", PublicOrigin: "https://auth.example.test", IssuerURL: "https://issuer.example.test/signin", Capacity: 2, binding: binding}
		if _, err := m.IdentityProviderConfig(); err != nil {
			t.Fatal(err)
		}
		runtime, err := m.NewIdentityProvider(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		p := runtime.(*Provider)
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a, b := open(), open()
	request := func(query string, cookie *http.Cookie) *http.Request {
		u, _ := url.Parse(a.CallbackURL() + query)
		r := &http.Request{Method: "GET", URL: u, Host: u.Host, TLS: &tls.ConnectionState{}}
		if cookie != nil {
			r.Header = http.Header{}
			r.AddCookie(cookie)
		}
		return r
	}
	begin, err := a.Login(t.Context(), request("", nil))
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := url.Parse(begin.RedirectURL)
	state := issuer.Query().Get("request")
	credential, err := b.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "subject-one", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
	if err != nil {
		t.Fatal(err)
	}
	query := "?" + (url.Values{"state": {state}, "ticket": {credential}}).Encode()
	if _, err := b.Login(t.Context(), request(query, nil)); !errors.Is(err, ErrDenied) {
		t.Fatal("unbound browser accepted", err)
	}
	var wg sync.WaitGroup
	wins := make(chan bool, 2)
	for _, p := range []*Provider{a, b} {
		wg.Add(1)
		go func(p *Provider) {
			defer wg.Done()
			result, err := p.Login(t.Context(), request(query, begin.Cookie))
			if err == nil && (result.Identity.Subject != "subject-one" || result.ExternalIdentity.Evidence.UserID == "") {
				t.Error("missing trusted identity")
			}
			wins <- err == nil
		}(p)
	}
	wg.Wait()
	close(wins)
	count := 0
	for ok := range wins {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent ticket winners: %d", count)
	}
	if _, err := a.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "another", Roles: []string{"authp/user"}}); err == nil {
		t.Fatal("spent state reissued")
	}
	var pending []string
	for range 2 {
		result, err := b.Login(t.Context(), request("", nil))
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(result.RedirectURL)
		pending = append(pending, u.Query().Get("request"))
	}
	if _, err := b.Login(t.Context(), request("", nil)); err == nil {
		t.Fatal("ticket capacity not enforced")
	}
	if err := b.run(t.Context(), func(d *document) (bool, error) {
		for id, v := range d.Tickets {
			v.Expires = 1
			d.Tickets[id] = v
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Issue(t.Context(), pending[0], &idp.LoginIdentity{Subject: "expired", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("expired request issued", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Login(t.Context(), request("", nil)); err != nil {
		t.Fatal("peer close lost shared client", err)
	}
}
