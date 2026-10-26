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

package security

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consultest"
	tickets "github.com/greenpau/caddy-security/plugins/identity-providers-consul"
	accounts "github.com/greenpau/caddy-security/plugins/identity-stores-consul"
)

const consulCompanionKey = "0123456789abcdef0123456789abcdef"

func TestCaddyConsulCompanionsE2E(t *testing.T) {
	address := consultest.Start(t)
	binary := buildSharedOAuthCaddy(t)
	cert, key, roots := cookieTLSCertificate(t)
	apiConfig := consulapi.DefaultConfig()
	apiConfig.Address = address
	client, err := consulapi.NewClient(apiConfig)
	if err != nil {
		t.Fatal(err)
	}
	storage := &storageconsul.ConsulStorage{ConsulClient: client, Prefix: "companion-e2e", AESKey: []byte(consulCompanionKey)}
	storageBlock := fmt.Sprintf("storage consul {\naddress %q\nprefix companion-e2e\naes_key %s\n}\n", address, consulCompanionKey)
	t.Run("password_refresh_restart", func(t *testing.T) {
		f := newPersistentCaddy(t, binary, cert, key, roots)
		management, err := accounts.New(t.Context(), &accounts.ConsulIdentityStore{Name: "accounts", Realm: "staff", Capacity: 8, Timeout: "5s"}, storage)
		if err != nil {
			t.Fatal(err)
		}
		defer management.Close()
		if _, err := management.Create(t.Context(), &accounts.Account{Username: "alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}}, sqliteIdentityPassword); err != nil {
			t.Fatal(err)
		}
		security := fmt.Sprintf(`identity store consul accounts {
 realm staff
 capacity 8
 timeout 5s
}
token refresh store consul sessions {
 max sessions 8
 max rotations 8
 timeout 5s
}
authentication portal myportal {
 enable identity store accounts
 crypto key sign-verify %s
 token refresh {
  store sessions
  realms staff
  public origin %s
  base path /auth
  body transport enabled
  max sessions 8
  max rotations 8
 }
}
authorization policy app_policy {
 crypto key verify %s
 validate bearer header
 allow roles authp/user
 disable auth redirect
}`, sqliteIdentitySigningKey, f.base, sqliteIdentitySigningKey)
		source := f.input(security, "route /auth/* {\nauthenticate with myportal\n}\nroute /resource {\nauthorize with app_policy\nrespond Consul-resource\n}", cert, key)
		source = strings.Replace(source, "auto_https off", "auto_https off\n"+storageBlock, 1)
		f.write(t, source)
		f.start(t)
		auth := base64.StdEncoding.EncodeToString([]byte("alice:" + sqliteIdentityPassword))
		response := persistentRequest(t, f.client, "GET", f.base+"/auth/basic/login/staff", nil, http.Header{"Authorization": {"Basic " + auth}}, 303)
		token := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
		persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}}, 200)
		native, err := authclient.NewClient(&authclient.Config{BaseURL: f.base + "/auth", Realm: "staff", Username: "alice", Password: sqliteIdentityPassword, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: f.client})
		if err != nil {
			t.Fatal(err)
		}
		login, err := native.Authenticate(t.Context())
		if err != nil || login.RefreshToken == "" {
			t.Fatal("Consul login missing refresh", err)
		}
		f.restart(t)
		refresh := &caddyTokenRefreshFixture{base: f.base, mount: "/auth", client: f.client}
		renewed, _ := refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, nil, 200)
		persistentRequest(t, f.client, "GET", f.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + renewed.AccessToken}}, 200)
		refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": login.RefreshToken}, nil, 401)
		refresh.post(t, f.client, "/api/refresh_token", map[string]string{"refresh_token": renewed.RefreshToken}, nil, 401)
		if err := management.DisableUser("alice", ""); err != nil {
			t.Fatal(err)
		}
		persistentRequest(t, f.client, "GET", f.base+"/auth/basic/login/staff", nil, http.Header{"Authorization": {"Basic " + auth}}, 401)
	})
	t.Run("ticket_callback_on_peer", func(t *testing.T) {
		first := newPersistentCaddy(t, binary, cert, key, roots)
		second := newPersistentCaddy(t, binary, cert, key, roots)
		cfg := &tickets.ConsulTicketIdentityProvider{Name: "tickets", Realm: "application", PublicOrigin: first.base, IssuerURL: "https://issuer.example.test/signin", Capacity: 8, Timeout: "5s"}
		issuer, err := tickets.New(t.Context(), cfg, storage)
		if err != nil {
			t.Fatal(err)
		}
		defer issuer.Close()
		for _, f := range []*persistentCaddy{first, second} {
			source := fmt.Sprintf(`{
 admin %s
 auto_https off
 %s
 security {
  identity provider consul tickets {
   realm application
   public_origin %s
   issuer_url https://issuer.example.test/signin
   capacity 8
   timeout 5s
  }
  authentication portal ticketportal {
   enable identity provider tickets
   crypto key sign-verify %s
  }
  authorization policy app_policy {
   crypto key verify %s
   validate bearer header
   allow roles authp/user
   disable auth redirect
  }
 }
}
%s {
 tls %q %q
 route /ready {
  respond "ready"
 }
 route /auth/* {
  authenticate with ticketportal
 }
 route /resource {
  authorize with app_policy
  respond "ticket resource"
 }
}`, f.admin, storageBlock, first.base, sqliteIdentitySigningKey, sqliteIdentitySigningKey, f.base, cert, key)
			f.write(t, source)
			f.start(t)
		}
		browser := first.browser(t)
		begin := persistentRequest(t, browser, "GET", first.base+"/auth/provider/application", nil, nil, http.StatusFound)
		location, err := url.Parse(begin.header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		state := location.Query().Get("request")
		credential, err := issuer.Issue(t.Context(), state, &idp.LoginIdentity{Subject: "trusted-alice", Email: "alice@example.test", Name: "Alice", Roles: []string{"authp/user"}})
		if err != nil {
			t.Fatal(err)
		}
		second.restart(t)
		transport := first.client.Transport.(*http.Transport).Clone()
		peerAddress := strings.TrimPrefix(second.base, "https://")
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, peerAddress)
		}
		defer transport.CloseIdleConnections()
		peer := &http.Client{Transport: transport, Jar: browser.Jar, Timeout: first.client.Timeout, CheckRedirect: first.client.CheckRedirect}
		callback := first.base + "/auth/provider/application?" + (url.Values{"state": {state}, "ticket": {credential}}).Encode()
		response := persistentRequest(t, peer, "GET", callback, nil, nil, 303)
		token := strings.TrimPrefix(response.header.Get("Authorization"), "Bearer ")
		if token == "" {
			t.Fatal("ticket callback issued no access credential")
		}
		persistentRequest(t, first.client, "GET", first.base+"/resource", nil, http.Header{"Authorization": {"Bearer " + token}}, 200)
		persistentRequest(t, peer, "GET", callback, nil, nil, 401)
	})
}
