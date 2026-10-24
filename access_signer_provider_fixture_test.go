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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

const signerLegacyProviderKind = "fixture-legacy-verified-oauth"

// This test-only compatibility module is not a bundled OAuth provider. Its
// genuine OAuth delegate retains its own private in-memory attachment; only
// the verified Response crosses the historical claims-only provider interface.
type signerLegacyProviderModule struct {
	Name    string       `json:"name"`
	Config  oauth.Config `json:"config"`
	Witness string       `json:"witness"`
	logger  *zap.Logger
}

type signerLegacyWitness struct {
	mu       sync.Mutex
	ids      []string
	payloads [][]byte
	closed   int
}

var signerLegacyWitnesses sync.Map

func init() { caddy.RegisterModule(signerLegacyProviderModule{}) }

func (signerLegacyProviderModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_providers.signer_legacy_oauth_fixture", New: func() caddy.Module { return new(signerLegacyProviderModule) }}
}

func (m *signerLegacyProviderModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	return nil
}

func (m *signerLegacyProviderModule) normalized() (*oauth.Config, error) {
	encoded, err := json.Marshal(m.Config)
	if err != nil {
		return nil, fmt.Errorf("invalid legacy fixture configuration")
	}
	var cfg oauth.Config
	if json.Unmarshal(encoded, &cfg) != nil {
		return nil, fmt.Errorf("invalid legacy fixture configuration")
	}
	cfg.Name = m.Name
	if cfg.Driver != "generic" || cfg.Attachment != nil || cfg.LoginStore != nil || cfg.IdentityTokenCookieEnabled || cfg.TLSInsecureSkipVerify || cfg.KeyVerificationDisabled || cfg.NonceDisabled || cfg.PKCEDisabled || cfg.DelayStart != 0 {
		return nil, fmt.Errorf("legacy fixture cannot weaken protocol verification")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid legacy fixture configuration")
	}
	return &cfg, nil
}

func (m *signerLegacyProviderModule) IdentityProviderConfig() (*idp.ExternalIdentityProviderConfig, error) {
	cfg, err := m.normalized()
	if err != nil {
		return nil, err
	}
	return idp.NewExternalIdentityProviderConfig(m.Name, signerLegacyProviderKind, "generic", cfg.Realm, cfg)
}

func (m *signerLegacyProviderModule) NewIdentityProvider(ctx context.Context) (idp.IdentityProvider, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("legacy fixture setup canceled")
	}
	cfg, err := m.normalized()
	if err != nil {
		return nil, err
	}
	entry, ok := signerLegacyWitnesses.Load(m.Witness)
	if !ok {
		return nil, fmt.Errorf("legacy fixture witness missing")
	}
	delegate, err := oauth.NewIdentityProvider(cfg, m.logger)
	if err != nil {
		return nil, fmt.Errorf("legacy fixture construction failed")
	}
	if delegate.Configure() != nil || ctx.Err() != nil {
		delegate.Close()
		return nil, fmt.Errorf("legacy fixture configuration failed")
	}
	icon := *delegate.GetLoginIcon()
	return &signerLegacyProvider{delegate: delegate, witness: entry.(*signerLegacyWitness), icon: &icon}, nil
}

// A single encoded fixture configuration avoids inventing product grammar.
func (m *signerLegacyProviderModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	body, err := readFlatDirectiveBlock(d, "legacy fixture")
	if err != nil || len(body) != 1 || len(body[0]) != 2 || body[0][0] != "config64" {
		return d.Errf("invalid legacy fixture body")
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(body[0][1])
	if err != nil || json.Unmarshal(data, m) != nil || m.Name != name {
		return d.Errf("invalid legacy fixture configuration")
	}
	_, err = m.normalized()
	return err
}

type signerLegacyProvider struct {
	// Named, not embedded: do not promote optional attachment/HTTP interfaces.
	delegate *oauth.IdentityProvider
	witness  *signerLegacyWitness
	icon     *icons.LoginIcon
	once     sync.Once
}

func (p *signerLegacyProvider) GetRealm() string          { return p.delegate.GetRealm() }
func (p *signerLegacyProvider) GetName() string           { return p.delegate.GetName() }
func (*signerLegacyProvider) GetKind() string             { return signerLegacyProviderKind }
func (*signerLegacyProvider) GetDriver() string           { return "generic" }
func (p *signerLegacyProvider) GetConfig() map[string]any { return p.delegate.GetConfig() }
func (p *signerLegacyProvider) Configure() error {
	if !p.Configured() {
		return fmt.Errorf("legacy fixture is not configured")
	}
	return nil
}
func (p *signerLegacyProvider) Configured() bool                 { return p.delegate.Configured() }
func (p *signerLegacyProvider) GetLoginIcon() *icons.LoginIcon   { return p.icon }
func (*signerLegacyProvider) GetLogoutURL() string               { return "" }
func (*signerLegacyProvider) GetIdentityTokenCookieName() string { return "" }
func (p *signerLegacyProvider) Close() error {
	p.once.Do(func() {
		p.delegate.Close()
		p.witness.mu.Lock()
		p.witness.closed++
		p.witness.mu.Unlock()
	})
	return nil
}

func (p *signerLegacyProvider) Request(op operator.Type, outer *requests.Request) error {
	denied := func() error { return fmt.Errorf("legacy fixture authentication denied") }
	if op != operator.Authenticate || outer == nil || outer.Upstream.Request == nil || outer.Upstream.Request.Method != http.MethodGet || outer.Upstream.Method != "oauth2" || outer.Upstream.Realm != p.GetRealm() || !p.Configured() || outer.ExternalIdentity != (requests.ExternalIdentity{}) || outer.Authentication != (requests.AuthenticationEvidence{}) {
		return denied()
	}
	returnURL := outer.Response.ReturnURL
	outer.Response = requests.Response{}
	inner := requests.NewRequest()
	inner.ID, inner.Logger, inner.Upstream = outer.ID, outer.Logger, outer.Upstream
	inner.Upstream.CookieNames = slices.Clone(outer.Upstream.CookieNames)
	inner.Upstream.Request = outer.Upstream.Request.Clone(outer.Upstream.Request.Context())
	inner.Response.ReturnURL = returnURL
	if err := p.delegate.Request(op, inner); err != nil {
		if errors.Is(err, oauth.ErrLoginUnavailable) {
			return oauth.ErrLoginUnavailable
		}
		return denied()
	}
	r := inner.Response
	if r.IdentityTokenCookie != (requests.IdentityTokenCookie{}) || r.Authenticated || r.Authorized || r.Workflow != "" || r.Title != "" || r.Message != "" || r.LoginState != "" || r.RedirectTokenName != "" {
		return denied()
	}
	switch r.Code {
	case http.StatusFound:
		if r.RedirectURL == "" || r.Payload != nil {
			return denied()
		}
	case http.StatusOK:
		payload, ok := r.Payload.(map[string]any)
		if !ok || len(payload) == 0 || !r.ReturnURLBound || r.RedirectURL != "" || inner.ExternalIdentity.Evidence.UserID == "" {
			return denied()
		}
		data, err := json.Marshal(payload)
		if err != nil || len(data) > 64<<10 {
			return denied()
		}
		// The genuine delegate did attach internally. This UUID remains private
		// and is inventoried only to prove it never becomes a portal identity.
		p.witness.mu.Lock()
		p.witness.ids = append(p.witness.ids, inner.ExternalIdentity.Evidence.UserID)
		p.witness.payloads = append(p.witness.payloads, data)
		p.witness.mu.Unlock()
	default:
		return denied()
	}
	outer.Response = requests.Response{Code: r.Code, RedirectURL: r.RedirectURL, Payload: r.Payload, ReturnURL: r.ReturnURL, ReturnURLBound: r.ReturnURLBound}
	return nil
}

var _ IdentityProviderBackendModule = (*signerLegacyProviderModule)(nil)
var _ caddy.Provisioner = (*signerLegacyProviderModule)(nil)
var _ caddyfile.Unmarshaler = (*signerLegacyProviderModule)(nil)
var _ idp.IdentityProvider = (*signerLegacyProvider)(nil)
var _ io.Closer = (*signerLegacyProvider)(nil)

func testAccessSignerLegacyProvider(t *testing.T, cert, tlsKey string, roots *x509.CertPool, pair tls.Certificate) {
	u := newOAuthE2EUpstream(t, pair, "EdDSA")
	u.fixedSubject = "verified-legacy-subject"
	witness := new(signerLegacyWitness)
	witnessName := t.Name()
	signerLegacyWitnesses.Store(witnessName, witness)
	t.Cleanup(func() {
		signerLegacyWitnesses.Delete(witnessName)
		witness.mu.Lock()
		defer witness.mu.Unlock()
		if witness.closed != 1 {
			t.Error("legacy delegate was not closed exactly once by its runtime owner")
		}
	})
	f := newAccessSignerFixture(t, accessSignerOptions{mount: "/tenant/auth", configure: func(input string) string {
		base := accessSignerOrigin(t, input)
		u.callback = base + "/tenant/auth/oauth2/legacy/authorization-code-callback"
		module := signerLegacyProviderModule{Name: "legacy", Witness: witnessName, Config: oauth.Config{Name: "legacy", Realm: "legacy", Driver: "generic", ClientID: oauthE2EClient, ClientSecret: oauthE2ESecret, BaseAuthURL: u.server.URL, AuthorizationURL: u.server.URL + "/authorize", TokenURL: u.server.URL + "/token", Issuer: u.server.URL, AccessTokenAudience: "resource-api", Scopes: []string{"openid", "profile", "email"}, JwksKeys: map[string]string{"identity": u.identity.pem(t, false), "access": u.access.pem(t, false)}}}
		encoded := base64.RawURLEncoding.EncodeToString(accessSignerJSON(t, module))
		declaration := "identity provider signer_legacy_oauth_fixture legacy {\nconfig64 " + encoded + "\n}\n"
		input = strings.Replace(input, "authentication portal myportal {", declaration+"authentication portal myportal {\nenable identity provider legacy\nenable cross-device login\ntransform user {\nmatch realm legacy\naction add role authp/user\n}\n", 1)
		return input
	}}, cert, tlsKey, roots)
	f.secrets = append(f.secrets, oauthE2ESecret)
	t.Cleanup(func() {
		u.mu.Lock()
		f.secrets = append(f.secrets, u.issuedSecrets...)
		u.mu.Unlock()
		witness.mu.Lock()
		f.secrets = append(f.secrets, witness.ids...)
		witness.mu.Unlock()
	})
	if _, ok := any(&signerLegacyProvider{}).(attachment.Consumer); ok {
		t.Fatal("legacy fixture exposed attachment capability")
	}
	if _, ok := any(&signerLegacyProvider{}).(idp.HTTPLoginProvider); ok {
		t.Fatal("legacy fixture exposed HTTP login capability")
	}
	requester := crossDeviceBrowser(t, f.oidcRPFixture)
	approver := crossDeviceBrowser(t, requester)
	interaction := crossDeviceStart(t, requester)
	f.secrets = append(f.secrets, interaction.Code, interaction.Secret, interaction.Display)
	crossDeviceBegin(t, approver, interaction)
	begin := func(browser *oidcRPFixture) string {
		r := browser.request(t, "GET", "/oauth2/legacy", nil, nil)
		accessSignerCapture(f.localIdentityFixture, r)
		r.requireStatus(t, 302)
		location, err := url.Parse(r.header.Get("Location"))
		if err != nil || location.Scheme+"://"+location.Host != u.server.URL || location.Path != "/authorize" {
			t.Fatal("legacy initiation escaped genuine issuer")
		}
		f.secrets = append(f.secrets, location.Query().Get("state"), location.Query().Get("nonce"))
		r = browser.request(t, "GET", location.String(), nil, nil)
		r.requireStatus(t, 302)
		callback, err := url.Parse(r.header.Get("Location"))
		if err != nil || callback.Scheme+"://"+callback.Host != f.base || callback.Path != f.mount+"/oauth2/legacy/authorization-code-callback" {
			t.Fatal("legacy callback escaped configured route")
		}
		f.secrets = append(f.secrets, callback.Query().Get("code"), callback.Query().Get("state"))
		return callback.String()
	}
	login := func(browser *oidcRPFixture, want int) oidcRPResponse {
		r := browser.request(t, "GET", begin(browser), nil, nil)
		accessSignerCapture(f.localIdentityFixture, r)
		r.requireStatus(t, want)
		return r
	}
	callback := login(approver, 303)
	if callback.header.Get("Location") != f.mount+"/cross-device/confirm" {
		t.Fatal("legacy provider did not reach explicit approval")
	}
	before := f.verify(t, crossDeviceCookie(approver, f.cookie))
	confirmation := approver.request(t, "GET", "/cross-device/confirm", nil, nil)
	confirmation.requireStatus(t, 200)
	crossDeviceDecision(t, approver, confirmation, "approve").requireStatus(t, 200)
	polled := crossDevicePost(t, requester, "poll", interaction.values())
	accessSignerCapture(f.localIdentityFixture, polled)
	polled.requireStatus(t, 200)
	access := crossDeviceCookie(requester, f.cookie)
	after := f.verify(t, access)
	if before["sub"] != u.fixedSubject || after["sub"] != u.fixedSubject || before["jti"] == after["jti"] || accessSignerNumber(t, after, "exp") > accessSignerNumber(t, before, "exp") || after["id"] != nil || after["sid"] != nil {
		t.Fatal("legacy selected transfer adopted local identity or changed verified proof")
	}
	f.consumers(t, access, true)
	crossDevicePost(t, requester, "poll", interaction.values()).requireStatus(t, 410)
	witness.mu.Lock()
	ids, payloads := slices.Clone(witness.ids), slices.Clone(witness.payloads)
	witness.mu.Unlock()
	if len(ids) != 1 || ids[0] == "" || len(payloads) != 1 {
		t.Fatal("legacy delegate did not complete its real private attachment")
	}
	for _, data := range [][]byte{payloads[0], accessSignerJSON(t, before), accessSignerJSON(t, after), polled.body} {
		if bytes.Contains(data, []byte(ids[0])) {
			t.Fatal("legacy response adopted the delegate's hidden local UUID")
		}
	}
	for _, failure := range []string{"state", "pkce", "identity nonce", "identity signature", "identity issuer", "identity audience"} {
		t.Run(failure, func(t *testing.T) {
			u.mu.Lock()
			u.failure = failure
			u.mu.Unlock()
			browser := crossDeviceBrowser(t, f.oidcRPFixture)
			r := login(browser, 401)
			providerDestinationNoIssuance(t, r)
			if crossDeviceCookie(browser, f.cookie) != "" {
				t.Fatal("unverified legacy provider issued access")
			}
		})
	}
	u.mu.Lock()
	u.failure = ""
	u.mu.Unlock()
	healthy := crossDeviceBrowser(t, f.oidcRPFixture)
	pending := begin(healthy)
	stranger := crossDeviceBrowser(t, f.oidcRPFixture)
	wrongBrowser := stranger.request(t, "GET", pending, nil, nil)
	accessSignerCapture(f.localIdentityFixture, wrongBrowser)
	wrongBrowser.requireStatus(t, 401)
	providerDestinationNoIssuance(t, wrongBrowser)
	completed := healthy.request(t, "GET", pending, nil, nil)
	accessSignerCapture(f.localIdentityFixture, completed)
	completed.requireStatus(t, 303)
	f.verify(t, crossDeviceCookie(healthy, f.cookie))
	replay := healthy.request(t, "GET", pending, nil, nil)
	accessSignerCapture(f.localIdentityFixture, replay)
	replay.requireStatus(t, 401)
	providerDestinationNoIssuance(t, replay)
}
