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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"

	"github.com/greenpau/caddy-security/internal/consulstate"
)

var ErrDenied = errors.New("Consul ticket authentication denied")

type ticket struct {
	Browser, Credential    [32]byte
	Expires, TicketExpires int64
	Identity               *idp.LoginIdentity
}
type document struct {
	Version, Capacity int
	Binding           string
	Tickets           map[[32]byte]ticket
}

// Provider exposes trusted ticket issuance and the standard browser login contract.
type Provider struct {
	config     ConsulTicketIdentityProvider
	handle     *consulstate.Handle
	attachment *attachment.Attachment
}

func (p *Provider) initial() document {
	c := p.config
	return document{Version: 1, Capacity: c.Capacity, Binding: strings.Join([]string{c.Name, c.Realm, c.PublicOrigin, c.BasePath, c.CookieName, c.IssuerURL}, "\x00"), Tickets: map[[32]byte]ticket{}}
}
func (p *Provider) valid(d *document) error {
	initial := p.initial()
	if d.Version != 1 || d.Capacity != initial.Capacity || d.Binding != initial.Binding || d.Tickets == nil || len(d.Tickets) > d.Capacity {
		return consulstate.ErrUnavailable
	}
	for _, t := range d.Tickets {
		if t.Expires <= 0 || t.Identity != nil && (t.Identity.Validate() != nil || t.TicketExpires <= 0 || t.TicketExpires > t.Expires) {
			return consulstate.ErrUnavailable
		}
	}
	return nil
}
func (p *Provider) run(ctx context.Context, action func(*document) (bool, error)) error {
	return consulstate.Update(ctx, p.handle, p.initial, func(d *document) (bool, error) {
		if err := p.valid(d); err != nil {
			return false, err
		}
		return action(d)
	})
}
func (p *Provider) check(ctx context.Context) error {
	return p.run(ctx, func(*document) (bool, error) { return false, nil })
}
func secret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", consulstate.ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
func validSecret(s string) bool {
	data, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(data) == 32 && base64.RawURLEncoding.EncodeToString(data) == s
}
func (p *Provider) callbackPath() string {
	return strings.TrimSuffix(p.config.BasePath, "/") + "/provider/" + p.config.Realm
}

// CallbackURL returns the pinned HTTPS callback destination.
func (p *Provider) CallbackURL() string { return p.config.PublicOrigin + p.callbackPath() }
func (p *Provider) cookie(value string, remove bool) *http.Cookie {
	c := &http.Cookie{Name: p.config.CookieName, Value: value, Path: p.callbackPath(), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300, Expires: time.Now().Add(300 * time.Second)}
	if remove {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	return c
}
func (p *Provider) begin(ctx context.Context) (*idp.HTTPLoginResult, error) {
	state, err := secret()
	if err != nil {
		return nil, err
	}
	browser, err := secret()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(state))
	expires := time.Now().Unix() + 300
	err = p.run(ctx, func(d *document) (bool, error) {
		now := time.Now().Unix()
		if now >= expires {
			return false, ErrDenied
		}
		for id, t := range d.Tickets {
			if now >= t.Expires {
				delete(d.Tickets, id)
			}
		}
		if len(d.Tickets) >= d.Capacity {
			return false, consulstate.ErrCapacity
		}
		if _, exists := d.Tickets[digest]; exists {
			return false, consulstate.ErrUnavailable
		}
		d.Tickets[digest] = ticket{Browser: sha256.Sum256([]byte(browser)), Expires: expires}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() >= expires {
		return nil, ErrDenied
	}
	issuer, _ := url.Parse(p.config.IssuerURL)
	issuer.RawQuery = (url.Values{"request": {state}, "callback": {p.CallbackURL()}}).Encode()
	return &idp.HTTPLoginResult{RedirectURL: issuer.String(), Cookie: p.cookie(browser, false)}, nil
}

// Issue is for a trusted application's authenticated decision, never anonymous
// HTTP input. It returns no credential on an uncertain write. Start a new login.
func (p *Provider) Issue(ctx context.Context, state string, input *idp.LoginIdentity) (string, error) {
	if p == nil || !p.handle.Ready() {
		return "", consulstate.ErrUnavailable
	}
	if !validSecret(state) || input == nil || input.Validate() != nil {
		return "", consulstate.ErrInvalid
	}
	identity := *input
	identity.Roles = append([]string(nil), input.Roles...)
	credential, err := secret()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(state))
	var deadline int64
	err = p.run(ctx, func(d *document) (bool, error) {
		t, ok := d.Tickets[digest]
		now := time.Now().Unix()
		if !ok || now >= t.Expires || t.Identity != nil {
			return false, ErrDenied
		}
		deadline = min(t.Expires, now+120)
		t.Credential = sha256.Sum256([]byte(credential))
		t.Identity = &identity
		t.TicketExpires = deadline
		d.Tickets[digest] = t
		return true, nil
	})
	if err != nil {
		return "", err
	}
	if time.Now().Unix() >= deadline {
		return "", ErrDenied
	}
	return credential, nil
}

// Login begins or consumes a canonical HTTPS GET with one browser-binding cookie.
func (p *Provider) Login(ctx context.Context, r *http.Request) (*idp.HTTPLoginResult, error) {
	if p == nil || !p.handle.Ready() {
		return nil, consulstate.ErrUnavailable
	}
	origin, _ := url.Parse(p.config.PublicOrigin)
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.TLS == nil || r.Host != origin.Host || r.URL.Path != p.callbackPath() || r.URL.EscapedPath() != p.callbackPath() || r.URL.Scheme != "" && r.URL.Scheme != "https" || r.URL.Fragment != "" || len(r.URL.RawQuery) > 1024 {
		return nil, ErrDenied
	}
	if r.URL.RawQuery == "" && !r.URL.ForceQuery {
		return p.begin(ctx)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(values) != 2 || len(values["state"]) != 1 || len(values["ticket"]) != 1 || !validSecret(values.Get("state")) || !validSecret(values.Get("ticket")) {
		return nil, ErrDenied
	}
	var browser string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == p.config.CookieName {
			browser = c.Value
			count++
		}
	}
	if count != 1 || !validSecret(browser) {
		return nil, ErrDenied
	}
	digest := sha256.Sum256([]byte(values.Get("state")))
	credential := sha256.Sum256([]byte(values.Get("ticket")))
	binding := sha256.Sum256([]byte(browser))
	var identity idp.LoginIdentity
	var deadline int64
	err = p.run(ctx, func(d *document) (bool, error) {
		t, ok := d.Tickets[digest]
		now := time.Now().Unix()
		if !ok || t.Identity == nil || now >= t.Expires || now >= t.TicketExpires || t.Credential != credential || t.Browser != binding {
			return false, ErrDenied
		}
		identity = *t.Identity
		identity.Roles = append([]string(nil), t.Identity.Roles...)
		deadline = t.TicketExpires
		delete(d.Tickets, digest)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() >= deadline {
		return nil, ErrDenied
	}
	rr := requests.NewRequest()
	rr.ExternalIdentity = requests.ExternalIdentity{Issuer: p.config.IssuerURL, Subject: identity.Subject}
	rr.Response.Payload = map[string]any{"email": identity.Email, "name": identity.Name}
	if err := p.attachment.Authenticate(ctx, rr, p.GetName(), p.GetKind()); err != nil {
		return nil, err
	}
	return &idp.HTTPLoginResult{Identity: &identity, ExternalIdentity: rr.ExternalIdentity, Cookie: p.cookie("", true)}, nil
}

// GetName returns the configured instance name.
func (p *Provider) GetName() string { return p.config.Name }

// GetRealm returns the configured login realm.
func (p *Provider) GetRealm() string { return p.config.Realm }

// GetKind returns the backend kind used by root binding.
func (p *Provider) GetKind() string { return "consul-ticket" }

// GetDriver identifies the trusted-application ticket protocol.
func (p *Provider) GetDriver() string { return "ticket" }

// GetConfig returns public identifiers without credentials or storage details.
func (p *Provider) GetConfig() map[string]any {
	return map[string]any{"name": p.GetName(), "realm": p.GetRealm(), "kind": p.GetKind()}
}

// Configure checks the current backend without changing configuration.
func (p *Provider) Configure() error {
	if p == nil {
		return consulstate.ErrUnavailable
	}
	return p.check(context.Background())
}

// Configured reports current readiness for root binding.
func (p *Provider) Configured() bool { return p != nil && p.Configure() == nil }

// Request rejects legacy dispatch; Login owns the ticket protocol.
func (p *Provider) Request(operator.Type, *requests.Request) error { return ErrDenied }

// GetLoginIcon returns detached portal login metadata.
func (p *Provider) GetLoginIcon() *icons.LoginIcon {
	i := icons.NewLoginIcon("ticket")
	i.SetRealm(p.GetRealm())
	i.SetEndpoint("provider/" + p.GetRealm())
	i.Text = "Application sign-in"
	return i
}

// GetLogoutURL returns no upstream logout endpoint.
func (p *Provider) GetLogoutURL() string { return "" }

// GetIdentityTokenCookieName returns no upstream identity-token cookie.
func (p *Provider) GetIdentityTokenCookieName() string { return "" }

// GetLoginCookieName returns the independent browser-binding cookie name.
func (p *Provider) GetLoginCookieName() string { return p.config.CookieName }

// IdentityAttachment returns the provider-owned core account binding.
func (p *Provider) IdentityAttachment() *attachment.Attachment { return p.attachment }

// Close retires this logical handle while retaining Caddy storage and peer data.
func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	return p.handle.Close()
}

var (
	_ idp.IdentityProvider  = (*Provider)(nil)
	_ idp.HTTPLoginProvider = (*Provider)(nil)
)
