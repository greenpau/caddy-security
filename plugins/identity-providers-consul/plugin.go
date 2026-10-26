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

// Package consul supplies shared single-use tickets issued by trusted applications.
package consul

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/portalpath"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulTicketIdentityProvider declares a browser-bound trusted-application provider.
// It installs no issuer HTTP endpoint. Pending requests and issued tickets are shared.
type ConsulTicketIdentityProvider struct {
	Name            string             `json:"name"`
	Realm           string             `json:"realm"`
	Prefix          string             `json:"prefix,omitempty"`
	Timeout         string             `json:"timeout,omitempty"`
	Capacity        int                `json:"capacity,omitempty"`
	PublicOrigin    string             `json:"public_origin"`
	BasePath        string             `json:"base_path,omitempty"`
	CookieName      string             `json:"cookie_name,omitempty"`
	IssuerURL       string             `json:"issuer_url"`
	Attachment      *attachment.Config `json:"attachment,omitempty"`
	binding         *consulstate.Binding
	prepared        *ConsulTicketIdentityProvider
	preparedBinding *consulstate.Binding
}

// New opens a separate trusted application/administration handle using borrowed
// Caddy Consul storage. The caller closes the returned handle after its calls drain.
func New(ctx context.Context, config *ConsulTicketIdentityProvider, storage *storageconsul.ConsulStorage) (*Provider, error) {
	if config == nil {
		return nil, consulstate.ErrInvalid
	}
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	c.binding, err = consulstate.Capture(storage)
	if err != nil {
		return nil, err
	}
	if _, err := c.IdentityProviderConfig(); err != nil {
		return nil, err
	}
	runtime, err := c.NewIdentityProvider(ctx)
	if err != nil {
		return nil, err
	}
	return runtime.(*Provider), nil
}

func init() { caddy.RegisterModule(ConsulTicketIdentityProvider{}) }

// CaddyModule registers the companion Caddy module.
func (ConsulTicketIdentityProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.identity_providers.consul", New: func() caddy.Module { return new(ConsulTicketIdentityProvider) }}
}
func matches(pattern, value string) bool { ok, _ := regexp.MatchString(pattern, value); return ok }
func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !consulstate.ValidText(raw, 2048) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || strings.ToLower(u.Host) != u.Host || strings.Contains(raw, "#") || raw != u.String() || strings.HasSuffix(u.Host, ":") {
		return nil, consulstate.ErrInvalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, consulstate.ErrInvalid
		}
	}
	return u, nil
}
func (m *ConsulTicketIdentityProvider) normalized() (ConsulTicketIdentityProvider, error) {
	if m == nil {
		return ConsulTicketIdentityProvider{}, consulstate.ErrInvalid
	}
	c := *m
	c.binding = nil
	c.prepared = nil
	c.preparedBinding = nil
	var err error
	c.Prefix, c.Timeout, err = consulstate.Normalize(c.Name, c.Prefix, c.Timeout, "security/tickets")
	if c.Capacity == 0 {
		c.Capacity = 1024
	}
	if err != nil || !matches(`^[A-Za-z0-9_-]{1,64}$`, c.Realm) || c.Capacity < 1 || c.Capacity > 10000 {
		return c, consulstate.ErrInvalid
	}
	origin, err := secureURL(c.PublicOrigin)
	if err != nil || origin.Path != "" {
		return c, consulstate.ErrInvalid
	}
	issuer, err := secureURL(c.IssuerURL)
	if err != nil || !matches(`^(/[A-Za-z0-9_-]+)+$`, issuer.Path) {
		return c, consulstate.ErrInvalid
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if len(c.BasePath) > 512 || c.BasePath != "/" && !matches(`^(/[A-Za-z0-9_-]+)+$`, c.BasePath) || portalpath.Validate(c.BasePath) != nil {
		return c, consulstate.ErrInvalid
	}
	callback := strings.TrimSuffix(c.BasePath, "/") + "/provider/" + c.Realm
	if c.IssuerURL == c.PublicOrigin+callback {
		return c, consulstate.ErrInvalid
	}
	if c.CookieName == "" {
		c.CookieName = "AUTHP_PROVIDER_SESSION_ID"
	}
	if len(c.CookieName) > 128 || (&http.Cookie{Name: c.CookieName}).Valid() != nil || cookie.ValidatePrefix(c.CookieName, "", callback, true) != nil {
		return c, consulstate.ErrInvalid
	}
	if c.Attachment != nil {
		copy := *c.Attachment
		if err := copy.Validate(); err != nil {
			return c, consulstate.ErrInvalid
		}
		c.Attachment = &copy
		if copy.LocalIdentityStore == "" {
			c.Attachment = nil
		}
	}
	return c, nil
}

// AttachmentStoreName returns the detached explicit root-owned attachment selector.
func (m *ConsulTicketIdentityProvider) AttachmentStoreName() (string, error) {
	c, err := m.normalized()
	if err != nil {
		return "", err
	}
	if c.Attachment == nil {
		return "", nil
	}
	return c.Attachment.LocalIdentityStore, nil
}

// Validate checks detached literal configuration without accessing Consul.
func (m *ConsulTicketIdentityProvider) Validate() error { _, err := m.normalized(); return err }

// Provision captures Caddy-owned storage without opening a logical runtime handle.
func (m *ConsulTicketIdentityProvider) Provision(ctx caddy.Context) error {
	b, err := consulstate.Bind(ctx)
	m.binding = b
	return err
}

// IdentityProviderConfig freezes normalized provider configuration and its root descriptor.
func (m *ConsulTicketIdentityProvider) IdentityProviderConfig() (*idp.ExternalIdentityProviderConfig, error) {
	c, err := m.normalized()
	if err != nil {
		return nil, err
	}
	identity := ""
	if m.binding != nil {
		identity = m.binding.Identity
	}
	descriptor, err := idp.NewExternalIdentityProviderConfig(c.Name, "consul-ticket", "ticket", c.Realm, struct {
		Config  ConsulTicketIdentityProvider
		Storage string
	}{c, identity})
	if err == nil {
		m.prepared = &c
		m.preparedBinding = m.binding
	}
	return descriptor, err
}

// NewIdentityProvider transfers a new logical ticket-provider handle to the app.
func (m *ConsulTicketIdentityProvider) NewIdentityProvider(ctx context.Context) (idp.IdentityProvider, error) {
	if m == nil || m.prepared == nil {
		return nil, consulstate.ErrUnavailable
	}
	c := *m.prepared
	handle, err := m.preparedBinding.Open("identity-providers", c.Name, c.Prefix, c.Timeout)
	if err != nil {
		return nil, err
	}
	ac := attachment.Config{}
	if c.Attachment != nil {
		ac = *c.Attachment
	}
	a, err := attachment.New(ac)
	if err != nil {
		_ = handle.Close()
		return nil, err
	}
	p := &Provider{config: c, handle: handle, attachment: a}
	if err := p.check(ctx); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return p, nil
}

// UnmarshalCaddyfile parses identity provider consul NAME with required realm,
// public_origin and issuer_url settings. Optional literal prefix, timeout, capacity,
// base_path, cookie_name and attach to local identity store NAME occur once.
// Defaults: security/tickets, 3s, 1024 requests, /auth and AUTHP_PROVIDER_SESSION_ID.
// Ticket requests last 300s; issued credentials last at most 120s. A trusted Go
// application calls Provider.Issue after independently authenticating its user.
// Explicit attachments still require a core-supported local identity store.
func (m *ConsulTicketIdentityProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	name, body, err := consulstate.Parse(d)
	if err != nil {
		return err
	}
	c := ConsulTicketIdentityProvider{Name: name}
	seen := map[string]bool{}
	for _, args := range body {
		if len(args) < 2 || seen[args[0]] || args[len(args)-1] == "" {
			return d.Errf("invalid Consul ticket setting")
		}
		seen[args[0]] = true
		if args[0] == "attach" {
			if len(args) != 6 || strings.Join(args[:5], " ") != "attach to local identity store" {
				return d.ArgErr()
			}
			c.Attachment = &attachment.Config{LocalIdentityStore: args[5]}
			continue
		}
		if len(args) != 2 {
			return d.ArgErr()
		}
		switch args[0] {
		case "realm":
			c.Realm = args[1]
		case "prefix":
			c.Prefix = args[1]
		case "timeout":
			c.Timeout = args[1]
		case "public_origin":
			c.PublicOrigin = args[1]
		case "issuer_url":
			c.IssuerURL = args[1]
		case "base_path":
			c.BasePath = args[1]
		case "cookie_name":
			c.CookieName = args[1]
		case "capacity":
			c.Capacity, err = strconv.Atoi(args[1])
			if err != nil || c.Capacity < 1 {
				return d.Errf("invalid Consul ticket capacity")
			}
		default:
			return d.Errf("unknown Consul ticket setting")
		}
	}
	c, err = c.normalized()
	if err != nil {
		return d.Errf("invalid Consul ticket configuration")
	}
	*m = c
	return nil
}

var (
	_ caddy.Module                         = (*ConsulTicketIdentityProvider)(nil)
	_ caddy.Provisioner                    = (*ConsulTicketIdentityProvider)(nil)
	_ caddy.Validator                      = (*ConsulTicketIdentityProvider)(nil)
	_ caddyfile.Unmarshaler                = (*ConsulTicketIdentityProvider)(nil)
	_ plugin.IdentityProviderBackendModule = (*ConsulTicketIdentityProvider)(nil)
)
