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

// Package consul adapts Caddy's configured Consul client to OAuth transactions.
package consul

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ConsulOAuthLoginStore borrows the configured pteich/caddy-tlsconsul client.
// The app owns each transaction handle; Caddy retains ownership of the client.
type ConsulOAuthLoginStore struct {
	Name     string `json:"name,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Timeout  string `json:"timeout,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
	storage  *storageconsul.ConsulStorage
}

func init() { caddy.RegisterModule(ConsulOAuthLoginStore{}) }

func (ConsulOAuthLoginStore) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.oauth_login_stores.consul", New: func() caddy.Module { return new(ConsulOAuthLoginStore) }}
}

func (m *ConsulOAuthLoginStore) normalized() (ConsulOAuthLoginStore, time.Duration, error) {
	if m == nil {
		return ConsulOAuthLoginStore{}, 0, fmt.Errorf("invalid Consul OAuth login storage configuration")
	}
	c := *m
	c.storage = nil
	if c.Prefix == "" {
		c.Prefix = "security/oauth-logins"
	}
	if c.Timeout == "" {
		c.Timeout = "3s"
	}
	if c.Capacity == 0 {
		c.Capacity = 1000
	}
	duration, err := time.ParseDuration(c.Timeout)
	probe := plugin.OAuthLoginStoreConfig{Name: c.Name, Driver: "consul", ConfigHash: strings.Repeat("0", 64)}
	if probe.Validate() != nil || err != nil || duration < time.Millisecond || duration > 30*time.Second || c.Capacity < 1 || c.Capacity > 1000 ||
		len(c.Prefix) > 512 || !utf8.ValidString(c.Prefix) || strings.TrimSpace(c.Prefix) != c.Prefix || strings.ContainsFunc(c.Prefix, unicode.IsControl) || path.Clean(c.Prefix) != c.Prefix || strings.HasPrefix(c.Prefix, "/") || c.Prefix == "." || strings.ContainsAny(c.Prefix, "\\\x00\r\n") {
		return c, 0, fmt.Errorf("invalid Consul OAuth login storage configuration")
	}
	for _, part := range strings.Split(c.Prefix, "/") {
		if part == ".." || part == "" {
			return c, 0, fmt.Errorf("invalid Consul OAuth login storage prefix")
		}
	}
	c.Timeout = duration.String()
	return c, duration, nil
}

func (m *ConsulOAuthLoginStore) Validate() error { _, _, err := m.normalized(); return err }

func (m *ConsulOAuthLoginStore) Provision(ctx caddy.Context) error {
	storage, ok := ctx.Storage().(*storageconsul.ConsulStorage)
	if !ok || storage == nil || storage.ConsulClient == nil {
		return fmt.Errorf("Consul OAuth login storage requires configured pteich/caddy-tlsconsul storage")
	}
	m.storage = storage
	return nil
}

type factory struct {
	descriptor plugin.OAuthLoginStoreConfig
	kv         consulKV
	codec      cipher.AEAD
	prefix     string
	timeout    time.Duration
	capacity   int
}

func (m *ConsulOAuthLoginStore) PrepareOAuthLoginStore() (plugin.OAuthLoginStoreFactory, error) {
	c, timeout, err := m.normalized()
	if err != nil {
		return nil, err
	}
	if m.storage == nil || m.storage.ConsulClient == nil {
		return nil, fmt.Errorf("Consul OAuth login storage has not been provisioned")
	}
	block, err := aes.NewCipher(append([]byte(nil), m.storage.AESKey...))
	if err != nil {
		return nil, fmt.Errorf("Consul OAuth login storage requires a valid storage encryption key")
	}
	codec, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Consul OAuth login storage encryption is unavailable")
	}
	nameHash := sha256.Sum256([]byte(c.Name))
	prefix := path.Join(m.storage.Prefix, c.Prefix, hex.EncodeToString(nameHash[:]))
	// Capture normalized values and the configured client, never mutable module fields.
	keyHash := sha256.Sum256(m.storage.AESKey)
	encoded, err := json.Marshal(struct {
		Config  ConsulOAuthLoginStore
		Address string
		Prefix  string
		Key     [32]byte
	}{c, m.storage.Address, prefix, keyHash})
	if err != nil {
		return nil, fmt.Errorf("Consul OAuth login storage configuration cannot be encoded")
	}
	digest := sha256.Sum256(encoded)
	return &factory{descriptor: plugin.OAuthLoginStoreConfig{Name: c.Name, Driver: "consul", ConfigHash: hex.EncodeToString(digest[:])},
		kv: m.storage.ConsulClient.KV(), codec: codec, prefix: prefix, timeout: timeout, capacity: c.Capacity}, nil
}

func (f *factory) OAuthLoginStoreConfig() (plugin.OAuthLoginStoreConfig, error) {
	return f.descriptor, nil
}

func (f *factory) NewOAuthLoginStore(ctx context.Context) (plugin.OAuthLoginStore, error) {
	s := &store{factory: *f, now: time.Now}
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	if _, _, err := s.readIndex(ctx); err != nil {
		return nil, fmt.Errorf("Consul OAuth login storage is unavailable or incompatible")
	}
	return s, nil
}

// UnmarshalCaddyfile parses a named backend inside security:
//
//	oauth login store consul <name> {
//	    prefix <relative-key-prefix>
//	    timeout <duration>
//	    capacity <count>
//	}
//
// The block may be omitted when using defaults. All settings are optional and
// occur once. Defaults are security/oauth-logins,
// 3s (1ms..30s) and 1000 (1..1000). Capacity is shared across this name's provider
// namespaces. The prefix is relative to Caddy's configured Consul storage prefix.
// Backend fields are literal apart from lexical environment substitution. Select
// the backend with login store <name> namespace <deployment> in each provider.
func (m *ConsulOAuthLoginStore) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	c := ConsulOAuthLoginStore{Name: d.Val()}
	if len(d.RemainingArgs()) != 0 {
		return d.ArgErr()
	}
	// Caddy's module segment extraction omits empty blocks. Treat a bare
	// declaration and an empty block identically; nonempty blocks stay strict.
	if !d.Next() {
		normalized, _, err := c.normalized()
		if err != nil {
			return d.Errf("invalid Consul OAuth login storage configuration")
		}
		*m = normalized
		return nil
	}
	d.Prev()
	body, err := caddyfileutil.ReadFlatBlock(d, "Consul OAuth login storage")
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, args := range body {
		if len(args) != 2 || seen[args[0]] || args[1] == "" {
			return d.Errf("invalid Consul OAuth login storage setting")
		}
		seen[args[0]] = true
		switch args[0] {
		case "prefix":
			c.Prefix = args[1]
		case "timeout":
			c.Timeout = args[1]
		case "capacity":
			c.Capacity, err = strconv.Atoi(args[1])
			if err != nil || c.Capacity == 0 {
				return d.Errf("invalid Consul OAuth login storage capacity")
			}
		default:
			return d.Errf("unknown Consul OAuth login storage setting")
		}
	}
	normalized, _, err := c.normalized()
	if err != nil {
		return d.Errf("invalid Consul OAuth login storage configuration")
	}
	*m = normalized
	return nil
}

var (
	_ caddy.Module                        = (*ConsulOAuthLoginStore)(nil)
	_ caddy.Provisioner                   = (*ConsulOAuthLoginStore)(nil)
	_ caddy.Validator                     = (*ConsulOAuthLoginStore)(nil)
	_ caddyfile.Unmarshaler               = (*ConsulOAuthLoginStore)(nil)
	_ plugin.OAuthLoginStoreBackendModule = (*ConsulOAuthLoginStore)(nil)
	_ plugin.OAuthLoginStoreFactory       = (*factory)(nil)
)
