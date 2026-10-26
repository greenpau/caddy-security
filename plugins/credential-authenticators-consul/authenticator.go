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
	"encoding/json"
	"errors"
	"net/mail"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authproxy"

	"github.com/greenpau/caddy-security/internal/consulstate"
	"github.com/greenpau/caddy-security/pkg/plugin"
)

// ErrDenied does not distinguish wrong-realm, unknown, expired or revoked keys.
var ErrDenied = errors.New("Consul credential authentication denied")

type credential struct {
	Subject, Email string
	Roles          []string
	Expires        int64
}
type document struct {
	Version, Capacity int
	Realm             string
	Keys              map[[32]byte]credential
}

// Authenticator owns one logical realm-bound handle. Every lookup reads fresh
// Consul state and fences the response against concurrent revocation.
type Authenticator struct {
	config ConsulCredentialAuthenticator
	handle *consulstate.Handle
}

func (a *Authenticator) initial() document {
	return document{Version: 1, Capacity: a.config.Capacity, Realm: a.config.Realm, Keys: map[[32]byte]credential{}}
}
func validClaims(v credential) bool {
	address, err := mail.ParseAddress(v.Email)
	if !consulstate.ValidText(v.Subject, 256) || !consulstate.ValidText(v.Email, 320) || err != nil || address.Address != v.Email || len(v.Roles) < 1 || len(v.Roles) > 32 || v.Expires <= 0 {
		return false
	}
	for _, role := range v.Roles {
		if !consulstate.ValidText(role, 128) {
			return false
		}
	}
	return true
}
func (a *Authenticator) valid(d *document) error {
	if d.Version != 1 || d.Capacity != a.config.Capacity || d.Realm != a.config.Realm || d.Keys == nil || len(d.Keys) > d.Capacity {
		return consulstate.ErrUnavailable
	}
	for _, v := range d.Keys {
		if !validClaims(v) {
			return consulstate.ErrUnavailable
		}
	}
	return nil
}
func (a *Authenticator) run(ctx context.Context, apply func(*document) (bool, error)) error {
	if a == nil {
		return consulstate.ErrUnavailable
	}
	return consulstate.Update(ctx, a.handle, a.initial, func(d *document) (bool, error) {
		if err := a.valid(d); err != nil {
			return false, err
		}
		return apply(d)
	})
}
func (a *Authenticator) check(ctx context.Context) error {
	return a.run(ctx, func(*document) (bool, error) { return false, nil })
}

// GetName returns the configured policy selector.
func (a *Authenticator) GetName() string {
	if a == nil {
		return ""
	}
	return a.config.Name
}

// GetConfig returns only public identifiers, never credentials or storage details.
func (a *Authenticator) GetConfig() map[string]any {
	if a == nil {
		return nil
	}
	return map[string]any{"name": a.config.Name, "realm": a.config.Realm, "kind": "consul"}
}

// RequireFreshAuthentication prevents successful keys from entering result caches.
func (*Authenticator) RequireFreshAuthentication() bool { return true }
func validKey(key string) bool {
	if len(key) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(key)
	return err == nil && len(data) == 32
}

// Issue generates a fresh 256-bit credential and publishes it only after commit.
// Expiry must be in the next 30 days. Only a SHA-256 digest is stored; expired
// records are pruned during admission. An uncertain write returns no credential.
func (a *Authenticator) Issue(ctx context.Context, subject, email string, roles []string, expires time.Time) (string, error) {
	v := credential{Subject: subject, Email: email, Roles: append([]string(nil), roles...), Expires: expires.Unix()}
	now := time.Now()
	if !validClaims(v) || v.Expires <= now.Unix() || expires.After(now.Add(30*24*time.Hour)) {
		return "", consulstate.ErrInvalid
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", consulstate.ErrUnavailable
	}
	key := base64.RawURLEncoding.EncodeToString(random[:])
	digest := sha256.Sum256([]byte(key))
	err := a.run(ctx, func(d *document) (bool, error) {
		now := time.Now().Unix()
		if v.Expires <= now {
			return false, consulstate.ErrInvalid
		}
		for k, v := range d.Keys {
			if now >= v.Expires {
				delete(d.Keys, k)
			}
		}
		if len(d.Keys) >= d.Capacity {
			return false, consulstate.ErrCapacity
		}
		if _, exists := d.Keys[digest]; exists {
			return false, consulstate.ErrUnavailable
		}
		d.Keys[digest] = v
		return true, nil
	})
	if err != nil {
		return "", err
	}
	if time.Now().Unix() >= v.Expires {
		return "", consulstate.ErrUnavailable
	}
	return key, nil
}

// Revoke atomically removes only this backend's key. Absence is idempotent success.
func (a *Authenticator) Revoke(ctx context.Context, key string) error {
	if !validKey(key) {
		return consulstate.ErrInvalid
	}
	digest := sha256.Sum256([]byte(key))
	return a.run(ctx, func(d *document) (bool, error) {
		_, exists := d.Keys[digest]
		delete(d.Keys, digest)
		return exists, nil
	})
}

// BasicAuth rejects unsupported password authentication and clears stale output.
func (a *Authenticator) BasicAuth(r *authproxy.Request) error {
	return a.BasicAuthContext(context.Background(), r)
}

// BasicAuthContext rejects unsupported password authentication and clears stale output.
func (*Authenticator) BasicAuthContext(_ context.Context, r *authproxy.Request) error {
	if r != nil {
		r.Response = authproxy.Response{}
	}
	return ErrDenied
}

// APIKeyAuth preserves the legacy entry point with a bounded operation context.
func (a *Authenticator) APIKeyAuth(r *authproxy.Request) error {
	return a.APIKeyAuthContext(context.Background(), r)
}

// APIKeyAuthContext binds realm and credential, reads current storage and publishes
// claims only after a successful version fence. Backend errors never reuse claims.
func (a *Authenticator) APIKeyAuthContext(ctx context.Context, r *authproxy.Request) error {
	if r == nil {
		return ErrDenied
	}
	r.Response = authproxy.Response{}
	if a == nil || !a.handle.Ready() {
		return consulstate.ErrUnavailable
	}
	if r.Realm != a.config.Realm || !validKey(r.Secret) {
		return ErrDenied
	}
	digest := sha256.Sum256([]byte(r.Secret))
	var found credential
	err := a.run(ctx, func(d *document) (bool, error) {
		v, exists := d.Keys[digest]
		if !exists || time.Now().Unix() >= v.Expires {
			return false, ErrDenied
		}
		v.Roles = append([]string(nil), v.Roles...)
		found = v
		return false, nil
	})
	if err != nil {
		return err
	}
	now := time.Now()
	if found.Expires <= now.Unix() {
		return ErrDenied
	}
	payload, err := json.Marshal(map[string]any{"sub": found.Subject, "email": found.Email, "roles": found.Roles, "origin": a.config.Realm, "iat": now.Unix(), "exp": min(found.Expires, now.Add(time.Minute).Unix()), "amr": []string{"api_key"}})
	if err != nil {
		return consulstate.ErrUnavailable
	}
	r.Response = authproxy.Response{Name: "access_token", Payload: string(payload), IsPlainPayload: true}
	return nil
}

// Close retires this logical handle without deleting shared keys or closing Caddy's client.
func (a *Authenticator) Close() error {
	if a == nil {
		return nil
	}
	return a.handle.Close()
}

var _ plugin.CredentialAuthenticator = (*Authenticator)(nil)
