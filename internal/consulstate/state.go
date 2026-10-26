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

// Package consulstate supplies bounded encrypted CAS documents to Consul companions.
package consulstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	consulapi "github.com/hashicorp/consul/api"
	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/caddyfileutil"
)

var (
	ErrInvalid     = errors.New("invalid Consul backend configuration or input")
	ErrUnavailable = errors.New("Consul backend unavailable or write outcome uncertain")
	ErrCapacity    = errors.New("Consul backend capacity reached")
)

// MaxPayload keeps each encrypted value below Consul's 512 KiB KV limit.
const MaxPayload = 384 << 10

// ValidText checks literal identifiers without changing their bytes.
func ValidText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s && !strings.ContainsFunc(s, unicode.IsControl)
}

// Normalize applies common defaults without accessing Caddy or Consul.
func Normalize(name, prefix, timeout, defaultPrefix string) (string, string, error) {
	if prefix == "" {
		prefix = defaultPrefix
	}
	if timeout == "" {
		timeout = "3s"
	}
	d, err := time.ParseDuration(timeout)
	if !ValidText(name, 128) || !ValidText(prefix, 512) || path.Clean(prefix) != prefix || strings.HasPrefix(prefix, "/") || prefix == "." || strings.Contains(prefix, "\\") || err != nil || d < time.Millisecond || d > 30*time.Second {
		return "", "", ErrInvalid
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == ".." || part == "" {
			return "", "", ErrInvalid
		}
	}
	return prefix, d.String(), nil
}

// Parse reads a module name and optional flat block. Callers validate each setting.
func Parse(d *caddyfile.Dispenser) (string, [][]string, error) {
	if !d.Next() {
		return "", nil, d.ArgErr()
	}
	name := d.Val()
	if len(d.RemainingArgs()) != 0 {
		return "", nil, d.ArgErr()
	}
	if !d.Next() {
		return name, nil, nil
	}
	d.Prev()
	body, err := caddyfileutil.ReadFlatBlock(d, "Consul backend")
	return name, body, err
}

// Binding captures only borrowed global storage resources. It never closes them.
type Binding struct {
	client *consulapi.Client
	codec  cipher.AEAD
	prefix string
	// Identity is safe configuration metadata, including the effective encryption key.
	Identity string
}

// Bind captures Caddy's ready supported storage client and a copied AES key.
func Bind(ctx caddy.Context) (*Binding, error) {
	storage, ok := ctx.Storage().(*storageconsul.ConsulStorage)
	if !ok {
		return nil, errors.New("Consul backend requires configured pteich/caddy-tlsconsul storage")
	}
	return Capture(storage)
}

// Capture freezes an explicitly supplied Caddy storage client and encryption key.
// Bind is the production entry point; tests use independent disposable clients.
func Capture(storage *storageconsul.ConsulStorage) (*Binding, error) {
	if storage == nil || storage.ConsulClient == nil {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(append([]byte(nil), storage.AESKey...))
	if err != nil {
		return nil, ErrInvalid
	}
	codec, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(storage.Prefix+"\x00"), storage.AESKey...))
	return &Binding{client: storage.ConsulClient, codec: codec, prefix: storage.Prefix, Identity: hex.EncodeToString(digest[:])}, nil
}

// Handle is one app-owned logical handle to a category/name document.
type Handle struct {
	binding *Binding
	key     string
	timeout time.Duration
	closed  atomic.Bool
}

// Open constructs a distinct handle without writing or adopting any state.
func (b *Binding) Open(category, name, prefix, timeout string) (*Handle, error) {
	if b == nil || b.client == nil || b.codec == nil {
		return nil, ErrUnavailable
	}
	duration, err := time.ParseDuration(timeout)
	if err != nil || duration < time.Millisecond || duration > 30*time.Second {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256([]byte(name))
	return &Handle{binding: b, key: path.Join(b.prefix, prefix, category, hex.EncodeToString(digest[:]), "state"), timeout: duration}, nil
}

// Close retires only this handle, leaving pending peer work and Caddy's client intact.
func (h *Handle) Close() error {
	if h != nil {
		h.closed.Store(true)
	}
	return nil
}
func (h *Handle) Ready() bool { return h != nil && h.binding != nil && !h.closed.Load() }
func (h *Handle) Context(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, h.timeout)
}
func options(ctx context.Context) *consulapi.QueryOptions {
	return (&consulapi.QueryOptions{RequireConsistent: true}).WithContext(ctx)
}

// Load decodes a detached document. Missing keys leave the supplied initial value intact.
func (h *Handle) Load(ctx context.Context, value any) (uint64, error) {
	if !h.Ready() || ctx == nil || ctx.Err() != nil {
		return 0, ErrUnavailable
	}
	pair, _, err := h.binding.client.KV().Get(h.key, options(ctx))
	if err != nil {
		return 0, ErrUnavailable
	}
	if pair == nil {
		return 0, nil
	}
	codec := h.binding.codec
	if len(pair.Value) < codec.NonceSize()+codec.Overhead() || len(pair.Value) > MaxPayload+codec.NonceSize()+codec.Overhead() {
		return 0, ErrUnavailable
	}
	data, err := codec.Open(nil, pair.Value[:codec.NonceSize()], pair.Value[codec.NonceSize():], []byte(h.key))
	if err != nil {
		return 0, ErrUnavailable
	}
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return 0, ErrUnavailable
	}
	return pair.ModifyIndex, nil
}

func (h *Handle) transaction(ctx context.Context, op *consulapi.KVTxnOp) (bool, error) {
	if !h.Ready() || ctx == nil || ctx.Err() != nil {
		return false, ErrUnavailable
	}
	ok, response, _, err := h.binding.client.KV().Txn(consulapi.KVTxnOps{op}, options(ctx))
	if err != nil {
		return false, ErrUnavailable
	}
	if !ok && (response == nil || len(response.Errors) != 1 || response.Errors[0].OpIndex != 0) {
		return false, ErrUnavailable
	}
	return ok, nil
}

// Check fences a read/callback against concurrent writes without changing the key.
func (h *Handle) Check(ctx context.Context, index uint64) (bool, error) {
	verb := consulapi.KVCheckIndex
	if index == 0 {
		verb = consulapi.KVCheckNotExists
	}
	return h.transaction(ctx, &consulapi.KVTxnOp{Verb: verb, Key: h.key, Index: index})
}

func (h *Handle) save(ctx context.Context, index uint64, value any) (bool, error) {
	var data bytes.Buffer
	if gob.NewEncoder(&data).Encode(value) != nil {
		return false, ErrInvalid
	}
	if data.Len() > MaxPayload {
		return false, ErrCapacity
	}
	codec := h.binding.codec
	nonce := make([]byte, codec.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return false, ErrUnavailable
	}
	encrypted := codec.Seal(nonce, nonce, data.Bytes(), []byte(h.key))
	return h.transaction(ctx, &consulapi.KVTxnOp{Verb: consulapi.KVCAS, Key: h.key, Index: index, Value: encrypted})
}

// Update retries only definite CAS conflicts, up to eight attempts. The callback
// must be retry-safe and keep results private until Update returns nil. Returning
// changed=true with an error commits terminal revocation before returning it.
// Network errors never retry, even when a server may already have committed.
func Update[T any](ctx context.Context, h *Handle, initial func() T, apply func(*T) (bool, error)) error {
	if !h.Ready() || ctx == nil {
		return ErrUnavailable
	}
	ctx, cancel := h.Context(ctx)
	defer cancel()
	for range 8 {
		state := initial()
		index, err := h.Load(ctx, &state)
		if err != nil {
			return err
		}
		changed, result := apply(&state)
		if result != nil && !changed {
			return result
		}
		var ok bool
		if changed {
			ok, err = h.save(ctx, index, &state)
		} else {
			ok, err = h.Check(ctx, index)
		}
		if err != nil {
			return err
		}
		if ok {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			return result
		}
	}
	return ErrUnavailable
}
