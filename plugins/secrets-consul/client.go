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

// Package consul supplies encrypted secret records through Caddy's Consul storage.
package consul

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	storageconsul "github.com/pteich/caddy-tlsconsul"

	"github.com/greenpau/caddy-security/internal/consulstate"
)

// ErrNotFound reports an absent secret record or exact top-level key.
var ErrNotFound = errors.New("Consul secret record or key not found")

// Config binds a module ID to one record. Backend fields remain literal.
type Config struct {
	Name    string `json:"name"`
	Record  string `json:"record"`
	Prefix  string `json:"prefix,omitempty"`
	Timeout string `json:"timeout,omitempty"`
}

func (c Config) normalized() (Config, error) {
	var err error
	c.Prefix, c.Timeout, err = consulstate.Normalize(c.Name, c.Prefix, c.Timeout, "security/secrets")
	if err != nil || strings.Contains(c.Name, ":") || !consulstate.ValidText(c.Record, 256) {
		return c, consulstate.ErrInvalid
	}
	return c, nil
}

const maxSecretBytes = 64 << 10

// Client is a trusted context-aware reader/provisioner for one encrypted record.
// Different manager names may intentionally select the same prefix and record.
type Client struct {
	config Config
	handle *consulstate.Handle
}
type document struct {
	Version int
	Record  string
	Present bool
	Data    []byte
}

// New opens an independent logical client using borrowed Caddy Consul storage.
// It never creates or overwrites a record; the caller owns Close.
func New(ctx context.Context, config *Config, storage *storageconsul.ConsulStorage) (*Client, error) {
	if config == nil {
		return nil, consulstate.ErrInvalid
	}
	c, err := config.normalized()
	if err != nil {
		return nil, err
	}
	b, err := consulstate.Capture(storage)
	if err != nil {
		return nil, err
	}
	return open(ctx, c, b)
}
func open(ctx context.Context, c Config, b *consulstate.Binding) (*Client, error) {
	handle, err := b.Open("secrets", c.Record, c.Prefix, c.Timeout)
	if err != nil {
		return nil, err
	}
	client := &Client{config: c, handle: handle}
	if err := client.run(ctx, func(*document) (bool, error) { return false, nil }); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return client, nil
}
func (c *Client) initial() document { return document{Version: 1, Record: c.config.Record} }
func (c *Client) run(ctx context.Context, apply func(*document) (bool, error)) error {
	if c == nil {
		return consulstate.ErrUnavailable
	}
	return consulstate.Update(ctx, c.handle, c.initial, func(d *document) (bool, error) {
		if d.Version != 1 || d.Record != c.config.Record || len(d.Data) > maxSecretBytes || !d.Present && len(d.Data) != 0 || d.Present && len(d.Data) == 0 {
			return false, consulstate.ErrUnavailable
		}
		return apply(d)
	})
}

// GetConfig exposes allowlisted metadata without prefixes, keys or values.
func (c *Client) GetConfig() map[string]any {
	if c == nil {
		return nil
	}
	return map[string]any{"name": c.config.Name, "kind": "consul", "record": c.config.Record}
}

// Put atomically replaces one record using trusted JSON-compatible values. It
// preserves exact strings and json.Number values, rejects unsupported types,
// invalid UTF-8, excessive nesting/nodes and records larger than 64 KiB.
func (c *Client) Put(ctx context.Context, values map[string]any) error {
	if len(values) == 0 || len(values) > 128 {
		return consulstate.ErrInvalid
	}
	nodes, text := 0, 0
	if !validValue(values, 0, &nodes, &text) {
		return consulstate.ErrInvalid
	}
	data, err := json.Marshal(values)
	if err != nil || len(data) > maxSecretBytes {
		return consulstate.ErrInvalid
	}
	return c.run(ctx, func(d *document) (bool, error) { d.Present = true; d.Data = data; return true, nil })
}
func validValue(value any, depth int, nodes, text *int) bool {
	*nodes++
	if depth > 16 || *nodes > 4096 {
		return false
	}
	switch v := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	case string:
		*text += len(v)
		return utf8.ValidString(v) && *text <= maxSecretBytes
	case json.Number:
		*text += len(v)
		if len(v) == 0 || *text > maxSecretBytes {
			return false
		}
		data, err := json.Marshal(v)
		return err == nil && bytes.Equal(data, []byte(v))
	case []any:
		for _, entry := range v {
			if !validValue(entry, depth+1, nodes, text) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, entry := range v {
			*text += len(key)
			if !consulstate.ValidText(key, 256) || *text > maxSecretBytes || !validValue(entry, depth+1, nodes, text) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
func decode(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > maxSecretBytes || !utf8.Valid(data) {
		return nil, consulstate.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var values map[string]any
	if decoder.Decode(&values) != nil || decoder.Decode(new(any)) != io.EOF || len(values) == 0 || len(values) > 128 {
		return nil, consulstate.ErrUnavailable
	}
	nodes, text := 0, 0
	if !validValue(values, 0, &nodes, &text) {
		return nil, consulstate.ErrUnavailable
	}
	return values, nil
}

// GetSecrets returns one detached coherent record. Missing or unavailable records
// never yield empty fallback objects. Numbers retain their exact json.Number text.
func (c *Client) GetSecrets(ctx context.Context) (map[string]any, error) {
	var result map[string]any
	err := c.run(ctx, func(d *document) (bool, error) {
		if !d.Present {
			return false, ErrNotFound
		}
		values, err := decode(d.Data)
		result = values
		return false, err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetSecret selects an exact top-level key; dots do not traverse objects.
func (c *Client) GetSecret(ctx context.Context, key string) (any, error) {
	values, err := c.GetSecrets(ctx)
	if err != nil {
		return nil, err
	}
	v, ok := values[key]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

// Delete atomically clears the selected record. Absence is idempotent success.
func (c *Client) Delete(ctx context.Context) error {
	return c.run(ctx, func(d *document) (bool, error) {
		present := d.Present
		d.Present = false
		d.Data = nil
		return present, nil
	})
}

// Close retires this client without deleting shared data or closing Caddy's client.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return c.handle.Close()
}
