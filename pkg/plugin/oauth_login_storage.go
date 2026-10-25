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

package plugin

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
)

// OAuthLoginStoreConfig identifies an immutable host factory and its runtime.
// ConfigHash is the lowercase SHA-256 of normalized backend configuration. It
// checks factory agreement; it is neither the provider's transaction namespace
// nor an AuthCrunch persistence epoch. Metadata contains no runtime handles.
type OAuthLoginStoreConfig struct {
	Name       string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Driver     string `json:"driver,omitempty" xml:"driver,omitempty" yaml:"driver,omitempty"`
	ConfigHash string `json:"config_hash,omitempty" xml:"config_hash,omitempty" yaml:"config_hash,omitempty"`
}

// OAuthLoginStoreBackendModule prepares a detached immutable factory without
// opening resources. Later changes to the module must not change the factory's
// metadata, storage path or constructor inputs. Module Cleanup must not dispose
// returned runtimes. Backend configuration remains literal at this boundary.
type OAuthLoginStoreBackendModule interface {
	PrepareOAuthLoginStore() (OAuthLoginStoreFactory, error)
}

// OAuthLoginStoreFactory creates a distinct app-owned backend for each call.
// Metadata is copied, and constructors must consume the already-prepared values.
// The context bounds setup only, not runtime lifetime. On failure, return any
// acquired resource as a safely closable partial result or unwind it before
// returning real nil. Neither factories nor modules own the returned backend.
type OAuthLoginStoreFactory interface {
	OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error)
	NewOAuthLoginStore(context.Context) (OAuthLoginStore, error)
}

// OAuthLoginStore preserves the upstream transactional interface. Its metadata
// method must attest an initialized, usable, not-closed runtime and return the
// factory's exact copied descriptor. Implement io.Closer when disposal is needed;
// the app invokes it only after consumers drain and the root closes. Never
// publish tentative results or add logical retries around upstream operations.
type OAuthLoginStore interface {
	oauth.LoginStore
	OAuthLoginStoreConfig() (OAuthLoginStoreConfig, error)
}

// Validate checks copied metadata without performing storage or network I/O.
func (c OAuthLoginStoreConfig) Validate() error {
	for _, value := range []string{c.Name, c.Driver} {
		if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("OAuth login store requires valid name and driver metadata")
		}
	}
	if len(c.ConfigHash) != 64 || strings.ToLower(c.ConfigHash) != c.ConfigHash {
		return fmt.Errorf("OAuth login store requires a configuration digest")
	}
	if _, err := hex.DecodeString(c.ConfigHash); err != nil {
		return fmt.Errorf("OAuth login store requires a configuration digest")
	}
	return nil
}
