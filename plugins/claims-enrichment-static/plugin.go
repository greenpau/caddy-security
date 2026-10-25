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

package static

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"

	"github.com/greenpau/caddy-security/pkg/plugin"
)

// StaticClaimsEnrichment supplies literal claims to request-local ACL decisions.
// ClaimsJSON is a JSON object encoded as a string so Caddy preserves precise
// numbers through configuration storage and reload. The backend owns no workers
// or resources; the app owns its immutable snapshot.
type StaticClaimsEnrichment struct {
	ClaimsJSON string `json:"claims_json"`
}

func init() { caddy.RegisterModule(StaticClaimsEnrichment{}) }

// CaddyModule returns the static claims enrichment factory's module information.
func (StaticClaimsEnrichment) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.claims_enrichment.static", New: func() caddy.Module { return new(StaticClaimsEnrichment) }}
}

// Validate checks literal values without allocating runtime resources.
func (m *StaticClaimsEnrichment) Validate() error {
	_, err := m.BackendConfig()
	return err
}

// Caddy decodes both its configuration tree and inline module objects through
// float64. Transport the JSON object as a string, decoding only at this boundary.
// BackendConfig returns a detached, validated configuration for host admission.
func (m *StaticClaimsEnrichment) BackendConfig() (*static.Config, error) {
	config := &static.Config{}
	decoder := json.NewDecoder(strings.NewReader(m.ClaimsJSON))
	decoder.UseNumber()
	if !utf8.ValidString(m.ClaimsJSON) || decoder.Decode(&config.Claims) != nil {
		return nil, fmt.Errorf("invalid static claims JSON object")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("invalid static claims JSON object")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// NewClaimsEnrichmentBackend validates the binding and constructs a detached backend.
func (m *StaticClaimsEnrichment) NewClaimsEnrichmentBackend(ctx context.Context, binding enrichment.Config) (enrichment.Backend, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := m.BackendConfig()
	if err != nil {
		return nil, err
	}
	if err := ValidateBinding(&binding, config); err != nil {
		return nil, err
	}
	return static.New(config)
}

// ValidateBinding checks the static source, freshness and attribute contract.
func ValidateBinding(binding *enrichment.Config, config *static.Config) error {
	if err := binding.Validate(); err != nil {
		return err
	}
	if err := config.Validate(); err != nil {
		return err
	}
	maxAge, _ := time.ParseDuration(binding.MaxAge)
	if binding.Source != static.Source || binding.Version != static.Version || maxAge < time.Minute {
		return fmt.Errorf("static claims requires its source and contract version and max age of at least one minute")
	}
	for _, attribute := range binding.Attributes {
		value, exists := config.Claims[attribute.Name]
		if !exists {
			return fmt.Errorf("static claims binding requests an unconfigured attribute")
		}
		if _, err := enrichment.CopyAttribute(value, attribute.Type); err != nil {
			return err
		}
	}
	return nil
}

var (
	_ caddy.Module                         = (*StaticClaimsEnrichment)(nil)
	_ caddy.Validator                      = (*StaticClaimsEnrichment)(nil)
	_ plugin.ClaimsEnrichmentBackendModule = (*StaticClaimsEnrichment)(nil)
)
