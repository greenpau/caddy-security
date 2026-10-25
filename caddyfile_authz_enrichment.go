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
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	enrichmentparser "github.com/greenpau/go-authcrunch/pkg/authz/enrichment/parser"
	staticparser "github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static/parser"

	staticplugin "github.com/greenpau/caddy-security/plugins/claims-enrichment-static"
)

// parseCaddyfileClaimsEnrichment parses one flat block per authorization policy:
//
//	claims enrichment static {
//		source static
//		version v1
//		issuer <exact-token-issuer>
//		realm <exact-token-origin>
//		subject claim <immutable-account-claim>
//		tenant claim <tenant-claim>
//		audience <required-token-audience>
//		timeout <duration>
//		max age <duration>
//		attribute <name> <string [list]|json>
//		claim <name> <literal-string>
//		claim <name> json <one-JSON-token>
//	}
//
// Binding scalars occur once; attributes and claims have unique names. Both
// bodies use AuthCrunch's shared parsers. Timeout defaults to 1s (maximum 30s),
// max age to 1m (static requires 1m through 24h). Claims are literal, bounded JSON;
// no runtime replacement or identity lookup occurs. Quote JSON as one Caddy
// token; use JSON strings for empty/whitespace values. A required enrichment
// failure denies authorization; only the detached ACL view receives values.
func parseCaddyfileClaimsEnrichment(d *caddyfile.Dispenser, policy string) (*ClaimsEnrichmentBinding, error) {
	args := d.RemainingArgs()
	if len(args) != 2 || args[0] != "enrichment" || args[1] != "static" {
		return nil, d.Errf("expected claims enrichment static block")
	}
	body, err := readFlatDirectiveBlock(d, "claims enrichment")
	if err != nil {
		return nil, err
	}
	var settings, claims []string
	for _, tokens := range body {
		// This codec uses EncodeArgs and preserves record-edge whitespace.
		statement := encodeOAuthDirective(tokens)
		if tokens[0] == "claim" {
			claims = append(claims, statement)
		} else {
			settings = append(settings, statement)
		}
	}
	binding, err := enrichmentparser.NewClaimsEnrichmentConfigFromDirectives(settings)
	if err != nil {
		return nil, d.Errf("%v", err)
	}
	config, err := staticparser.NewStaticClaimsEnrichmentConfigFromDirectives(claims)
	if err != nil {
		return nil, d.Errf("%v", err)
	}
	if err := staticplugin.ValidateBinding(binding, config); err != nil {
		return nil, d.Errf("%v", err)
	}
	// Both Caddy's config tree and inline module loader round bare JSON numbers.
	// Protect the complete object with one string before either sees its values.
	claimsJSON, err := json.Marshal(config.Claims)
	if err != nil {
		return nil, d.Errf("invalid static claims configuration")
	}
	raw, err := json.Marshal(struct {
		Driver string `json:"driver"`
		*StaticClaimsEnrichment
	}{Driver: "static", StaticClaimsEnrichment: &StaticClaimsEnrichment{ClaimsJSON: string(claimsJSON)}})
	if err != nil {
		return nil, d.Errf("invalid static claims configuration")
	}
	return &ClaimsEnrichmentBinding{Policy: policy, Config: binding, BackendRaw: raw}, nil
}
