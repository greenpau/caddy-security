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
	externalparser "github.com/greenpau/go-authcrunch/pkg/authz/external/parser"
	httpjsonparser "github.com/greenpau/go-authcrunch/plugins/external-authorization/httpjson/parser"
)

// parseCaddyfileExternalAuthorization parses one flat block per local policy:
//
//	external authorization httpjson {
//		endpoint <https-url-or-literal-loopback-http-url>
//		policy <remote-policy>
//		version <remote-policy-revision>
//		issuer <exact-authenticated-issuer>
//		realm <exact-authenticated-origin>
//		subject claim <claim-name>
//		tenant claim <claim-name>
//		attribute <original-authenticated-claim-name>
//		timeout <duration>
//		tls ca file <pem-path>
//		tls client certificate <cert-pem-path> <key-pem-path>
//	}
//
// Endpoint, remote policy/revision, issuer and realm are required. Scalars occur
// once; attribute repeats for unique names (maximum 16). Subject defaults to sub;
// tenant and attributes are omitted by default. Timeout defaults to 1s, accepts
// 1ms–30s, and configures both the total decision deadline and each HTTP call.
// The two AuthCrunch parsers own endpoint and identity validation. TLS is host
// configuration: optional exclusive CA trust and a paired mTLS service identity,
// HTTPS only, with regular PEM files up to 1 MiB each. All values are literal;
// no runtime placeholder/secret expansion or request-derived settings apply.
// Every local allow requires external allow; explicit bypass retains its meaning.
func parseCaddyfileExternalAuthorization(d *caddyfile.Dispenser, policy string) (*ExternalAuthorizationBinding, error) {
	args := d.RemainingArgs()
	if len(args) != 2 || args[0] != "authorization" || args[1] != "httpjson" {
		return nil, d.Errf("expected external authorization httpjson block")
	}
	body, err := readFlatDirectiveBlock(d, "external authorization")
	if err != nil {
		return nil, err
	}
	var settings, transport []string
	module := &HTTPJSONExternalAuthorization{}
	seenTLS := make(map[string]bool)
	for _, tokens := range body {
		statement := encodeOAuthDirective(tokens)
		switch tokens[0] {
		case "endpoint":
			transport = append(transport, statement)
		case "timeout":
			settings = append(settings, statement)
			transport = append(transport, statement)
		case "tls":
			if module.TLS == nil {
				module.TLS = &ExternalAuthorizationTLS{}
			}
			if len(tokens) < 2 || seenTLS[tokens[1]] {
				return nil, d.Errf("invalid or duplicate external authorization TLS directive")
			}
			switch {
			case len(tokens) == 4 && tokens[1] == "ca" && tokens[2] == "file" && tokens[3] != "":
				module.TLS.RootCAFile = tokens[3]
			case len(tokens) == 5 && tokens[1] == "client" && tokens[2] == "certificate" && tokens[3] != "" && tokens[4] != "":
				module.TLS.ClientCertificateFile, module.TLS.ClientKeyFile = tokens[3], tokens[4]
			default:
				return nil, d.Errf("invalid external authorization TLS directive")
			}
			seenTLS[tokens[1]] = true
		default:
			settings = append(settings, statement)
		}
	}
	binding, err := externalparser.NewExternalAuthorizationConfigFromDirectives(settings)
	if err != nil {
		return nil, d.Errf("%v", err)
	}
	config, err := httpjsonparser.NewHTTPJSONAuthorizerConfigFromDirectives(transport)
	if err != nil {
		return nil, d.Errf("%v", err)
	}
	module.Endpoint, module.Timeout = config.Endpoint, config.Timeout
	if err := module.Validate(); err != nil {
		return nil, d.Errf("%v", err)
	}
	raw, err := json.Marshal(struct {
		Driver string `json:"driver"`
		*HTTPJSONExternalAuthorization
	}{Driver: "httpjson", HTTPJSONExternalAuthorization: module})
	if err != nil {
		return nil, d.Errf("invalid external authorization configuration")
	}
	return &ExternalAuthorizationBinding{Policy: policy, Config: binding, BackendRaw: raw}, nil
}
