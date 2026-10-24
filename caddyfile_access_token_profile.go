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
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	kmsparser "github.com/greenpau/go-authcrunch/pkg/kms/parser"
)

// readCaddyfileAccessTokenProfile preserves one complete portal/policy block:
//
//	access token profile {
//	    issuer <exact-issuer>
//	    audience <exact-audience>
//	    key ids <kid> [<kid>...]
//	    max lifetime <seconds>
//	}
//
// All settings are required and occur once. The shared pure parser owns bounds,
// IDs and strict access-token semantics. Algorithm/purpose are fixed. This
// profile's lifetime uses integer seconds; signer backend lifetime is a duration.
// Literal blocks validate now. Runtime-backed blocks retain complete encoded
// statements and validate only after exact one-pass replacement; no PEM is read.
func readCaddyfileAccessTokenProfile(d *caddyfile.Dispenser, args []string) ([]string, error) {
	if len(args) != 2 || args[0] != "token" || args[1] != "profile" {
		return nil, d.Errf("expected access token profile block")
	}
	body, err := readFlatDirectiveBlock(d, "access token profile")
	if err != nil {
		return nil, err
	}
	statements := make([]string, 0, len(body))
	for _, tokens := range body {
		statements = append(statements, encodeOAuthDirective(tokens))
	}
	return statements, nil
}

func parseAccessTokenProfile(statements []string) (*kms.AccessTokenProfileConfig, error) {
	config, err := kmsparser.NewAccessTokenProfileConfigFromDirectives(statements)
	if err != nil {
		return nil, fmt.Errorf("invalid access token profile configuration")
	}
	return config, nil
}
