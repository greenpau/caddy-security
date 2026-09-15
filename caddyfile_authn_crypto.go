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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// parseCaddyfileAuthPortalCrypto forwards encoded crypto statements to
// go-authcrunch/pkg/kms. Full grammar and key loading are validated after runtime
// replacement, not by this wrapper. The same grammar applies to policies.
//
// Syntax:
//
//	crypto default token <name|lifetime> <value>
//	crypto default autogenerate tag <tag>
//	crypto default autogenerate algorithm <ES512|EdDSA|Ed25519>
//	crypto key [<kid>] token <name|lifetime> <value>
//	crypto key [<kid>] <sign|verify|sign-verify|auto> <shared_secret>
//	crypto key [<kid>] <sign|verify|sign-verify|auto> from <file|directory> <path>
//	crypto key [<kid>] <sign|verify|sign-verify|auto> from env <variable> [as <key|file|directory>]
//	crypto key <kid> system <64_hex_characters>
//
// Token lifetime is in seconds. Key attributes are order-sensitive. Portal
// issuance requires a signing key; policies need verification material. PEM
// loading supports RSA, ECDSA, and Ed25519; system keys serve the System API.
// See .codex/skills/configuration-crypto/SKILL.md for material and usage details.
func parseCaddyfileAuthPortalCrypto(h *caddyfile.Dispenser, portal *authn.PortalConfig, rootDirective string, args []string) error {
	if len(args) < 3 {
		return h.Errf("%v", errors.ErrConfigDirectiveShort.WithArgs(rootDirective, args))
	}

	switch args[0] {
	case "key":
	case "default":
	default:
		return h.Errf("%v", errors.ErrConfigDirectiveValueUnsupported.WithArgs(rootDirective, args))
	}

	updatedArgs := append([]string{cryptoKeyword}, args...)
	portal.AddRawCryptoKeyStoreConfig(cfgutil.EncodeArgs(updatedArgs))
	return nil
}
