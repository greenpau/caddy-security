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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func parseCaddyfileAuthorizationCrypto(h *caddyfile.Dispenser, repl *caddy.Replacer, policy *authz.PolicyConfig, rootDirective string, args []string) error {
	if len(args) < 3 {
		return h.Errf("%v", errors.ErrConfigDirectiveShort.WithArgs(rootDirective, args))
	}
	encodedArgs := cfgutil.EncodeArgs(util.FindReplaceAll(repl, args))
	switch args[0] {
	case "key":
	case "default":
	default:
		return h.Errf("%v", errors.ErrConfigDirectiveValueUnsupported.WithArgs(rootDirective, args))
	}
	policy.AddRawCryptoConfigs(encodedArgs)
	return nil
}
