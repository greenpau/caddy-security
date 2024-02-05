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
	"github.com/andrewsonpradeep/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	identPrefix = "security.identity"
)

func parseCaddyfileIdentity(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config, kind string) error {
	args := util.FindReplaceAll(repl, d.RemainingArgs())
	if len(args) < 3 {
		return d.ArgErr()
	}
	switch {
	case ((kind == "local" || kind == "ldap") && (args[0] == "identity")):
		if args[1] != "store" {
			return d.ArgErr()
		}
		if err := parseCaddyfileIdentityStore(d, repl, cfg, kind, args[2], args[3:]); err != nil {
			return err
		}
	case ((kind == "oauth" || kind == "saml") && (args[0] == "identity")):
		if args[1] != "provider" {
			return d.ArgErr()
		}
		if err := parseCaddyfileIdentityProvider(d, repl, cfg, kind, args[2], args[3:]); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(identPrefix, args)
	}
	return nil
}
