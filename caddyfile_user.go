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
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	userPrefix = "security.user"
)

func parseCaddyfileUser(d *caddyfile.Dispenser, repl *caddy.Replacer, cfg *authcrunch.Config) error {
	args := util.FindReplaceAll(repl, d.RemainingArgs())
	if len(args) < 2 {
		return d.ArgErr()
	}
	switch {
	case args[0] == "registration":
		if err := parseCaddyfileUserRegistration(d, repl, cfg, args[1]); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(userPrefix, args)
	}
	return nil
}
