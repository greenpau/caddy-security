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
	//	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	// "github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/go-authcrunch"
	//	"strconv"
	//	"strings"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("security", parseCaddyfile)
}

// parseCaddyfile parses security app configuration.
//
// Syntax:
//
//   security {
//     credentials ...
//     identity store <name>
//     sso provider <name>
//     [saml|oauth] identity provider <name>
//     authentication ...
//     authorization ...
//   }
//
func parseCaddyfile(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	repl := caddy.NewReplacer()
	app := new(App)
	app.Config = authcrunch.NewConfig()

	if !d.Next() {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		tld := d.Val()
		switch tld {
		case "credentials":
			if err := parseCaddyfileCredentials(d, repl, app.Config); err != nil {
				return nil, err
			}
		case "messaging":
			if err := parseCaddyfileMessaging(d, repl, app.Config); err != nil {
				return nil, err
			}
		case "local", "ldap", "oauth", "saml":
			if err := parseCaddyfileIdentity(d, repl, app.Config, tld); err != nil {
				return nil, err
			}
		case "user":
			if err := parseCaddyfileUser(d, repl, app.Config); err != nil {
				return nil, err
			}
		case "authentication":
			if err := parseCaddyfileAuthentication(d, repl, app.Config); err != nil {
				return nil, err
			}
		case "authorization":
			if err := parseCaddyfileAuthorization(d, repl, app.Config); err != nil {
				return nil, err
			}
		case "sso":
			if err := parseCaddyfileSingleSignOnProvider(d, repl, app.Config); err != nil {
				return nil, err
			}
		default:
			return nil, d.ArgErr()
		}
	}

	if err := app.Config.Validate(); err != nil {
		return nil, err
	}

	return httpcaddyfile.App{
		Name:  appName,
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
