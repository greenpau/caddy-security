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
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/caddy-security/pkg/util"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("authorize", getMiddlewareFromParseAuthzPluginCaddyfile)
}

func getMiddlewareFromParseAuthzPluginCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a, err := parseAuthzPluginCaddyfile(h)
	if err != nil {
		return nil, err
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			authzPluginName: caddyconfig.JSON(AuthzMiddleware{Authorizer: a}, nil),
		},
	}, nil
}

// parseAuthzPluginCaddyfile parses authorization plugin configuration.
//
// Syntax:
//
//   authorize [<matcher>] with <policy_name>
//
// Examples:
//
//   authorize with mypolicy
//   authorize * with mypolicy
//   authorize /* with mypolicy
//   authorize /app* with mypolicy
//
func parseAuthzPluginCaddyfile(h httpcaddyfile.Helper) (*authz.Authorizer, error) {
	var i int
	repl := caddy.NewReplacer()
	args := util.FindReplaceAll(repl, h.RemainingArgs())
	a := &authz.Authorizer{}
	if args[0] != "authorize" {
		return nil, h.Errf("directive should start with authorize: %s", args)
	}

	switch len(args) {
	case 3:
		i = 1
		a.Path = "*"
		a.GatekeeperName = args[2]
	case 4:
		i = 2
		a.Path = args[1]
		a.GatekeeperName = args[3]
	default:
		return nil, h.Errf("malformed directive: %s", args)
	}

	if args[0] != "authorize" {
		return nil, h.Errf("directive should start with authorize: %s", args)
	}
	if args[i] != "with" {
		return nil, h.Errf("directive must contain %q keyword: %s", "with", args)
	}
	return a, nil
}
