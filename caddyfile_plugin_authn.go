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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/caddy-security/pkg/util"
)

func init() {
	httpcaddyfile.RegisterDirective("authenticate", getRouteFromParseAuthnPluginCaddyfile)
}

func getRouteFromParseAuthnPluginCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	m, err := parseAuthnPluginCaddyfile(h)
	if err != nil {
		return nil, err
	}

	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{m["path"]}),
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				&AuthnMiddleware{
					RouteMatcher: m["path"],
					PortalName:   m["portal_name"],
				},
				"handler",
				authnPluginName,
				nil,
			),
		},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil
}

// parseAuthnPluginCaddyfile parses authentication plugin configuration.
//
// Syntax:
//
//   authenticate [<matcher>] with <portal_name>
//
// Examples:
//
//   authenticate with myportal
//   authenticate * with myportal
//   authenticate /* with myportal
//   authenticate /auth* with myportal
//
func parseAuthnPluginCaddyfile(h httpcaddyfile.Helper) (map[string]string, error) {
	var i int
	repl := caddy.NewReplacer()
	args := util.FindReplaceAll(repl, h.RemainingArgs())
	m := make(map[string]string)

	if args[0] != "authenticate" {
		return nil, h.Errf("directive should start with authenticate: %s", args)
	}

	switch len(args) {
	case 3:
		i = 1
		m["path"] = "*"
		m["portal_name"] = args[2]
	case 4:
		i = 2
		m["path"] = args[1]
		m["portal_name"] = args[3]
	default:
		return nil, h.Errf("malformed directive: %s", args)
	}

	if args[0] != "authenticate" {
		return nil, h.Errf("directive should start with authenticate: %s", args)
	}
	if args[i] != "with" {
		return nil, h.Errf("directive must contain %q keyword: %s", "with", args)
	}
	return m, nil
}
