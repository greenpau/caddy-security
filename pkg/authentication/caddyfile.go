package authentication

import (
	"encoding/json"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/greenpau/aaasf/pkg/authn"
	"github.com/greenpau/caddy-security/pkg/util"
)

func init() {
	httpcaddyfile.RegisterDirective("authenticate", getRouteFromParseCaddyfile)
}

func getRouteFromParseCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	a, err := parseCaddyfile(h)
	if err != nil {
		return nil, err
	}

	pathMatcher := caddy.ModuleMap{
		"path": h.JSON(caddyhttp.MatchPath{a.Path}),
	}

	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				&Middleware{
					Authenticator: a,
				},
				"handler",
				"authenticator",
				nil,
			),
		},
	}
	subroute := new(caddyhttp.Subroute)
	subroute.Routes = append([]caddyhttp.Route{route}, subroute.Routes...)
	return h.NewRoute(pathMatcher, subroute), nil
}

// parseCaddyfile parses authentication plugin configuration.
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
func parseCaddyfile(h httpcaddyfile.Helper) (*authn.Authenticator, error) {
	var i int
	repl := caddy.NewReplacer()
	args := util.FindReplaceAll(repl, h.RemainingArgs())
	a := &authn.Authenticator{}
	if args[0] != "authenticate" {
		return nil, h.Errf("directive should start with authenticate: %s", args)
	}

	switch len(args) {
	case 3:
		i = 1
		a.Path = "*"
		a.PortalName = args[2]
	case 4:
		i = 2
		a.Path = args[1]
		a.PortalName = args[3]
	default:
		return nil, h.Errf("malformed directive: %s", args)
	}

	if args[0] != "authenticate" {
		return nil, h.Errf("directive should start with authenticate: %s", args)
	}
	if args[i] != "with" {
		return nil, h.Errf("directive must contain %q keyword: %s", "with", args)
	}
	return a, nil
}
