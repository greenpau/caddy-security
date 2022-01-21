package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"github.com/greenpau/aaasf/pkg/authz"
	"github.com/greenpau/caddy-security/pkg/util"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("authorize", getMiddlewareFromParseCaddyfile)
}

func getMiddlewareFromParseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	a, err := parseCaddyfile(h)
	if err != nil {
		return nil, err
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"authorizer": caddyconfig.JSON(Middleware{Authorizer: a}, nil),
		},
	}, nil
}

// parseCaddyfile parses authorization plugin configuration.
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
func parseCaddyfile(h httpcaddyfile.Helper) (*authz.Authorizer, error) {
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
