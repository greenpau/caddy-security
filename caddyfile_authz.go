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
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

const (
	authzPrefix = "security.authorization"
)

// parseCaddyfileAuthorization parses authorization configuration.
//
// Syntax:
//
//	authorization portal <name> {
//	}
func parseCaddyfileAuthorization(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	var rootDirective string
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "policy":
		p := &authz.PolicyConfig{Name: args[1]}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			rootDirective = mkcp(authzPrefix, args[0], k)
			switch k {
			case "crypto":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationCrypto(d, p, rootDirective, v); err != nil {
					return err
				}
			case "acl":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationACL(d, p, rootDirective, v); err != nil {
					return err
				}
			case "allow", "deny":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationACLShortcuts(d, p, rootDirective, k, v); err != nil {
					return err
				}
			case "bypass":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationBypass(d, p, rootDirective, v); err != nil {
					return err
				}
			case "enable", "disable", "validate", "set", "with":
				if err := parseCaddyfileAuthorizationMisc(d, p, rootDirective, k, d.RemainingArgs()); err != nil {
					return err
				}
			case "inject":
				v := d.RemainingArgs()
				if err := parseCaddyfileAuthorizationHeaderInjection(d, p, rootDirective, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, d.RemainingArgs())
			}
		}
		if err := cfg.AddAuthorizationPolicy(p); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authzPrefix, args)
	}
	return nil
}

func resolvePolicyConfigs(cfgs []*authz.PolicyConfig, repl *caddy.Replacer) ([]*authz.PolicyConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*authz.PolicyConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		clone, err := resolvePolicyConfig(cfg, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, clone)
	}
	return clones, nil
}

func resolvePolicyConfig(cfg *authz.PolicyConfig, repl *caddy.Replacer) (*authz.PolicyConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	name := util.FindReplace(repl, cfg.Name)
	authURLPath := util.FindReplace(repl, cfg.AuthURLPath)
	authRedirectQueryParameter := util.FindReplace(repl, cfg.AuthRedirectQueryParameter)
	bypassConfigs, err := resolveBypassConfigs(cfg.BypassConfigs, repl)
	if err != nil {
		return nil, err
	}
	headerInjectionConfigs, err := resolveHeaderInjectionConfigs(cfg.HeaderInjectionConfigs, repl)
	if err != nil {
		return nil, err
	}
	accessListRules, err := resolveRuleConfigurations(cfg.AccessListRules, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyConfigs, err := resolveCryptoKeyConfigs(cfg.CryptoKeyConfigs, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyStoreConfig := cloneInterfaceMap(cfg.CryptoKeyStoreConfig, repl)
	authProxyConfig, err := resolveAuthProxyConfig(cfg.AuthProxyConfig, repl)
	if err != nil {
		return nil, err
	}
	allowedTokenSources := util.FindReplaceAll(repl, cfg.AllowedTokenSources)
	forbiddenURL := util.FindReplace(repl, cfg.ForbiddenURL)
	userIdentityField := util.FindReplace(repl, cfg.UserIdentityField)
	loginHintValidators := util.FindReplaceAll(repl, cfg.LoginHintValidators)

	return &authz.PolicyConfig{
		Name:                        name,
		AuthURLPath:                 authURLPath,
		AuthRedirectDisabled:        cfg.AuthRedirectDisabled,
		AuthRedirectQueryDisabled:   cfg.AuthRedirectQueryDisabled,
		AuthRedirectQueryParameter:  authRedirectQueryParameter,
		AuthRedirectStatusCode:      cfg.AuthRedirectStatusCode,
		RedirectWithJavascript:      cfg.RedirectWithJavascript,
		BypassConfigs:               bypassConfigs,
		HeaderInjectionConfigs:      headerInjectionConfigs,
		AccessListRules:             accessListRules,
		CryptoKeyConfigs:            cryptoKeyConfigs,
		CryptoKeyStoreConfig:        cryptoKeyStoreConfig,
		AuthProxyConfig:             authProxyConfig,
		AllowedTokenSources:         allowedTokenSources,
		StripTokenEnabled:           cfg.StripTokenEnabled,
		ForbiddenURL:                forbiddenURL,
		UserIdentityField:           userIdentityField,
		ValidateBearerHeader:        cfg.ValidateBearerHeader,
		ValidateMethodPath:          cfg.ValidateMethodPath,
		ValidateAccessListPathClaim: cfg.ValidateAccessListPathClaim,
		ValidateSourceAddress:       cfg.ValidateSourceAddress,
		PassClaimsWithHeaders:       cfg.PassClaimsWithHeaders,
		LoginHintValidators:         loginHintValidators,
		AdditionalScopes:            cfg.AdditionalScopes,
	}, nil
}

func resolveBypassConfigs(cfgs []*bypass.Config, repl *caddy.Replacer) ([]*bypass.Config, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*bypass.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		matchType := util.FindReplace(repl, cfg.MatchType)
		uri := util.FindReplace(repl, cfg.URI)
		clones = append(clones, &bypass.Config{
			MatchType: matchType,
			URI:       uri,
		})
	}
	return clones, nil
}

func resolveHeaderInjectionConfigs(cfgs []*injector.Config, repl *caddy.Replacer) ([]*injector.Config, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*injector.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		header := util.FindReplace(repl, cfg.Header)
		field := util.FindReplace(repl, cfg.Field)
		clones = append(clones, &injector.Config{
			Header: header,
			Field:  field,
		})
	}
	return clones, nil
}

func resolveAuthProxyConfig(cfg *authproxy.Config, repl *caddy.Replacer) (*authproxy.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	portalName := util.FindReplace(repl, cfg.PortalName)

	return &authproxy.Config{
		PortalName: portalName,
		BasicAuth: authproxy.BasicAuthConfig{
			Enabled: cfg.BasicAuth.Enabled,
			Realms:  cloneInterfaceBoolMap(cfg.BasicAuth.Realms),
		},
		APIKeyAuth: authproxy.APIKeyAuthConfig{
			Enabled: cfg.APIKeyAuth.Enabled,
			Realms:  cloneInterfaceBoolMap(cfg.APIKeyAuth.Realms),
		},
	}, nil
}
