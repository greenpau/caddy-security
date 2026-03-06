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

func cloneResolvedPolicyConfigs(cfgs []*authz.PolicyConfig, repl *caddy.Replacer) ([]*authz.PolicyConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*authz.PolicyConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		clone, err := cloneResolvedPolicyConfig(cfg, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, clone)
	}
	return clones, nil
}

func cloneResolvedPolicyConfig(cfg *authz.PolicyConfig, repl *caddy.Replacer) (*authz.PolicyConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	name, err := resolveRuntimeString(cfg.Name, repl)
	if err != nil {
		return nil, err
	}
	authURLPath, err := resolveRuntimeString(cfg.AuthURLPath, repl)
	if err != nil {
		return nil, err
	}
	authRedirectQueryParameter, err := resolveRuntimeString(cfg.AuthRedirectQueryParameter, repl)
	if err != nil {
		return nil, err
	}
	bypassConfigs, err := cloneResolvedBypassConfigs(cfg.BypassConfigs, repl)
	if err != nil {
		return nil, err
	}
	headerInjectionConfigs, err := cloneResolvedHeaderInjectionConfigs(cfg.HeaderInjectionConfigs, repl)
	if err != nil {
		return nil, err
	}
	accessListRules, err := cloneResolvedRuleConfigurations(cfg.AccessListRules, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyConfigs, err := cloneResolvedCryptoKeyConfigs(cfg.CryptoKeyConfigs, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyStoreConfig, err := cloneResolvedInterfaceMap(cfg.CryptoKeyStoreConfig, repl)
	if err != nil {
		return nil, err
	}
	authProxyConfig, err := cloneResolvedAuthProxyConfig(cfg.AuthProxyConfig, repl)
	if err != nil {
		return nil, err
	}
	allowedTokenSources, err := cloneResolvedStringSlice(cfg.AllowedTokenSources, repl)
	if err != nil {
		return nil, err
	}
	forbiddenURL, err := resolveRuntimeString(cfg.ForbiddenURL, repl)
	if err != nil {
		return nil, err
	}
	userIdentityField, err := resolveRuntimeString(cfg.UserIdentityField, repl)
	if err != nil {
		return nil, err
	}
	loginHintValidators, err := cloneResolvedStringSlice(cfg.LoginHintValidators, repl)
	if err != nil {
		return nil, err
	}

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

func cloneResolvedBypassConfigs(cfgs []*bypass.Config, repl *caddy.Replacer) ([]*bypass.Config, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*bypass.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		matchType, err := resolveRuntimeString(cfg.MatchType, repl)
		if err != nil {
			return nil, err
		}
		uri, err := resolveRuntimeString(cfg.URI, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &bypass.Config{
			MatchType: matchType,
			URI:       uri,
		})
	}
	return clones, nil
}

func cloneResolvedHeaderInjectionConfigs(cfgs []*injector.Config, repl *caddy.Replacer) ([]*injector.Config, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*injector.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		header, err := resolveRuntimeString(cfg.Header, repl)
		if err != nil {
			return nil, err
		}
		field, err := resolveRuntimeString(cfg.Field, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &injector.Config{
			Header: header,
			Field:  field,
		})
	}
	return clones, nil
}

func cloneResolvedAuthProxyConfig(cfg *authproxy.Config, repl *caddy.Replacer) (*authproxy.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	portalName, err := resolveRuntimeString(cfg.PortalName, repl)
	if err != nil {
		return nil, err
	}

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
