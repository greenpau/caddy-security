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
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/bypass"
	"github.com/greenpau/go-authcrunch/pkg/authz/injector"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/sso"
)

func resolveRuntimeConfig(cfg *authcrunch.Config) (*authcrunch.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	repl := caddy.NewReplacer()
	resolvedCfg := &authcrunch.Config{}

	var err error
	if resolvedCfg.Credentials, err = cloneResolvedCredentialsConfig(cfg.Credentials, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.Messaging, err = cloneResolvedMessagingConfig(cfg.Messaging, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.AuthenticationPortals, err = cloneResolvedPortalConfigs(cfg.AuthenticationPortals, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.AuthorizationPolicies, err = cloneResolvedPolicyConfigs(cfg.AuthorizationPolicies, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.IdentityStores, err = cloneResolvedIdentityStoreConfigs(cfg.IdentityStores, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.IdentityProviders, err = cloneResolvedIdentityProviderConfigs(cfg.IdentityProviders, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.SingleSignOnProviders, err = cloneResolvedSingleSignOnProviderConfigs(cfg.SingleSignOnProviders, repl); err != nil {
		return nil, err
	}
	if resolvedCfg.UserRegistries, err = cloneResolvedUserRegistryConfigs(cfg.UserRegistries, repl); err != nil {
		return nil, err
	}

	return resolvedCfg, nil
}

func cloneResolvedCredentialsConfig(cfg *credentials.Config, repl *caddy.Replacer) (*credentials.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	clone := &credentials.Config{}
	if len(cfg.Generic) > 0 {
		clone.Generic = make([]*credentials.Generic, 0, len(cfg.Generic))
		for _, entry := range cfg.Generic {
			resolvedEntry, err := cloneResolvedGenericCredential(entry, repl)
			if err != nil {
				return nil, err
			}
			clone.Generic = append(clone.Generic, resolvedEntry)
		}
	}
	return clone, nil
}

func cloneResolvedGenericCredential(cfg *credentials.Generic, repl *caddy.Replacer) (*credentials.Generic, error) {
	if cfg == nil {
		return nil, nil
	}

	name, err := resolveRuntimeString(cfg.Name, repl)
	if err != nil {
		return nil, err
	}
	username, err := resolveRuntimeString(cfg.Username, repl)
	if err != nil {
		return nil, err
	}
	password, err := resolveRuntimeString(cfg.Password, repl)
	if err != nil {
		return nil, err
	}
	domain, err := resolveRuntimeString(cfg.Domain, repl)
	if err != nil {
		return nil, err
	}

	return &credentials.Generic{
		Name:     name,
		Username: username,
		Password: password,
		Domain:   domain,
	}, nil
}

func cloneResolvedMessagingConfig(cfg *messaging.Config, repl *caddy.Replacer) (*messaging.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	clone := &messaging.Config{}
	if len(cfg.EmailProviders) > 0 {
		clone.EmailProviders = make([]*messaging.EmailProvider, 0, len(cfg.EmailProviders))
		for _, provider := range cfg.EmailProviders {
			resolvedProvider, err := cloneResolvedEmailProvider(provider, repl)
			if err != nil {
				return nil, err
			}
			clone.EmailProviders = append(clone.EmailProviders, resolvedProvider)
		}
	}
	if len(cfg.FileProviders) > 0 {
		clone.FileProviders = make([]*messaging.FileProvider, 0, len(cfg.FileProviders))
		for _, provider := range cfg.FileProviders {
			resolvedProvider, err := cloneResolvedFileProvider(provider, repl)
			if err != nil {
				return nil, err
			}
			clone.FileProviders = append(clone.FileProviders, resolvedProvider)
		}
	}

	return clone, nil
}

func cloneResolvedEmailProvider(cfg *messaging.EmailProvider, repl *caddy.Replacer) (*messaging.EmailProvider, error) {
	if cfg == nil {
		return nil, nil
	}

	name, err := resolveRuntimeString(cfg.Name, repl)
	if err != nil {
		return nil, err
	}
	address, err := resolveRuntimeString(cfg.Address, repl)
	if err != nil {
		return nil, err
	}
	protocol, err := resolveRuntimeString(cfg.Protocol, repl)
	if err != nil {
		return nil, err
	}
	credentialsName, err := resolveRuntimeString(cfg.Credentials, repl)
	if err != nil {
		return nil, err
	}
	senderEmail, err := resolveRuntimeString(cfg.SenderEmail, repl)
	if err != nil {
		return nil, err
	}
	senderName, err := resolveRuntimeString(cfg.SenderName, repl)
	if err != nil {
		return nil, err
	}
	templates, err := cloneResolvedStringMap(cfg.Templates, repl)
	if err != nil {
		return nil, err
	}
	bcc, err := cloneResolvedStringSlice(cfg.BlindCarbonCopy, repl)
	if err != nil {
		return nil, err
	}

	return &messaging.EmailProvider{
		Name:            name,
		Address:         address,
		Protocol:        protocol,
		Credentials:     credentialsName,
		SenderEmail:     senderEmail,
		SenderName:      senderName,
		Templates:       templates,
		Passwordless:    cfg.Passwordless,
		BlindCarbonCopy: bcc,
	}, nil
}

func cloneResolvedFileProvider(cfg *messaging.FileProvider, repl *caddy.Replacer) (*messaging.FileProvider, error) {
	if cfg == nil {
		return nil, nil
	}

	name, err := resolveRuntimeString(cfg.Name, repl)
	if err != nil {
		return nil, err
	}
	rootDir, err := resolveRuntimeString(cfg.RootDir, repl)
	if err != nil {
		return nil, err
	}
	templates, err := cloneResolvedStringMap(cfg.Templates, repl)
	if err != nil {
		return nil, err
	}

	return &messaging.FileProvider{
		Name:      name,
		RootDir:   rootDir,
		Templates: templates,
	}, nil
}

func cloneResolvedPortalConfigs(cfgs []*authn.PortalConfig, repl *caddy.Replacer) ([]*authn.PortalConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*authn.PortalConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		clone, err := cloneResolvedPortalConfig(cfg, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, clone)
	}
	return clones, nil
}

func cloneResolvedPortalConfig(cfg *authn.PortalConfig, repl *caddy.Replacer) (*authn.PortalConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	name, err := resolveRuntimeString(cfg.Name, repl)
	if err != nil {
		return nil, err
	}
	uiConfig, err := cloneResolvedUIParameters(cfg.UI, repl)
	if err != nil {
		return nil, err
	}
	transformerConfigs, err := cloneResolvedTransformerConfigs(cfg.UserTransformerConfigs, repl)
	if err != nil {
		return nil, err
	}
	cookieConfig, err := cloneResolvedCookieConfig(cfg.CookieConfig, repl)
	if err != nil {
		return nil, err
	}
	identityStores, err := cloneResolvedStringSlice(cfg.IdentityStores, repl)
	if err != nil {
		return nil, err
	}
	identityProviders, err := cloneResolvedStringSlice(cfg.IdentityProviders, repl)
	if err != nil {
		return nil, err
	}
	ssoProviders, err := cloneResolvedStringSlice(cfg.SingleSignOnProviders, repl)
	if err != nil {
		return nil, err
	}
	userRegistries, err := cloneResolvedStringSlice(cfg.UserRegistries, repl)
	if err != nil {
		return nil, err
	}
	accessListConfigs, err := cloneResolvedRuleConfigurations(cfg.AccessListConfigs, repl)
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
	loginRedirects, err := cloneResolvedRedirectURIMatchConfigs(cfg.TrustedLoginRedirectURIConfigs, repl)
	if err != nil {
		return nil, err
	}
	logoutRedirects, err := cloneResolvedRedirectURIMatchConfigs(cfg.TrustedLogoutRedirectURIConfigs, repl)
	if err != nil {
		return nil, err
	}
	adminRoles, err := cloneResolvedInterfaceMap(cfg.PortalAdminRoles, repl)
	if err != nil {
		return nil, err
	}
	userRoles, err := cloneResolvedInterfaceMap(cfg.PortalUserRoles, repl)
	if err != nil {
		return nil, err
	}
	guestRoles, err := cloneResolvedInterfaceMap(cfg.PortalGuestRoles, repl)
	if err != nil {
		return nil, err
	}
	adminRolePatterns, err := cloneResolvedStringSlice(cfg.PortalAdminRolePatterns, repl)
	if err != nil {
		return nil, err
	}
	userRolePatterns, err := cloneResolvedStringSlice(cfg.PortalUserRolePatterns, repl)
	if err != nil {
		return nil, err
	}
	guestRolePatterns, err := cloneResolvedStringSlice(cfg.PortalGuestRolePatterns, repl)
	if err != nil {
		return nil, err
	}

	return &authn.PortalConfig{
		Name:                            name,
		UI:                              uiConfig,
		UserTransformerConfigs:          transformerConfigs,
		CookieConfig:                    cookieConfig,
		IdentityStores:                  identityStores,
		IdentityProviders:               identityProviders,
		SingleSignOnProviders:           ssoProviders,
		UserRegistries:                  userRegistries,
		AccessListConfigs:               accessListConfigs,
		TokenValidatorOptions:           cloneTokenValidatorOptions(cfg.TokenValidatorOptions),
		CryptoKeyConfigs:                cryptoKeyConfigs,
		CryptoKeyStoreConfig:            cryptoKeyStoreConfig,
		TokenGrantorOptions:             cloneTokenGrantorOptions(cfg.TokenGrantorOptions),
		TrustedLoginRedirectURIConfigs:  loginRedirects,
		TrustedLogoutRedirectURIConfigs: logoutRedirects,
		PortalAdminRoles:                adminRoles,
		PortalUserRoles:                 userRoles,
		PortalGuestRoles:                guestRoles,
		PortalAdminRolePatterns:         adminRolePatterns,
		PortalUserRolePatterns:          userRolePatterns,
		PortalGuestRolePatterns:         guestRolePatterns,
		API:                             cloneAPIConfig(cfg.API),
	}, nil
}

func cloneResolvedUIParameters(cfg *ui.Parameters, repl *caddy.Replacer) (*ui.Parameters, error) {
	if cfg == nil {
		return nil, nil
	}

	theme, err := resolveRuntimeString(cfg.Theme, repl)
	if err != nil {
		return nil, err
	}
	templates, err := cloneResolvedStringMap(cfg.Templates, repl)
	if err != nil {
		return nil, err
	}
	title, err := resolveRuntimeString(cfg.Title, repl)
	if err != nil {
		return nil, err
	}
	logoURL, err := resolveRuntimeString(cfg.LogoURL, repl)
	if err != nil {
		return nil, err
	}
	logoDescription, err := resolveRuntimeString(cfg.LogoDescription, repl)
	if err != nil {
		return nil, err
	}
	metaTitle, err := resolveRuntimeString(cfg.MetaTitle, repl)
	if err != nil {
		return nil, err
	}
	metaDescription, err := resolveRuntimeString(cfg.MetaDescription, repl)
	if err != nil {
		return nil, err
	}
	metaAuthor, err := resolveRuntimeString(cfg.MetaAuthor, repl)
	if err != nil {
		return nil, err
	}
	privateLinks, err := cloneResolvedLinks(cfg.PrivateLinks, repl)
	if err != nil {
		return nil, err
	}
	autoRedirectURL, err := resolveRuntimeString(cfg.AutoRedirectURL, repl)
	if err != nil {
		return nil, err
	}
	realms, err := cloneResolvedUserRealms(cfg.Realms, repl)
	if err != nil {
		return nil, err
	}
	customCSSPath, err := resolveRuntimeString(cfg.CustomCSSPath, repl)
	if err != nil {
		return nil, err
	}
	customJsPath, err := resolveRuntimeString(cfg.CustomJsPath, repl)
	if err != nil {
		return nil, err
	}
	customHTMLHeaderPath, err := resolveRuntimeString(cfg.CustomHTMLHeaderPath, repl)
	if err != nil {
		return nil, err
	}
	staticAssets, err := cloneResolvedStaticAssets(cfg.StaticAssets, repl)
	if err != nil {
		return nil, err
	}
	language, err := resolveRuntimeString(cfg.Language, repl)
	if err != nil {
		return nil, err
	}

	return &ui.Parameters{
		Theme:                   theme,
		Templates:               templates,
		AllowRoleSelection:      cfg.AllowRoleSelection,
		Title:                   title,
		LogoURL:                 logoURL,
		LogoDescription:         logoDescription,
		MetaTitle:               metaTitle,
		MetaDescription:         metaDescription,
		MetaAuthor:              metaAuthor,
		PrivateLinks:            privateLinks,
		AutoRedirectURL:         autoRedirectURL,
		Realms:                  realms,
		PasswordRecoveryEnabled: cfg.PasswordRecoveryEnabled,
		CustomCSSPath:           customCSSPath,
		CustomJsPath:            customJsPath,
		CustomHTMLHeaderPath:    customHTMLHeaderPath,
		StaticAssets:            staticAssets,
		Language:                language,
		DisabledPages:           cloneStringBoolMap(cfg.DisabledPages),
	}, nil
}

func cloneResolvedLinks(cfgs []ui.Link, repl *caddy.Replacer) ([]ui.Link, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]ui.Link, 0, len(cfgs))
	for _, cfg := range cfgs {
		link, err := resolveRuntimeString(cfg.Link, repl)
		if err != nil {
			return nil, err
		}
		title, err := resolveRuntimeString(cfg.Title, repl)
		if err != nil {
			return nil, err
		}
		style, err := resolveRuntimeString(cfg.Style, repl)
		if err != nil {
			return nil, err
		}
		target, err := resolveRuntimeString(cfg.Target, repl)
		if err != nil {
			return nil, err
		}
		iconName, err := resolveRuntimeString(cfg.IconName, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, ui.Link{
			Link:          link,
			Title:         title,
			Style:         style,
			OpenNewWindow: cfg.OpenNewWindow,
			Target:        target,
			TargetEnabled: cfg.TargetEnabled,
			IconName:      iconName,
			IconEnabled:   cfg.IconEnabled,
		})
	}
	return clones, nil
}

func cloneResolvedUserRealms(cfgs []ui.UserRealm, repl *caddy.Replacer) ([]ui.UserRealm, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]ui.UserRealm, 0, len(cfgs))
	for _, cfg := range cfgs {
		name, err := resolveRuntimeString(cfg.Name, repl)
		if err != nil {
			return nil, err
		}
		label, err := resolveRuntimeString(cfg.Label, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, ui.UserRealm{
			Name:  name,
			Label: label,
		})
	}
	return clones, nil
}

func cloneResolvedStaticAssets(cfgs []ui.StaticAsset, repl *caddy.Replacer) ([]ui.StaticAsset, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]ui.StaticAsset, 0, len(cfgs))
	for _, cfg := range cfgs {
		path, err := resolveRuntimeString(cfg.Path, repl)
		if err != nil {
			return nil, err
		}
		fsPath, err := resolveRuntimeString(cfg.FsPath, repl)
		if err != nil {
			return nil, err
		}
		contentType, err := resolveRuntimeString(cfg.ContentType, repl)
		if err != nil {
			return nil, err
		}
		content, err := resolveRuntimeString(cfg.Content, repl)
		if err != nil {
			return nil, err
		}
		encodedContent, err := resolveRuntimeString(cfg.EncodedContent, repl)
		if err != nil {
			return nil, err
		}
		checksum, err := resolveRuntimeString(cfg.Checksum, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, ui.StaticAsset{
			Path:           path,
			FsPath:         fsPath,
			Restricted:     cfg.Restricted,
			ContentType:    contentType,
			Content:        content,
			EncodedContent: encodedContent,
			Checksum:       checksum,
		})
	}
	return clones, nil
}

func cloneResolvedTransformerConfigs(cfgs []*transformer.Config, repl *caddy.Replacer) ([]*transformer.Config, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*transformer.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		matchers, err := cloneResolvedStringSlice(cfg.Matchers, repl)
		if err != nil {
			return nil, err
		}
		actions, err := cloneResolvedStringSlice(cfg.Actions, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &transformer.Config{
			Matchers: matchers,
			Actions:  actions,
		})
	}
	return clones, nil
}

func cloneResolvedCookieConfig(cfg *cookie.Config, repl *caddy.Replacer) (*cookie.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	domains, err := cloneResolvedCookieDomainConfigs(cfg.Domains, repl)
	if err != nil {
		return nil, err
	}
	path, err := resolveRuntimeString(cfg.Path, repl)
	if err != nil {
		return nil, err
	}
	sameSite, err := resolveRuntimeString(cfg.SameSite, repl)
	if err != nil {
		return nil, err
	}

	return &cookie.Config{
		Domains:            domains,
		Path:               path,
		Lifetime:           cfg.Lifetime,
		Insecure:           cfg.Insecure,
		SameSite:           sameSite,
		StripDomainEnabled: cfg.StripDomainEnabled,
		GuessDomainEnabled: cfg.GuessDomainEnabled,
	}, nil
}

func cloneResolvedCookieDomainConfigs(cfgs map[string]*cookie.DomainConfig, repl *caddy.Replacer) (map[string]*cookie.DomainConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make(map[string]*cookie.DomainConfig, len(cfgs))
	for domain, cfg := range cfgs {
		if cfg == nil {
			clones[domain] = nil
			continue
		}
		resolvedDomain, err := resolveRuntimeString(cfg.Domain, repl)
		if err != nil {
			return nil, err
		}
		path, err := resolveRuntimeString(cfg.Path, repl)
		if err != nil {
			return nil, err
		}
		sameSite, err := resolveRuntimeString(cfg.SameSite, repl)
		if err != nil {
			return nil, err
		}
		clones[domain] = &cookie.DomainConfig{
			Seq:                cfg.Seq,
			Domain:             resolvedDomain,
			Path:               path,
			Lifetime:           cfg.Lifetime,
			Insecure:           cfg.Insecure,
			SameSite:           sameSite,
			StripDomainEnabled: cfg.StripDomainEnabled,
		}
	}
	return clones, nil
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

func cloneResolvedIdentityStoreConfigs(cfgs []*ids.IdentityStoreConfig, repl *caddy.Replacer) ([]*ids.IdentityStoreConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*ids.IdentityStoreConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		name, err := resolveRuntimeString(cfg.Name, repl)
		if err != nil {
			return nil, err
		}
		kind, err := resolveRuntimeString(cfg.Kind, repl)
		if err != nil {
			return nil, err
		}
		params, err := cloneResolvedInterfaceMap(cfg.Params, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &ids.IdentityStoreConfig{
			Name:   name,
			Kind:   kind,
			Params: params,
		})
	}
	return clones, nil
}

func cloneResolvedIdentityProviderConfigs(cfgs []*idp.IdentityProviderConfig, repl *caddy.Replacer) ([]*idp.IdentityProviderConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*idp.IdentityProviderConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		name, err := resolveRuntimeString(cfg.Name, repl)
		if err != nil {
			return nil, err
		}
		kind, err := resolveRuntimeString(cfg.Kind, repl)
		if err != nil {
			return nil, err
		}
		params, err := cloneResolvedInterfaceMap(cfg.Params, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &idp.IdentityProviderConfig{
			Name:   name,
			Kind:   kind,
			Params: params,
		})
	}
	return clones, nil
}

func cloneResolvedSingleSignOnProviderConfigs(cfgs []*sso.SingleSignOnProviderConfig, repl *caddy.Replacer) ([]*sso.SingleSignOnProviderConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*sso.SingleSignOnProviderConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		name, err := resolveRuntimeString(cfg.Name, repl)
		if err != nil {
			return nil, err
		}
		driver, err := resolveRuntimeString(cfg.Driver, repl)
		if err != nil {
			return nil, err
		}
		entityID, err := resolveRuntimeString(cfg.EntityID, repl)
		if err != nil {
			return nil, err
		}
		locations, err := cloneResolvedStringSlice(cfg.Locations, repl)
		if err != nil {
			return nil, err
		}
		privateKeyPath, err := resolveRuntimeString(cfg.PrivateKeyPath, repl)
		if err != nil {
			return nil, err
		}
		certPath, err := resolveRuntimeString(cfg.CertPath, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &sso.SingleSignOnProviderConfig{
			Name:           name,
			Driver:         driver,
			EntityID:       entityID,
			Locations:      locations,
			PrivateKeyPath: privateKeyPath,
			CertPath:       certPath,
		})
	}
	return clones, nil
}

func cloneResolvedUserRegistryConfigs(cfgs []*registry.UserRegistryConfig, repl *caddy.Replacer) ([]*registry.UserRegistryConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*registry.UserRegistryConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		name, err := resolveRuntimeString(cfg.Name, repl)
		if err != nil {
			return nil, err
		}
		title, err := resolveRuntimeString(cfg.Title, repl)
		if err != nil {
			return nil, err
		}
		code, err := resolveRuntimeString(cfg.Code, repl)
		if err != nil {
			return nil, err
		}
		dropbox, err := resolveRuntimeString(cfg.Dropbox, repl)
		if err != nil {
			return nil, err
		}
		termsLink, err := resolveRuntimeString(cfg.TermsConditionsLink, repl)
		if err != nil {
			return nil, err
		}
		privacyLink, err := resolveRuntimeString(cfg.PrivacyPolicyLink, repl)
		if err != nil {
			return nil, err
		}
		emailProvider, err := resolveRuntimeString(cfg.EmailProvider, repl)
		if err != nil {
			return nil, err
		}
		adminEmails, err := cloneResolvedStringSlice(cfg.AdminEmails, repl)
		if err != nil {
			return nil, err
		}
		identityStore, err := resolveRuntimeString(cfg.IdentityStore, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &registry.UserRegistryConfig{
			Name:                    name,
			Disabled:                cfg.Disabled,
			Title:                   title,
			Code:                    code,
			Dropbox:                 dropbox,
			RequireAcceptTerms:      cfg.RequireAcceptTerms,
			RequireDomainMailRecord: cfg.RequireDomainMailRecord,
			TermsConditionsLink:     termsLink,
			PrivacyPolicyLink:       privacyLink,
			EmailProvider:           emailProvider,
			AdminEmails:             adminEmails,
			IdentityStore:           identityStore,
		})
	}
	return clones, nil
}

func cloneResolvedRuleConfigurations(cfgs []*acl.RuleConfiguration, repl *caddy.Replacer) ([]*acl.RuleConfiguration, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*acl.RuleConfiguration, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		comment, err := resolveRuntimeString(cfg.Comment, repl)
		if err != nil {
			return nil, err
		}
		conditions, err := cloneResolvedStringSlice(cfg.Conditions, repl)
		if err != nil {
			return nil, err
		}
		action, err := resolveRuntimeString(cfg.Action, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &acl.RuleConfiguration{
			Comment:    comment,
			Conditions: conditions,
			Action:     action,
		})
	}
	return clones, nil
}

func cloneResolvedCryptoKeyConfigs(cfgs []*kms.CryptoKeyConfig, repl *caddy.Replacer) ([]*kms.CryptoKeyConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*kms.CryptoKeyConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		id, err := resolveRuntimeString(cfg.ID, repl)
		if err != nil {
			return nil, err
		}
		usage, err := resolveRuntimeString(cfg.Usage, repl)
		if err != nil {
			return nil, err
		}
		tokenName, err := resolveRuntimeString(cfg.TokenName, repl)
		if err != nil {
			return nil, err
		}
		source, err := resolveRuntimeString(cfg.Source, repl)
		if err != nil {
			return nil, err
		}
		algorithm, err := resolveRuntimeString(cfg.Algorithm, repl)
		if err != nil {
			return nil, err
		}
		envVarName, err := resolveRuntimeString(cfg.EnvVarName, repl)
		if err != nil {
			return nil, err
		}
		envVarType, err := resolveRuntimeString(cfg.EnvVarType, repl)
		if err != nil {
			return nil, err
		}
		envVarValue, err := resolveRuntimeString(cfg.EnvVarValue, repl)
		if err != nil {
			return nil, err
		}
		filePath, err := resolveRuntimeString(cfg.FilePath, repl)
		if err != nil {
			return nil, err
		}
		dirPath, err := resolveRuntimeString(cfg.DirPath, repl)
		if err != nil {
			return nil, err
		}
		secret, err := resolveRuntimeString(cfg.Secret, repl)
		if err != nil {
			return nil, err
		}
		preferredSignMethod, err := resolveRuntimeString(cfg.PreferredSignMethod, repl)
		if err != nil {
			return nil, err
		}
		evalExpr, err := cloneResolvedStringSlice(cfg.EvalExpr, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &kms.CryptoKeyConfig{
			Seq:                 cfg.Seq,
			ID:                  id,
			Usage:               usage,
			TokenName:           tokenName,
			Source:              source,
			Algorithm:           algorithm,
			EnvVarName:          envVarName,
			EnvVarType:          envVarType,
			EnvVarValue:         envVarValue,
			FilePath:            filePath,
			DirPath:             dirPath,
			TokenLifetime:       cfg.TokenLifetime,
			Secret:              secret,
			PreferredSignMethod: preferredSignMethod,
			EvalExpr:            evalExpr,
		})
	}
	return clones, nil
}

func cloneResolvedRedirectURIMatchConfigs(cfgs []*redirects.RedirectURIMatchConfig, repl *caddy.Replacer) ([]*redirects.RedirectURIMatchConfig, error) {
	if len(cfgs) == 0 {
		return nil, nil
	}

	clones := make([]*redirects.RedirectURIMatchConfig, 0, len(cfgs))
	for _, cfg := range cfgs {
		if cfg == nil {
			clones = append(clones, nil)
			continue
		}
		pathMatchType, err := resolveRuntimeString(cfg.PathMatchType, repl)
		if err != nil {
			return nil, err
		}
		path, err := resolveRuntimeString(cfg.Path, repl)
		if err != nil {
			return nil, err
		}
		domainMatchType, err := resolveRuntimeString(cfg.DomainMatchType, repl)
		if err != nil {
			return nil, err
		}
		domain, err := resolveRuntimeString(cfg.Domain, repl)
		if err != nil {
			return nil, err
		}
		clones = append(clones, &redirects.RedirectURIMatchConfig{
			PathMatchType:   pathMatchType,
			Path:            path,
			DomainMatchType: domainMatchType,
			Domain:          domain,
		})
	}
	return clones, nil
}

func cloneTokenValidatorOptions(cfg *options.TokenValidatorOptions) *options.TokenValidatorOptions {
	if cfg == nil {
		return nil
	}
	return &options.TokenValidatorOptions{
		ValidateSourceAddress:       cfg.ValidateSourceAddress,
		ValidateBearerHeader:        cfg.ValidateBearerHeader,
		ValidateMethodPath:          cfg.ValidateMethodPath,
		ValidateAccessListPathClaim: cfg.ValidateAccessListPathClaim,
	}
}

func cloneTokenGrantorOptions(cfg *options.TokenGrantorOptions) *options.TokenGrantorOptions {
	if cfg == nil {
		return nil
	}
	return &options.TokenGrantorOptions{
		EnableSourceAddress: cfg.EnableSourceAddress,
	}
}

func cloneAPIConfig(cfg *authn.APIConfig) *authn.APIConfig {
	if cfg == nil {
		return nil
	}
	return &authn.APIConfig{
		ProfileEnabled: cfg.ProfileEnabled,
		AdminEnabled:   cfg.AdminEnabled,
	}
}

func cloneResolvedStringSlice(values []string, repl *caddy.Replacer) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make([]string, 0, len(values))
	for _, value := range values {
		resolvedValue, err := resolveRuntimeString(value, repl)
		if err != nil {
			return nil, err
		}
		clone = append(clone, resolvedValue)
	}
	return clone, nil
}

func cloneResolvedStringMap(values map[string]string, repl *caddy.Replacer) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make(map[string]string, len(values))
	for key, value := range values {
		resolvedValue, err := resolveRuntimeString(value, repl)
		if err != nil {
			return nil, err
		}
		clone[key] = resolvedValue
	}
	return clone, nil
}

func cloneResolvedInterfaceMap(values map[string]interface{}, repl *caddy.Replacer) (map[string]interface{}, error) {
	if len(values) == 0 {
		return nil, nil
	}

	clone := make(map[string]interface{}, len(values))
	for key, value := range values {
		resolvedValue, err := cloneResolvedDynamicValue(value, repl)
		if err != nil {
			return nil, err
		}
		clone[key] = resolvedValue
	}
	return clone, nil
}

func cloneResolvedDynamicValue(value interface{}, repl *caddy.Replacer) (interface{}, error) {
	switch v := value.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v, nil
	case string:
		return resolveRuntimeString(v, repl)
	case []string:
		return cloneResolvedStringSlice(v, repl)
	case []interface{}:
		clone := make([]interface{}, 0, len(v))
		for _, entry := range v {
			resolvedEntry, err := cloneResolvedDynamicValue(entry, repl)
			if err != nil {
				return nil, err
			}
			clone = append(clone, resolvedEntry)
		}
		return clone, nil
	case []map[string]interface{}:
		clone := make([]map[string]interface{}, 0, len(v))
		for _, entry := range v {
			resolvedEntry, err := cloneResolvedInterfaceMap(entry, repl)
			if err != nil {
				return nil, err
			}
			clone = append(clone, resolvedEntry)
		}
		return clone, nil
	case map[string]interface{}:
		return cloneResolvedInterfaceMap(v, repl)
	default:
		return nil, fmt.Errorf("failed cloning config value of type %T", value)
	}
}

func cloneStringBoolMap(values map[string]bool) map[string]bool {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]bool, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneInterfaceBoolMap(values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]interface{}, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func resolveRuntimeString(s string, repl *caddy.Replacer) (string, error) {
	if !containsPlaceholderCandidate(s) {
		return s, nil
	}

	resolvedString := s
	for {
		nextResolvedString := repl.ReplaceKnown(resolvedString, "")
		if nextResolvedString == resolvedString {
			break
		}
		resolvedString = nextResolvedString
	}

	if unresolvedPlaceholder := findPlaceholderCandidate(resolvedString); unresolvedPlaceholder != "" {
		return "", fmt.Errorf("failed resolving placeholder in %q: unknown placeholder %q", s, unresolvedPlaceholder)
	}

	return resolvedString, nil
}

func containsPlaceholderCandidate(s string) bool {
	return findPlaceholderCandidate(s) != ""
}

func findPlaceholderCandidate(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] != '{' {
			continue
		}
		if i > 0 && s[i-1] == '\\' {
			continue
		}

		end := strings.IndexByte(s[i+1:], '}')
		if end < 0 {
			return ""
		}
		end += i + 1

		candidate := s[i : end+1]
		if len(candidate) > 2 && isPlaceholderNameStart(candidate[1]) {
			return candidate
		}
	}
	return ""
}

func isPlaceholderNameStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}
