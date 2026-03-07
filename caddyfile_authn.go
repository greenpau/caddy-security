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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/redirects"
)

const (
	authnPrefix = "security.authentication"
)

// parseCaddyfileAuthentication parses authentication configuration.
//
// Syntax:
//
//	  authentication portal <name> {
//
//		crypto key sign-verify <shared_secret>
//
//		ui {
//			template <login|portal> <file_path>
//			logo_url <file_path|url_path>
//			logo_description <value>
//			custom css path <path>
//			custom js path <path>
//			custom html header path <path>
//			static_asset <uri> <content_type> <path>
//			allow settings for role <role>
//		}
//
//	    cookie domain <name>
//	    cookie path <name>
//	    cookie lifetime <seconds>
//	    cookie samesite <lax|strict|none>
//	    cookie insecure <on|off>
//
//	    validate source address
//
//	    enable source ip tracking
//	    enable admin api
//	    enable identity store <name>
//	    enable identity provider <name>
//	    enable sso provider <name>
//	    enable user registration <name>
//
//		trust [login|logout] redirect uri domain [exact|partial|prefix|suffix|regex] <domain_name> path [exact|partial|prefix|suffix|regex] <path>
//
//	}
func parseCaddyfileAuthentication(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	// rootDirective is config key prefix.
	var rootDirective string
	backendHelpURL := "https://github.com/greenpau/caddy-security/issues/83"
	args := d.RemainingArgs()
	if len(args) != 2 {
		return d.ArgErr()
	}
	switch args[0] {
	case "portal":
		p := &authn.PortalConfig{
			Name: args[1],
			UI: &ui.Parameters{
				Templates: make(map[string]string),
			},
			CookieConfig:          &cookie.Config{},
			TokenValidatorOptions: &options.TokenValidatorOptions{},
			TokenGrantorOptions:   &options.TokenGrantorOptions{},
			API: &authn.APIConfig{
				ProfileEnabled: true,
			},
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := d.RemainingArgs()
			rootDirective = mkcp(authnPrefix, args[0], k)
			switch k {
			case "crypto":
				if err := parseCaddyfileAuthPortalCrypto(d, p, rootDirective, v); err != nil {
					return err
				}
			case "cookie":
				if err := parseCaddyfileAuthPortalCookie(d, p, rootDirective, v); err != nil {
					return err
				}
			case "backend", "backends":
				return fmt.Errorf("The backend directive is no longer supported. Please see %s for details", backendHelpURL)
			case "ui":
				if err := parseCaddyfileAuthPortalUI(d, p, rootDirective); err != nil {
					return err
				}
			case "transform":
				if err := parseCaddyfileAuthPortalTransform(d, p, rootDirective, v); err != nil {
					return err
				}
			case "enable", "validate", "trust":
				if err := parseCaddyfileAuthPortalMisc(d, p, rootDirective, k, v); err != nil {
					return err
				}
			default:
				return errors.ErrMalformedDirective.WithArgs(rootDirective, v)
			}
		}

		if err := cfg.AddAuthenticationPortal(p); err != nil {
			return err
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(authnPrefix, args)
	}
	return nil
}

func mkcp(parts ...string) string {
	return strings.Join(parts, ".")
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

	name := util.FindReplace(repl, cfg.Name)
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
	identityStores := util.FindReplaceAll(repl, cfg.IdentityStores)
	identityProviders := util.FindReplaceAll(repl, cfg.IdentityProviders)
	ssoProviders := util.FindReplaceAll(repl, cfg.SingleSignOnProviders)
	userRegistries := util.FindReplaceAll(repl, cfg.UserRegistries)
	accessListConfigs, err := cloneResolvedRuleConfigurations(cfg.AccessListConfigs, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyConfigs, err := cloneResolvedCryptoKeyConfigs(cfg.CryptoKeyConfigs, repl)
	if err != nil {
		return nil, err
	}
	cryptoKeyStoreConfig := cloneInterfaceMap(cfg.CryptoKeyStoreConfig, repl)
	loginRedirects, err := cloneResolvedRedirectURIMatchConfigs(cfg.TrustedLoginRedirectURIConfigs, repl)
	if err != nil {
		return nil, err
	}
	logoutRedirects, err := cloneResolvedRedirectURIMatchConfigs(cfg.TrustedLogoutRedirectURIConfigs, repl)
	if err != nil {
		return nil, err
	}
	adminRoles := cloneInterfaceMap(cfg.PortalAdminRoles, repl)
	userRoles := cloneInterfaceMap(cfg.PortalUserRoles, repl)
	guestRoles := cloneInterfaceMap(cfg.PortalGuestRoles, repl)
	adminRolePatterns := util.FindReplaceAll(repl, cfg.PortalAdminRolePatterns)
	userRolePatterns := util.FindReplaceAll(repl, cfg.PortalUserRolePatterns)
	guestRolePatterns := util.FindReplaceAll(repl, cfg.PortalGuestRolePatterns)

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

	theme := util.FindReplace(repl, cfg.Theme)
	templates := cloneReplacedStringMap(cfg.Templates, repl)
	title := util.FindReplace(repl, cfg.Title)
	logoURL := util.FindReplace(repl, cfg.LogoURL)
	logoDescription := util.FindReplace(repl, cfg.LogoDescription)
	metaTitle := util.FindReplace(repl, cfg.MetaTitle)
	metaDescription := util.FindReplace(repl, cfg.MetaDescription)
	metaAuthor := util.FindReplace(repl, cfg.MetaAuthor)
	privateLinks, err := cloneResolvedLinks(cfg.PrivateLinks, repl)
	if err != nil {
		return nil, err
	}
	autoRedirectURL := util.FindReplace(repl, cfg.AutoRedirectURL)
	realms, err := cloneResolvedUserRealms(cfg.Realms, repl)
	if err != nil {
		return nil, err
	}
	customCSSPath := util.FindReplace(repl, cfg.CustomCSSPath)
	customJsPath := util.FindReplace(repl, cfg.CustomJsPath)
	customHTMLHeaderPath := util.FindReplace(repl, cfg.CustomHTMLHeaderPath)
	staticAssets, err := cloneResolvedStaticAssets(cfg.StaticAssets, repl)
	if err != nil {
		return nil, err
	}
	language := util.FindReplace(repl, cfg.Language)

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
		clones = append(clones, ui.Link{
			Link:          util.FindReplace(repl, cfg.Link),
			Title:         util.FindReplace(repl, cfg.Title),
			Style:         util.FindReplace(repl, cfg.Style),
			OpenNewWindow: cfg.OpenNewWindow,
			Target:        util.FindReplace(repl, cfg.Target),
			TargetEnabled: cfg.TargetEnabled,
			IconName:      util.FindReplace(repl, cfg.IconName),
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
		clones = append(clones, ui.UserRealm{
			Name:  util.FindReplace(repl, cfg.Name),
			Label: util.FindReplace(repl, cfg.Label),
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
		clones = append(clones, ui.StaticAsset{
			Path:           util.FindReplace(repl, cfg.Path),
			FsPath:         util.FindReplace(repl, cfg.FsPath),
			Restricted:     cfg.Restricted,
			ContentType:    util.FindReplace(repl, cfg.ContentType),
			Content:        util.FindReplace(repl, cfg.Content),
			EncodedContent: util.FindReplace(repl, cfg.EncodedContent),
			Checksum:       util.FindReplace(repl, cfg.Checksum),
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
		matchers := util.FindReplaceAll(repl, cfg.Matchers)
		actions := util.FindReplaceAll(repl, cfg.Actions)
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
	path := util.FindReplace(repl, cfg.Path)
	sameSite := util.FindReplace(repl, cfg.SameSite)

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
		resolvedDomain := util.FindReplace(repl, cfg.Domain)
		path := util.FindReplace(repl, cfg.Path)
		sameSite := util.FindReplace(repl, cfg.SameSite)
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
		id := util.FindReplace(repl, cfg.ID)
		usage := util.FindReplace(repl, cfg.Usage)
		tokenName := util.FindReplace(repl, cfg.TokenName)
		source := util.FindReplace(repl, cfg.Source)
		algorithm := util.FindReplace(repl, cfg.Algorithm)
		envVarName := util.FindReplace(repl, cfg.EnvVarName)
		envVarType := util.FindReplace(repl, cfg.EnvVarType)
		envVarValue := util.FindReplace(repl, cfg.EnvVarValue)
		filePath := util.FindReplace(repl, cfg.FilePath)
		dirPath := util.FindReplace(repl, cfg.DirPath)
		secret := util.FindReplace(repl, cfg.Secret)
		preferredSignMethod := util.FindReplace(repl, cfg.PreferredSignMethod)
		evalExpr := util.FindReplaceAll(repl, cfg.EvalExpr)
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
		pathMatchType := util.FindReplace(repl, cfg.PathMatchType)
		path := util.FindReplace(repl, cfg.Path)
		domainMatchType := util.FindReplace(repl, cfg.DomainMatchType)
		domain := util.FindReplace(repl, cfg.Domain)
		clones = append(clones, &redirects.RedirectURIMatchConfig{
			PathMatchType:   pathMatchType,
			Path:            path,
			DomainMatchType: domainMatchType,
			Domain:          domain,
		})
	}
	return clones, nil
}

func cloneInterfaceMap(values map[string]interface{}, repl *caddy.Replacer) map[string]interface{} {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]interface{}, len(values))
	for key, value := range values {
		clone[key] = cloneInterfaceValue(value, repl)
	}
	return clone
}

func cloneInterfaceValue(value interface{}, repl *caddy.Replacer) interface{} {
	switch v := value.(type) {
	case string:
		return util.FindReplace(repl, v)
	case []string:
		return util.FindReplaceAll(repl, v)
	case []interface{}:
		clone := make([]interface{}, 0, len(v))
		for _, entry := range v {
			clone = append(clone, cloneInterfaceValue(entry, repl))
		}
		return clone
	case []map[string]interface{}:
		clone := make([]map[string]interface{}, 0, len(v))
		for _, entry := range v {
			clone = append(clone, cloneInterfaceMap(entry, repl))
		}
		return clone
	case map[string]interface{}:
		return cloneInterfaceMap(v, repl)
	default:
		return v
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

func cloneReplacedStringMap(values map[string]string, repl *caddy.Replacer) map[string]string {
	if len(values) == 0 {
		return nil
	}

	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = util.FindReplace(repl, value)
	}
	return clone
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
