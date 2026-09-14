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
	"fmt"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"github.com/greenpau/go-authcrunch/pkg/idp/saml"
	"github.com/greenpau/go-authcrunch/pkg/ids/ldap"
	"github.com/greenpau/go-authcrunch/pkg/ids/local"
)

// validateIdentityParameters checks the JSON shape against the same public
// types AuthCrunch uses. Some dispatch validators ignore decoding errors, which
// can otherwise turn malformed parameters into partially decoded runtime data.
// Leave field allowlists, defaults, and semantic validation to AuthCrunch.
func validateIdentityParameters(kind string, params map[string]any) error {
	var config any
	switch kind {
	case "local":
		config = new(local.Config)
	case "ldap":
		config = new(ldap.Config)
	case "oauth":
		config = new(oauth.Config)
	case "saml":
		config = new(saml.Config)
	default:
		return nil // The dispatcher reports unsupported kinds.
	}
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}
	if cfg, ok := config.(*local.Config); ok {
		return validateConfigSlice("config.users", cfg.Users, func(user *local.User, path string) error {
			return validateConfigSlice(path+".api_keys", user.APIKeys, nil)
		})
	}
	return nil
}

// validateConfigObjects rejects null entries in typed object collections before
// calling AuthCrunch validators or constructors that dereference them. Optional
// object fields remain nullable. Add checks here when upstream introduces new
// component collections; provider parameters are checked separately above.
func validateConfigObjects(cfg *authcrunch.Config) error {
	for _, err := range []error{
		validateConfigSlice("config.identity_stores", cfg.IdentityStores, nil),
		validateConfigSlice("config.identity_providers", cfg.IdentityProviders, nil),
		validateConfigSlice("config.sso_providers", cfg.SingleSignOnProviders, nil),
		validateConfigSlice("config.oauth_applications", cfg.OAuthApplications, nil),
		validateConfigSlice("config.authentication_portals", cfg.AuthenticationPortals, validatePortalConfigObjects),
		validateConfigSlice("config.authorization_policies", cfg.AuthorizationPolicies, validatePolicyConfigObjects),
	} {
		if err != nil {
			return err
		}
	}
	if cfg.Credentials != nil {
		if err := validateConfigSlice("config.credentials.generic", cfg.Credentials.Generic, nil); err != nil {
			return err
		}
	}
	if cfg.Messaging != nil {
		if err := validateConfigSlice("config.messaging.email_providers", cfg.Messaging.EmailProviders, nil); err != nil {
			return err
		}
		if err := validateConfigSlice("config.messaging.file_providers", cfg.Messaging.FileProviders, nil); err != nil {
			return err
		}
	}
	if cfg.UserRegistration != nil {
		return validateConfigSlice("config.user_registration.local_providers", cfg.UserRegistration.LocalProviders, nil)
	}
	return nil
}

func validatePortalConfigObjects(cfg *authn.PortalConfig, path string) error {
	for _, err := range []error{
		validateConfigSlice(path+".user_transformer_configs", cfg.UserTransformerConfigs, nil),
		validateConfigSlice(path+".access_list_configs", cfg.AccessListConfigs, nil),
		validateConfigSlice(path+".trusted_login_redirect_uri_configs", cfg.TrustedLoginRedirectURIConfigs, nil),
		validateConfigSlice(path+".trusted_logout_redirect_uri_configs", cfg.TrustedLogoutRedirectURIConfigs, nil),
	} {
		if err != nil {
			return err
		}
	}
	if cfg.UI != nil {
		for _, err := range []error{
			validateConfigSlice(path+".ui.private_links", cfg.UI.PrivateLinks, nil),
			validateConfigSlice(path+".ui.static_assets", cfg.UI.StaticAssets, nil),
			validateConfigSlice(path+".ui.realms", cfg.UI.Realms, nil),
		} {
			if err != nil {
				return err
			}
		}
	}
	if cfg.CookieConfig != nil {
		if err := validateConfigMap(path+".cookie_config.domains", cfg.CookieConfig.Domains); err != nil {
			return err
		}
	}
	if cfg.OIDCProvider != nil {
		return validateConfigSlice(path+".oidc_provider.clients", cfg.OIDCProvider.Clients, nil)
	}
	return nil
}

func validatePolicyConfigObjects(cfg *authz.PolicyConfig, path string) error {
	for _, err := range []error{
		validateConfigSlice(path+".access_list_rules", cfg.AccessListRules, nil),
		validateConfigSlice(path+".bypass_configs", cfg.BypassConfigs, nil),
		validateConfigSlice(path+".header_injection_configs", cfg.HeaderInjectionConfigs, nil),
	} {
		if err != nil {
			return err
		}
	}
	if cfg.AuthProxyConfig != nil {
		return validateConfigMap(path+".auth_proxy_config.realms", cfg.AuthProxyConfig.Realms)
	}
	return nil
}

func validateConfigSlice[T any](path string, entries []*T, visit func(*T, string) error) error {
	for i, entry := range entries {
		entryPath := fmt.Sprintf("%s[%d]", path, i)
		if entry == nil {
			return fmt.Errorf("%s must not be null", entryPath)
		}
		if visit != nil {
			if err := visit(entry, entryPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateConfigMap[T any](path string, entries map[string]*T) error {
	for key, entry := range entries {
		if entry == nil {
			return fmt.Errorf("%s[%q] must not be null", path, key)
		}
	}
	return nil
}
