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
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	caddyfileadapter "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/sso"
)

func TestParseCaddyfilePreservesFilePlaceholders(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "google-client-secret.txt")
	if err := os.WriteFile(secretFile, []byte("super-secret-value"), 0600); err != nil {
		t.Fatalf("failed writing secret file: %v", err)
	}

	t.Setenv("GOOGLE_CLIENT_SECRET_FILE", secretFile)

	app, err := parseCaddyfile(caddyfile.NewTestDispenser(`
		security {
			credentials smtp.contoso.com {
				username foo
				password {file.`+secretFile+`}
			}

			oauth identity provider authp {
				realm authp
				driver generic
				client_id foo
				client_secret {file.{$GOOGLE_CLIENT_SECRET_FILE}}
				base_auth_url https://localhost/oauth
				response_type code
				required_token_fields access_token
				authorization_url https://localhost/oauth/authorize
				token_url https://localhost/oauth/access_token
				jwks key 87329db33bf testdata/oauth/87329db33bf_pub.pem
				disable key verification
				disable tls verification
			}

			authentication portal myportal {
				enable identity provider authp
			}
		}`), nil)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	got := unpack(t, string(app.(httpcaddyfile.App).Value))

	creds := got["config"].(map[string]interface{})["credentials"].(map[string]interface{})
	generic := creds["generic"].([]interface{})[0].(map[string]interface{})
	if gotPassword := generic["password"]; gotPassword != fmt.Sprintf("{file.%s}", secretFile) {
		t.Fatalf("unexpected password: got %v", gotPassword)
	}

	providers := got["config"].(map[string]interface{})["identity_providers"].([]interface{})
	params := providers[0].(map[string]interface{})["params"].(map[string]interface{})
	if gotSecret := params["client_secret"]; gotSecret != fmt.Sprintf("{file.%s}", secretFile) {
		t.Fatalf("unexpected client_secret: got %v", gotSecret)
	}
}

func TestCaddyfileAdapterPreservesSecurityPlaceholders(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "google-client-secret.txt")
	if err := os.WriteFile(secretFile, []byte("super-secret-value"), 0600); err != nil {
		t.Fatalf("failed writing secret file: %v", err)
	}

	t.Setenv("GOOGLE_CLIENT_SECRET_FILE", secretFile)

	adapter := caddyfileadapter.Adapter{ServerType: httpcaddyfile.ServerType{}}
	adapted, _, err := adapter.Adapt([]byte(`
		{
			admin off
			security {
				credentials smtp.contoso.com {
					username foo
					password {file.`+secretFile+`}
				}

				oauth identity provider authp {
					realm authp
					driver generic
					client_id foo
					client_secret {file.{$GOOGLE_CLIENT_SECRET_FILE}}
					base_auth_url https://localhost/oauth
					response_type code
					required_token_fields access_token
					authorization_url https://localhost/oauth/authorize
					token_url https://localhost/oauth/access_token
					jwks key 87329db33bf testdata/oauth/87329db33bf_pub.pem
					disable key verification
					disable tls verification
				}

				authentication portal myportal {
					enable identity provider authp
				}
			}
		}

		http://localhost {
			respond "ok"
		}
	`), nil)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	var cfg caddy.Config
	if err := json.Unmarshal(adapted, &cfg); err != nil {
		t.Fatalf("failed unmarshalling adapted config: %v", err)
	}

	var app App
	if err := json.Unmarshal(cfg.AppsRaw["security"], &app); err != nil {
		t.Fatalf("failed unmarshalling security app config: %v", err)
	}

	got := unpack(t, app.Config)
	creds := got["credentials"].(map[string]interface{})["generic"].([]interface{})[0].(map[string]interface{})
	if gotPassword := creds["password"]; gotPassword != fmt.Sprintf("{file.%s}", secretFile) {
		t.Fatalf("unexpected adapted password: got %v", gotPassword)
	}

	providers := got["identity_providers"].([]interface{})
	params := providers[0].(map[string]interface{})["params"].(map[string]interface{})
	if gotSecret := params["client_secret"]; gotSecret != fmt.Sprintf("{file.%s}", secretFile) {
		t.Fatalf("unexpected adapted client_secret: got %v", gotSecret)
	}
}

func TestResolveRuntimeConfig(t *testing.T) {
	secretDir := t.TempDir()
	passwordFile := filepath.Join(secretDir, "smtp-password.txt")
	clientSecretFile := filepath.Join(secretDir, "client-secret.txt")
	tokenSecretFile := filepath.Join(secretDir, "token-secret.txt")
	if err := os.WriteFile(passwordFile, []byte("smtp-password"), 0600); err != nil {
		t.Fatalf("failed writing password file: %v", err)
	}
	if err := os.WriteFile(clientSecretFile, []byte("client-secret"), 0600); err != nil {
		t.Fatalf("failed writing client secret file: %v", err)
	}
	if err := os.WriteFile(tokenSecretFile, []byte("token-secret"), 0600); err != nil {
		t.Fatalf("failed writing token secret file: %v", err)
	}

	t.Setenv("TMP_LOCAL_DB_PATH", filepath.Join(secretDir, "users.json"))

	appConfig, err := loadAppFromCaddyfile(t, `
		security {
			credentials smtp.contoso.com {
				username foo
				password {file.`+passwordFile+`}
			}

			local identity store localdb {
				realm local
				path {env.TMP_LOCAL_DB_PATH}
			}

			oauth identity provider authp {
				realm authp
				driver generic
				client_id foo
				client_secret {file.`+clientSecretFile+`}
				base_auth_url https://localhost/oauth
				response_type code
				required_token_fields access_token
				authorization_url https://localhost/oauth/authorize
				token_url https://localhost/oauth/access_token
				jwks key 87329db33bf testdata/oauth/87329db33bf_pub.pem
				disable key verification
				disable tls verification
			}

			authentication portal myportal {
				crypto key sign-verify {file.`+tokenSecretFile+`}
				enable identity store localdb
				enable identity provider authp
			}
		}`)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	resolvedConfig, err := resolveRuntimeConfig(appConfig.Config)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	original := unpack(t, appConfig.Config)
	resolved := unpack(t, resolvedConfig)

	originalCreds := original["credentials"].(map[string]interface{})["generic"].([]interface{})[0].(map[string]interface{})
	resolvedCreds := resolved["credentials"].(map[string]interface{})["generic"].([]interface{})[0].(map[string]interface{})
	if got := originalCreds["password"]; got != fmt.Sprintf("{file.%s}", passwordFile) {
		t.Fatalf("unexpected original password: got %v", got)
	}
	if got := resolvedCreds["password"]; got != "smtp-password" {
		t.Fatalf("unexpected resolved password: got %v", got)
	}

	originalStore := original["identity_stores"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	resolvedStore := resolved["identity_stores"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	if got := originalStore["path"]; got != "{env.TMP_LOCAL_DB_PATH}" {
		t.Fatalf("unexpected original path: got %v", got)
	}
	if got := resolvedStore["path"]; got != filepath.Join(secretDir, "users.json") {
		t.Fatalf("unexpected resolved path: got %v", got)
	}

	originalProvider := original["identity_providers"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	resolvedProvider := resolved["identity_providers"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	if got := originalProvider["client_secret"]; got != fmt.Sprintf("{file.%s}", clientSecretFile) {
		t.Fatalf("unexpected original client_secret: got %v", got)
	}
	if got := resolvedProvider["client_secret"]; got != "client-secret" {
		t.Fatalf("unexpected resolved client_secret: got %v", got)
	}

	originalPortal := original["authentication_portals"].([]interface{})[0].(map[string]interface{})
	resolvedPortal := resolved["authentication_portals"].([]interface{})[0].(map[string]interface{})
	originalTokenSecret := originalPortal["crypto_key_configs"].([]interface{})[0].(map[string]interface{})["token_secret"]
	resolvedTokenSecret := resolvedPortal["crypto_key_configs"].([]interface{})[0].(map[string]interface{})["token_secret"]
	if got := originalTokenSecret; got != fmt.Sprintf("{file.%s}", tokenSecretFile) {
		t.Fatalf("unexpected original token_secret: got %v", got)
	}
	if got := resolvedTokenSecret; got != "token-secret" {
		t.Fatalf("unexpected resolved token_secret: got %v", got)
	}
}

func TestResolveRuntimeConfigUsesLegacyReplacementSemantics(t *testing.T) {
	appConfig, err := loadAppFromCaddyfile(t, `
			security {
				credentials smtp.contoso.com {
					username foo
					password {unknown.secret}
			}

			local identity store localdb {
				realm local
				path /tmp/localdb
			}

			authentication portal myportal {
				enable identity store localdb
			}
		}`)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	resolvedConfig, err := resolveRuntimeConfig(appConfig.Config)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	resolved := unpack(t, resolvedConfig)
	resolvedCreds := resolved["credentials"].(map[string]interface{})["generic"].([]interface{})[0].(map[string]interface{})
	if got := resolvedCreds["password"]; got != "ERROR_REPLACEMENT" {
		t.Fatalf("unexpected password replacement: got %v", got)
	}
}

func TestResolveRuntimeConfigCoversAdditionalSections(t *testing.T) {
	secretDir := t.TempDir()
	providerSecretFile := filepath.Join(secretDir, "provider-secret.txt")
	policySecretFile := filepath.Join(secretDir, "policy-secret.txt")
	templateFile := filepath.Join(secretDir, "template.html")
	if err := os.WriteFile(providerSecretFile, []byte("provider-secret"), 0600); err != nil {
		t.Fatalf("failed writing provider secret file: %v", err)
	}
	if err := os.WriteFile(policySecretFile, []byte("policy-secret"), 0600); err != nil {
		t.Fatalf("failed writing policy secret file: %v", err)
	}
	if err := os.WriteFile(templateFile, []byte("template-contents"), 0600); err != nil {
		t.Fatalf("failed writing template file: %v", err)
	}

	t.Setenv("SENDER_NAME", "Contoso Auth")
	t.Setenv("ADMIN_EMAIL", "admin@example.com")
	t.Setenv("PORTAL_NAME", "myportal")
	t.Setenv("PORTAL_TITLE", "My Portal")
	t.Setenv("POLICY_NAME", "mypolicy")
	t.Setenv("RULE_COMMENT", "allow admins")
	t.Setenv("AUTH_URL_PATH", "/auth")
	t.Setenv("EXTRA_TOKEN_SOURCE", "query")
	t.Setenv("FORBIDDEN_URL", "https://example.com/forbidden")
	t.Setenv("DB_PATH", filepath.Join(secretDir, "users.json"))
	t.Setenv("USERINFO_ENDPOINT", "https://idp.example.com/userinfo")
	t.Setenv("EXTRA_FIELD", "refresh_token")
	t.Setenv("SSO_NAME", "corp-saml")
	t.Setenv("SSO_DRIVER", "generic")
	t.Setenv("SSO_ENTITY", "urn:contoso:saml")
	t.Setenv("SSO_LOC1", "https://sso.example.com/login")
	t.Setenv("SSO_LOC2", "https://sso.example.com/logout")
	t.Setenv("SSO_KEY", "/etc/caddy/sso.key")
	t.Setenv("SSO_CERT", "/etc/caddy/sso.crt")
	t.Setenv("REGISTRY_NAME", "signup")
	t.Setenv("REGISTRY_TITLE", "Join Us")
	t.Setenv("REGISTRY_DROPBOX", filepath.Join(secretDir, "registration.db"))
	t.Setenv("TERMS_LINK", "https://example.com/terms")
	t.Setenv("PRIVACY_LINK", "https://example.com/privacy")
	t.Setenv("EMAIL_PROVIDER", "mailer")
	t.Setenv("IDENTITY_STORE", "localdb")

	cfg := &authcrunch.Config{
		Messaging: &messaging.Config{
			EmailProviders: []*messaging.EmailProvider{
				{
					Name:            "mailer",
					Address:         "smtp.example.com:587",
					Protocol:        "smtp",
					Credentials:     "smtp-creds",
					SenderEmail:     "noreply@example.com",
					SenderName:      "{env.SENDER_NAME}",
					Templates:       map[string]string{"password_recovery": "{file." + templateFile + "}"},
					BlindCarbonCopy: []string{"{env.ADMIN_EMAIL}"},
				},
			},
		},
		AuthenticationPortals: []*authn.PortalConfig{
			{
				Name: "{env.PORTAL_NAME}",
				UI: &ui.Parameters{
					Title:     "{env.PORTAL_TITLE}",
					Templates: map[string]string{"login": "{file." + templateFile + "}"},
				},
			},
		},
		AuthorizationPolicies: []*authz.PolicyConfig{
			{
				Name:              "{env.POLICY_NAME}",
				AuthURLPath:       "{env.AUTH_URL_PATH}",
				AllowedTokenSources: []string{"header", "{env.EXTRA_TOKEN_SOURCE}"},
				ForbiddenURL:      "{env.FORBIDDEN_URL}",
				AccessListRules: []*acl.RuleConfiguration{
					{
						Comment:    "{env.RULE_COMMENT}",
						Conditions: []string{"match role authp/admin"},
						Action:     "allow stop",
					},
				},
				AuthProxyConfig: &authproxy.Config{
					PortalName: "{env.PORTAL_NAME}",
					BasicAuth: authproxy.BasicAuthConfig{
						Enabled: true,
						Realms: map[string]interface{}{
							"local": true,
						},
					},
				},
				CryptoKeyStoreConfig: map[string]interface{}{
					"token_secret": "{file." + policySecretFile + "}",
				},
			},
		},
		IdentityStores: []*ids.IdentityStoreConfig{
			{
				Name: "localdb",
				Kind: "local",
				Params: map[string]interface{}{
					"path":          "{env.DB_PATH}",
					"support_email": "{env.ADMIN_EMAIL}",
				},
			},
		},
		IdentityProviders: []*idp.IdentityProviderConfig{
			{
				Name: "authp",
				Kind: "generic",
				Params: map[string]interface{}{
					"client_secret":         "{file." + providerSecretFile + "}",
					"user_info_url":         "{env.USERINFO_ENDPOINT}",
					"required_token_fields": []interface{}{"access_token", "{env.EXTRA_FIELD}"},
				},
			},
		},
		SingleSignOnProviders: []*sso.SingleSignOnProviderConfig{
			{
				Name:           "{env.SSO_NAME}",
				Driver:         "{env.SSO_DRIVER}",
				EntityID:       "{env.SSO_ENTITY}",
				Locations:      []string{"{env.SSO_LOC1}", "{env.SSO_LOC2}"},
				PrivateKeyPath: "{env.SSO_KEY}",
				CertPath:       "{env.SSO_CERT}",
			},
		},
		UserRegistries: []*registry.UserRegistryConfig{
			{
				Name:                "{env.REGISTRY_NAME}",
				Title:               "{env.REGISTRY_TITLE}",
				Dropbox:             "{env.REGISTRY_DROPBOX}",
				TermsConditionsLink: "{env.TERMS_LINK}",
				PrivacyPolicyLink:   "{env.PRIVACY_LINK}",
				EmailProvider:       "{env.EMAIL_PROVIDER}",
				AdminEmails:         []string{"{env.ADMIN_EMAIL}"},
				IdentityStore:       "{env.IDENTITY_STORE}",
			},
		},
	}

	resolvedConfig, err := resolveRuntimeConfig(cfg)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	original := unpack(t, cfg)
	resolved := unpack(t, resolvedConfig)

	originalMessaging := original["messaging"].(map[string]interface{})["email_providers"].([]interface{})[0].(map[string]interface{})
	resolvedMessaging := resolved["messaging"].(map[string]interface{})["email_providers"].([]interface{})[0].(map[string]interface{})
	if got := originalMessaging["sender_name"]; got != "{env.SENDER_NAME}" {
		t.Fatalf("unexpected original sender_name: got %v", got)
	}
	if got := resolvedMessaging["sender_name"]; got != "Contoso Auth" {
		t.Fatalf("unexpected resolved sender_name: got %v", got)
	}
	if got := resolvedMessaging["templates"].(map[string]interface{})["password_recovery"]; got != "template-contents" {
		t.Fatalf("unexpected resolved messaging template: got %v", got)
	}

	originalPortal := original["authentication_portals"].([]interface{})[0].(map[string]interface{})
	resolvedPortal := resolved["authentication_portals"].([]interface{})[0].(map[string]interface{})
	if got := originalPortal["name"]; got != "{env.PORTAL_NAME}" {
		t.Fatalf("unexpected original portal name: got %v", got)
	}
	if got := resolvedPortal["name"]; got != "myportal" {
		t.Fatalf("unexpected resolved portal name: got %v", got)
	}
	if got := resolvedPortal["ui"].(map[string]interface{})["templates"].(map[string]interface{})["login"]; got != "template-contents" {
		t.Fatalf("unexpected resolved portal template: got %v", got)
	}

	originalPolicy := original["authorization_policies"].([]interface{})[0].(map[string]interface{})
	resolvedPolicy := resolved["authorization_policies"].([]interface{})[0].(map[string]interface{})
	if got := originalPolicy["auth_proxy_config"].(map[string]interface{})["portal_name"]; got != "{env.PORTAL_NAME}" {
		t.Fatalf("unexpected original auth proxy portal name: got %v", got)
	}
	if got := resolvedPolicy["auth_proxy_config"].(map[string]interface{})["portal_name"]; got != "myportal" {
		t.Fatalf("unexpected resolved auth proxy portal name: got %v", got)
	}
	if got := resolvedPolicy["crypto_key_store_config"].(map[string]interface{})["token_secret"]; got != "policy-secret" {
		t.Fatalf("unexpected resolved policy token secret: got %v", got)
	}

	originalStore := original["identity_stores"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	resolvedStore := resolved["identity_stores"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	if got := originalStore["path"]; got != "{env.DB_PATH}" {
		t.Fatalf("unexpected original identity store path: got %v", got)
	}
	if got := resolvedStore["path"]; got != filepath.Join(secretDir, "users.json") {
		t.Fatalf("unexpected resolved identity store path: got %v", got)
	}

	originalProvider := original["identity_providers"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	resolvedProvider := resolved["identity_providers"].([]interface{})[0].(map[string]interface{})["params"].(map[string]interface{})
	if got := originalProvider["client_secret"]; got != fmt.Sprintf("{file.%s}", providerSecretFile) {
		t.Fatalf("unexpected original provider client_secret: got %v", got)
	}
	if got := resolvedProvider["client_secret"]; got != "provider-secret" {
		t.Fatalf("unexpected resolved provider client_secret: got %v", got)
	}
	if got := resolvedProvider["required_token_fields"].([]interface{})[1]; got != "refresh_token" {
		t.Fatalf("unexpected resolved provider token field: got %v", got)
	}

	originalSSO := original["sso_providers"].([]interface{})[0].(map[string]interface{})
	resolvedSSO := resolved["sso_providers"].([]interface{})[0].(map[string]interface{})
	if got := originalSSO["name"]; got != "{env.SSO_NAME}" {
		t.Fatalf("unexpected original sso name: got %v", got)
	}
	if got := resolvedSSO["name"]; got != "corp-saml" {
		t.Fatalf("unexpected resolved sso name: got %v", got)
	}

	originalRegistry := original["user_registries"].([]interface{})[0].(map[string]interface{})
	resolvedRegistry := resolved["user_registries"].([]interface{})[0].(map[string]interface{})
	if got := originalRegistry["admin_emails"].([]interface{})[0]; got != "{env.ADMIN_EMAIL}" {
		t.Fatalf("unexpected original admin email: got %v", got)
	}
	if got := resolvedRegistry["admin_emails"].([]interface{})[0]; got != "admin@example.com" {
		t.Fatalf("unexpected resolved admin email: got %v", got)
	}
}

func loadAppFromCaddyfile(t *testing.T, input string) (*App, error) {
	t.Helper()

	app, err := parseCaddyfile(caddyfile.NewTestDispenser(input), nil)
	if err != nil {
		return nil, err
	}

	var parsedApp App
	if err := json.Unmarshal(app.(httpcaddyfile.App).Value, &parsedApp); err != nil {
		return nil, err
	}

	return &parsedApp, nil
}
