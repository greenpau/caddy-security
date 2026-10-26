// Copyright 2026 Paul Greenberg greenpau@outlook.com
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

// Tests explicitly select companions. Production imports the host contracts
// only; operators select modules through xcaddy --with or their own main package.
import (
	claimsstatic "github.com/greenpau/caddy-security/plugins/claims-enrichment-static"
	credentialsconsul "github.com/greenpau/caddy-security/plugins/credential-authenticators-consul"
	credentialssqlite "github.com/greenpau/caddy-security/plugins/credential-authenticators-sqlite"
	signingrsapss "github.com/greenpau/caddy-security/plugins/cryptographic-signing-rsapss"
	externalhttpjson "github.com/greenpau/caddy-security/plugins/external-authorization-httpjson"
	providersconsul "github.com/greenpau/caddy-security/plugins/identity-providers-consul"
	providerssqlite "github.com/greenpau/caddy-security/plugins/identity-providers-sqlite"
	storesconsul "github.com/greenpau/caddy-security/plugins/identity-stores-consul"
	storessqlite "github.com/greenpau/caddy-security/plugins/identity-stores-sqlite"
	messagingsqlite "github.com/greenpau/caddy-security/plugins/messaging-sqlite"
	loginsconsul "github.com/greenpau/caddy-security/plugins/oauth-login-storage-consul"
	loginssqlite "github.com/greenpau/caddy-security/plugins/oauth-login-storage-sqlite"
	registrationsqlite "github.com/greenpau/caddy-security/plugins/registration-workflows-sqlite"
	secretsconsul "github.com/greenpau/caddy-security/plugins/secrets-consul"
	secretssqlite "github.com/greenpau/caddy-security/plugins/secrets-sqlite"
	refreshconsul "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-consul"
	refreshsqlite "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-sqlite"
)

type RSAPSSAccessSigner = signingrsapss.RSAPSSAccessSigner
type rsapssAccessSignerFactory = signingrsapss.Factory
type StaticClaimsEnrichment = claimsstatic.StaticClaimsEnrichment
type ConsulCredentialAuthenticator = credentialsconsul.ConsulCredentialAuthenticator
type SQLiteCredentialAuthenticator = credentialssqlite.SQLiteCredentialAuthenticator
type HTTPJSONExternalAuthorization = externalhttpjson.HTTPJSONExternalAuthorization
type ExternalAuthorizationTLS = externalhttpjson.ExternalAuthorizationTLS
type ConsulTicketIdentityProvider = providersconsul.ConsulTicketIdentityProvider
type SQLiteTicketIdentityProvider = providerssqlite.SQLiteTicketIdentityProvider
type ConsulIdentityStore = storesconsul.ConsulIdentityStore
type SQLiteIdentityStore = storessqlite.SQLiteIdentityStore
type SQLiteMessagingProvider = messagingsqlite.SQLiteMessagingProvider
type ConsulOAuthLoginStore = loginsconsul.ConsulOAuthLoginStore
type SQLiteOAuthLoginStore = loginssqlite.SQLiteOAuthLoginStore
type sqliteOAuthLoginStoreFactory = loginssqlite.Factory
type ConsulRefreshStore = refreshconsul.ConsulRefreshStore
type SQLiteRefreshStore = refreshsqlite.SQLiteRefreshStore
type sqliteRefreshStoreFactory = refreshsqlite.Factory
type SQLiteRegistrationWorkflow = registrationsqlite.SQLiteRegistrationWorkflow
type ConsulSecretsManager = secretsconsul.ConsulSecretsManager
type SQLiteSecretsManager = secretssqlite.SQLiteSecretsManager
