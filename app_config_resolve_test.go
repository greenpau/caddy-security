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

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
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
