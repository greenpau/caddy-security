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

package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/greenpau/caddy-security"
	_ "github.com/greenpau/caddy-security/plugins/claims-enrichment-static"
	_ "github.com/greenpau/caddy-security/plugins/credential-authenticators-consul"
	_ "github.com/greenpau/caddy-security/plugins/credential-authenticators-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/cryptographic-signing-rsapss"
	_ "github.com/greenpau/caddy-security/plugins/external-authorization-httpjson"
	_ "github.com/greenpau/caddy-security/plugins/identity-providers-consul"
	_ "github.com/greenpau/caddy-security/plugins/identity-providers-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/identity-stores-consul"
	_ "github.com/greenpau/caddy-security/plugins/identity-stores-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/messaging-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/oauth-login-storage-consul"
	_ "github.com/greenpau/caddy-security/plugins/oauth-login-storage-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/registration-workflows-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/secrets-consul"
	_ "github.com/greenpau/caddy-security/plugins/secrets-sqlite"
	_ "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-consul"
	_ "github.com/greenpau/caddy-security/plugins/session-and-refresh-storage-sqlite"
	_ "github.com/greenpau/caddy-trace"
)

func main() { caddycmd.Main() }
