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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/backends"
	"github.com/greenpau/go-authcrunch/pkg/errors"
)

func parseCaddyfileAuthPortalBackendShortcuts(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, ckp string, v []string) error {
	if len(v) == 0 {
		return errors.ErrConfigDirectiveShort.WithArgs(ckp, v)
	}
	if v[len(v)-1] == "disabled" {
		return nil
	}
	m := make(map[string]interface{})
	switch v[0] {
	case "local":
		if len(v) != 3 {
			return errors.ErrMalformedDirective.WithArgs(ckp, v)
		}
		m["name"] = fmt.Sprintf("local_backend_%d", len(portal.BackendConfigs))
		m["method"] = "local"
		m["path"] = v[1]
		m["realm"] = v[2]
	case "google":
		if len(v) != 3 {
			return errors.ErrMalformedDirective.WithArgs(ckp, v)
		}
		m["name"] = fmt.Sprintf("google_backend_%d", len(portal.BackendConfigs))
		m["method"] = "oauth2"
		m["realm"] = "google"
		m["provider"] = "google"
		m["client_id"] = v[1]
		m["client_secret"] = v[2]
		m["scopes"] = []string{"openid", "email", "profile"}
	case "github":
		if len(v) != 3 {
			return errors.ErrMalformedDirective.WithArgs(ckp, v)
		}
		m["name"] = fmt.Sprintf("github_backend_%d", len(portal.BackendConfigs))
		m["method"] = "oauth2"
		m["realm"] = "github"
		m["provider"] = "github"
		m["client_id"] = v[1]
		m["client_secret"] = v[2]
		m["scopes"] = []string{"read:user"}
	case "facebook":
		if len(v) != 3 {
			return errors.ErrMalformedDirective.WithArgs(ckp, v)
		}
		m["name"] = fmt.Sprintf("facebook_backend_%d", len(portal.BackendConfigs))
		m["method"] = "oauth2"
		m["realm"] = "facebook"
		m["provider"] = "facebook"
		m["client_id"] = v[1]
		m["client_secret"] = v[2]
		m["scopes"] = []string{"email"}
	default:
		return errors.ErrConfigDirectiveValueUnsupported.WithArgs(ckp, v)
	}

	backendConfig, err := backends.NewConfig(m)
	if err != nil {
		return errors.ErrConfigDirectiveFail.WithArgs(ckp, v, err)
	}
	portal.BackendConfigs = append(portal.BackendConfigs, *backendConfig)
	return nil
}
