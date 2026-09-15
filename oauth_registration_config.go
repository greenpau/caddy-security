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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

// OAuthApplicationSource retains current policy and an immutable credential
// reference. Stored ID/secret values are never serialized into host config.
type OAuthApplicationSource struct {
	Name       string   `json:"name"`
	Revision   string   `json:"revision"`
	Directives []string `json:"directives"`
	Digest     string   `json:"digest"`
}

func applicationSource(header, body []string) (*OAuthApplicationSource, []string, error) {
	source := &OAuthApplicationSource{Name: header[2]}
	var directives []string
	for _, statement := range body {
		args, err := cfgutil.DecodeArgs(statement)
		if err != nil || len(args) == 0 {
			return nil, nil, fmt.Errorf("invalid application statement")
		}
		if args[0] == "registration" {
			if source.Revision != "" || len(args) != 2 {
				return nil, nil, fmt.Errorf("registration requires one revision and occurs once")
			}
			source.Revision = args[1]
			if _, err := registrationFilename("application", source.Name, source.Revision); err != nil {
				return nil, nil, err
			}
		} else {
			directives = append(directives, statement)
		}
	}
	source.Directives = directives
	return source, directives, nil
}

func (source *OAuthApplicationSource) load(ctx context.Context, store *oauthRegistrationStore) (*oidc.OAuthApplicationConfig, error) {
	if source == nil {
		return nil, fmt.Errorf("nil application source")
	}
	previous, err := store.application(ctx, source.Name, source.Revision)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(previous)
	if err != nil {
		return nil, fmt.Errorf("cannot fingerprint stored registration")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if source.Digest != "" && source.Digest != digest {
		return nil, fmt.Errorf("stored registration changed since adaptation")
	}
	source.Digest = digest
	application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(encodeOAuthDirective([]string{"oauth", "application", source.Name}), source.Directives, previous)
	if err != nil {
		return nil, err
	}
	// An explicit credential change is a rotation, and must already be durable.
	// Policy fields deliberately remain owned by the current declaration.
	if application.Client.ClientID != previous.Client.ClientID || application.Client.ClientSecret != previous.Client.ClientSecret || (application.Client.TokenEndpointAuthMethod == "none") != (previous.Client.TokenEndpointAuthMethod == "none") {
		return nil, fmt.Errorf("application credentials differ from stored revision; provision and select a new revision")
	}
	return application, nil
}

func (app *App) addOAuthApplication(ctx context.Context, header, body []string) error {
	source, directives, err := applicationSource(header, body)
	if err != nil {
		return err
	}
	if source.Revision == "" {
		application, err := oidcparser.NewOAuthApplicationConfigFromDirectives(encodeOAuthDirective(header), directives, nil)
		if err != nil {
			return err
		}
		return app.Config.AddOAuthApplication(application)
	}
	store, err := app.OAuthRegistrationStore.open(ctx)
	if err != nil {
		return err
	}
	defer store.root.Close()
	application, err := source.load(ctx, store)
	if err != nil {
		return err
	}
	if err := app.Config.AddOAuthApplication(application); err != nil {
		return err
	}
	// Explicit credentials were checked against this immutable record. Omit them
	// from serialized directives too, including an explicitly supplied client ID.
	source.Directives = nil
	for _, statement := range directives {
		args, _ := cfgutil.DecodeArgs(statement)
		if args[0] != "client_id" && args[0] != "client_secret" {
			source.Directives = append(source.Directives, statement)
		}
	}
	app.OAuthApplicationSources = append(app.OAuthApplicationSources, source)
	return nil
}

func (app *App) resolveOAuthRegistrationConfig(ctx context.Context, cfg *authcrunch.Config) error {
	if app.OAuthRegistrationStore != nil {
		store, err := app.OAuthRegistrationStore.open(ctx)
		if err != nil {
			return err
		}
		defer store.root.Close()
		for _, source := range app.OAuthApplicationSources {
			if source == nil || source.Digest == "" {
				return fmt.Errorf("application source requires a registration digest")
			}
			copy := *source
			application, err := copy.load(ctx, store)
			if err != nil {
				return err
			}
			if err := cfg.AddOAuthApplication(application); err != nil {
				return err
			}
		}
	} else if len(app.OAuthApplicationSources) != 0 {
		return fmt.Errorf("application sources require an oauth registration store")
	}
	for name, directives := range app.OIDCProviderDirectives {
		found := false
		for _, portal := range cfg.AuthenticationPortals {
			if portal != nil && portal.Name == name {
				if err := cfg.ConfigureOIDCProvider(portal, directives); err != nil {
					return err
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("OIDC provider references an unknown portal")
		}
	}
	return validateOIDCProviderKeyFiles(ctx, cfg)
}

// Enforce private provider keys for both Caddyfile directives and native JSON.
// Check the completed runtime config before any provider can open its keys.
func validateOIDCProviderKeyFiles(ctx context.Context, cfg *authcrunch.Config) error {
	for _, portal := range cfg.AuthenticationPortals {
		if portal == nil || portal.OIDCProvider == nil || !portal.OIDCProvider.Enabled {
			continue
		}
		for _, path := range portal.OIDCProvider.SigningKeyFiles {
			// Dir/Base clean paths lexically, while AuthCrunch opens the original
			// string. Reject traversal before either operation so a symlink
			// followed by .. cannot select a different key.
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return fmt.Errorf("OIDC provider key requires a clean absolute file path")
			}
			keyStore := &OAuthRegistrationStoreConfig{Path: filepath.Dir(path)}
			store, err := keyStore.open(ctx)
			if err != nil {
				return fmt.Errorf("OIDC provider key storage: %w", err)
			}
			_, err = store.read(ctx, filepath.Base(path))
			store.root.Close()
			if err != nil {
				return fmt.Errorf("OIDC provider key: %w", err)
			}
		}
	}
	return nil
}

// Caddy retains the declarative JSON for autosave and admin configuration views.
// Remove transient stored credentials and their copied provider snapshots.
func (app *App) omitStoredOAuthRegistrationSnapshots() {
	managed := make(map[string]bool)
	for _, source := range app.OAuthApplicationSources {
		managed[source.Name] = true
	}
	var explicit []*oidc.OAuthApplicationConfig
	for _, application := range app.Config.OAuthApplications {
		if !managed[application.Name] {
			explicit = append(explicit, application)
		}
	}
	app.Config.OAuthApplications = explicit
	for _, portal := range app.Config.AuthenticationPortals {
		if _, ok := app.OIDCProviderDirectives[portal.Name]; ok {
			portal.OIDCProvider = nil
		}
	}
}
