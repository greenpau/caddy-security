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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/greenpau/go-authcrunch/pkg/oidc"
	oidcparser "github.com/greenpau/go-authcrunch/pkg/oidc/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/spf13/cobra"
)

// Register separate actions under the reusable security command namespace.
// Each leaf exposes only the flags its operation accepts.
func addSecurityProvisioningCommands(parent *cobra.Command) {
	oauth := &cobra.Command{Use: "oauth", Short: "Manage OAuth applications, client credentials, and provisioning storage"}
	oauthInit := &cobra.Command{Use: "init", Short: "Initialize private OAuth provisioning storage"}
	oauthProvisioning := &cobra.Command{Use: "provisioning", Short: "Initialize storage for OAuth client credentials and OIDC provider keys"}
	oauthInit.AddCommand(oauthProvisioning)
	oauthCreate := &cobra.Command{Use: "create", Short: "Create OAuth applications"}
	oauthRotate := &cobra.Command{Use: "rotate", Short: "Rotate OAuth client credentials"}
	oauth.AddCommand(oauthInit, oauthCreate, oauthRotate)
	oidc := &cobra.Command{Use: "oidc", Short: "Manage OIDC provider signing keys"}
	oidcCreate := &cobra.Command{Use: "create", Short: "Create OIDC provider resources"}
	oidcSigning := &cobra.Command{Use: "signing", Short: "Create OIDC provider signing keys"}
	oidc.AddCommand(oidcCreate)
	oidcCreate.AddCommand(oidcSigning)
	parent.AddCommand(oauth, oidc)
	for _, group := range []*cobra.Command{parent, oauth, oauthInit, oauthProvisioning, oauthCreate, oauthRotate, oidc, oidcCreate, oidcSigning} {
		// Bypass Cobra's legacy root argument error, which echoes user input.
		group.Args = cobra.ArbitraryArgs
		group.RunE = cmdSecurityGroup
	}

	for _, action := range []struct {
		parent                       *cobra.Command
		name, operation, short, long string
	}{
		{oauthProvisioning, "store", "init", "Create a private store for OAuth client credentials and OIDC provider signing keys", "Create the private directory used to persist OAuth application registrations (client IDs and secrets) and OIDC provider signing keys. The parent directory must already exist and be trusted. The private input file must contain only an oauth registration store block. Existing paths are refused."},
		{oauthCreate, "application", "create", "Create and save a named OAuth application and its client credentials", "Create the first registration for an OAuth application, generating omitted client credentials. The private input file must contain the oauth registration store and the selected oauth application block. Existing registrations are refused."},
		{oauthRotate, "secret", "rotate", "Save a new OAuth client secret while preserving the client ID", "Create a new registration revision using an explicit different client_secret from the private input file and the client ID from --from. Selecting token_endpoint_auth_method none deliberately removes the secret for a public client. Retain the previous revision for recovery and select the new revision in Caddy configuration to activate it."},
		{oidcSigning, "key", "key", "Create and save a dedicated OIDC provider RSA signing key", "Create a dedicated RSA signing key for the provider identified by --name. The private input file must contain only an oauth registration store block. Select the new key file in the provider configuration to activate it; existing key revisions are refused."},
	} {
		cmd := &cobra.Command{
			Use:   action.name,
			Short: action.short,
			Long:  action.long + "\n\nThe input file must be owner-only (0600) in a private directory (0700). Imports and environment expansion are unsupported. Success prints the resulting path; credentials remain in private files. Creating a revision does not change the running configuration.",
			RunE: caddycmd.WrapCommandFuncForCobra(func(flags caddycmd.Flags) (int, error) {
				return cmdSecurityProvision(flags, action.operation)
			}),
		}
		cmd.Flags().String("config", "", "Private provisioning Caddyfile (required)")
		if action.operation != "init" {
			nameHelp := "OAuth application nickname (required)"
			if action.operation == "key" {
				nameHelp = "OIDC provider name (required)"
			}
			cmd.Flags().String("name", "", nameHelp)
			cmd.Flags().String("revision", "", "New immutable revision (required)")
		}
		if action.operation == "rotate" {
			cmd.Flags().String("from", "", "Previous application revision (required)")
		}
		action.parent.AddCommand(cmd)
	}
}

type provisioningInput struct {
	store        *OAuthRegistrationStoreConfig
	applications map[string][]string
}

// A deliberately separate parser entry point: ordinary Caddy adaptation never
// invokes credential constructors, accepts creation modes, or publishes files.
func parseProvisioningInput(filename string, data []byte) (*provisioningInput, error) {
	// Tokenization replaces malformed UTF-8; reject it before credentials or
	// storage identities can silently change their bytes.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("invalid provisioning file UTF-8")
	}
	tokens, err := caddyfile.Tokenize(data, filename)
	if err != nil {
		return nil, fmt.Errorf("invalid provisioning file syntax")
	}
	d := caddyfile.NewDispenser(tokens)
	input := &provisioningInput{applications: make(map[string][]string)}
	for d.Next() {
		if d.Val() != "oauth" || !d.NextArg() {
			return nil, fmt.Errorf("expected oauth application or oauth registration store declaration")
		}
		kind := d.Val()
		d.Prev()
		switch kind {
		case "registration":
			if input.store != nil {
				return nil, fmt.Errorf("duplicate oauth registration store")
			}
			input.store, err = parseCaddyfileOAuthRegistrationStore(d)
			if err != nil {
				return nil, err
			}
		case "application":
			header, body, err := readOAuthApplication(d)
			if err != nil {
				return nil, err
			}
			if _, exists := input.applications[header[2]]; exists {
				return nil, fmt.Errorf("duplicate provisioning application")
			}
			input.applications[header[2]] = body
		default:
			return nil, fmt.Errorf("unsupported provisioning declaration")
		}
	}
	if err := input.store.validate(); err != nil {
		return nil, err
	}
	return input, nil
}

func cmdSecurityProvision(flags caddycmd.Flags, operation string) (int, error) {
	if flags.NArg() != 0 {
		return 1, fmt.Errorf("security provisioning commands accept named flags only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	filename := flags.String("config")
	if filename == "" {
		return 1, fmt.Errorf("a private provisioning config is required")
	}
	// Input may contain an explicit rotation secret; check it like a record.
	// Abs cleans .. components, which could otherwise change the requested file
	// before symlink checks. Relative paths remain supported when already clean.
	if filepath.Clean(filename) != filename {
		return 1, fmt.Errorf("provisioning config requires a clean file path")
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return 1, fmt.Errorf("a private provisioning config is required")
	}
	if err := checkRegistrationDirectory(ctx, filepath.Dir(abs), true); err != nil {
		return 1, err
	}
	root, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return 1, err
	}
	defer root.Close()
	data, err := (&oauthRegistrationStore{root: root}).read(ctx, filepath.Base(abs))
	if err != nil {
		return 1, err
	}
	input, err := parseProvisioningInput(abs, data)
	if err != nil {
		return 1, err
	}
	var name, revision, from string
	if operation != "init" {
		name, revision = flags.String("name"), flags.String("revision")
	}
	if operation == "rotate" {
		from = flags.String("from")
	}
	path, err := provisionRegistration(ctx, input, operation, name, revision, from)
	if err != nil {
		return 1, err
	}
	if _, err := fmt.Fprintln(os.Stdout, path); err != nil {
		// Publication is already durable. Preserve it for deliberate recovery;
		// a failed path handoff must not look like a successful command.
		return 1, fmt.Errorf("provisioning completed; cannot write result path: %w", err)
	}
	return 0, nil
}

func provisionRegistration(ctx context.Context, input *provisioningInput, operation, name, revision, from string) (string, error) {
	if input == nil {
		return "", fmt.Errorf("missing provisioning input")
	}
	if operation == "init" {
		if name != "" || revision != "" || from != "" || len(input.applications) != 0 {
			return "", fmt.Errorf("init accepts only an oauth registration store")
		}
		if err := input.store.initialize(ctx); err != nil {
			return "", err
		}
		return input.store.Path, nil
	}
	if operation != "create" && operation != "rotate" && operation != "key" {
		return "", fmt.Errorf("expected init, create, rotate, or key operation")
	}
	if operation != "rotate" && from != "" {
		return "", fmt.Errorf("only rotate accepts a previous revision")
	}
	kind := "application"
	if operation == "key" {
		kind = "key"
	}
	filename, err := registrationFilename(kind, name, revision)
	if err != nil {
		return "", err
	}
	store, err := input.store.open(ctx)
	if err != nil {
		return "", err
	}
	defer store.root.Close()
	unlock, err := store.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	if _, err := store.root.Lstat(filename); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			return "", fmt.Errorf("registration revision exists: %w", fs.ErrExist)
		}
		return "", fmt.Errorf("inspect registration revision: %w", err)
	}
	if operation == "create" {
		// Nicknames are hashed and revisions cannot contain glob characters.
		prefix := filename[:len(filename)-len(revision)-len(".json")]
		dir, err := store.root.Open(".")
		if err != nil {
			return "", fmt.Errorf("inspect existing registrations: %w", err)
		}
		records, err := dir.ReadDir(-1)
		dir.Close()
		if err != nil {
			return "", fmt.Errorf("inspect existing registrations: %w", err)
		}
		for _, record := range records {
			if strings.HasPrefix(record.Name(), prefix) && strings.HasSuffix(record.Name(), ".json") {
				return "", fmt.Errorf("application already exists; use rotate: %w", fs.ErrExist)
			}
		}
	}
	var data []byte
	if operation == "key" {
		if len(input.applications) != 0 {
			return "", fmt.Errorf("key accepts only an oauth registration store")
		}
		// Provider-owned, independent of any application and access-token keys.
		data, err = oidc.GenerateSigningKey()
	} else {
		body, exists := input.applications[name]
		if !exists || len(input.applications) != 1 {
			return "", fmt.Errorf("provisioning requires exactly the selected application")
		}
		var application *oidc.OAuthApplicationConfig
		if operation == "create" {
			var client *oidc.ClientConfig
			client, err = oidcparser.NewOIDCClientConfigFromDirectives(name, body)
			if err == nil {
				application, err = oidc.NewOAuthApplicationConfig(name, client)
			}
		} else {
			var previous *oidc.OAuthApplicationConfig
			previous, err = store.application(ctx, name, from)
			if err != nil {
				return "", err
			}
			application, err = oidcparser.NewOAuthApplicationConfigFromDirectives(encodeOAuthDirective([]string{"oauth", "application", name}), body, previous)
			if err == nil {
				if application.Client.ClientID != previous.Client.ClientID {
					return "", fmt.Errorf("rotation must retain the client ID")
				}
				explicitSecret := false
				for _, statement := range body {
					args, _ := cfgutil.DecodeArgs(statement)
					if len(args) > 0 && args[0] == "client_secret" {
						explicitSecret = true
					}
				}
				if application.Client.TokenEndpointAuthMethod != "none" && (!explicitSecret || application.Client.ClientSecret == previous.Client.ClientSecret) {
					return "", fmt.Errorf("rotation requires an explicit different client_secret")
				}
				if application.Client.TokenEndpointAuthMethod == "none" && previous.Client.TokenEndpointAuthMethod == "none" {
					return "", fmt.Errorf("public client has no secret to rotate")
				}
			}
		}
		if err == nil {
			data, err = json.Marshal(application)
		}
	}
	if err != nil {
		return "", err
	}
	if err := store.publish(ctx, filename, func(f *os.File) error { _, err := f.Write(data); return err }); err != nil {
		return "", err
	}
	return filepath.Join(input.store.Path, filename), nil
}
