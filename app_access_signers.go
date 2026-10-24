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
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

// AccessSignerBackendModule prepares an immutable factory without loading keys
// or acquiring resources. Module cleanup never owns returned signer handles.
type AccessSignerBackendModule interface {
	PrepareAccessSigner() (AccessSignerFactory, error)
}

// AccessSignerFactory freezes copied configuration and core metadata. Every
// constructor call transfers a fresh signer to the app; later module mutations
// cannot change it. A failed constructor returns a safely closable partial
// handle, or real nil after unwinding acquisition. The context applies to setup,
// not runtime lifetime. Optional io.Closer ownership belongs solely to the app.
type AccessSignerFactory interface {
	AccessSignerConfig() (kms.ExternalAccessSignerConfig, error)
	NewAccessSigner(context.Context) (kms.AccessSigner, error)
}

type preparedAccessSigner struct {
	config  kms.ExternalAccessSignerConfig
	factory AccessSignerFactory
}

func prepareAccessSignerFactory(module AccessSignerBackendModule) (factory AccessSignerFactory, err error) {
	defer func() {
		if recover() != nil {
			factory = nil
			err = fmt.Errorf("access signer preparation failed")
		}
	}()
	factory, err = module.PrepareAccessSigner()
	if err != nil || factory == nil {
		return nil, fmt.Errorf("access signer preparation failed")
	}
	return factory, nil
}

func readAccessSignerConfig(factory AccessSignerFactory) (config kms.ExternalAccessSignerConfig, err error) {
	defer func() {
		if recover() != nil {
			config = kms.ExternalAccessSignerConfig{}
			err = fmt.Errorf("access signer metadata is unavailable")
		}
	}()
	if factory == nil {
		return config, fmt.Errorf("access signer metadata is unavailable")
	}
	config, err = factory.AccessSignerConfig()
	if err != nil || config.Validate() != nil {
		return kms.ExternalAccessSignerConfig{}, fmt.Errorf("access signer metadata is invalid")
	}
	return config, nil
}

// prepareAccessSigners checks every selected reference before any constructor.
// Root descriptors are derived only on the app's private resolved config.
func (app *App) prepareAccessSigners(ctx caddy.Context, config *authcrunch.Config) error {
	if config == nil || len(config.ExternalAccessSigners) != 0 {
		return fmt.Errorf("external access signer descriptors are derived from security access signer modules")
	}
	loader := &App{AccessSignerConfigs: make([]json.RawMessage, len(app.AccessSignerConfigs))}
	for i, raw := range app.AccessSignerConfigs {
		if !utf8.Valid(raw) {
			return fmt.Errorf("access signer module configuration is invalid")
		}
		loader.AccessSignerConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "AccessSignerConfigs")
	if err != nil {
		return fmt.Errorf("access signer module configuration failed")
	}
	seen := make(map[string]bool)
	var prepared []preparedAccessSigner
	var descriptors []*kms.ExternalAccessSignerConfig
	for i, entry := range loaded.([]any) {
		module, ok := entry.(AccessSignerBackendModule)
		if !ok {
			return fmt.Errorf("access signer %d has an incompatible module interface", i)
		}
		factory, err := prepareAccessSignerFactory(module)
		if err != nil {
			return fmt.Errorf("access signer %d preparation failed", i)
		}
		descriptor, err := readAccessSignerConfig(factory)
		if err != nil || seen[descriptor.Name] {
			return fmt.Errorf("access signer %d requires valid unique metadata", i)
		}
		seen[descriptor.Name] = true
		prepared = append(prepared, preparedAccessSigner{config: descriptor, factory: factory})
		copy := descriptor
		descriptors = append(descriptors, &copy)
	}
	for i, portal := range config.AuthenticationPortals {
		if portal == nil || portal.AccessSigner != "" && !seen[portal.AccessSigner] {
			return fmt.Errorf("portal %d requires a valid declared access signer", i)
		}
	}
	config.ExternalAccessSigners = descriptors
	app.accessSigners = prepared
	app.pluginContext = ctx
	return nil
}

func accessSignerMetadataMatches(signer kms.AccessSigner, config kms.ExternalAccessSignerConfig) error {
	if kms.ValidateAccessSignerBinding(&kms.AccessSignerBinding{Config: &config, Signer: signer}) != nil {
		return fmt.Errorf("access signer runtime metadata does not match its declaration")
	}
	return nil
}

// attachAccessSigners transfers exact dynamic instances and every acquired
// closer, even on failure. Root owns key/profile checks; it only borrows handles.
func (app *App) attachAccessSigners(ctx context.Context) (map[string]kms.AccessSigner, []io.Closer, error) {
	signers := make(map[string]kms.AccessSigner, len(app.accessSigners))
	var closers []io.Closer
	for i, binding := range app.accessSigners {
		signer, err := binding.factory.NewAccessSigner(ctx)
		if closer, ok := signer.(io.Closer); ok {
			closers = append(closers, accessSignerOwnedCloser{closer: closer})
		}
		if err != nil || signer == nil {
			return nil, closers, fmt.Errorf("access signer %d construction failed", i)
		}
		if accessSignerMetadataMatches(signer, binding.config) != nil {
			return nil, closers, fmt.Errorf("access signer %d has invalid runtime metadata", i)
		}
		signers[binding.config.Name] = signer
	}
	return signers, closers, nil
}

type accessSignerOwnedCloser struct{ closer io.Closer }

func (c accessSignerOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("access signer cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("access signer cleanup failed")
	}
	return nil
}
