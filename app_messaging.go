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
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	messagingsqlite "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
)

// MessagingProviderBackendModule validates configuration without opening storage.
// Each factory call transfers a fresh provider and optional io.Closer to the app.
// On failure, return a closable partial result or unwind before returning nil.
// Module Cleanup must not close returned providers. The constructor context only
// bounds setup; the app owns worker cancellation separately from Caddy cleanup.
type MessagingProviderBackendModule interface {
	MessagingProviderName() (string, error)
	NewMessagingProvider(context.Context) (messaging.Provider, error)
}

type preparedMessagingProvider struct {
	name        string
	module      MessagingProviderBackendModule
	delivery    *messaging.EmailProvider
	credentials *credentials.GenericCredential
}

// prepareMessagingProviders rejects binding errors before any queue is opened.
func (app *App) prepareMessagingProviders(ctx caddy.Context, config *authcrunch.Config) error {
	if len(app.MessagingProviderConfigs) == 0 {
		return nil
	}
	if config.Messaging == nil {
		config.Messaging = &messaging.Config{}
	}
	providers := config.Messaging
	if len(providers.RawConfigs)+len(providers.EmailProviders)+len(providers.FileProviders) != 0 {
		if err := providers.Validate(); err != nil {
			return fmt.Errorf("messaging transport configuration failed")
		}
	}
	loader := &App{MessagingProviderConfigs: make([]json.RawMessage, len(app.MessagingProviderConfigs))}
	for i, raw := range app.MessagingProviderConfigs {
		loader.MessagingProviderConfigs[i] = slices.Clone(raw)
	}
	loaded, err := ctx.LoadModule(loader, "MessagingProviderConfigs")
	if err != nil {
		return fmt.Errorf("messaging provider module configuration failed")
	}
	seen := make(map[string]bool)
	for i, entry := range loaded.([]any) {
		module, ok := entry.(MessagingProviderBackendModule)
		if !ok {
			return fmt.Errorf("messaging provider %d has an incompatible module interface", i)
		}
		name, err := module.MessagingProviderName()
		if err != nil || name == "" || len(name) > 128 || !utf8.ValidString(name) || strings.TrimSpace(name) != name || strings.ContainsFunc(name, unicode.IsControl) || seen[name] || providers.FindProvider(name) {
			return fmt.Errorf("messaging provider %d requires a valid unique name", i)
		}
		seen[name] = true
		binding := preparedMessagingProvider{name: name, module: module}
		if sqlite, ok := module.(*SQLiteMessagingProvider); ok && sqlite.Delivery != "" {
			provider := providers.ExtractEmailProvider(sqlite.Delivery)
			if provider == nil {
				return fmt.Errorf("messaging provider %d delivery must select an email provider", i)
			}
			binding.delivery = provider
			if !provider.Passwordless {
				// Native credential lists can be supplied without raw instructions.
				// Require exactly one valid match; do not silently select duplicates.
				if config.Credentials != nil {
					for _, cred := range config.Credentials.Generic {
						if cred == nil || cred.Name != provider.Credentials {
							continue
						}
						if binding.credentials != nil || cred.Validate() != nil {
							return fmt.Errorf("messaging provider %d delivery credentials are invalid", i)
						}
						copy := *cred
						binding.credentials = &copy
					}
				}
				if binding.credentials == nil {
					return fmt.Errorf("messaging provider %d delivery credentials are missing", i)
				}
			}
		}
		app.messagingProviders = append(app.messagingProviders, binding)
	}
	app.pluginContext = ctx
	return nil
}

func (app *App) attachMessagingProviders(ctx context.Context, config *authcrunch.Config) ([]io.Closer, []*sqliteMessagingWorker, error) {
	var closers []io.Closer
	var workers []*sqliteMessagingWorker
	for i, binding := range app.messagingProviders {
		provider, err := binding.module.NewMessagingProvider(ctx)
		if closer, ok := provider.(io.Closer); ok {
			closers = append(closers, messagingOwnedCloser{closer})
		}
		if err != nil || bindMessagingProvider(config.Messaging, binding.name, provider) != nil {
			return closers, nil, fmt.Errorf("messaging provider %d construction failed", i)
		}
		if binding.delivery != nil {
			queue, ok := provider.(*messagingsqlite.Outbox)
			if !ok || queue == nil {
				return closers, nil, fmt.Errorf("messaging provider %d has no SQLite delivery queue", i)
			}
			workers = append(workers, &sqliteMessagingWorker{queue: queue, send: binding.delivery.SendContext, credentials: binding.credentials, logger: app.logger})
		}
	}
	if len(app.messagingProviders) != 0 {
		if err := validateMessagingBindings(config.Messaging); err != nil {
			return closers, nil, fmt.Errorf("messaging runtime binding validation failed")
		}
	}
	return closers, workers, nil
}

// Confine recovery to plugin validation: a typed nil provider may panic through
// promoted methods. Such a broken factory must not abort candidate unwinding.
func bindMessagingProvider(config *messaging.Config, name string, provider messaging.Provider) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid messaging provider")
		}
	}()
	return config.AddProvider(name, provider)
}

// Config validation calls plugin Validate methods again. Keep this second
// plugin boundary contained too, so partial candidate resources can unwind.
func validateMessagingBindings(config *messaging.Config) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("invalid messaging provider")
		}
	}()
	return config.Validate()
}

type messagingOwnedCloser struct{ closer io.Closer }

func (c messagingOwnedCloser) Close() (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("messaging provider cleanup failed")
		}
	}()
	if c.closer.Close() != nil {
		return fmt.Errorf("messaging provider cleanup failed")
	}
	return nil
}
