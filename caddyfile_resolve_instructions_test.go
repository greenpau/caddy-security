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
	"fmt"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/greenpau/go-authcrunch"
	"go.uber.org/zap"
)

const lifecycleInstructionValue = "synthetic \"quoted\" value with spaces\nand a newline"

// This test module returns only synthetic data and never exposes it in GetConfig.
type lifecycleSecrets struct{}

func (*lifecycleSecrets) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.secrets.security_lifecycle", New: func() caddy.Module { return new(lifecycleSecrets) }}
}

func (*lifecycleSecrets) GetConfig(context.Context) map[string]any {
	return map[string]any{"id": "lifecycle"}
}

func (*lifecycleSecrets) GetSecret(context.Context) (map[string]any, error) {
	return map[string]any{"input": lifecycleInstructionValue}, nil
}

func (*lifecycleSecrets) GetSecretByKey(_ context.Context, key string) (any, error) {
	if key != "input" {
		return nil, fmt.Errorf("unknown test secret key %q", key)
	}
	return lifecycleInstructionValue, nil
}

func init() { caddy.RegisterModule(&lifecycleSecrets{}) }

func lifecycleInstructionsConfig(reference string) *authcrunch.Config {
	cfg := lifecycleConfig()
	cfg.AddCredential([]string{"name mail", "username alice", "password " + reference})
	cfg.AddMessagingProvider([]string{"name mail", "kind email", "address 127.0.0.1:1", "protocol smtp", "credentials mail", "sender alice@example.test " + reference})
	cfg.UserRegistration.RawConfigs[0] = append(cfg.UserRegistration.RawConfigs[0], "title "+reference, "email provider mail")
	return cfg
}

func assertLifecycleInstructions(t *testing.T, cfg *authcrunch.Config) {
	t.Helper()
	if cfg.Credentials == nil || len(cfg.Credentials.Generic) != 1 || cfg.Credentials.Generic[0].Password != lifecycleInstructionValue {
		t.Fatal("credential replacement changed the password or left a reference unresolved")
	}
	if cfg.Messaging == nil || len(cfg.Messaging.EmailProviders) != 1 || cfg.Messaging.EmailProviders[0].SenderName != lifecycleInstructionValue {
		t.Fatal("messaging replacement changed the sender name or left a reference unresolved")
	}
	if cfg.UserRegistration == nil || len(cfg.UserRegistration.LocalProviders) != 1 || cfg.UserRegistration.LocalProviders[0].Title != lifecycleInstructionValue {
		t.Fatal("registration replacement changed the title or left a reference unresolved")
	}
}

func TestResolveRuntimeAppConfigEncodedInstructions(t *testing.T) {
	t.Setenv("CADDY_SECURITY_INSTRUCTION_VALUE", lifecycleInstructionValue)
	for _, tc := range []struct{ name, reference string }{
		{"environment", "{env.CADDY_SECURITY_INSTRUCTION_VALUE}"},
		{"secret", "secrets:lifecycle:input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lifecycleInstructionsConfig(tc.reference)
			if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&lifecycleSecrets{}}, cfg, zap.NewNop()); err != nil {
				t.Fatal(err)
			}
			assertLifecycleInstructions(t, cfg)
		})
	}
	cfg := lifecycleInstructionsConfig("secrets:lifecycle:missing")
	if err := ResolveRuntimeAppConfig(t.Context(), caddy.NewReplacer(), []SecretsManager{&lifecycleSecrets{}}, cfg, zap.NewNop()); err == nil || !strings.Contains(err.Error(), "RawCredentialConfigs[0][2]") {
		t.Fatalf("missing raw credential secret accepted: %v", err)
	}
}
