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
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func accessSignerTestModuleConfig(path string) *RSAPSSAccessSigner {
	return &RSAPSSAccessSigner{Name: "primary", KeyFile: path, KeyID: "current", Issuer: "https://auth.example.test/auth", Audience: "service-a"}
}

func accessSignerTestFactory(t *testing.T, module *RSAPSSAccessSigner) *rsapssAccessSignerFactory {
	t.Helper()
	factory, err := module.PrepareAccessSigner()
	if err != nil {
		t.Fatal("cannot prepare access signer fixture")
	}
	result, ok := factory.(*rsapssAccessSignerFactory)
	if !ok || result == nil {
		t.Fatal("access signer lost immutable factory")
	}
	return result
}

func TestRSAPSSAccessSignerPreparation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "key.pem")
	module := accessSignerTestModuleConfig(path)
	before, _ := json.Marshal(module)
	if module.Validate() != nil {
		t.Fatal("pure signer validation rejected valid configuration")
	}
	factory := accessSignerTestFactory(t, module)
	descriptor, err := factory.AccessSignerConfig()
	if err != nil || descriptor.Validate() != nil || descriptor.Name != "primary" || descriptor.Kind != "rsapss" || descriptor.Policy.Algorithm != "PS256" || descriptor.Policy.TokenType != "authcrunch-access+jwt" || descriptor.Policy.MaxLifetimeSeconds != 900 {
		t.Fatal("invalid normalized signer descriptor")
	}
	if factory.signingConfig().MaxLifetime != "15m0s" {
		t.Fatal("signer duration was not normalized")
	}
	for _, duration := range []string{"", "15m", "900s", "900000ms"} {
		copy := *module
		copy.MaxLifetime = duration
		next := accessSignerTestFactory(t, &copy)
		metadata, _ := next.AccessSignerConfig()
		if metadata != descriptor || copy.MaxLifetime != duration {
			t.Fatal("equivalent duration changed binding or input")
		}
	}
	renamed := *module
	renamed.Name = "other"
	renamedDescriptor, _ := accessSignerTestFactory(t, &renamed).AccessSignerConfig()
	if renamedDescriptor.ConfigDigest != descriptor.ConfigDigest || renamedDescriptor.Name == descriptor.Name {
		t.Fatal("root-assigned name changed backend digest")
	}
	for _, change := range []func(*RSAPSSAccessSigner){func(m *RSAPSSAccessSigner) { m.KeyFile += "-other" }, func(m *RSAPSSAccessSigner) { m.KeyID = "retiring" }, func(m *RSAPSSAccessSigner) { m.Issuer += "/other" }, func(m *RSAPSSAccessSigner) { m.Audience = "other" }, func(m *RSAPSSAccessSigner) { m.MaxLifetime = "10m" }} {
		copy := *module
		change(&copy)
		metadata, _ := accessSignerTestFactory(t, &copy).AccessSignerConfig()
		if metadata.ConfigDigest == descriptor.ConfigDigest {
			t.Fatal("material signer configuration did not change digest")
		}
	}
	copy := factory.signingConfig()
	copy.KeyFile = "mutated"
	descriptor.Policy.Issuer = "mutated"
	next, _ := factory.AccessSignerConfig()
	if factory.signingConfig().KeyFile != path || next.Policy.Issuer == "mutated" {
		t.Fatal("factory exposed mutable configuration")
	}
	after, _ := json.Marshal(module)
	if !bytes.Equal(before, after) {
		t.Fatal("validation mutated native declaration")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("pure preparation opened key storage")
	}
}

func TestRSAPSSAccessSignerInvalidConfiguration(t *testing.T) {
	for name, change := range map[string]func(*RSAPSSAccessSigner){
		"empty_name": func(m *RSAPSSAccessSigner) { m.Name = "" }, "padded_name": func(m *RSAPSSAccessSigner) { m.Name = " primary" }, "long_name": func(m *RSAPSSAccessSigner) { m.Name = strings.Repeat("a", 129) }, "utf8_name": func(m *RSAPSSAccessSigner) { m.Name = "a\xff" },
		"empty_path": func(m *RSAPSSAccessSigner) { m.KeyFile = "" }, "padded_path": func(m *RSAPSSAccessSigner) { m.KeyFile += " " }, "control_path": func(m *RSAPSSAccessSigner) { m.KeyFile += "\nprivate-signer-diagnostic" },
		"bad_kid": func(m *RSAPSSAccessSigner) { m.KeyID = "bad kid" }, "wrong_algorithm": func(m *RSAPSSAccessSigner) { m.Algorithm = "RS256" }, "empty_issuer": func(m *RSAPSSAccessSigner) { m.Issuer = "" }, "empty_audience": func(m *RSAPSSAccessSigner) { m.Audience = "" }, "short_lifetime": func(m *RSAPSSAccessSigner) { m.MaxLifetime = "500ms" }, "fraction_lifetime": func(m *RSAPSSAccessSigner) { m.MaxLifetime = "1.5s" }, "long_lifetime": func(m *RSAPSSAccessSigner) { m.MaxLifetime = "25h" }, "runtime_lifetime": func(m *RSAPSSAccessSigner) { m.MaxLifetime = "{env.PRIVATE}" },
	} {
		t.Run(name, func(t *testing.T) {
			module := accessSignerTestModuleConfig(filepath.Join(t.TempDir(), "absent", "key.pem"))
			change(module)
			err := module.Validate()
			if err == nil || strings.Contains(err.Error(), "private-signer-diagnostic") {
				t.Fatal("invalid signer configuration accepted or disclosed")
			}
		})
	}
	var nilModule *RSAPSSAccessSigner
	if nilModule.Validate() == nil {
		t.Fatal("nil signer declaration accepted")
	}
	for _, path := range []string{"relative.pem", "/private/{env.LITERAL_KEY}.pem"} {
		if accessSignerTestModuleConfig(path).Validate() != nil {
			t.Fatal("host changed public literal path semantics")
		}
	}
}

func TestRSAPSSAccessSignerFrozenRuntime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("cannot generate fixture key")
	}
	if os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600) != nil {
		t.Fatal("cannot write fixture key")
	}
	module := accessSignerTestModuleConfig(path)
	raw, _ := json.Marshal(struct {
		Driver string `json:"driver"`
		*RSAPSSAccessSigner
	}{"rsapss", module})
	app := &App{AccessSignerConfigs: []json.RawMessage{raw}}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	loaded, err := ctx.LoadModule(app, "AccessSignerConfigs")
	if err != nil {
		cancel()
		t.Fatal("cannot load signer module")
	}
	factory := accessSignerTestFactory(t, loaded.([]any)[0].(*RSAPSSAccessSigner))
	exported := loaded.([]any)[0].(*RSAPSSAccessSigner)
	exported.KeyFile = filepath.Join(dir, "missing.pem")
	exported.KeyID = "changed"
	exported.Issuer = "changed"
	setup, stopSetup := context.WithCancel(t.Context())
	signer, err := factory.NewAccessSigner(setup)
	if err != nil {
		cancel()
		t.Fatal("cannot construct frozen signer")
	}
	stopSetup()
	cancel()
	metadata, err := signer.Metadata()
	descriptor, _ := factory.AccessSignerConfig()
	if err != nil || metadata.ConfigDigest != descriptor.ConfigDigest || metadata.Policy != descriptor.Policy {
		t.Fatal("runtime metadata differs from frozen factory")
	}
	now := time.Now().Unix()
	claims := map[string]any{"iss": descriptor.Policy.Issuer, "aud": descriptor.Policy.Audience, "sub": "alice", "iat": now, "nbf": now, "exp": now + 60}
	token, err := signer.Sign(t.Context(), claims)
	if err != nil {
		t.Fatal("module or setup cleanup disposed signer runtime")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("signer returned malformed token")
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	var fields map[string]any
	if err != nil || json.Unmarshal(header, &fields) != nil || fields["alg"] != "PS256" || fields["kid"] != "current" || fields["typ"] != "authcrunch-access+jwt" {
		t.Fatal("signer lost strict access header")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}) != nil {
		t.Fatal("returned access token failed independent PS256 verification")
	}
	second, err := factory.NewAccessSigner(t.Context())
	if err != nil || second == signer {
		t.Fatal("factory reused runtime instance")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if value, err := factory.NewAccessSigner(canceled); err == nil || value != nil {
		t.Fatal("canceled setup published signer")
	}
}

func TestRSAPSSAccessSignerConstructionFailure(t *testing.T) {
	factory := accessSignerTestFactory(t, accessSignerTestModuleConfig(filepath.Join(t.TempDir(), "missing-private-key.pem")))
	if signer, err := factory.NewAccessSigner(t.Context()); err == nil || signer != nil || strings.Contains(err.Error(), "missing-private-key") {
		t.Fatal("failed constructor disclosed private path or returned runtime")
	}
	var absent *rsapssAccessSignerFactory
	if _, err := absent.AccessSignerConfig(); err == nil {
		t.Fatal("nil factory exposed descriptor")
	}
	if signer, err := absent.NewAccessSigner(t.Context()); err == nil || signer != nil {
		t.Fatal("nil factory constructed signer")
	}
}

func TestRSAPSSAccessSignerNativeConfiguration(t *testing.T) {
	for _, raw := range []string{`null`, `{"driver":"absent"}`, `{"driver":"rsapss","name":"primary","key_file":false}`, `{"driver":"rsapss","unknown":"private-signer-diagnostic"}`} {
		ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
		app := &App{AccessSignerConfigs: []json.RawMessage{json.RawMessage(raw)}}
		if _, err := ctx.LoadModule(app, "AccessSignerConfigs"); err == nil {
			cancel()
			t.Fatal("invalid native signer module accepted")
		}
		cancel()
	}
}
