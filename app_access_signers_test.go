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
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/kms"
)

const accessSignerPrivateDiagnostic = "private-signer-diagnostic"

type accessSignerMockModule struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Failure string `json:"failure,omitempty"`
	probe   *accessSignerMockProbe
}
type accessSignerMockProbe struct {
	module               *accessSignerMockModule
	constructed, cleaned int
	instances            []*accessSignerMockRuntime
	closes               []string
}

var accessSignerMockProbes sync.Map

func (accessSignerMockModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.app_test", New: func() caddy.Module { return new(accessSignerMockModule) }}
}
func (m *accessSignerMockModule) Provision(caddy.Context) error {
	value, ok := accessSignerMockProbes.Load(m.Label)
	if !ok {
		return fmt.Errorf("missing signer probe")
	}
	m.probe = value.(*accessSignerMockProbe)
	m.probe.module = m
	return nil
}
func (m *accessSignerMockModule) Cleanup() error {
	if m.probe != nil {
		m.probe.cleaned++
	}
	return nil
}
func (m *accessSignerMockModule) PrepareAccessSigner() (AccessSignerFactory, error) {
	switch m.Failure {
	case "prepare_error":
		return nil, fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	case "prepare_panic":
		panic(accessSignerPrivateDiagnostic)
	case "prepare_nil":
		return nil, nil
	case "prepare_typed_nil":
		return (*accessSignerMockFactory)(nil), nil
	}
	policy := kms.AccessSignerPolicy{Algorithm: "PS256", KeyID: "current", TokenType: kms.AccessTokenType, Issuer: "https://auth.example.test/auth", Audience: "service-a", MaxLifetimeSeconds: 900}
	descriptor, err := kms.NewExternalAccessSignerConfig(m.Name, "app_test", policy, struct{ Label string }{m.Label})
	if err != nil {
		return nil, err
	}
	return &accessSignerMockFactory{config: *descriptor, failure: m.Failure, probe: m.probe}, nil
}

type accessSignerMockFactory struct {
	config  kms.ExternalAccessSignerConfig
	failure string
	probe   *accessSignerMockProbe
}

func (f *accessSignerMockFactory) AccessSignerConfig() (kms.ExternalAccessSignerConfig, error) {
	switch f.failure {
	case "descriptor_error":
		return kms.ExternalAccessSignerConfig{}, fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	case "descriptor_panic":
		panic(accessSignerPrivateDiagnostic)
	case "descriptor_invalid":
		copy := f.config
		copy.ConfigDigest = "bad"
		return copy, nil
	}
	return f.config, nil
}
func (f *accessSignerMockFactory) NewAccessSigner(context.Context) (kms.AccessSigner, error) {
	f.probe.constructed++
	switch f.failure {
	case "nil":
		return nil, nil
	case "typed_nil":
		return (*accessSignerMockRuntime)(nil), nil
	case "typed_nil_partial":
		return (*accessSignerMockRuntime)(nil), fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	}
	runtime := &accessSignerMockRuntime{config: f.config, failure: f.failure, probe: f.probe}
	f.probe.instances = append(f.probe.instances, runtime)
	if f.failure == "partial" {
		return runtime, fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	}
	if f.failure == "resource_free" {
		return &accessSignerResourceFree{inner: runtime}, nil
	}
	return runtime, nil
}

type accessSignerMockRuntime struct {
	config  kms.ExternalAccessSignerConfig
	failure string
	probe   *accessSignerMockProbe
	closed  bool
}

func (s *accessSignerMockRuntime) Sign(context.Context, map[string]any) (string, error) {
	return "", fmt.Errorf("not a signing fixture")
}
func (s *accessSignerMockRuntime) PublicJWKS() ([]byte, error) {
	return nil, fmt.Errorf("not a key fixture")
}
func (s *accessSignerMockRuntime) Metadata() (kms.AccessSignerMetadata, error) {
	switch s.failure {
	case "metadata_error":
		return kms.AccessSignerMetadata{}, fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	case "metadata_panic":
		panic(accessSignerPrivateDiagnostic)
	}
	out := kms.AccessSignerMetadata{Kind: s.config.Kind, ConfigDigest: s.config.ConfigDigest, Policy: s.config.Policy}
	switch s.failure {
	case "kind":
		out.Kind = "other"
	case "digest":
		out.ConfigDigest = strings.Repeat("0", 64)
	case "policy":
		out.Policy.Audience = "other"
	}
	return out, nil
}
func (s *accessSignerMockRuntime) Close() error {
	// Intentionally nil-unsafe: the host must contain only this cleanup boundary.
	s.closed = true
	s.probe.closes = append(s.probe.closes, s.config.Name)
	switch s.failure {
	case "close_panic":
		panic(accessSignerPrivateDiagnostic)
	case "close_error":
		return fmt.Errorf("%s", accessSignerPrivateDiagnostic)
	}
	return nil
}

type accessSignerResourceFree struct{ inner *accessSignerMockRuntime }

func (s *accessSignerResourceFree) Sign(ctx context.Context, c map[string]any) (string, error) {
	return s.inner.Sign(ctx, c)
}
func (s *accessSignerResourceFree) PublicJWKS() ([]byte, error) { return s.inner.PublicJWKS() }
func (s *accessSignerResourceFree) Metadata() (kms.AccessSignerMetadata, error) {
	return s.inner.Metadata()
}

type accessSignerWrongModule struct{}

func (accessSignerWrongModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "security.access_signers.app_wrong", New: func() caddy.Module { return new(accessSignerWrongModule) }}
}
func init() {
	caddy.RegisterModule(accessSignerMockModule{})
	caddy.RegisterModule(accessSignerWrongModule{})
}

func accessSignerMockApp(t *testing.T, failures ...string) (*App, caddy.Context, []*accessSignerMockProbe) {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	app := &App{}
	var probes []*accessSignerMockProbe
	for i, failure := range failures {
		label := fmt.Sprintf("%s/%d", t.Name(), i)
		probe := new(accessSignerMockProbe)
		accessSignerMockProbes.Store(label, probe)
		t.Cleanup(func() { accessSignerMockProbes.Delete(label) })
		probes = append(probes, probe)
		app.AccessSignerConfigs = append(app.AccessSignerConfigs, caddyconfig.JSONModuleObject(&accessSignerMockModule{Name: fmt.Sprintf("signer%d", i), Label: label, Failure: failure}, "driver", "app_test", nil))
	}
	return app, ctx, probes
}
func accessSignerCloseAll(t *testing.T, closers []io.Closer) {
	t.Helper()
	for _, closer := range slices.Backward(closers) {
		if err := closer.Close(); err != nil && strings.Contains(err.Error(), accessSignerPrivateDiagnostic) {
			t.Fatal("cleanup exposed plugin diagnostic")
		}
	}
}

func TestAppAccessSignerPreparation(t *testing.T) {
	app, ctx, probes := accessSignerMockApp(t, "")
	declared := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "signer0"}}}
	app.Config = declared
	before, _ := json.Marshal(app)
	resolved := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "signer0"}}}
	if err := app.prepareAccessSigners(ctx, resolved); err != nil {
		t.Fatal(err)
	}
	if len(resolved.ExternalAccessSigners) != 1 || len(app.accessSigners) != 1 || probes[0].constructed != 0 {
		t.Fatal("preparation did not freeze metadata without construction")
	}
	resolved.ExternalAccessSigners[0].Policy.Audience = "changed"
	if app.accessSigners[0].config.Policy.Audience != "service-a" {
		t.Fatal("root descriptor aliases private factory snapshot")
	}
	after, _ := json.Marshal(app)
	if !bytes.Equal(before, after) {
		t.Fatal("preparation mutated declarative App or raw modules")
	}
	probes[0].module.Name = "changed"
	probes[0].module.Failure = "nil"
	handles, closers, err := app.attachAccessSigners(t.Context())
	if err != nil || len(closers) != 1 || handles["signer0"] != probes[0].instances[0] {
		t.Fatal("factory lost exact instance or read mutated module")
	}
	second, secondClosers, err := app.attachAccessSigners(t.Context())
	if err != nil || second["signer0"] == handles["signer0"] {
		t.Fatal("factory reused an owned runtime")
	}
	accessSignerCloseAll(t, secondClosers)
	accessSignerCloseAll(t, closers)
	if probes[0].constructed != 2 || !slices.Equal(probes[0].closes, []string{"signer0", "signer0"}) {
		t.Fatal("runtime ownership was not independent")
	}
}

func TestAppAccessSignerPreflightRejects(t *testing.T) {
	for _, failure := range []string{"prepare_error", "prepare_panic", "prepare_nil", "prepare_typed_nil", "descriptor_error", "descriptor_panic", "descriptor_invalid", "duplicate", "unknown_selection", "native_descriptor", "wrong_interface", "bad_raw_utf8"} {
		t.Run(failure, func(t *testing.T) {
			mode := failure
			if slices.Contains([]string{"duplicate", "unknown_selection", "native_descriptor", "wrong_interface", "bad_raw_utf8"}, failure) {
				mode = ""
			}
			app, ctx, probes := accessSignerMockApp(t, mode)
			config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "signer0"}}}
			switch failure {
			case "duplicate":
				app.AccessSignerConfigs = append(app.AccessSignerConfigs, slices.Clone(app.AccessSignerConfigs[0]))
			case "unknown_selection":
				config.AuthenticationPortals[0].AccessSigner = "absent"
			case "native_descriptor":
				config.ExternalAccessSigners = []*kms.ExternalAccessSignerConfig{nil}
			case "wrong_interface":
				app.AccessSignerConfigs = []json.RawMessage{json.RawMessage(`{"driver":"app_wrong"}`)}
			case "bad_raw_utf8":
				app.AccessSignerConfigs = []json.RawMessage{[]byte("{\"driver\":\"rsapss\",\"name\":\"\xff\"}")}
			}
			rawBefore := slices.Clone(app.AccessSignerConfigs[0])
			before, _ := json.Marshal(config)
			err := app.prepareAccessSigners(ctx, config)
			if err == nil || strings.Contains(err.Error(), accessSignerPrivateDiagnostic) {
				t.Fatal("invalid signer preflight accepted or disclosed")
			}
			after, _ := json.Marshal(config)
			if !bytes.Equal(before, after) || !bytes.Equal(rawBefore, app.AccessSignerConfigs[0]) || len(app.accessSigners) != 0 || probes[0].constructed != 0 {
				t.Fatal("rejected candidate mutated config or constructed runtime")
			}
		})
	}
	app, ctx, _ := accessSignerMockApp(t)
	config := &authcrunch.Config{AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", AccessSigner: "absent"}}}
	if app.prepareAccessSigners(ctx, config) == nil {
		t.Fatal("missing selection accepted without modules")
	}
}

func TestAppAccessSignerRuntimeFailures(t *testing.T) {
	for _, failure := range []string{"nil", "typed_nil", "typed_nil_partial", "partial", "metadata_error", "metadata_panic", "kind", "digest", "policy"} {
		t.Run(failure, func(t *testing.T) {
			app, ctx, probes := accessSignerMockApp(t, "close_panic", failure, "")
			config := &authcrunch.Config{}
			if app.prepareAccessSigners(ctx, config) != nil {
				t.Fatal("cannot prepare failure fixture")
			}
			handles, closers, err := app.attachAccessSigners(t.Context())
			if err == nil || handles != nil || strings.Contains(err.Error(), accessSignerPrivateDiagnostic) {
				t.Fatal("invalid runtime accepted or disclosed")
			}
			expected := 2
			if failure == "nil" {
				expected = 1
			}
			if len(closers) != expected || probes[2].constructed != 0 {
				t.Fatal("partial acquisition was lost or construction continued")
			}
			accessSignerCloseAll(t, closers)
			if !probes[0].instances[0].closed {
				t.Fatal("later cleanup error prevented earlier release")
			}
			if len(probes[1].instances) > 0 && !probes[1].instances[0].closed {
				t.Fatal("partial failed runtime leaked")
			}
		})
	}
}

func TestAppAccessSignerOptionalCloser(t *testing.T) {
	app, ctx, probes := accessSignerMockApp(t, "resource_free", "close_error", "")
	if app.prepareAccessSigners(ctx, &authcrunch.Config{}) != nil {
		t.Fatal("cannot prepare closer fixture")
	}
	handles, closers, err := app.attachAccessSigners(t.Context())
	if err != nil || len(handles) != 3 || len(closers) != 2 {
		t.Fatal("optional closer contract rejected")
	}
	order := []string{}
	for i, closer := range slices.Backward(closers) {
		err := closer.Close()
		if err != nil && strings.Contains(err.Error(), accessSignerPrivateDiagnostic) {
			t.Fatal("cleanup diagnostic leaked")
		}
		order = append(order, probes[i+1].closes...)
	}
	if !slices.Equal(order, []string{"signer2", "signer1"}) || probes[0].instances[0].closed {
		t.Fatal("cleanup order or optional ownership changed")
	}
}

var _ kms.AccessSigner = (*accessSignerMockRuntime)(nil)
